//! Hand-rolled UTC date helpers for budget accumulator period keys (M2.5.3).
//!
//! No external date crate is used anywhere in the fabric workspace; these
//! functions compute day and ISO-8601 week keys from the hub's UTC timestamp
//! strings using integer arithmetic only.
//!
//! ## Parity contract with the Python oracle
//!
//! The Python `BudgetEnforcer` keys accumulators as:
//! - day  = `datetime.strftime("%Y-%m-%d")`           → `"YYYY-MM-DD"`
//! - week = `f"{iso.year}-W{iso.week:02d}"` from `datetime.isocalendar()`
//!          → `"YYYY-WNN"` using the **ISO year** (not the calendar year) and
//!          a zero-padded 2-digit ISO week number.
//!
//! These functions must produce byte-identical keys to the Python forms above
//! for every UTC instant, so the Rust hub's `budget_state` rows and the Python
//! enforcer's in-memory totals agree.
//!
//! Hub timestamps are formatted `"YYYY-MM-DD HH:MM:SS"` (UTC, space-separated),
//! so the day key is simply the first 10 characters and the ISO week is derived
//! from the parsed year/month/day.

/// Days from the civil date (proleptic Gregorian) to 1970-01-01.
///
/// Howard Hinnant's `days_from_civil` algorithm. Correct for any year; we only
/// ever feed it post-1970 dates, but the algorithm itself handles all eras.
/// Returns the signed day count (0 for 1970-01-01).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = (m + if m > 2 { -3 } else { 9 }) % 12; // Mar=0..Feb=11
    let doy = (153 * mp + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146097 + doe - 719468
}

/// ISO weekday for a day-count: Monday = 1 … Sunday = 7.
///
/// 1970-01-01 (day 0) was a Thursday → 4.
fn iso_weekday(days: i64) -> i64 {
    (days + 3).rem_euclid(7) + 1
}

/// `(y + y/4 - y/100 + y/400) mod 7`, used to decide 52- vs 53-week years.
fn p(y: i64) -> i64 {
    (y + y.div_euclid(4) - y.div_euclid(100) + y.div_euclid(400)).rem_euclid(7)
}

/// Number of ISO weeks in the given ISO year: 53 if the year "long", else 52.
fn weeks_in_year(y: i64) -> i64 {
    if p(y) == 4 || p(y - 1) == 3 {
        53
    } else {
        52
    }
}

/// Parse the `YYYY-MM-DD` prefix of a hub timestamp into `(year, month, day)`.
///
/// Returns `None` if the string is too short or the prefix is not numeric in
/// the expected positions. Callers treat `None` as "unparseable" and fall back.
fn parse_ymd(now: &str) -> Option<(i64, i64, i64)> {
    let b = now.as_bytes();
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let digits = |start: usize, len: usize| -> Option<i64> {
        let mut v: i64 = 0;
        for &c in &b[start..start + len] {
            if !c.is_ascii_digit() {
                return None;
            }
            v = v * 10 + (c - b'0') as i64;
        }
        Some(v)
    };
    let y = digits(0, 4)?;
    let m = digits(5, 2)?;
    let d = digits(8, 2)?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some((y, m, d))
}

/// Day key `"YYYY-MM-DD"` — the first 10 characters of a hub UTC timestamp.
///
/// Falls back to the whole trimmed string if it is shorter than 10 chars
/// (never expected for hub timestamps, but keeps the function total).
pub fn day_key(now: &str) -> String {
    if now.len() >= 10 {
        now[..10].to_owned()
    } else {
        now.to_owned()
    }
}

/// ISO-8601 week key `"YYYY-WNN"` using the ISO year and 2-digit ISO week.
///
/// Byte-identical to the Python `f"{iso.year}-W{iso.week:02d}"` form. If the
/// timestamp cannot be parsed, falls back to the day key so a row is still
/// written under *some* stable key rather than being dropped.
pub fn iso_week_key(now: &str) -> String {
    let Some((y, m, d)) = parse_ymd(now) else {
        return day_key(now);
    };
    let days = days_from_civil(y, m, d);
    let wd = iso_weekday(days);
    let ordinal = days - days_from_civil(y, 1, 1) + 1; // 1-based day of year
    let mut week = (ordinal - wd + 10) / 7;
    let mut iso_year = y;
    if week < 1 {
        iso_year = y - 1;
        week = weeks_in_year(iso_year);
    } else if week > weeks_in_year(y) {
        iso_year = y + 1;
        week = 1;
    }
    format!("{iso_year}-W{week:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_is_thursday() {
        // 1970-01-01 is day 0 and a Thursday (ISO weekday 4).
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(iso_weekday(0), 4);
    }

    #[test]
    fn weekday_round_trip() {
        // 1970-01-05 Monday, 1970-01-04 Sunday.
        assert_eq!(iso_weekday(days_from_civil(1970, 1, 5)), 1);
        assert_eq!(iso_weekday(days_from_civil(1970, 1, 4)), 7);
    }

    #[test]
    fn day_key_takes_first_ten() {
        assert_eq!(day_key("2026-06-04 10:09:09"), "2026-06-04");
        assert_eq!(day_key("2026-06-04T10:09:09Z"), "2026-06-04");
    }

    /// Canonical ISO-8601 week-date edge cases (Wikipedia reference table).
    /// These are the year-boundary cases where the ISO year differs from the
    /// calendar year, plus the 53-week-year cases.
    #[test]
    fn iso_week_canonical_edge_cases() {
        let cases = [
            ("2005-01-01", "2004-W53"),
            ("2005-01-02", "2004-W53"),
            ("2005-12-31", "2005-W52"),
            ("2006-01-01", "2005-W52"),
            ("2006-01-02", "2006-W01"),
            ("2007-01-01", "2007-W01"),
            ("2007-12-30", "2007-W52"),
            ("2007-12-31", "2008-W01"),
            ("2008-01-01", "2008-W01"),
            ("2008-12-28", "2008-W52"),
            ("2008-12-29", "2009-W01"),
            ("2008-12-31", "2009-W01"),
            ("2009-01-01", "2009-W01"),
            ("2009-12-31", "2009-W53"),
            ("2010-01-01", "2009-W53"),
            ("2010-01-03", "2009-W53"),
            ("2010-01-04", "2010-W01"),
            // Additional 53-week years and boundaries.
            ("2015-12-31", "2015-W53"),
            ("2016-01-01", "2015-W53"),
            ("2016-01-04", "2016-W01"),
            ("2020-12-31", "2020-W53"),
            ("2021-01-01", "2020-W53"),
            ("2021-01-04", "2021-W01"),
            ("2023-01-01", "2022-W52"),
            ("2024-12-30", "2025-W01"),
            ("2026-01-01", "2026-W01"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                iso_week_key(&format!("{input} 12:00:00")),
                expected,
                "iso_week_key({input})"
            );
        }
    }

    #[test]
    fn iso_week_is_two_digits() {
        // 2026-01-01 is a Thursday, so ISO week 1 of 2026 spans Mon 2025-12-29
        // .. Sun 2026-01-04; Mon 2026-01-05 begins W02. Weeks are zero-padded
        // to two digits to match Python's :02d.
        assert_eq!(iso_week_key("2026-01-04 00:00:00"), "2026-W01");
        assert_eq!(iso_week_key("2026-01-05 00:00:00"), "2026-W02");
        assert!(iso_week_key("2026-06-04 00:00:00").contains("-W"));
    }

    #[test]
    fn unparseable_falls_back_to_day_key() {
        // "not-a-date" is exactly 10 chars but b[4] != '-', so parsing fails
        // and day_key returns the first 10 chars unchanged.
        assert_eq!(iso_week_key("not-a-date"), "not-a-date");
        assert_eq!(iso_week_key("short"), "short");
    }
}
