//! Cost ledger routes (M2.5.2).
//!
//! GET /cost/summary[?since_days=7]     — aggregated spend by model + day
//! GET /cost/records[?since_days=30&limit=500] — raw rows newest-first
//! GET /cost/budget                      — current period spend (no caps — hub policy in Python)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::HubState;
use fabric_store::CostStore;

#[derive(Deserialize)]
pub struct SinceQuery {
    pub since_days: Option<i64>,
    pub limit: Option<i64>,
}

fn since_iso(days: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let cutoff = now - days * 86400;
    epoch_to_iso(cutoff)
}

fn epoch_to_iso(ts: i64) -> String {
    let ts = ts as u64;
    let secs = ts % 60;
    let mins = (ts / 60) % 60;
    let hours = (ts / 3600) % 24;
    let mut days = (ts / 86400) as i64;
    let mut year = 1970i64;
    loop {
        let diy = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if days < diy { break; }
        days -= diy;
        year += 1;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let md = [31i64, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0usize;
    for (i, &m) in md.iter().enumerate() {
        if days < m { month = i; break; }
        days -= m;
    }
    format!("{year:04}-{:02}-{:02} 00:00:00", month + 1, days + 1)
}

fn today_str() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let iso = epoch_to_iso(now);
    iso[..10].to_owned()
}

fn this_week_str() -> String {
    // Simple ISO week: YYYY-WNN
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days_since_epoch = now / 86400;
    // Jan 1 1970 was a Thursday (day 3, 0=Mon). ISO week starts Monday.
    let dow = ((days_since_epoch + 3) % 7) as i64; // 0=Mon
    let monday = now - dow * 86400;
    let week_iso = epoch_to_iso(monday);
    // Approximate week number from Jan 1
    let year_str = &week_iso[..4];
    let year: i64 = year_str.parse().unwrap_or(1970);
    let jan1_dow = {
        // Day of week for Jan 1 of this year
        let mut y = year - 1;
        let mut d = 365 * y + y / 4 - y / 100 + y / 400 + 1;
        ((d + 3) % 7) as i64
    };
    let day_of_year: i64 = (days_since_epoch - (monday - dow * 86400) / 86400).max(0) / 7 + 1;
    format!("{year:04}-W{:02}", day_of_year.max(1).min(53))
}

pub async fn cost_summary(
    State(state): State<Arc<HubState>>,
    Query(q): Query<SinceQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let days = q.since_days.unwrap_or(7).max(0);
    let since = if days > 0 { Some(since_iso(days)) } else { None };
    let rows = state
        .store
        .query_cost(since.as_deref(), 100_000)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut by_model: HashMap<String, (f64, i64)> = HashMap::new();
    let mut by_day: HashMap<String, (f64, i64)> = HashMap::new();
    let mut total_cost = 0.0f64;
    let mut total_tokens = 0i64;
    let mut total_wall = 0.0f64;

    for r in &rows {
        let tokens = r.prompt_tokens + r.completion_tokens;
        total_cost += r.cost_usd;
        total_tokens += tokens;
        total_wall += r.wall_seconds;
        let e = by_model.entry(r.model_id.clone()).or_default();
        e.0 += r.cost_usd; e.1 += tokens;
        let day = r.created_at.get(..10).unwrap_or("").to_owned();
        let e = by_day.entry(day).or_default();
        e.0 += r.cost_usd; e.1 += tokens;
    }

    let by_model_json: serde_json::Map<String, Value> = by_model
        .into_iter()
        .map(|(k, (c, t))| (k, json!({"cost_usd": (c * 1_000_000.0).round() / 1_000_000.0, "tokens": t})))
        .collect();
    let mut by_day_sorted: Vec<(String, (f64, i64))> = by_day.into_iter().collect();
    by_day_sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let by_day_json: serde_json::Map<String, Value> = by_day_sorted
        .into_iter()
        .map(|(k, (c, t))| (k, json!({"cost_usd": (c * 1_000_000.0).round() / 1_000_000.0, "tokens": t})))
        .collect();

    Ok(Json(json!({
        "since_days": days,
        "total_cost_usd": (total_cost * 1_000_000.0).round() / 1_000_000.0,
        "total_tokens": total_tokens,
        "total_wall_seconds": (total_wall * 100.0).round() / 100.0,
        "record_count": rows.len(),
        "by_model": by_model_json,
        "by_day": by_day_json,
    })))
}

pub async fn cost_records(
    State(state): State<Arc<HubState>>,
    Query(q): Query<SinceQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let days = q.since_days.unwrap_or(30).max(0);
    let limit = q.limit.unwrap_or(500).min(10_000);
    let since = if days > 0 { Some(since_iso(days)) } else { None };
    let rows = state
        .store
        .query_cost(since.as_deref(), limit)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({
        "records": rows,
        "count": rows.len(),
        "since_days": days,
    })))
}

pub async fn cost_budget(
    State(state): State<Arc<HubState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    // Compute today and this-week totals from the ledger.
    let today = today_str();
    let week = this_week_str();
    let today_since = format!("{today} 00:00:00");
    let week_since = since_iso(7); // approximate; precise week computed client-side

    let today_rows = state.store.query_cost(Some(&today_since), 100_000).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let week_rows = state.store.query_cost(Some(&week_since), 100_000).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let daily_spend: f64 = today_rows.iter().map(|r| r.cost_usd).sum();
    let weekly_spend: f64 = week_rows.iter().map(|r| r.cost_usd).sum();

    Ok(Json(json!({
        "today": today,
        "week": week,
        "daily_spend_usd": (daily_spend * 1_000_000.0).round() / 1_000_000.0,
        "weekly_spend_usd": (weekly_spend * 1_000_000.0).round() / 1_000_000.0,
    })))
}
