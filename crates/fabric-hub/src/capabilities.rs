//! Capability predicate parser/evaluator ported from the retired Python hub.

use serde_json::Value;

#[derive(Debug, Clone, PartialEq)]
struct Predicate {
    raw: String,
    path: String,
    op: Option<String>,
    literal: Option<Value>,
}

fn parse(expr: &str) -> Result<Predicate, String> {
    let text = expr.trim();
    if text.is_empty() {
        return Err("empty capability predicate".into());
    }
    for op in ["==", "!=", ">=", "<=", ">", "<", "~=", " in "] {
        if let Some(idx) = text.find(op) {
            let lhs = text[..idx].trim();
            let rhs = text[idx + op.len()..].trim();
            if op == " in " {
                return Ok(Predicate {
                    raw: text.into(),
                    path: rhs.into(),
                    op: Some("in".into()),
                    literal: Some(parse_literal(lhs)),
                });
            }
            return Ok(Predicate {
                raw: text.into(),
                path: lhs.into(),
                op: Some(op.into()),
                literal: Some(parse_literal(rhs)),
            });
        }
    }
    Ok(Predicate {
        raw: text.into(),
        path: text.into(),
        op: None,
        literal: None,
    })
}

fn parse_literal(token: &str) -> Value {
    let trimmed = token.trim();
    let unquoted = if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
    {
        &trimmed[1..trimmed.len().saturating_sub(1)]
    } else {
        trimmed
    };
    if let Ok(value) = unquoted.parse::<i64>() {
        return Value::from(value);
    }
    if unquoted.matches('.').count() == 1 {
        if let Ok(value) = unquoted.parse::<f64>() {
            return Value::from(value);
        }
    }
    Value::from(unquoted)
}

fn resolve<'a>(caps: &'a Value, path: &str) -> Option<Value> {
    let mut current = caps;
    for part in path.split('.').filter(|part| !part.is_empty()) {
        match current {
            Value::Object(map) => current = map.get(part)?,
            Value::Array(values) => {
                return Some(Value::Bool(
                    values.iter().any(|value| value.as_str() == Some(part)),
                ));
            }
            Value::String(label) => {
                let lower = label.to_lowercase();
                let target = part.to_lowercase();
                let (_, tail) = lower.split_once(&target)?;
                let version = tail
                    .trim_start_matches([':', '-'])
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_end_matches([',', ';', ')']);
                return Some(if version.is_empty() {
                    Value::Bool(true)
                } else {
                    Value::String(version.into())
                });
            }
            _ => return None,
        }
    }
    Some(current.clone())
}

fn display(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}

fn version_tuple(value: &Value) -> Option<Vec<u64>> {
    let text = display(value);
    if text.trim().is_empty() {
        return None;
    }
    text.split('.')
        .map(|part| {
            let digits: String = part.chars().filter(char::is_ascii_digit).collect();
            (!digits.is_empty())
                .then(|| digits.parse::<u64>().ok())
                .flatten()
        })
        .collect()
}

fn compare_ordered(value: &Value, literal: &Value, op: &str) -> Option<bool> {
    if let (Some(a), Some(b)) = (value.as_f64(), literal.as_f64()) {
        return Some(match op {
            ">=" => a >= b,
            ">" => a > b,
            "<=" => a <= b,
            "<" => a < b,
            _ => false,
        });
    }
    let mut a = version_tuple(value)?;
    let mut b = version_tuple(literal)?;
    let width = a.len().max(b.len());
    a.resize(width, 0);
    b.resize(width, 0);
    Some(match op {
        ">=" => a >= b,
        ">" => a > b,
        "<=" => a <= b,
        "<" => a < b,
        _ => false,
    })
}

fn evaluate(predicate: &Predicate, caps: &Value) -> Result<(), String> {
    let Some(value) = resolve(caps, &predicate.path) else {
        return Err(format!("missing {}", predicate.path));
    };
    let Some(op) = predicate.op.as_deref() else {
        let present = match &value {
            Value::Null | Value::Bool(false) => false,
            Value::String(v) => !v.is_empty(),
            Value::Array(v) => !v.is_empty(),
            Value::Object(v) => !v.is_empty(),
            _ => true,
        };
        return present
            .then_some(())
            .ok_or_else(|| format!("empty {}", predicate.path));
    };
    let literal = predicate.literal.as_ref().expect("comparison literal");
    let ok = match op {
        "in" => match &value {
            Value::Array(values) => values.iter().any(|item| item == literal),
            Value::String(text) => text.contains(&display(literal)),
            _ => return Err(format!("{} not iterable", predicate.path)),
        },
        "==" => display(&value) == display(literal),
        "!=" => display(&value) != display(literal),
        "~=" => {
            let a = version_tuple(&value);
            let b = version_tuple(literal);
            match (a, b) {
                (Some(a), Some(b)) if b.len() >= 2 && !a.is_empty() => {
                    a[0] == b[0] && compare_ordered(&value, literal, ">=").unwrap_or(false)
                }
                _ => false,
            }
        }
        ">=" | ">" | "<=" | "<" => compare_ordered(&value, literal, op).unwrap_or(false),
        _ => false,
    };
    ok.then_some(()).ok_or_else(|| {
        format!(
            "{}={} {} {} failed",
            predicate.path,
            display(&value),
            op,
            display(literal)
        )
    })
}

pub(crate) fn match_required(required: &Value, caps: &Value) -> (bool, Vec<String>) {
    let mut missing = Vec::new();
    for raw in required
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        match parse(raw).and_then(|predicate| evaluate(&predicate, caps)) {
            Ok(()) => {}
            Err(reason) => missing.push(reason),
        }
    }
    (missing.is_empty(), missing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn matches_presence_membership_versions_and_gpu_labels() {
        let caps = json!({
            "toolchains": ["rust", "node"],
            "python": "3.13.1",
            "ram_gb": 64,
            "cpu": {"cores": 16},
            "gpu": "nvidia:cuda:12.4"
        });
        let (ok, missing) = match_required(
            &json!([
                "toolchains.rust",
                "python ~= 3.12",
                "ram_gb >= 32",
                "cpu.cores >= 8",
                "gpu.cuda >= 12"
            ]),
            &caps,
        );
        assert!(ok, "{missing:?}");
    }

    #[test]
    fn reports_each_failed_predicate_without_panicking() {
        let (ok, missing) = match_required(
            &json!(["toolchains.go", "ram_gb >= 128", ""]),
            &json!({"toolchains": ["rust"], "ram_gb": 8}),
        );
        assert!(!ok);
        assert_eq!(missing.len(), 3);
    }
}
