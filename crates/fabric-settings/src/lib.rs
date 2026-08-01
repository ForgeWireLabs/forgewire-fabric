//! Three-tier settings resolution for Fabric.
//!
//! Immutable binary defaults are overlaid by a hub-wide rqlite document and
//! finally by a repo/task policy snapshot. Persistence and audit remain Hub
//! concerns; this crate owns validation, deterministic merge, and redaction.

#![deny(rust_2018_idioms)]

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

const DEFAULTS_JSON: &str = include_str!("../config/settings.defaults.json");
const SCHEMA_JSON: &str = include_str!("../schemas/settings.schema.json");
const REDACTED: &str = "[REDACTED]";

#[derive(Debug, Error)]
pub enum SettingsError {
    #[error("settings document is invalid JSON: {0}")]
    InvalidJson(String),
    #[error("unknown settings key: {0}")]
    UnknownKey(String),
    #[error("settings key is read-only: {0}")]
    ReadOnly(String),
    #[error("settings value for {key} has type {actual}; expected {expected}")]
    TypeMismatch {
        key: String,
        expected: &'static str,
        actual: &'static str,
    },
    #[error("settings root must be an object")]
    RootNotObject,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct SettingsSnapshot {
    pub revision: i64,
    pub defaults: Value,
    pub hub: Value,
    pub repo: Value,
    pub effective: Value,
}

impl Serialize for SettingsSnapshot {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let redact = |value: &Value| redact_value(value).map_err(serde::ser::Error::custom);
        #[derive(Serialize)]
        struct Safe {
            revision: i64,
            defaults: Value,
            hub: Value,
            repo: Value,
            effective: Value,
        }
        Safe {
            revision: self.revision,
            defaults: redact(&self.defaults)?,
            hub: redact(&self.hub)?,
            repo: redact(&self.repo)?,
            effective: redact(&self.effective)?,
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SettingsChange {
    pub key: String,
    pub before: Value,
    pub after: Value,
}

impl SettingsSnapshot {
    pub fn new(revision: i64, hub: Value, repo: Value) -> Result<Self, SettingsError> {
        let defaults = defaults()?;
        validate_overlay(&defaults, &hub, "")?;
        validate_overlay(&defaults, &repo, "")?;
        let mut effective = defaults.clone();
        merge(&mut effective, &hub);
        merge(&mut effective, &repo);
        derive_read_only(&mut effective);
        Ok(Self {
            revision,
            defaults,
            hub,
            repo,
            effective,
        })
    }

    pub fn get(&self, key: &str, show_sensitive: bool) -> Result<Value, SettingsError> {
        let value = pointer(&self.effective, key)
            .cloned()
            .ok_or_else(|| SettingsError::UnknownKey(key.to_owned()))?;
        if !show_sensitive && sensitive_paths()?.iter().any(|path| path == key) {
            Ok(Value::String(REDACTED.to_owned()))
        } else {
            Ok(value)
        }
    }

    pub fn redacted_effective(&self) -> Result<Value, SettingsError> {
        let mut value = self.effective.clone();
        for path in sensitive_paths()? {
            if let Some(slot) = pointer_mut(&mut value, &path) {
                if !slot.is_null() {
                    *slot = Value::String(REDACTED.to_owned());
                }
            }
        }
        Ok(value)
    }

    pub fn set_hub(&self, key: &str, value: Value) -> Result<Self, SettingsError> {
        if read_only_paths()?.iter().any(|path| path == key) {
            return Err(SettingsError::ReadOnly(key.to_owned()));
        }
        let expected = pointer(&self.defaults, key)
            .ok_or_else(|| SettingsError::UnknownKey(key.to_owned()))?;
        validate_value(key, expected, &value)?;
        let mut hub = self.hub.clone();
        set_pointer(&mut hub, key, value)?;
        Self::new(self.revision + 1, hub, self.repo.clone())
    }

    pub fn reset_hub(&self, key: &str) -> Result<Self, SettingsError> {
        if read_only_paths()?.iter().any(|path| path == key) {
            return Err(SettingsError::ReadOnly(key.to_owned()));
        }
        if pointer(&self.defaults, key).is_none() {
            return Err(SettingsError::UnknownKey(key.to_owned()));
        }
        let mut hub = self.hub.clone();
        remove_pointer(&mut hub, key);
        Self::new(self.revision + 1, hub, self.repo.clone())
    }

    pub fn import_hub(&self, hub: Value) -> Result<(Self, Vec<SettingsChange>), SettingsError> {
        let next = Self::new(self.revision + 1, hub, self.repo.clone())?;
        let mut changes = Vec::new();
        diff_values("", &self.effective, &next.effective, &mut changes)?;
        Ok((next, changes))
    }
}

fn redact_value(value: &Value) -> Result<Value, SettingsError> {
    let mut value = value.clone();
    for path in sensitive_paths()? {
        if let Some(slot) = pointer_mut(&mut value, &path) {
            if !slot.is_null() {
                *slot = Value::String(REDACTED.into());
            }
        }
    }
    Ok(value)
}

fn diff_values(
    prefix: &str,
    before: &Value,
    after: &Value,
    out: &mut Vec<SettingsChange>,
) -> Result<(), SettingsError> {
    if before == after {
        return Ok(());
    }
    if let (Some(a), Some(b)) = (before.as_object(), after.as_object()) {
        let mut keys: Vec<_> = a.keys().chain(b.keys()).collect();
        keys.sort();
        keys.dedup();
        for key in keys {
            let path = if prefix.is_empty() {
                key.clone()
            } else {
                format!("{prefix}.{key}")
            };
            diff_values(
                &path,
                a.get(key).unwrap_or(&Value::Null),
                b.get(key).unwrap_or(&Value::Null),
                out,
            )?;
        }
    } else {
        let sensitive = sensitive_paths()?.iter().any(|p| p == prefix);
        out.push(SettingsChange {
            key: prefix.into(),
            before: if sensitive && !before.is_null() {
                Value::String(REDACTED.into())
            } else {
                before.clone()
            },
            after: if sensitive && !after.is_null() {
                Value::String(REDACTED.into())
            } else {
                after.clone()
            },
        });
    }
    Ok(())
}

pub fn defaults() -> Result<Value, SettingsError> {
    serde_json::from_str(DEFAULTS_JSON)
        .map_err(|error| SettingsError::InvalidJson(error.to_string()))
}

pub fn schema() -> Result<Value, SettingsError> {
    serde_json::from_str(SCHEMA_JSON).map_err(|error| SettingsError::InvalidJson(error.to_string()))
}

fn merge(base: &mut Value, overlay: &Value) {
    match (base, overlay) {
        (Value::Object(base), Value::Object(overlay)) => {
            for (key, value) in overlay {
                if let Some(base_value) = base.get_mut(key) {
                    merge(base_value, value);
                } else {
                    base.insert(key.clone(), value.clone());
                }
            }
        }
        (base, overlay) => *base = overlay.clone(),
    }
}

fn validate_overlay(defaults: &Value, overlay: &Value, prefix: &str) -> Result<(), SettingsError> {
    let Some(entries) = overlay.as_object() else {
        return Err(SettingsError::RootNotObject);
    };
    let defaults = defaults.as_object().ok_or(SettingsError::RootNotObject)?;
    for (key, value) in entries {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        let expected = defaults
            .get(key)
            .ok_or_else(|| SettingsError::UnknownKey(path.clone()))?;
        if expected.is_object() && value.is_object() {
            validate_overlay(expected, value, &path)?;
        } else {
            validate_value(&path, expected, value)?;
        }
    }
    Ok(())
}

fn validate_value(key: &str, _expected: &Value, actual: &Value) -> Result<(), SettingsError> {
    let node = schema_for_path(key)?;
    let actual_type = value_type(actual);
    let compatible = node.get("type").is_some_and(|types| {
        types == actual_type
            || (types == "integer" && (actual.as_i64().is_some() || actual.as_u64().is_some()))
            || types.as_array().is_some_and(|allowed| {
                allowed.iter().any(|kind| {
                    kind == actual_type
                        || (kind == "integer"
                            && (actual.as_i64().is_some() || actual.as_u64().is_some()))
                })
            })
    });
    if compatible {
        if node.get("const").is_some_and(|constant| constant != actual) {
            return Err(SettingsError::TypeMismatch {
                key: key.into(),
                expected: "schema constant",
                actual: value_type(actual),
            });
        }
        if let Some(values) = node.get("enum").and_then(Value::as_array) {
            if !values.contains(actual) {
                return Err(SettingsError::TypeMismatch {
                    key: key.into(),
                    expected: "allowed enum value",
                    actual: value_type(actual),
                });
            }
        }
        if let Some(number) = actual.as_f64() {
            if node
                .get("minimum")
                .and_then(Value::as_f64)
                .is_some_and(|m| number < m)
                || node
                    .get("maximum")
                    .and_then(Value::as_f64)
                    .is_some_and(|m| number > m)
            {
                return Err(SettingsError::TypeMismatch {
                    key: key.into(),
                    expected: "number within schema bounds",
                    actual: "number",
                });
            }
            if node
                .get("exclusiveMinimum")
                .and_then(Value::as_f64)
                .is_some_and(|m| number <= m)
            {
                return Err(SettingsError::TypeMismatch {
                    key: key.into(),
                    expected: "number above schema minimum",
                    actual: "number",
                });
            }
        }
        if let Some(items) = actual.as_array() {
            if node.get("uniqueItems").and_then(Value::as_bool) == Some(true)
                && items
                    .iter()
                    .enumerate()
                    .any(|(i, v)| items[..i].contains(v))
            {
                return Err(SettingsError::TypeMismatch {
                    key: key.into(),
                    expected: "unique array values",
                    actual: "array",
                });
            }
            if node.pointer("/items/type") == Some(&Value::String("string".into()))
                && items
                    .iter()
                    .any(|v| !v.is_string() || v.as_str().is_some_and(str::is_empty))
            {
                return Err(SettingsError::TypeMismatch {
                    key: key.into(),
                    expected: "non-empty string array",
                    actual: "array",
                });
            }
        }
        if node.get("format") == Some(&Value::String("uri".into()))
            && actual.as_str().is_some_and(|v| !v.contains("://"))
        {
            return Err(SettingsError::TypeMismatch {
                key: key.into(),
                expected: "URI",
                actual: "string",
            });
        }
        Ok(())
    } else {
        Err(SettingsError::TypeMismatch {
            key: key.to_owned(),
            expected: "schema-declared type",
            actual: value_type(actual),
        })
    }
}

fn schema_for_path(key: &str) -> Result<Value, SettingsError> {
    let mut node = schema()?;
    for segment in key.split('.') {
        node = node
            .get("properties")
            .and_then(|v| v.get(segment))
            .cloned()
            .ok_or_else(|| SettingsError::UnknownKey(key.into()))?;
    }
    Ok(node)
}

fn value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn pointer<'a>(root: &'a Value, key: &str) -> Option<&'a Value> {
    key.split('.')
        .try_fold(root, |value, segment| value.get(segment))
}

fn pointer_mut<'a>(root: &'a mut Value, key: &str) -> Option<&'a mut Value> {
    let mut current = root;
    for segment in key.split('.') {
        current = current.get_mut(segment)?;
    }
    Some(current)
}

fn set_pointer(root: &mut Value, key: &str, value: Value) -> Result<(), SettingsError> {
    let segments: Vec<&str> = key.split('.').collect();
    let Some((last, parents)) = segments.split_last() else {
        return Err(SettingsError::UnknownKey(key.to_owned()));
    };
    let mut current = root.as_object_mut().ok_or(SettingsError::RootNotObject)?;
    for segment in parents {
        let entry = current
            .entry((*segment).to_owned())
            .or_insert_with(|| Value::Object(Map::new()));
        let actual = value_type(entry);
        current = entry.as_object_mut().ok_or(SettingsError::TypeMismatch {
            key: key.to_owned(),
            expected: "object",
            actual,
        })?;
    }
    current.insert((*last).to_owned(), value);
    Ok(())
}

fn remove_pointer(root: &mut Value, key: &str) {
    let segments: Vec<&str> = key.split('.').collect();
    let Some((last, parents)) = segments.split_last() else {
        return;
    };
    let mut current = root;
    for segment in parents {
        let Some(next) = current.get_mut(segment) else {
            return;
        };
        current = next;
    }
    if let Some(entries) = current.as_object_mut() {
        entries.remove(*last);
    }
}

fn schema_paths(flag: &str) -> Result<Vec<String>, SettingsError> {
    fn walk(node: &Value, prefix: &str, flag: &str, out: &mut Vec<String>) {
        if node.get(flag).and_then(Value::as_bool).unwrap_or(false) && !prefix.is_empty() {
            out.push(prefix.to_owned());
        }
        if let Some(properties) = node.get("properties").and_then(Value::as_object) {
            for (key, child) in properties {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                walk(child, &path, flag, out);
            }
        }
    }
    let mut paths = Vec::new();
    walk(&schema()?, "", flag, &mut paths);
    Ok(paths)
}

fn sensitive_paths() -> Result<Vec<String>, SettingsError> {
    schema_paths("x-sensitive")
}

fn read_only_paths() -> Result<Vec<String>, SettingsError> {
    schema_paths("readOnly")
}

fn derive_read_only(settings: &mut Value) {
    let external = settings
        .pointer("/history/external_db/dsn")
        .and_then(Value::as_str)
        .is_some_and(|dsn| !dsn.trim().is_empty());
    let provision = settings
        .pointer("/history/external_db/provision")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    settings["history"]["mode"] = Value::String(
        if provision {
            "fabric-managed"
        } else if external {
            "external"
        } else {
            "thin"
        }
        .to_owned(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tier_order_and_derived_history_mode_are_deterministic() {
        let snapshot = SettingsSnapshot::new(
            4,
            json!({"runner": {"heartbeat_seconds": 20}, "history": {"external_db": {"dsn": "postgres://operator:pw@db/fabric"}}}),
            json!({"runner": {"heartbeat_seconds": 5}}),
        )
        .unwrap();
        assert_eq!(snapshot.effective["runner"]["heartbeat_seconds"], 5);
        assert_eq!(snapshot.effective["history"]["mode"], "external");
        assert_eq!(snapshot.revision, 4);
    }

    #[test]
    fn sensitive_values_are_redacted_but_nulls_stay_null() {
        let snapshot = SettingsSnapshot::new(
            1,
            json!({"history": {"external_db": {"dsn": "postgres://u:p@db/fabric"}}}),
            json!({}),
        )
        .unwrap();
        assert_eq!(
            snapshot.get("history.external_db.dsn", false).unwrap(),
            REDACTED
        );
        assert_eq!(
            snapshot.get("history.external_db.dsn", true).unwrap(),
            "postgres://u:p@db/fabric"
        );
        assert_eq!(
            snapshot.redacted_effective().unwrap()["secrets"]["key_file"],
            Value::Null
        );
    }

    #[test]
    fn unknown_types_and_read_only_writes_fail_closed() {
        let snapshot = SettingsSnapshot::new(0, json!({}), json!({})).unwrap();
        assert!(matches!(
            snapshot.set_hub("runner.heartbeat_seconds", json!("fast")),
            Err(SettingsError::TypeMismatch { .. })
        ));
        assert!(matches!(
            snapshot.set_hub("history.mode", json!("external")),
            Err(SettingsError::ReadOnly(_))
        ));
        assert!(matches!(
            snapshot.set_hub("unknown.key", json!(1)),
            Err(SettingsError::UnknownKey(_))
        ));
    }

    #[test]
    fn reset_restores_default_and_preserves_revision_monotonicity() {
        let snapshot = SettingsSnapshot::new(8, json!({}), json!({}))
            .unwrap()
            .set_hub("runner.heartbeat_seconds", json!(30))
            .unwrap();
        assert_eq!(snapshot.effective["runner"]["heartbeat_seconds"], 30);
        let reset = snapshot.reset_hub("runner.heartbeat_seconds").unwrap();
        assert_eq!(reset.effective["runner"]["heartbeat_seconds"], 10);
        assert_eq!(reset.revision, 10);
    }

    #[test]
    fn serialization_and_import_diff_redact_sensitive_values() {
        let snapshot = SettingsSnapshot::new(
            1,
            json!({"history":{"external_db":{"dsn":"postgres://u:old@db/x"}}}),
            json!({}),
        )
        .unwrap();
        let serialized = serde_json::to_string(&snapshot).unwrap();
        assert!(!serialized.contains("u:old"));
        let (_next, diff) = snapshot
            .import_hub(json!({"history":{"external_db":{"dsn":"postgres://u:new@db/x"}}}))
            .unwrap();
        let change = diff
            .iter()
            .find(|c| c.key == "history.external_db.dsn")
            .unwrap();
        assert_eq!(change.before, REDACTED);
        assert_eq!(change.after, REDACTED);
    }
}
