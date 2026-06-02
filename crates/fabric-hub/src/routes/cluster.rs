//! Cluster health, /hosts summary, and /audit/day routes.

use std::sync::Arc;
use std::collections::HashMap;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Value};

use fabric_store::{AuditStore, HostRoleStore, LabelStore, RunnerStore, DispatcherStore};

use crate::state::HubState;

// ── GET /cluster/health ────────────────────────────────────────────────────

pub async fn cluster_health(
    State(state): State<Arc<HubState>>,
) -> Json<Value> {
    let rqlite = if state.backend.starts_with("rqlite") {
        let host = std::env::var("FORGEWIRE_HUB_RQLITE_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port: u16 = std::env::var("FORGEWIRE_HUB_RQLITE_PORT").ok()
            .and_then(|v| v.parse().ok()).unwrap_or(4001);
        let cons = std::env::var("FORGEWIRE_HUB_RQLITE_CONSISTENCY").unwrap_or_else(|_| "strong".into());
        Some(json!({ "host": host, "port": port, "consistency": cons }))
    } else {
        None
    };

    Json(json!({
        "backend": state.backend,
        "rqlite": rqlite,
        "labels_snapshot": {
            "status": "unknown",
            "applied": 0,
            "path": null,
            "exists": false,
            "size_bytes": null,
            "mtime": null,
        },
    }))
}

// ── GET /hosts ─────────────────────────────────────────────────────────────

pub async fn list_hosts(
    State(state): State<Arc<HubState>>,
) -> Result<Json<Value>, (StatusCode, String)> {
    let runners = state.store.list_runners().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let dispatchers = state.store.list_dispatchers().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let host_roles = state.store.list_host_roles().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let labels = state.store.get_labels().await.unwrap_or(json!({}));

    let host_aliases: HashMap<String, String> = labels["host_aliases"]
        .as_object()
        .map(|m| m.iter().map(|(k, v)| (k.to_lowercase(), v.as_str().unwrap_or("").to_owned())).collect())
        .unwrap_or_default();
    let runner_aliases: HashMap<String, String> = labels["runner_aliases"]
        .as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_owned())).collect())
        .unwrap_or_default();

    // Active hub hostname — best effort from env
    let active_hub_hostname = std::env::var("COMPUTERNAME")
        .unwrap_or_else(|_| std::process::Command::new("hostname")
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default())
        .to_lowercase();

    let hub_url = format!("http://{}:{}", state.host, state.port);

    // Collect all hostnames
    let mut hostnames: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    hostnames.insert(active_hub_hostname.clone());

    let mut runners_by_host: HashMap<String, Vec<Value>> = HashMap::new();
    let mut dispatchers_by_host: HashMap<String, Vec<Value>> = HashMap::new();
    let mut roles_by_host: HashMap<String, HashMap<String, Value>> = HashMap::new();

    for runner in &runners {
        let h = runner.hostname.to_lowercase();
        hostnames.insert(h.clone());
        let mut rv = serde_json::to_value(runner).unwrap_or(Value::Null);
        // Attach alias
        let alias = runner_aliases.get(&runner.runner_id)
            .cloned()
            .unwrap_or_else(|| host_aliases.get(&h).cloned().unwrap_or_default());
        if let Some(obj) = rv.as_object_mut() {
            obj.insert("alias".into(), json!(alias));
            obj.insert("host_alias".into(), json!(host_aliases.get(&h).cloned().unwrap_or_default()));
        }
        runners_by_host.entry(h).or_default().push(rv);
    }
    for dispatcher in &dispatchers {
        let h = dispatcher.hostname.as_deref().unwrap_or("").to_lowercase();
        if !h.is_empty() {
            dispatchers_by_host.entry(h).or_default()
                .push(serde_json::to_value(dispatcher).unwrap_or(Value::Null));
        }
    }
    for role in &host_roles {
        let h = role.hostname.to_lowercase();
        hostnames.insert(h.clone());
        roles_by_host.entry(h).or_default()
            .insert(role.role.clone(), serde_json::to_value(role).unwrap_or(Value::Null));
    }

    let hosts: Vec<Value> = hostnames.iter().map(|hostname| {
        let host_runners = runners_by_host.get(hostname).cloned().unwrap_or_default();
        let host_dispatchers = dispatchers_by_host.get(hostname).cloned().unwrap_or_default();
        let stored = roles_by_host.get(hostname).cloned().unwrap_or_default();
        let is_active_hub = hostname == &active_hub_hostname;

        let host_alias = host_aliases.get(hostname).cloned().unwrap_or_default();
        let runner_alias = host_runners.iter()
            .find_map(|r| r["alias"].as_str().filter(|s| !s.is_empty()).map(|s| s.to_owned()))
            .unwrap_or_default();
        let label = if !host_alias.is_empty() { host_alias.clone() } else { runner_alias };

        // Build role summaries
        let hub_head = role_summary(is_active_hub, if is_active_hub { "active" } else { "standby" }, "active_hub", Some(hub_url.clone()), vec![], vec![], json!({}), None);
        let control  = role_summary(is_active_hub, if is_active_hub { "master" } else { "slave" }, "active_hub", None, vec![], vec![], json!({}), None);

        let dispatcher_ids: Vec<String> = host_dispatchers.iter()
            .filter_map(|d| d["dispatcher_id"].as_str().map(|s| s.to_owned()))
            .collect();
        let dispatch_row = stored.get("dispatch");
        let dispatch_enabled = !host_dispatchers.is_empty() || dispatch_row.map(|r| r["enabled"].as_bool().unwrap_or(false)).unwrap_or(false);
        let dispatch_status = if !host_dispatchers.is_empty() {
            "registered".to_owned()
        } else {
            dispatch_row.and_then(|r| r["status"].as_str()).unwrap_or("disabled").to_owned()
        };
        let dispatch_meta = dispatch_row.and_then(|r| r.get("metadata")).cloned().unwrap_or(json!({}));
        let dispatch_updated = dispatch_row.and_then(|r| r["updated_at"].as_str()).map(|s| s.to_owned());
        let dispatch_source = if !host_dispatchers.is_empty() { "dispatcher_registry" } else { "derived" };
        let dispatch = role_summary(dispatch_enabled, &dispatch_status, dispatch_source, None, vec![], dispatcher_ids, dispatch_meta, dispatch_updated);

        let command_runner = build_runner_role(&host_runners, stored.get("command_runner"), "command");
        let agent_runner   = build_runner_role(&host_runners, stored.get("agent_runner"), "agent");

        json!({
            "hostname": hostname,
            "label": label,
            "display_name": if label.is_empty() { hostname.clone() } else { label },
            "is_active_hub": is_active_hub,
            "roles": {
                "hub_head": hub_head,
                "control": control,
                "dispatch": dispatch,
                "command_runner": command_runner,
                "agent_runner": agent_runner,
            },
            "runners": host_runners,
            "dispatchers": host_dispatchers,
        })
    }).collect();

    Ok(Json(json!({
        "hub_protocol_version": state.protocol_version,
        "hub_name": labels["hub_name"].as_str().unwrap_or(""),
        "active_hub_hostname": active_hub_hostname,
        "active_hub_address": hub_url,
        "hosts": hosts,
    })))
}

fn role_summary(
    enabled: bool,
    status: &str,
    source: &str,
    address: Option<String>,
    runner_ids: Vec<String>,
    dispatcher_ids: Vec<String>,
    metadata: Value,
    updated_at: Option<String>,
) -> Value {
    json!({
        "enabled": enabled,
        "status": status,
        "source": source,
        "address": address,
        "runner_ids": runner_ids,
        "dispatcher_ids": dispatcher_ids,
        "metadata": metadata,
        "updated_at": updated_at,
    })
}

fn runner_kind_from_tags(tags: &Value) -> &'static str {
    if let Some(arr) = tags.as_array() {
        for t in arr {
            if let Some(s) = t.as_str() {
                if s.to_lowercase().replace('=', ":") == "kind:command" {
                    return "command";
                }
            }
        }
    }
    "agent"
}

fn build_runner_role(runners: &[Value], role_row: Option<&Value>, kind: &str) -> Value {
    let role_runners: Vec<&Value> = runners.iter()
        .filter(|r| runner_kind_from_tags(&r["tags"]) == kind)
        .collect();
    let enabled = !role_runners.is_empty() || role_row.map(|r| r["enabled"].as_bool().unwrap_or(false)).unwrap_or(false);
    let status = if !role_runners.is_empty() {
        runner_rollup_status(&role_runners)
    } else {
        role_row.and_then(|r| r["status"].as_str()).unwrap_or("disabled").to_owned()
    };
    let source = if !role_runners.is_empty() { "runner_heartbeat" } else if role_row.is_some() { "host_roles" } else { "derived" };
    let runner_ids: Vec<String> = role_runners.iter()
        .filter_map(|r| r["runner_id"].as_str().map(|s| s.to_owned()))
        .collect();
    let meta = role_row.and_then(|r| r.get("metadata")).cloned().unwrap_or(json!({}));
    let updated = role_row.and_then(|r| r["updated_at"].as_str()).map(|s| s.to_owned());
    role_summary(enabled, &status, source, None, runner_ids, vec![], meta, updated)
}

fn runner_rollup_status(runners: &[&Value]) -> String {
    let states: Vec<&str> = runners.iter()
        .filter_map(|r| r["state"].as_str())
        .collect();
    if states.iter().any(|&s| s == "online") { return "online".into(); }
    if states.iter().any(|&s| s == "degraded") { return "degraded".into(); }
    if states.iter().any(|&s| s == "draining") { return "draining".into(); }
    "offline".into()
}

// ── GET /audit/day/{day} ───────────────────────────────────────────────────

pub async fn audit_day(
    State(state): State<Arc<HubState>>,
    Path(day): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    // Validate format YYYY-MM-DD
    if day.len() != 10 || !day.chars().enumerate().all(|(i, c)| {
        if i == 4 || i == 7 { c == '-' } else { c.is_ascii_digit() }
    }) {
        return Err((StatusCode::BAD_REQUEST, "day must be YYYY-MM-DD".into()));
    }
    let events = state.store.audit_events_for_day(&day).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (verified, err) = state.store.verify_audit_chain(&events).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(json!({ "day": day, "events": events, "verified": verified, "error": err })))
}
