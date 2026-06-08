//! Phase 2.8 (M2.8.1) — MCP manifest normalization.
//!
//! Pure-function projection: given a runner's advertised `mcp_manifest`,
//! produce the normalized `runner_capabilities` row set the capability
//! router consults at claim time. No rqlite, no I/O, no async.
//!
//! Contract is locked in `tests/fixtures/phase_2_8/SPEC.md` and exercised
//! against the fixture cases in `tests/fixtures/phase_2_8/capability_index.json`
//! via the unit tests at the bottom of this file.

use fabric_store::RunnerCapabilityRow;
use serde_json::{json, Value};
use std::collections::HashSet;

/// Project an `mcp_manifest` blob into the normalized `runner_capabilities`
/// row set for `runner_id`.
///
/// The projection rules (see SPEC.md):
/// - Tools become rows with `capability_kind = "tool"`, `name = tool.name`,
///   `extra = { "input_schema": <schema> }`.
/// - Resources become rows with `capability_kind = "resource"`,
///   `name = resource.uri`, `description = resource.name`,
///   `extra = { "mime_type": <mime_type> }`.
/// - Prompts become rows with `capability_kind = "prompt"`,
///   `name = prompt.name`, `extra = { "arguments": <arguments> }`.
/// - Multi-server collisions on `(capability_kind, name)` resolve to the
///   first occurrence in `servers[]` order.
///
/// `manifest` may be `Value::Null`, an empty object, or absent the `servers`
/// key — all yield an empty row set.
pub fn normalize_manifest_to_rows(
    runner_id: &str,
    manifest: &Value,
) -> Vec<RunnerCapabilityRow> {
    let mut rows: Vec<RunnerCapabilityRow> = Vec::new();
    let mut seen: HashSet<(String, String)> = HashSet::new();

    let servers = match manifest.get("servers").and_then(|v| v.as_array()) {
        Some(s) => s,
        None => return rows,
    };

    for server in servers {
        let server_id = server
            .get("server_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();

        // Tools
        if let Some(tools) = server.get("tools").and_then(|v| v.as_array()) {
            for tool in tools {
                let name = match tool.get("name").and_then(|v| v.as_str()) {
                    Some(s) if !s.is_empty() => s.to_owned(),
                    _ => continue,
                };
                let key = ("tool".to_owned(), name.clone());
                if !seen.insert(key) {
                    continue;
                }
                rows.push(RunnerCapabilityRow {
                    runner_id: runner_id.to_owned(),
                    capability_kind: "tool".to_owned(),
                    name,
                    source_server: server_id.clone(),
                    description: tool
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_owned()),
                    extra: json!({
                        "input_schema": tool.get("input_schema").cloned().unwrap_or(Value::Null)
                    }),
                });
            }
        }

        // Resources
        if let Some(resources) = server.get("resources").and_then(|v| v.as_array()) {
            for resource in resources {
                let name = match resource.get("uri").and_then(|v| v.as_str()) {
                    Some(s) if !s.is_empty() => s.to_owned(),
                    _ => continue,
                };
                let key = ("resource".to_owned(), name.clone());
                if !seen.insert(key) {
                    continue;
                }
                rows.push(RunnerCapabilityRow {
                    runner_id: runner_id.to_owned(),
                    capability_kind: "resource".to_owned(),
                    name,
                    source_server: server_id.clone(),
                    description: resource
                        .get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_owned()),
                    extra: json!({
                        "mime_type": resource.get("mime_type").cloned().unwrap_or(Value::Null)
                    }),
                });
            }
        }

        // Prompts
        if let Some(prompts) = server.get("prompts").and_then(|v| v.as_array()) {
            for prompt in prompts {
                let name = match prompt.get("name").and_then(|v| v.as_str()) {
                    Some(s) if !s.is_empty() => s.to_owned(),
                    _ => continue,
                };
                let key = ("prompt".to_owned(), name.clone());
                if !seen.insert(key) {
                    continue;
                }
                rows.push(RunnerCapabilityRow {
                    runner_id: runner_id.to_owned(),
                    capability_kind: "prompt".to_owned(),
                    name,
                    source_server: server_id.clone(),
                    description: prompt
                        .get("description")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_owned()),
                    extra: json!({
                        "arguments": prompt.get("arguments").cloned().unwrap_or(json!([]))
                    }),
                });
            }
        }
    }

    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::from_str;

    const FIXTURE: &str = include_str!(
        "../../../tests/fixtures/phase_2_8/capability_index.json"
    );

    #[derive(serde::Deserialize)]
    struct Fixture {
        cases: Vec<FixtureCase>,
    }

    #[derive(serde::Deserialize)]
    struct FixtureCase {
        case: String,
        runner_id: String,
        manifest: Value,
        expected_rows: Vec<ExpectedRow>,
    }

    #[derive(serde::Deserialize)]
    struct ExpectedRow {
        runner_id: String,
        capability_kind: String,
        name: String,
        source_server: String,
        description: Option<String>,
    }

    fn assert_row_match(actual: &RunnerCapabilityRow, expected: &ExpectedRow, case: &str) {
        assert_eq!(
            actual.runner_id, expected.runner_id,
            "[{case}] runner_id mismatch"
        );
        assert_eq!(
            actual.capability_kind, expected.capability_kind,
            "[{case}] capability_kind mismatch on {}",
            expected.name
        );
        assert_eq!(
            actual.name, expected.name,
            "[{case}] name mismatch"
        );
        assert_eq!(
            actual.source_server, expected.source_server,
            "[{case}] source_server mismatch on {}",
            expected.name
        );
        assert_eq!(
            actual.description, expected.description,
            "[{case}] description mismatch on {}",
            expected.name
        );
    }

    #[test]
    fn all_fixture_cases_project_correctly() {
        let fixture: Fixture = from_str(FIXTURE).expect("parse capability_index.json");
        for case in &fixture.cases {
            let rows = normalize_manifest_to_rows(&case.runner_id, &case.manifest);
            assert_eq!(
                rows.len(),
                case.expected_rows.len(),
                "[{}] row count: actual {} != expected {}\nactual rows: {:#?}\nexpected: {:#?}",
                case.case,
                rows.len(),
                case.expected_rows.len(),
                rows,
                case.expected_rows
                    .iter()
                    .map(|e| (&e.capability_kind, &e.name))
                    .collect::<Vec<_>>(),
            );
            for (actual, expected) in rows.iter().zip(case.expected_rows.iter()) {
                assert_row_match(actual, expected, &case.case);
            }
        }
    }

    #[test]
    fn null_manifest_yields_empty_rows() {
        let rows = normalize_manifest_to_rows("runner-x", &Value::Null);
        assert!(rows.is_empty());
    }

    #[test]
    fn missing_servers_key_yields_empty_rows() {
        let rows =
            normalize_manifest_to_rows("runner-x", &json!({ "schema_version": 1 }));
        assert!(rows.is_empty());
    }

    #[test]
    fn empty_servers_array_yields_empty_rows() {
        let rows = normalize_manifest_to_rows(
            "runner-x",
            &json!({ "schema_version": 1, "servers": [] }),
        );
        assert!(rows.is_empty());
    }

    #[test]
    fn missing_tool_name_skipped() {
        let manifest = json!({
            "schema_version": 1,
            "servers": [
                {
                    "server_id": "s",
                    "tools": [
                        { "description": "no name field" },
                        { "name": "", "description": "empty name" },
                        { "name": "valid", "description": "kept" }
                    ],
                    "resources": [],
                    "prompts": []
                }
            ]
        });
        let rows = normalize_manifest_to_rows("r", &manifest);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "valid");
    }

    #[test]
    fn collision_first_server_wins() {
        let manifest = json!({
            "schema_version": 1,
            "servers": [
                { "server_id": "a", "tools": [{ "name": "x", "description": "from-a" }], "resources": [], "prompts": [] },
                { "server_id": "b", "tools": [{ "name": "x", "description": "from-b" }], "resources": [], "prompts": [] }
            ]
        });
        let rows = normalize_manifest_to_rows("r", &manifest);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].source_server, "a");
        assert_eq!(rows[0].description.as_deref(), Some("from-a"));
    }

    #[test]
    fn cross_kind_same_name_no_collision() {
        // A tool named "x" and a prompt named "x" should both project — the
        // collision check is per `(capability_kind, name)`, not `name` alone.
        let manifest = json!({
            "schema_version": 1,
            "servers": [
                {
                    "server_id": "s",
                    "tools":    [{ "name": "x", "description": "tool-x" }],
                    "resources": [],
                    "prompts":  [{ "name": "x", "description": "prompt-x" }]
                }
            ]
        });
        let rows = normalize_manifest_to_rows("r", &manifest);
        assert_eq!(rows.len(), 2);
        let kinds: HashSet<_> = rows.iter().map(|r| r.capability_kind.as_str()).collect();
        assert!(kinds.contains("tool"));
        assert!(kinds.contains("prompt"));
    }
}
