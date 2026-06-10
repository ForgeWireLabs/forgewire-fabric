//! Deterministic dispatch and completion policy evaluation for ForgeWire Fabric.
//!
//! # Policy file
//!
//! The hub searches for `policy.yaml` at the configured policy path on every
//! dispatch. If the file does not exist, a safe annotated default is written
//! automatically so operators can start immediately and tune later.
//!
//! Load or auto-generate:
//! ```no_run
//! use fabric_policy::FabricPolicy;
//! let policy = FabricPolicy::load_or_create("/path/to/repo/policy.yaml").unwrap();
//! ```

#![deny(rust_2018_idioms)]

use std::path::Path;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error ────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("IO error reading/writing policy file: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML parse error in policy file: {0}")]
    Parse(#[from] serde_yaml::Error),
}

// ── FabricPolicy ─────────────────────────────────────────────────────────────

/// Full operator policy configuration. All fields are optional; omitting a
/// field uses the permissive default (allow everything). This is intentional:
/// a missing field never silently blocks work.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FabricPolicy {
    // ── Branch protection ────────────────────────────────────────────────────
    /// Branches that require explicit approval before any task may target them.
    /// Supports glob patterns (fnmatch-style).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_branches: Vec<String>,

    /// Branches that are always blocked — no approval path, always denied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_branches: Vec<String>,

    /// If non-empty, only these branches are permitted (allowlist semantics).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_branches: Vec<String>,

    // ── Path protection ──────────────────────────────────────────────────────
    /// Path globs that are always denied, regardless of scope or approval.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_paths: Vec<String>,

    // ── Scope control ────────────────────────────────────────────────────────
    /// If non-empty, tasks whose scope_globs don't match are denied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_scope_globs: Vec<String>,

    /// Scope globs that are always blocked.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_scope_globs: Vec<String>,

    /// Scope globs that require operator approval before execution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub require_approval_for_scopes: Vec<String>,

    // ── Approval gates ───────────────────────────────────────────────────────
    /// Actions that require operator approval at runtime intent check.
    /// Valid values: "merge", "push", "network_egress", "shell_exec",
    /// "fs_write", "destructive_fs".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub require_approval: Vec<String>,

    // ── Egress ───────────────────────────────────────────────────────────────
    /// Hostnames/domains permitted for outbound network access.
    /// If non-empty, any egress not matching this list is denied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress_allowlist: Vec<String>,

    // ── Diff limits ──────────────────────────────────────────────────────────
    /// Maximum number of changed lines permitted at completion time.
    /// Tasks that exceed this are denied at the completion gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_diff_lines: Option<i64>,

    // ── Concurrency ──────────────────────────────────────────────────────────
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent_tasks: Option<i64>,

    // ── Signed dispatch ──────────────────────────────────────────────────────
    #[serde(default)]
    pub require_signed_dispatch: bool,

    // ── Budget ───────────────────────────────────────────────────────────────
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily_budget_usd: Option<f64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weekly_budget_usd: Option<f64>,

    /// Fraction of the weekly budget that triggers a warning (0.0–1.0).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weekly_alert_threshold: Option<f64>,

    // ── Legacy nested budget (kept for DispatchGate compat) ─────────────────
    #[serde(default, skip_serializing_if = "BudgetPolicy::is_default")]
    pub budget: BudgetPolicy,
}

impl FabricPolicy {
    /// Load policy from `path`. If the file does not exist, write a safe
    /// annotated default and return it. If the file exists but is malformed,
    /// return a `PolicyError::Parse`.
    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        if path.exists() {
            let contents = std::fs::read_to_string(path)?;
            let policy: FabricPolicy = serde_yaml::from_str(&contents)?;
            tracing_or_eprintln(format!("policy loaded from {}", path.display()));
            Ok(policy)
        } else {
            let default = FabricPolicy::safe_default();
            let yaml = Self::annotated_default_yaml();
            // Create parent directories if needed
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            std::fs::write(path, yaml)?;
            tracing_or_eprintln(format!(
                "policy.yaml not found — wrote safe default to {}",
                path.display()
            ));
            Ok(default)
        }
    }

    /// Load policy from `path` if it exists; return `FabricPolicy::default()`
    /// (permissive) if the file is absent. Unlike `load_or_create`, this does
    /// NOT write anything to disk. Useful for startup paths where the policy
    /// path is optional.
    pub fn load_optional(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        if path.exists() {
            let contents = std::fs::read_to_string(path)?;
            let policy: FabricPolicy = serde_yaml::from_str(&contents)?;
            Ok(policy)
        } else {
            Ok(FabricPolicy::default())
        }
    }

    /// The recommended safe default — sensible gates for a real repo without
    /// being so restrictive it breaks a fresh setup.
    pub fn safe_default() -> Self {
        FabricPolicy {
            protected_branches: vec!["main".into(), "release/*".into()],
            forbidden_paths: vec![
                ".github/workflows/**".into(),
                "secrets/**".into(),
            ],
            max_diff_lines: Some(2000),
            require_approval: vec![
                "merge".into(),
                "push".into(),
                "network_egress".into(),
            ],
            egress_allowlist: vec![
                "pypi.org".into(),
                "github.com".into(),
            ],
            daily_budget_usd: Some(5.00),
            weekly_budget_usd: Some(25.00),
            ..Default::default()
        }
    }

    /// Produces the annotated YAML that is written on auto-generate. Keeping
    /// this as a string (rather than serialising the struct) preserves comments.
    fn annotated_default_yaml() -> &'static str {
        r#"# policy.yaml — auto-generated by Fabric on first dispatch
#
# This file was created automatically because no policy.yaml was found.
# Check it into your repository, adjust as needed, and Fabric will pick
# up changes on the next dispatch.
#
# All fields are optional. Omitting a field uses the permissive default
# (allow everything). The hub evaluates this file at three gate points:
#   dispatch      — before a task enters the queue
#   runtime_intent — before a runner executes a gated action
#   completion    — when a task submits its result
#
# Schema version: 1

# Branches that require explicit approval before any task may target them.
protected_branches: [main, "release/*"]

# Paths that are always denied, regardless of scope or approval.
forbidden_paths: [".github/workflows/**", "secrets/**"]

# Maximum changed lines allowed at completion time.
max_diff_lines: 2000

# Actions that require operator approval at runtime intent check.
# Options: merge, push, network_egress, shell_exec, fs_write, destructive_fs
require_approval: [merge, push, network_egress]

# Outbound network access is restricted to these hosts.
# Remove or leave empty to allow all egress.
egress_allowlist: ["pypi.org", "github.com"]

# Spending caps enforced at dispatch time.
daily_budget_usd: 5.00
weekly_budget_usd: 25.00
"#
    }

    /// Returns the effective `BudgetPolicy` for this config, merging both the
    /// flat top-level fields and the nested `budget` block.
    pub fn effective_budget(&self) -> BudgetPolicy {
        BudgetPolicy {
            daily_cost_cap_usd: self.daily_budget_usd.or(self.budget.daily_cost_cap_usd),
            weekly_cost_cap_usd: self.weekly_budget_usd.or(self.budget.weekly_cost_cap_usd),
            weekly_task_cap: self.budget.weekly_task_cap,
        }
    }
}

fn tracing_or_eprintln(msg: String) {
    // Use eprintln as fallback — tracing may not be initialised in test contexts.
    eprintln!("[fabric-policy] {msg}");
}

// ── BudgetPolicy ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BudgetPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weekly_task_cap: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily_cost_cap_usd: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weekly_cost_cap_usd: Option<f64>,
}

impl BudgetPolicy {
    pub fn is_default(&self) -> bool {
        self.weekly_task_cap.is_none()
            && self.daily_cost_cap_usd.is_none()
            && self.weekly_cost_cap_usd.is_none()
    }

    pub fn has_cost_caps(&self) -> bool {
        self.daily_cost_cap_usd.is_some() || self.weekly_cost_cap_usd.is_some()
    }

    pub fn check_cost(&self, daily_spend_usd: f64, weekly_spend_usd: f64) -> PolicyDecision {
        if let Some(cap) = self.daily_cost_cap_usd {
            if daily_spend_usd >= cap {
                return PolicyDecision::deny(format!(
                    "daily budget exceeded: ${daily_spend_usd:.4} of ${cap:.4} cap"
                ));
            }
        }
        if let Some(cap) = self.weekly_cost_cap_usd {
            if weekly_spend_usd >= cap {
                return PolicyDecision::deny(format!(
                    "weekly budget exceeded: ${weekly_spend_usd:.4} of ${cap:.4} cap"
                ));
            }
        }
        PolicyDecision::allow()
    }
}

// ── PolicyDecision ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub denied: bool,
    pub needs_approval: bool,
    pub reasons: Vec<String>,
}

impl PolicyDecision {
    pub fn allow() -> Self {
        Self { allowed: true, denied: false, needs_approval: false, reasons: vec![] }
    }
    pub fn deny(reason: impl Into<String>) -> Self {
        Self { allowed: false, denied: true, needs_approval: false, reasons: vec![reason.into()] }
    }
    pub fn require_approval(reason: impl Into<String>) -> Self {
        Self { allowed: false, denied: false, needs_approval: true, reasons: vec![reason.into()] }
    }
}

// ── DispatchRequest / CompletionRequest ──────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DispatchRequest {
    pub task_id: String,
    pub scope_globs: Vec<String>,
    pub target_branch: Option<String>,
    pub dispatcher_id: Option<String>,
    // M2.9.2: command-kind fields for cwd-based forbidden-path and scope checks.
    pub kind: String,
    pub cwd: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CompletionRequest {
    pub task_id: String,
    pub changed_paths: Vec<String>,
    pub diff_lines: i64,
}

// ── PolicyEngine ─────────────────────────────────────────────────────────────

pub struct PolicyEngine {
    policy: FabricPolicy,
}

impl PolicyEngine {
    pub fn new(policy: FabricPolicy) -> Self {
        Self { policy }
    }

    pub fn evaluate_dispatch(&self, req: &DispatchRequest) -> PolicyDecision {
        let p = &self.policy;

        // ── Branch checks ────────────────────────────────────────────────────
        if let Some(ref branch) = req.target_branch {
            // Hard-blocked branches
            for blocked in &p.blocked_branches {
                if glob_match(blocked, branch) {
                    return PolicyDecision::deny(format!(
                        "branch '{branch}' is blocked by policy"
                    ));
                }
            }
            // Allowlist (if configured)
            if !p.allowed_branches.is_empty()
                && !p.allowed_branches.iter().any(|a| glob_match(a, branch))
            {
                return PolicyDecision::deny(format!(
                    "branch '{branch}' not in allowed list"
                ));
            }
            // Protected branches require approval
            for pat in &p.protected_branches {
                if glob_match(pat, branch) {
                    return PolicyDecision::require_approval(format!(
                        "branch '{branch}' is protected — operator approval required"
                    ));
                }
            }
        }

        // ── Scope checks ─────────────────────────────────────────────────────
        for glob in &req.scope_globs {
            // Hard-blocked scopes
            for blocked in &p.blocked_scope_globs {
                if scopes_overlap(glob, blocked) {
                    return PolicyDecision::deny(format!(
                        "scope '{glob}' blocked by policy"
                    ));
                }
            }
            // Forbidden paths
            for forbidden in &p.forbidden_paths {
                if scopes_overlap(glob, forbidden) {
                    return PolicyDecision::deny(format!(
                        "scope '{glob}' overlaps forbidden path '{forbidden}'"
                    ));
                }
            }
            // Approval-required scopes
            for approval_scope in &p.require_approval_for_scopes {
                if scopes_overlap(glob, approval_scope) {
                    return PolicyDecision::require_approval(format!(
                        "scope '{glob}' requires operator approval"
                    ));
                }
            }
        }

        // M2.9.2: for command-kind briefs, check cwd against forbidden paths and
        // scope prefixes (belt-and-suspenders; the runner also checks at spawn).
        if req.kind == "command" {
            if let Some(ref cwd) = req.cwd {
                if !cwd.is_empty() {
                    for forbidden in &p.forbidden_paths {
                        if glob_match(forbidden, cwd) || cwd.starts_with(forbidden.trim_end_matches("/**").trim_end_matches('*')) {
                            return PolicyDecision::deny(format!(
                                "cwd '{cwd}' overlaps forbidden path '{forbidden}'"
                            ));
                        }
                    }
                    // Scope-escape check: if scope_prefixes are configured and cwd
                    // does not start with any of them, deny.
                    if !req.scope_globs.is_empty()
                        && !req.scope_globs.iter().any(|prefix| {
                            let p = prefix.trim_end_matches("/**").trim_end_matches('*');
                            p.is_empty() || cwd.starts_with(p)
                        })
                    {
                        return PolicyDecision::deny(format!(
                            "cwd '{cwd}' is outside the allowed scope prefixes"
                        ));
                    }
                }
            }
        }

        PolicyDecision::allow()
    }

    pub fn evaluate_completion(&self, req: &CompletionRequest) -> PolicyDecision {
        // Diff line cap
        if let Some(max) = self.policy.max_diff_lines {
            if req.diff_lines > max {
                return PolicyDecision::deny(format!(
                    "diff too large: {} lines exceeds policy limit of {}",
                    req.diff_lines, max
                ));
            }
        }

        // Forbidden paths at completion
        for path in &req.changed_paths {
            for forbidden in &self.policy.forbidden_paths {
                if glob_match(forbidden, path) {
                    return PolicyDecision::deny(format!(
                        "changed path '{path}' overlaps forbidden path '{forbidden}'"
                    ));
                }
            }
        }

        PolicyDecision::allow()
    }

    /// Check whether a runtime intent action requires approval.
    pub fn evaluate_intent(&self, action: &str) -> PolicyDecision {
        if self.policy.require_approval.iter().any(|a| a == action) {
            return PolicyDecision::require_approval(format!(
                "action '{action}' requires operator approval per policy"
            ));
        }
        PolicyDecision::allow()
    }
}

// ── BudgetEnforcer ───────────────────────────────────────────────────────────

pub struct BudgetEnforcer {
    policy: BudgetPolicy,
    tasks_this_week: i64,
}

impl BudgetEnforcer {
    pub fn new(policy: BudgetPolicy) -> Self {
        Self { policy, tasks_this_week: 0 }
    }

    pub fn check_dispatch(&self) -> PolicyDecision {
        if let Some(cap) = self.policy.weekly_task_cap {
            if self.tasks_this_week >= cap {
                return PolicyDecision::deny(format!(
                    "weekly task cap reached ({cap} tasks)"
                ));
            }
        }
        PolicyDecision::allow()
    }

    pub fn record_dispatch(&mut self) {
        self.tasks_this_week += 1;
    }

    pub fn reset_weekly(&mut self) {
        self.tasks_this_week = 0;
    }
}

// ── DispatchGate ─────────────────────────────────────────────────────────────

pub struct DispatchGate {
    pub engine: PolicyEngine,
    pub budget: BudgetEnforcer,
}

impl DispatchGate {
    pub fn new(policy: FabricPolicy) -> Self {
        let budget_policy = policy.effective_budget();
        Self {
            engine: PolicyEngine::new(policy),
            budget: BudgetEnforcer::new(budget_policy),
        }
    }

    pub fn evaluate_dispatch(&self, req: &DispatchRequest) -> PolicyDecision {
        let budget = self.budget.check_dispatch();
        if budget.denied {
            return budget;
        }
        self.engine.evaluate_dispatch(req)
    }

    pub fn evaluate_completion(&self, req: &CompletionRequest) -> PolicyDecision {
        self.engine.evaluate_completion(req)
    }

    pub fn evaluate_intent(&self, action: &str) -> PolicyDecision {
        self.engine.evaluate_intent(action)
    }
}

// ── Glob helpers ─────────────────────────────────────────────────────────────

/// Minimal glob match: supports `*` (any segment chars) and `**` (any path).
fn glob_match(pattern: &str, value: &str) -> bool {
    if pattern == "**" {
        return true;
    }
    // Normalise trailing /**
    let pat = pattern.trim_end_matches("/**");
    if !pat.contains('*') {
        return value == pat || value.starts_with(&format!("{pat}/"));
    }
    // Convert glob to a simple prefix check for common patterns
    let pat_parts: Vec<&str> = pat.split('/').collect();
    let val_parts: Vec<&str> = value.split('/').collect();
    glob_parts_match(&pat_parts, &val_parts)
}

fn glob_parts_match(pat: &[&str], val: &[&str]) -> bool {
    match (pat.first(), val.first()) {
        (None, _) => true,
        (Some(&"**"), _) => true,
        (Some(p), Some(v)) => {
            segment_match(p, v) && glob_parts_match(&pat[1..], &val[1..])
        }
        (Some(_), None) => false,
    }
}

fn segment_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" || pattern == "**" {
        return true;
    }
    if !pattern.contains('*') {
        return pattern == value;
    }
    // Simple leading/trailing wildcard
    if let Some(suffix) = pattern.strip_prefix('*') {
        return value.ends_with(suffix);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return value.starts_with(prefix);
    }
    false
}

/// True if two scope glob patterns could refer to overlapping paths.
fn scopes_overlap(a: &str, b: &str) -> bool {
    // Normalise: strip trailing /**
    let a = a.trim_end_matches("/**").trim_end_matches('*');
    let b = b.trim_end_matches("/**").trim_end_matches('*');
    a.starts_with(b) || b.starts_with(a)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(policy: FabricPolicy) -> DispatchGate {
        DispatchGate::new(policy)
    }

    fn req(scope: &str, branch: Option<&str>) -> DispatchRequest {
        DispatchRequest {
            task_id: "t1".into(),
            scope_globs: vec![scope.into()],
            target_branch: branch.map(Into::into),
            dispatcher_id: None,
            kind: "agent".into(),
            cwd: None,
        }
    }

    #[test]
    fn default_policy_allows_everything() {
        let d = gate(FabricPolicy::default()).evaluate_dispatch(&req("core/**", Some("agent/test")));
        assert!(d.allowed);
    }

    #[test]
    fn blocked_branch_denied() {
        let p = FabricPolicy { blocked_branches: vec!["main".into()], ..Default::default() };
        assert!(gate(p).evaluate_dispatch(&req("core/**", Some("main"))).denied);
    }

    #[test]
    fn protected_branch_requires_approval() {
        let p = FabricPolicy {
            protected_branches: vec!["main".into()],
            ..Default::default()
        };
        let d = gate(p).evaluate_dispatch(&req("core/**", Some("main")));
        assert!(d.needs_approval);
    }

    #[test]
    fn forbidden_path_denied_at_dispatch() {
        let p = FabricPolicy {
            forbidden_paths: vec![".github/workflows/**".into()],
            ..Default::default()
        };
        let d = gate(p).evaluate_dispatch(&req(".github/workflows/ci.yml", None));
        assert!(d.denied);
    }

    #[test]
    fn approval_required_scope() {
        let p = FabricPolicy {
            require_approval_for_scopes: vec!["secrets/".into()],
            ..Default::default()
        };
        let d = gate(p).evaluate_dispatch(&req("secrets/vault/**", None));
        assert!(d.needs_approval);
    }

    #[test]
    fn diff_lines_cap_at_completion() {
        let p = FabricPolicy { max_diff_lines: Some(100), ..Default::default() };
        let engine = PolicyEngine::new(p);
        let d = engine.evaluate_completion(&CompletionRequest {
            task_id: "t1".into(),
            changed_paths: vec![],
            diff_lines: 101,
        });
        assert!(d.denied);
        assert!(d.reasons[0].contains("diff too large"));
    }

    #[test]
    fn diff_lines_at_limit_allowed() {
        let p = FabricPolicy { max_diff_lines: Some(100), ..Default::default() };
        let engine = PolicyEngine::new(p);
        let d = engine.evaluate_completion(&CompletionRequest {
            task_id: "t1".into(),
            changed_paths: vec![],
            diff_lines: 100,
        });
        assert!(d.allowed);
    }

    #[test]
    fn intent_gate_requires_approval() {
        let p = FabricPolicy {
            require_approval: vec!["merge".into(), "push".into()],
            ..Default::default()
        };
        let engine = PolicyEngine::new(p);
        assert!(engine.evaluate_intent("merge").needs_approval);
        assert!(engine.evaluate_intent("push").needs_approval);
        assert!(engine.evaluate_intent("shell_exec").allowed);
    }

    #[test]
    fn cost_cap_allows_under_budget() {
        let b = BudgetPolicy {
            daily_cost_cap_usd: Some(10.0),
            weekly_cost_cap_usd: Some(50.0),
            ..Default::default()
        };
        assert!(b.check_cost(5.0, 20.0).allowed);
    }

    #[test]
    fn cost_cap_denies_at_daily() {
        let b = BudgetPolicy { daily_cost_cap_usd: Some(10.0), ..Default::default() };
        assert!(b.check_cost(10.0, 0.0).denied);
        assert!(b.check_cost(9.99, 0.0).allowed);
    }

    #[test]
    fn cost_cap_denies_over_weekly() {
        let b = BudgetPolicy { weekly_cost_cap_usd: Some(50.0), ..Default::default() };
        assert!(b.check_cost(0.0, 55.0).denied);
    }

    #[test]
    fn safe_default_has_expected_gates() {
        let p = FabricPolicy::safe_default();
        assert!(!p.protected_branches.is_empty());
        assert!(!p.forbidden_paths.is_empty());
        assert!(p.max_diff_lines.is_some());
        assert!(!p.require_approval.is_empty());
        assert!(p.daily_budget_usd.is_some());
        assert!(p.weekly_budget_usd.is_some());
    }

    #[test]
    fn load_or_create_writes_default_when_absent() {
        let dir = std::env::temp_dir().join(format!("fabric-policy-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("policy.yaml");
        assert!(!path.exists());

        let policy = FabricPolicy::load_or_create(&path).unwrap();
        assert!(path.exists(), "policy.yaml should have been written");
        assert!(!policy.protected_branches.is_empty());

        // Second load should parse the written file
        let policy2 = FabricPolicy::load_or_create(&path).unwrap();
        assert_eq!(policy.protected_branches, policy2.protected_branches);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn budget_cap_enforced() {
        let p = FabricPolicy {
            budget: BudgetPolicy { weekly_task_cap: Some(2), ..Default::default() },
            ..Default::default()
        };
        let mut g = gate(p);
        g.budget.record_dispatch();
        g.budget.record_dispatch();
        let d = g.evaluate_dispatch(&req("**", None));
        assert!(d.denied);
        assert!(d.reasons[0].contains("weekly task cap"));
    }

    #[test]
    fn safe_default_yaml_is_valid() {
        let yaml = FabricPolicy::annotated_default_yaml();
        let p: FabricPolicy = serde_yaml::from_str(yaml).expect("annotated default must parse");
        assert!(!p.protected_branches.is_empty());
    }
}
