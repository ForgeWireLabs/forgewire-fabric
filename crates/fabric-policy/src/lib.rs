//! Deterministic dispatch and completion policy evaluation for ForgeWire Fabric.
//!
//! Mirrors the Python `FabricPolicyEngine` + `BudgetEnforcer` + `HubDispatchGate`
//! from `forgewire_fabric.policy`. The policy engine evaluates a dispatch or
//! completion request against a `FabricPolicy` config and returns a structured
//! `PolicyDecision`.

#![deny(rust_2018_idioms)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FabricPolicy {
    #[serde(default)]
    pub require_signed_dispatch: bool,
    #[serde(default)]
    pub max_concurrent_tasks: Option<i64>,
    #[serde(default)]
    pub allowed_branches: Vec<String>,
    #[serde(default)]
    pub blocked_branches: Vec<String>,
    #[serde(default)]
    pub allowed_scope_globs: Vec<String>,
    #[serde(default)]
    pub blocked_scope_globs: Vec<String>,
    #[serde(default)]
    pub require_approval_for_scopes: Vec<String>,
    #[serde(default)]
    pub budget: BudgetPolicy,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BudgetPolicy {
    #[serde(default)]
    pub weekly_task_cap: Option<i64>,
    #[serde(default)]
    pub daily_cost_cap_usd: Option<f64>,
    #[serde(default)]
    pub weekly_cost_cap_usd: Option<f64>,
}

impl BudgetPolicy {
    /// True if any cost cap is configured (lets callers skip the store read
    /// entirely when no caps apply).
    pub fn has_cost_caps(&self) -> bool {
        self.daily_cost_cap_usd.is_some() || self.weekly_cost_cap_usd.is_some()
    }

    /// Evaluate the current accumulated spend against the configured cost caps.
    /// Denies a new dispatch when a period's spend has already reached its cap.
    /// `daily_spend_usd` / `weekly_spend_usd` come from the persistent
    /// `budget_state` accumulators, so this is correct across hub restarts.
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

#[derive(Debug, Clone)]
pub struct DispatchRequest {
    pub task_id: String,
    pub scope_globs: Vec<String>,
    pub target_branch: Option<String>,
    pub dispatcher_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CompletionRequest {
    pub task_id: String,
    pub changed_paths: Vec<String>,
    pub diff_lines: i64,
}

pub struct PolicyEngine {
    policy: FabricPolicy,
}

impl PolicyEngine {
    pub fn new(policy: FabricPolicy) -> Self {
        Self { policy }
    }

    pub fn evaluate_dispatch(&self, req: &DispatchRequest) -> PolicyDecision {
        // Branch blocking
        if let Some(ref branch) = req.target_branch {
            for blocked in &self.policy.blocked_branches {
                if branch.contains(blocked) {
                    return PolicyDecision::deny(format!("branch '{branch}' is blocked by policy"));
                }
            }
            if !self.policy.allowed_branches.is_empty()
                && !self.policy.allowed_branches.iter().any(|a| branch.contains(a))
            {
                return PolicyDecision::deny(format!("branch '{branch}' not in allowed list"));
            }
        }

        // Scope blocking
        for glob in &req.scope_globs {
            for blocked in &self.policy.blocked_scope_globs {
                if glob.starts_with(blocked) || blocked.starts_with(glob) {
                    return PolicyDecision::deny(format!("scope '{glob}' blocked by policy"));
                }
            }
        }

        // Approval-required scopes
        for glob in &req.scope_globs {
            for approval_scope in &self.policy.require_approval_for_scopes {
                if glob.starts_with(approval_scope) || approval_scope.starts_with(glob) {
                    return PolicyDecision::require_approval(format!(
                        "scope '{glob}' requires operator approval"
                    ));
                }
            }
        }

        PolicyDecision::allow()
    }

    pub fn evaluate_completion(&self, _req: &CompletionRequest) -> PolicyDecision {
        PolicyDecision::allow()
    }
}

/// Budget enforcer — tracks task counts and costs against policy caps.
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

/// Combined dispatch gate — evaluates both policy and budget.
pub struct DispatchGate {
    pub engine: PolicyEngine,
    pub budget: BudgetEnforcer,
}

impl DispatchGate {
    pub fn new(policy: FabricPolicy) -> Self {
        let budget_policy = policy.budget.clone();
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_allows_everything() {
        let gate = DispatchGate::new(FabricPolicy::default());
        let req = DispatchRequest {
            task_id: "1".into(),
            scope_globs: vec!["core/**".into()],
            target_branch: Some("agent/test".into()),
            dispatcher_id: None,
        };
        let d = gate.evaluate_dispatch(&req);
        assert!(d.allowed);
    }

    #[test]
    fn blocked_branch_denied() {
        let policy = FabricPolicy {
            blocked_branches: vec!["main".into()],
            ..Default::default()
        };
        let gate = DispatchGate::new(policy);
        let req = DispatchRequest {
            task_id: "1".into(),
            scope_globs: vec!["core/**".into()],
            target_branch: Some("main".into()),
            dispatcher_id: None,
        };
        let d = gate.evaluate_dispatch(&req);
        assert!(d.denied);
    }

    #[test]
    fn approval_required_scope() {
        let policy = FabricPolicy {
            require_approval_for_scopes: vec!["forgewire_core/".into()],
            ..Default::default()
        };
        let gate = DispatchGate::new(policy);
        let req = DispatchRequest {
            task_id: "1".into(),
            scope_globs: vec!["forgewire_core/bus/**".into()],
            target_branch: None,
            dispatcher_id: None,
        };
        let d = gate.evaluate_dispatch(&req);
        assert!(d.needs_approval);
    }

    #[test]
    fn cost_cap_allows_under_budget() {
        let b = BudgetPolicy {
            daily_cost_cap_usd: Some(10.0),
            weekly_cost_cap_usd: Some(50.0),
            ..Default::default()
        };
        assert!(b.has_cost_caps());
        assert!(b.check_cost(5.0, 20.0).allowed);
    }

    #[test]
    fn cost_cap_denies_at_or_over_daily() {
        let b = BudgetPolicy { daily_cost_cap_usd: Some(10.0), ..Default::default() };
        let d = b.check_cost(10.0, 0.0); // at the cap denies (>=)
        assert!(d.denied);
        assert!(d.reasons[0].contains("daily budget exceeded"));
        assert!(b.check_cost(12.5, 0.0).denied);
        assert!(b.check_cost(9.99, 0.0).allowed);
    }

    #[test]
    fn cost_cap_denies_over_weekly() {
        let b = BudgetPolicy { weekly_cost_cap_usd: Some(50.0), ..Default::default() };
        let d = b.check_cost(0.0, 55.0);
        assert!(d.denied);
        assert!(d.reasons[0].contains("weekly budget exceeded"));
    }

    #[test]
    fn no_caps_means_no_store_read_and_always_allows() {
        let b = BudgetPolicy::default();
        assert!(!b.has_cost_caps());
        assert!(b.check_cost(1_000_000.0, 1_000_000.0).allowed);
    }

    #[test]
    fn budget_cap_enforced() {
        let policy = FabricPolicy {
            budget: BudgetPolicy {
                weekly_task_cap: Some(2),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut gate = DispatchGate::new(policy);
        gate.budget.record_dispatch();
        gate.budget.record_dispatch();

        let req = DispatchRequest {
            task_id: "3".into(),
            scope_globs: vec!["**".into()],
            target_branch: None,
            dispatcher_id: None,
        };
        let d = gate.evaluate_dispatch(&req);
        assert!(d.denied);
        assert!(d.reasons[0].contains("weekly task cap"));
    }
}
