// Keep each route declaration beside the handlers that own it. The macro emits
// both the Axum router and (for regression tests) a method/path manifest from a
// single declaration, so the equivalence check cannot drift from registration.
macro_rules! owned_router {
    (
        $visibility:vis fn $router:ident, $manifest:ident {
            $( $method_name:literal $method:ident $path:literal => $handler:path; )+
        }
    ) => {
        $visibility fn $router() -> axum::Router<std::sync::Arc<crate::state::HubState>> {
            axum::Router::new()
                $(.route($path, axum::routing::$method($handler)))+
        }

        #[cfg(test)]
        pub(super) const $manifest: &[(&str, &str)] = &[
            $(($method_name, $path)),+
        ];
    };
}

pub mod accounts;
pub mod admin;
pub mod agents;
pub mod approvals;
pub mod audit;
pub mod authn;
pub mod cluster;
pub mod cost;
pub mod dispatchers;
pub mod health;
pub mod history;
pub mod labels;
pub mod policy;
pub mod runners;
pub mod secrets;
pub mod settings;
pub mod state;
pub mod streams;
pub mod tasks;
pub mod webauthn_bridge;
pub mod webauthn_doctor;
pub mod whoami;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_route_manifest_matches_pre_split_table() {
        let actual: Vec<_> = [
            tasks::ROUTES,
            streams::ROUTES,
            tasks::INTENT_ROUTES,
            streams::INPUT_ROUTES,
            state::ROUTES,
            runners::ROUTES,
            dispatchers::ROUTES,
            approvals::ROUTES,
            agents::ROUTES,
            cluster::ROUTES,
            audit::ROUTES,
            cluster::AUDIT_ROUTES,
            admin::ROUTES,
            cost::ROUTES,
            policy::ROUTES,
            history::ROUTES,
            secrets::ROUTES,
            settings::ROUTES,
            labels::ROUTES,
            accounts::ROUTES,
            authn::ROUTES,
            whoami::ROUTES,
        ]
        .into_iter()
        .flatten()
        .copied()
        .collect();

        assert_eq!(
            actual,
            [
                ("GET", "/tasks"),
                ("POST", "/tasks"),
                ("POST", "/tasks/v2"),
                ("GET", "/tasks/waiting"),
                ("POST", "/tasks/claim"),
                ("POST", "/tasks/claim-loom"),
                ("POST", "/tasks/claim-fabric"),
                ("GET", "/tasks/{task_id}"),
                ("GET", "/tasks/{task_id}/events"),
                ("POST", "/tasks/{task_id}/start"),
                ("POST", "/tasks/{task_id}/cancel"),
                ("POST", "/tasks/{task_id}/progress"),
                ("POST", "/tasks/{task_id}/stream"),
                ("GET", "/tasks/{task_id}/stream"),
                ("POST", "/tasks/{task_id}/stream/bulk"),
                ("POST", "/tasks/{task_id}/result"),
                ("POST", "/tasks/{task_id}/notes"),
                ("GET", "/tasks/{task_id}/notes"),
                ("POST", "/tasks/{task_id}/intent"),
                ("POST", "/tasks/{task_id}/input"),
                ("GET", "/tasks/{task_id}/input"),
                ("GET", "/state/snapshot"),
                ("POST", "/state/import"),
                ("GET", "/runners"),
                ("POST", "/runners/register"),
                ("POST", "/runners/{runner_id}/heartbeat"),
                ("POST", "/runners/{runner_id}/drain"),
                ("POST", "/runners/{runner_id}/drain-by-dispatcher"),
                ("POST", "/runners/{runner_id}/undrain-by-dispatcher"),
                ("DELETE", "/runners/{runner_id}"),
                ("POST", "/dispatchers/register"),
                ("GET", "/dispatchers"),
                ("DELETE", "/dispatchers/{dispatcher_id}"),
                ("GET", "/approvals"),
                ("GET", "/approvals/{approval_id}"),
                ("POST", "/approvals/{approval_id}/approve"),
                ("POST", "/approvals/{approval_id}/deny"),
                ("GET", "/agents"),
                ("GET", "/capabilities/{kind}/{name}"),
                ("GET", "/cluster/health"),
                ("GET", "/hosts"),
                ("GET", "/audit/tasks/{task_id}"),
                ("GET", "/audit/tail"),
                ("GET", "/audit/day/{day}"),
                ("GET", "/admin/role-tokens"),
                ("POST", "/admin/role-tokens"),
                ("POST", "/admin/role-tokens/split"),
                ("POST", "/admin/role-tokens/migrate"),
                ("DELETE", "/admin/role-tokens/{token_id}"),
                ("GET", "/admin/binaries/manifest"),
                ("GET", "/admin/binaries/{name}"),
                ("POST", "/admin/update"),
                ("GET", "/cost/summary"),
                ("GET", "/cost/records"),
                ("GET", "/cost/budget"),
                ("GET", "/policy"),
                ("GET", "/history/status"),
                ("POST", "/secrets"),
                ("GET", "/secrets"),
                ("DELETE", "/secrets/{name}"),
                ("GET", "/settings"),
                ("GET", "/settings/schema"),
                ("PUT", "/settings/{*key}"),
                ("DELETE", "/settings/{*key}"),
                ("GET", "/labels"),
                ("PUT", "/labels/hub"),
                ("PUT", "/labels/runners/{runner_id}"),
                ("PUT", "/labels/hosts/{hostname}"),
                ("POST", "/hosts/roles"),
                ("GET", "/accounts"),
                ("POST", "/accounts"),
                ("GET", "/accounts/{account_id}"),
                ("PATCH", "/accounts/{account_id}"),
                ("POST", "/accounts/{account_id}/membership"),
                ("DELETE", "/accounts/{account_id}/membership/{role}"),
                ("POST", "/accounts/{account_id}/disable"),
                ("POST", "/accounts/{account_id}/enable"),
                ("POST", "/accounts/{account_id}/recovery-codes"),
                ("POST", "/accounts/{account_id}/recovery/complete"),
                ("POST", "/accounts/{account_id}/delete"),
                ("POST", "/accounts/{account_id}/tombstone"),
                ("GET", "/accounts/{account_id}/security-history"),
                ("GET", "/accounts/export"),
                ("POST", "/accounts/import"),
                ("GET", "/auth-policy"),
                ("GET", "/auth/sessions"),
                ("DELETE", "/auth/sessions/{session_id}"),
                ("POST", "/auth/logout"),
                ("POST", "/auth/logout-all"),
                ("GET", "/auth/me"),
                ("POST", "/auth/passkeys/register/options"),
                ("POST", "/auth/passkeys/register/verify"),
                ("DELETE", "/auth/passkeys/{credential_id}"),
                ("POST", "/auth/step-up/options"),
                ("POST", "/auth/step-up/verify"),
                ("GET", "/whoami"),
            ]
        );
    }

    /// `public_route_manifest_remains_health_only` (pre-114C.3-debt-closeout
    /// name) is intentionally gone, not renamed-and-kept: the assertion it
    /// made (only `/healthz` is ever public) stopped being true the moment
    /// bootstrap/login/refresh had to be reachable without a credential --
    /// this replacement asserts the new, deliberately-widened public surface
    /// exactly, rather than silently dropping the invariant.
    ///
    /// `/auth/webauthn/doctor` (114C.6 Slice 7) joined this list rather than
    /// the authenticated one on purpose: it reports `rp_id`/allowed-origins
    /// config, which is operator-configured routing information, not a
    /// secret -- the bridge page already reveals the RP ID to any browser
    /// that reaches it, and the origins are by definition meant to be
    /// publicly reachable. See that route's own doc comment for the full
    /// reasoning.
    #[test]
    fn public_route_manifest_covers_health_and_self_service_auth_only() {
        let actual: Vec<_> = [
            health::ROUTES,
            authn::PUBLIC_ROUTES,
            webauthn_bridge::PUBLIC_ROUTES,
            webauthn_doctor::PUBLIC_ROUTES,
        ]
        .into_iter()
        .flatten()
        .copied()
        .collect();
        assert_eq!(
            actual,
            [
                ("GET", "/healthz"),
                ("GET", "/auth/bootstrap/status"),
                ("POST", "/auth/bootstrap"),
                ("POST", "/auth/login"),
                ("POST", "/auth/refresh"),
                ("POST", "/auth/passkeys/options"),
                ("POST", "/auth/passkeys/verify"),
                ("GET", "/auth/webauthn/bridge"),
                ("GET", "/auth/webauthn/bridge.js"),
                ("GET", "/auth/webauthn/doctor"),
            ]
        );
    }
}
