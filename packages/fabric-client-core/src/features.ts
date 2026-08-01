export const FABRIC_FEATURES = [
  "signed_dispatch",
  "task_stream",
  "runner_drain",
  "approval_decisions",
  "cost",
  "audit",
  "secrets",
  "cluster_health",
  "human_accounts",
] as const;

export type FabricFeature = (typeof FABRIC_FEATURES)[number];

export interface FeatureSignals {
  readonly protocolVersion?: number | string;
  readonly advertised?: readonly string[];
}

/**
 * Features that must be explicitly advertised and are never inferred from
 * protocol version alone. 114C's account routes are additive to protocol v4
 * -- `PROTOCOL_VERSION` does not move for 114C (locked in
 * `114C-name-lock.md`) -- so a pre-114C hub and a post-114C hub both report
 * protocol 4. Falling them under the same "protocol >= 4 implies support"
 * rule every other feature here uses would mark every pre-114C hub as
 * supporting human accounts, which is exactly the downgrade/compatibility
 * failure 114C.1's acceptance criterion ("older protocol-v4 hubs produce a
 * supported 'feature unavailable' state, not a generic failure") exists to
 * prevent.
 */
const ADVERTISEMENT_ONLY_FEATURES: ReadonlySet<FabricFeature> = new Set(["human_accounts"]);

/**
 * Normalize Hub capability signals once so skins do not infer support from
 * individual payload shapes. Explicit advertisement wins; protocol v4 is the
 * compatibility floor for the current operator surface, except for
 * {@link ADVERTISEMENT_ONLY_FEATURES}, which requires explicit advertisement
 * regardless of protocol version.
 */
export function detectFabricFeatures(signals: FeatureSignals): ReadonlySet<FabricFeature> {
  const advertised = new Set((signals.advertised ?? []).map((item) => item.trim().toLowerCase()));
  const protocol = Number(signals.protocolVersion ?? 0);
  const supported = new Set<FabricFeature>();

  for (const feature of FABRIC_FEATURES) {
    if (advertised.has(feature)) {
      supported.add(feature);
      continue;
    }
    if (protocol >= 4 && !ADVERTISEMENT_ONLY_FEATURES.has(feature)) supported.add(feature);
  }
  return supported;
}

export function supportsFabricFeature(signals: FeatureSignals, feature: FabricFeature): boolean {
  return detectFabricFeatures(signals).has(feature);
}
