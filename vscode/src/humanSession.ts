/**
 * VS Code side of protected human-account session storage (114C.6 Slice 5c).
 *
 * Implements `SessionCredentialStore` from `@forgewire/fabric-client-core`
 * over `vscode.SecretStorage`, mirroring `TauriSessionCredentialStore` in
 * `desktop/src/session.ts` (114C.6 Slice 5a) -- same interface, same
 * camelCase-in/JSON-out shape, different backing store because the two
 * clients have different protected-storage primitives available to them.
 *
 * The VSIX has one active hub connection at a time (see `SECRET_TOKEN_KEY` /
 * `DispatcherSession`'s `forgewire.dispatcherIdentity` in extension.ts and
 * hubClient.ts, both single fixed keys, no per-hub profile concept yet), so
 * `profileId` is honored in the storage key for forward compatibility with
 * `SessionCredentialStore`'s contract, but every call site here passes the
 * same constant until a real multi-profile model exists.
 */

import * as vscode from "vscode";
import type { SessionCredentialStore, SessionSecrets } from "@forgewire/fabric-client-core";

export const DEFAULT_SESSION_PROFILE_ID = "default";

const KEY_PREFIX = "forgewire.humanSession.";

interface StoredSessionSecrets {
  session_id: string;
  access_secret: string;
  refresh_secret: string;
}

function toStored(secrets: SessionSecrets): StoredSessionSecrets {
  return {
    session_id: secrets.sessionId,
    access_secret: secrets.accessSecret,
    refresh_secret: secrets.refreshSecret,
  };
}

function fromStored(raw: string | undefined): SessionSecrets | undefined {
  if (!raw) return undefined;
  let parsed: Partial<StoredSessionSecrets>;
  try {
    parsed = JSON.parse(raw) as Partial<StoredSessionSecrets>;
  } catch {
    return undefined; // corrupted storage -- treat as absent, not a crash
  }
  if (!parsed.session_id || !parsed.access_secret || !parsed.refresh_secret) return undefined;
  return {
    sessionId: parsed.session_id,
    accessSecret: parsed.access_secret,
    refreshSecret: parsed.refresh_secret,
  };
}

export class VscodeSessionCredentialStore implements SessionCredentialStore {
  constructor(private readonly secrets: vscode.SecretStorage) {}

  async get(profileId: string): Promise<SessionSecrets | undefined> {
    return fromStored(await this.secrets.get(KEY_PREFIX + profileId));
  }

  async set(profileId: string, secrets: SessionSecrets): Promise<void> {
    await this.secrets.store(KEY_PREFIX + profileId, JSON.stringify(toStored(secrets)));
  }

  async delete(profileId: string): Promise<void> {
    await this.secrets.delete(KEY_PREFIX + profileId);
  }
}
