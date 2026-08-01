/**
 * Human-session credential storage and WebAuthn passkey ceremonies for the
 * Desktop client (114C.6 Slice 5).
 *
 * Two distinct concerns live here, deliberately kept apart:
 *
 * 1. `TauriSessionCredentialStore` implements `SessionCredentialStore` from
 *    `@forgewire/fabric-client-core` over the OS credential store (Windows
 *    Credential Manager / macOS Keychain / Linux Secret Service) via three
 *    Tauri commands. This closes the still-open Desktop half of 114C.3's
 *    "protected session storage adapters" deliverable.
 *
 * 2. The passkey ceremony functions call `navigator.credentials` directly.
 *    Tauri's webview is a real DOM context, so unlike a VS Code extension
 *    host this can run WebAuthn natively -- no bridge needed. The private
 *    key never leaves the platform authenticator; only the public
 *    attestation/assertion response crosses into this code, which is what
 *    makes 114C.6's "private keys never enter Fabric storage or renderer
 *    state" true by construction.
 *
 * Deployment constraint (114C.6 scope decision, enforced hub-side too):
 * WebAuthn requires a secure context, so passkeys work when the hub is
 * reached over `https://` or a loopback origin. A plain-HTTP LAN hub cannot
 * run a ceremony at all; `passkeySupportError` below reports that up front
 * rather than letting `navigator.credentials` fail opaquely mid-prompt.
 */

import { invoke } from "@tauri-apps/api/core";
import type { SessionCredentialStore, SessionSecrets } from "@forgewire/fabric-client-core";
import type { DesktopTransport } from "./api";

const tauriTransport: DesktopTransport = {
  invoke: <T>(command: string, args?: Record<string, unknown>) => invoke<T>(command, args)
};

/** Desktop has one active hub connection at a time (mirrors VSIX's
 *  `DEFAULT_SESSION_PROFILE_ID` in `vscode/src/humanSession.ts`), so every
 *  call site uses this same constant until a real multi-profile model
 *  exists. */
export const DEFAULT_SESSION_PROFILE_ID = "default";

/** Wire shape of the Tauri commands (snake_case), distinct from the
 *  camelCase `SessionSecrets` the shared client-core interface uses. */
interface NativeSessionSecrets {
  session_id: string;
  access_secret: string;
  refresh_secret: string;
  session_signing_key?: string | null;
}

function toNative(secrets: SessionSecrets): NativeSessionSecrets {
  return {
    session_id: secrets.sessionId,
    access_secret: secrets.accessSecret,
    refresh_secret: secrets.refreshSecret,
    // 114E: only present for key-bound (PoP) sessions; omitted otherwise so a
    // bearer-only session round-trips unchanged.
    session_signing_key: secrets.sessionSigningKey
  };
}

function fromNative(native: NativeSessionSecrets | null | undefined): SessionSecrets | undefined {
  if (!native || !native.session_id || !native.access_secret || !native.refresh_secret) {
    return undefined;
  }
  return {
    sessionId: native.session_id,
    accessSecret: native.access_secret,
    refreshSecret: native.refresh_secret,
    sessionSigningKey: native.session_signing_key ?? undefined
  };
}

export class TauriSessionCredentialStore implements SessionCredentialStore {
  constructor(private readonly transport: DesktopTransport = tauriTransport) {}

  async get(profileId: string): Promise<SessionSecrets | undefined> {
    const native = await this.transport.invoke<NativeSessionSecrets | null>(
      "load_session_secrets",
      { profileId }
    );
    return fromNative(native);
  }

  async set(profileId: string, secrets: SessionSecrets): Promise<void> {
    await this.transport.invoke<void>("save_session_secrets", {
      profileId,
      secrets: toNative(secrets)
    });
  }

  async delete(profileId: string): Promise<void> {
    await this.transport.invoke<void>("clear_session_secrets", { profileId });
  }
}

// ---- WebAuthn support detection ------------------------------------------

/**
 * Why a passkey ceremony cannot run right now, or `null` if it can.
 *
 * Checks the **page** origin, not the hub URL: WebAuthn binds a credential
 * to the origin of the page that calls `navigator.credentials`, and the hub
 * only ever sees that origin second-hand in `clientDataJSON`. Which means
 * the hub's `auth.passkeys.allowed_origins` must list *this app's* origin,
 * not the hub's own address -- {@link passkeyOriginAdvice} produces the
 * exact value an operator needs to paste there.
 *
 * Per-platform reality, verified against tauri 2.11's
 * `manager::tauri_protocol_url` rather than assumed:
 *   - Windows: `http://tauri.localhost` -- a `.localhost` origin, which
 *     browsers treat as potentially trustworthy, so ceremonies work.
 *   - macOS/Linux: `tauri://localhost` -- a custom scheme, which is not a
 *     WebAuthn-eligible origin. Passkeys are unavailable there; this
 *     reports that plainly instead of letting the prompt fail opaquely.
 *   - Dev (`npm run tauri:dev`): `http://localhost:5173`, which works.
 *
 * This matches 114C.6's own acceptance wording, which scopes the Desktop
 * passkey proof to Windows.
 */
export function passkeySupportError(
  win: Pick<Window, "isSecureContext" | "location"> & { PublicKeyCredential?: unknown } = window
): string | null {
  if (typeof win.PublicKeyCredential === "undefined") {
    return "This build does not support passkeys (no WebAuthn in the webview).";
  }
  const origin = win.location.origin;
  if (origin.startsWith("tauri://")) {
    return (
      "Passkeys are not available on this platform: the app is served from the custom " +
      `scheme ${origin}, which browsers do not accept as a WebAuthn origin. Passkeys ` +
      "on Desktop are supported on Windows (http://tauri.localhost). Use password sign-in here."
    );
  }
  if (!win.isSecureContext) {
    return `Passkeys need a secure context; this app is running at ${origin}.`;
  }
  return null;
}

/**
 * The origin an operator must add to the hub's `auth.passkeys.allowed_origins`
 * for this client's ceremonies to be accepted. Reported from the live page
 * rather than hardcoded, because it differs per platform and between dev and
 * production builds -- surfacing the real value beats documenting a guess.
 */
export function passkeyOriginAdvice(
  win: Pick<Window, "location"> = window
): { origin: string; suggestedRpId: string | null } {
  const origin = win.location.origin;
  let suggestedRpId: string | null = null;
  try {
    const host = new URL(origin).hostname;
    // The RP ID must be a registrable domain suffix of the origin's host.
    // For `tauri.localhost` (and `localhost:5173`), `localhost` satisfies
    // that and keeps one RP ID working across dev and production.
    suggestedRpId = host === "localhost" || host.endsWith(".localhost") ? "localhost" : host;
  } catch {
    suggestedRpId = null;
  }
  return { origin, suggestedRpId };
}

// ---- base64url <-> ArrayBuffer -------------------------------------------
//
// The hub speaks the WebAuthn JSON shape (base64url strings); the browser API
// speaks ArrayBuffers. These conversions are pure and exported so they are
// unit-testable without a DOM or an authenticator.

export function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded.padEnd(padded.length + ((4 - (padded.length % 4)) % 4), "="));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function bytesToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Convert the hub's `publicKey` creation options (JSON, base64url) into the
 * `PublicKeyCredentialCreationOptions` the browser API requires.
 */
export function decodeCreationOptions(
  publicKey: Record<string, unknown>
): PublicKeyCredentialCreationOptions {
  const options = { ...publicKey } as Record<string, unknown>;
  options.challenge = base64UrlToBytes(String(publicKey.challenge));
  const user = { ...(publicKey.user as Record<string, unknown>) };
  user.id = base64UrlToBytes(String(user.id));
  options.user = user;
  if (Array.isArray(publicKey.excludeCredentials)) {
    options.excludeCredentials = publicKey.excludeCredentials.map((entry) => ({
      ...(entry as Record<string, unknown>),
      id: base64UrlToBytes(String((entry as Record<string, unknown>).id))
    }));
  }
  return options as unknown as PublicKeyCredentialCreationOptions;
}

/**
 * Convert the hub's `publicKey` request options (JSON, base64url) into the
 * `PublicKeyCredentialRequestOptions` the browser API requires.
 */
export function decodeRequestOptions(
  publicKey: Record<string, unknown>
): PublicKeyCredentialRequestOptions {
  const options = { ...publicKey } as Record<string, unknown>;
  options.challenge = base64UrlToBytes(String(publicKey.challenge));
  if (Array.isArray(publicKey.allowCredentials)) {
    options.allowCredentials = publicKey.allowCredentials.map((entry) => ({
      ...(entry as Record<string, unknown>),
      id: base64UrlToBytes(String((entry as Record<string, unknown>).id))
    }));
  }
  return options as unknown as PublicKeyCredentialRequestOptions;
}

/** Serialize a registration credential into the hub's expected JSON shape. */
export function encodeRegistrationCredential(credential: PublicKeyCredential): unknown {
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: bytesToBase64Url(response.attestationObject),
      clientDataJSON: bytesToBase64Url(response.clientDataJSON)
    }
  };
}

/** Serialize an authentication assertion into the hub's expected JSON shape. */
export function encodeAssertionCredential(credential: PublicKeyCredential): unknown {
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bytesToBase64Url(response.authenticatorData),
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      signature: bytesToBase64Url(response.signature),
      userHandle: response.userHandle ? bytesToBase64Url(response.userHandle) : null
    }
  };
}
