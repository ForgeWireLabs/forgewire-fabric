/**
 * Client-side logic for the hub-served WebAuthn bridge (114C.6 Slice 5b).
 *
 * Neither client can run a passkey ceremony in its own UI (the VS Code
 * extension host has no DOM; the Tauri webview serves from a `tauri://`
 * custom scheme on macOS/Linux and its CSP forbids reaching the hub), so both
 * open a hub-served page in the system browser and listen on a loopback URL
 * for the result. Everything here is pure -- URL construction, callback
 * parsing, and reply validation -- so it is unit-testable without a browser,
 * a socket, or an authenticator, and is shared rather than reimplemented in
 * each client.
 */

export type BridgeMode = "login" | "register" | "step-up";

export interface BridgeSessionPayload {
  readonly sessionId: string;
  readonly accountId: string;
  readonly assuranceLevel: string;
  readonly accessSecret: string;
  readonly refreshSecret: string;
}

export type BridgeOutcome =
  | { readonly status: "ok"; readonly mode: "login"; readonly session: BridgeSessionPayload }
  | { readonly status: "ok"; readonly mode: "register"; readonly credentialId: string | null }
  // 114C.7 Slice 4c-3: step-up is a "credential relay" -- the browser page runs
  // navigator.credentials.get and returns only the (public, single-use) WebAuthn
  // assertion. The session bearer never enters the page; the client makes the
  // step_up_options/verify hub calls itself and consumes this assertion there.
  | { readonly status: "ok"; readonly mode: "step-up"; readonly credential: Record<string, unknown> }
  | { readonly status: "error"; readonly message: string };

/**
 * A random value the client generates per attempt, echoed back by the bridge
 * page. The loopback listener rejects any reply whose state does not match,
 * so another local process cannot feed the client a result for a flow it did
 * not start.
 *
 * `randomBytes` is a required parameter rather than defaulting to a global
 * `crypto`: this package compiles against `lib: ["ES2022"]` with no DOM and no
 * Node types, deliberately, so the same logic is usable from the VS Code
 * extension host and from a browser webview without assuming either. Making
 * the CSPRNG an explicit argument keeps that property and puts the
 * security-relevant dependency in view at each call site instead of hiding it
 * behind an ambient global.
 */
export function generateBridgeState(randomBytes: (length: number) => Uint8Array): string {
  const bytes = randomBytes(16);
  let out = "";
  // padStart matters: a bare toString(16) renders 0x0a as "a", which would
  // shorten the nonce and let distinct byte sequences collide.
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

/**
 * The one path the loopback listener answers on.
 *
 * Shared rather than written literally in both places: `buildBridgeUrl` tells
 * the browser where to POST and the listener decides what to accept, so if
 * those two ever disagreed the ceremony would fail at the last step, after
 * the user had already completed an authenticator prompt.
 */
export const BRIDGE_CALLBACK_PATH = "/callback";

/**
 * How long a client should wait for the browser ceremony before giving up and
 * closing its listener. Generous, because it spans the user finding the tab,
 * typing a username, and completing a biometric prompt -- but finite, because
 * an abandoned flow must not leave a socket listening indefinitely.
 */
export const BRIDGE_FLOW_TIMEOUT_MS = 5 * 60 * 1000;

/**
 * Cap on the callback body a client will buffer. The real payload is well
 * under a kilobyte; anything larger is a local process abusing the listener,
 * and reading it unbounded would be a memory-exhaustion foothold.
 */
export const MAX_BRIDGE_CALLBACK_BYTES = 64 * 1024;

/**
 * Whether an inbound request to the loopback listener is worth reading a body
 * from at all.
 *
 * Browsers send a CORS preflight and speculative GETs to loopback ports, and
 * any local process can connect to one. Checking method and path before
 * buffering keeps the listener from doing work on requests that cannot be the
 * ceremony's reply. It is *not* the security boundary -- the `state` check in
 * `parseBridgeCallback` is -- but it is the cheap first filter.
 */
export function bridgeCallbackRequestIsAcceptable(request: {
  method: string | undefined;
  url: string | undefined;
}): boolean {
  if ((request.method ?? "").toUpperCase() !== "POST") return false;
  const url = request.url ?? "";
  // Compare only the path: the browser may append nothing, but a query string
  // or fragment must not cause a false reject.
  const path = url.split(/[?#]/)[0];
  return path === BRIDGE_CALLBACK_PATH;
}

/**
 * Build the URL to open in the system browser.
 *
 * The hub re-validates `callback` as loopback before serving the page, so a
 * caller cannot use this to point the ceremony's reply at an arbitrary host --
 * but this builds only loopback callbacks in the first place.
 */
export function buildBridgeUrl(options: {
  hubUrl: string;
  mode: BridgeMode;
  callbackPort: number;
  state: string;
  /**
   * 114C.7 Slice 4c-3: the step-up WebAuthn request options (the `public_key`
   * from `step_up_options`), JSON-stringified. Only step-up mode sets it; the
   * page runs `navigator.credentials.get` on it. Not a secret -- a single-use
   * challenge plus the account's (non-secret, opaque) credential IDs -- but it
   * does expose those IDs to browser history / process args, a documented
   * privacy note tracked for hub-side hardening.
   */
  challenge?: string;
}): string {
  const base = options.hubUrl.replace(/\/+$/, "");
  // Always loopback, never derived from `hubUrl`: this is where session
  // secrets come back, so it must stay on the machine that started the flow
  // even when the hub itself is remote.
  const callback = `http://127.0.0.1:${options.callbackPort}${BRIDGE_CALLBACK_PATH}`;
  // Hand-encoded rather than URLSearchParams: this package compiles against
  // `lib: ["ES2022"]` with no DOM and no Node types (see generateBridgeState).
  const params = [
    `mode=${encodeURIComponent(options.mode)}`,
    `callback=${encodeURIComponent(callback)}`,
    `state=${encodeURIComponent(options.state)}`
  ];
  if (options.challenge !== undefined) params.push(`challenge=${encodeURIComponent(options.challenge)}`);
  return `${base}/auth/webauthn/bridge?${params.join("&")}`;
}

/**
 * Parse and validate the JSON body the bridge page POSTs to the loopback
 * listener.
 *
 * Returns `null` when the reply does not belong to this attempt (state
 * mismatch) or is not well-formed -- the caller should keep waiting or time
 * out rather than acting on it. A malformed *success* is treated as an error
 * rather than silently dropped, so a client never reports "signed in" without
 * a usable session.
 */
export function parseBridgeCallback(
  body: unknown,
  expectedState: string,
  mode: BridgeMode
): BridgeOutcome | null {
  if (typeof body !== "object" || body === null) return null;
  const payload = body as Record<string, unknown>;

  // Constant-time comparison is unnecessary here: `state` is not a
  // credential, it is a correlation nonce, and the listener is loopback-only.
  if (typeof payload.state !== "string" || payload.state !== expectedState) return null;

  if (payload.status === "error") {
    const message = typeof payload.message === "string" ? payload.message : "The ceremony failed.";
    return { status: "error", message };
  }
  if (payload.status !== "ok") return null;

  if (mode === "register") {
    const credentialId = typeof payload.credential_id === "string" ? payload.credential_id : null;
    return { status: "ok", mode: "register", credentialId };
  }

  if (mode === "step-up") {
    // Only the raw WebAuthn assertion crosses back -- the client feeds it to
    // step_up_verify itself. A success with no assertion is an error, never a
    // silent "stepped up", mirroring the incomplete-session handling below.
    const credential = payload.credential;
    if (typeof credential !== "object" || credential === null) {
      return { status: "error", message: "The hub reported success but returned no assertion." };
    }
    return { status: "ok", mode: "step-up", credential: credential as Record<string, unknown> };
  }

  const session = payload.session;
  if (typeof session !== "object" || session === null) {
    return { status: "error", message: "The hub reported success but returned no session." };
  }
  const s = session as Record<string, unknown>;
  const required = ["session_id", "account_id", "access_secret", "refresh_secret"] as const;
  for (const key of required) {
    if (typeof s[key] !== "string" || (s[key] as string).length === 0) {
      return { status: "error", message: "The hub returned an incomplete session." };
    }
  }
  return {
    status: "ok",
    mode: "login",
    session: {
      sessionId: s.session_id as string,
      accountId: s.account_id as string,
      assuranceLevel: typeof s.assurance_level === "string" ? s.assurance_level : "aal1",
      accessSecret: s.access_secret as string,
      refreshSecret: s.refresh_secret as string
    }
  };
}

/**
 * A minimal HTML body for the loopback listener to return to the browser tab,
 * so the user sees a definite end state rather than a connection error. Static
 * and parameter-free -- nothing from the reply is echoed back into it, so it
 * cannot become a reflection sink.
 */
export const BRIDGE_CALLBACK_ACK_HTML =
  "<!doctype html><meta charset=utf-8><title>Done</title>" +
  "<p style=\"font-family:system-ui;margin:3rem\">You can close this tab and return to the app.</p>";
