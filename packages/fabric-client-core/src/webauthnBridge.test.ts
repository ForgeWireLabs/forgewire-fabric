import { describe, expect, it } from "vitest";
import {
  BRIDGE_CALLBACK_PATH,
  BRIDGE_FLOW_TIMEOUT_MS,
  MAX_BRIDGE_CALLBACK_BYTES,
  bridgeCallbackRequestIsAcceptable,
  buildBridgeUrl,
  generateBridgeState,
  parseBridgeCallback,
  type BridgeOutcome
} from "./webauthnBridge.js";

const STATE = "0123456789abcdef0123456789abcdef";

describe("buildBridgeUrl", () => {
  it("targets the bridge route with a loopback callback and the state nonce", () => {
    const url = new URL(
      buildBridgeUrl({
        hubUrl: "http://localhost:8765",
        mode: "login",
        callbackPort: 53123,
        state: STATE
      })
    );
    expect(url.pathname).toBe("/auth/webauthn/bridge");
    expect(url.searchParams.get("mode")).toBe("login");
    expect(url.searchParams.get("state")).toBe(STATE);
    expect(url.searchParams.get("callback")).toBe("http://127.0.0.1:53123/callback");
  });

  it("tolerates a hub url with trailing slashes without producing a double slash", () => {
    const url = buildBridgeUrl({
      hubUrl: "http://localhost:8765///",
      mode: "register",
      callbackPort: 1,
      state: STATE
    });
    expect(url).toContain("http://localhost:8765/auth/webauthn/bridge?");
  });

  it("only ever builds a loopback callback, regardless of the hub host", () => {
    // The callback is where secrets are returned; it must never follow the
    // hub's host, even for a remote hub.
    const url = new URL(
      buildBridgeUrl({
        hubUrl: "https://fabric.example:8765",
        mode: "login",
        callbackPort: 4321,
        state: STATE
      })
    );
    expect(url.searchParams.get("callback")).toBe("http://127.0.0.1:4321/callback");
  });

  it("rewrites an IP-literal loopback hub url to localhost", () => {
    // Regression: this is the exact shape the VS Code extension's
    // auto-discovered local hub uses (`http://127.0.0.1:<port>` in
    // hubClient.ts), against a realm's default rp_id of "localhost". An
    // IP-literal origin can never satisfy any rp_id, so the bridge page must
    // open at a host that actually matches -- mirrors the identical fix
    // already landed for Desktop's `build_bridge_url` (webauthn_bridge.rs).
    const url = buildBridgeUrl({
      hubUrl: "http://127.0.0.1:8765",
      mode: "login",
      callbackPort: 53123,
      state: STATE
    });
    expect(url.startsWith("http://localhost:8765/auth/webauthn/bridge?")).toBe(true);
    // The loopback callback is unaffected -- it is never derived from hubUrl.
    expect(url).toContain("callback=http%3A%2F%2F127.0.0.1%3A53123%2Fcallback");
  });

  it("leaves an already-localhost hub url unchanged", () => {
    const url = buildBridgeUrl({
      hubUrl: "http://localhost:8765",
      mode: "register",
      callbackPort: 1,
      state: STATE
    });
    expect(url.startsWith("http://localhost:8765/auth/webauthn/bridge?")).toBe(true);
  });

  it("rewrites a .localhost subdomain to localhost too", () => {
    const url = buildBridgeUrl({
      hubUrl: "http://tauri.localhost:8765",
      mode: "login",
      callbackPort: 1,
      state: STATE
    });
    expect(url.startsWith("http://localhost:8765/auth/webauthn/bridge?")).toBe(true);
  });

  it("leaves a remote non-loopback hub url unchanged", () => {
    // A remote hub's rp_id is whatever that realm configured -- this has no
    // basis to override it, unlike the loopback case where the realm's
    // default is known.
    const url = buildBridgeUrl({
      hubUrl: "https://fabric.example:8765",
      mode: "login",
      callbackPort: 1,
      state: STATE
    });
    expect(url.startsWith("https://fabric.example:8765/auth/webauthn/bridge?")).toBe(true);
  });

  it("carries the step-up challenge only when supplied, and never a secret", () => {
    // 114C.7 Slice 4c-3: step-up passes the public WebAuthn request options in
    // the query; login/register never do.
    const login = new URL(buildBridgeUrl({ hubUrl: "http://localhost:8765", mode: "login", callbackPort: 1, state: STATE }));
    expect(login.searchParams.has("challenge")).toBe(false);

    const stepUp = new URL(
      buildBridgeUrl({
        hubUrl: "http://localhost:8765",
        mode: "step-up",
        callbackPort: 1,
        state: STATE,
        challenge: JSON.stringify({ challenge: "abc", allowCredentials: [{ id: "cred-1" }] })
      })
    );
    expect(stepUp.searchParams.get("mode")).toBe("step-up");
    expect(JSON.parse(stepUp.searchParams.get("challenge")!)).toEqual({
      challenge: "abc",
      allowCredentials: [{ id: "cred-1" }]
    });
    // The URL carries no access/refresh secret in step-up mode.
    expect(stepUp.toString()).not.toContain("access_secret");
    expect(stepUp.toString()).not.toContain("refresh");
  });
});

describe("bridgeCallbackRequestIsAcceptable", () => {
  it("accepts the POST the bridge page actually sends", () => {
    expect(bridgeCallbackRequestIsAcceptable({ method: "POST", url: BRIDGE_CALLBACK_PATH })).toBe(
      true
    );
    expect(bridgeCallbackRequestIsAcceptable({ method: "post", url: "/callback" })).toBe(true);
  });

  it("rejects methods and paths that cannot be the ceremony reply", () => {
    // Browsers probe loopback ports with preflights and speculative GETs, and
    // any local process can connect. None of these should cause the listener
    // to buffer a body.
    expect(bridgeCallbackRequestIsAcceptable({ method: "GET", url: "/callback" })).toBe(false);
    expect(bridgeCallbackRequestIsAcceptable({ method: "OPTIONS", url: "/callback" })).toBe(false);
    expect(bridgeCallbackRequestIsAcceptable({ method: "POST", url: "/" })).toBe(false);
    expect(bridgeCallbackRequestIsAcceptable({ method: "POST", url: "/callback/../admin" })).toBe(
      false
    );
    expect(bridgeCallbackRequestIsAcceptable({ method: undefined, url: undefined })).toBe(false);
  });

  it("ignores a query string or fragment on the callback path", () => {
    // A false reject here would strand the user after they had already
    // completed the authenticator prompt.
    expect(bridgeCallbackRequestIsAcceptable({ method: "POST", url: "/callback?x=1" })).toBe(true);
    expect(bridgeCallbackRequestIsAcceptable({ method: "POST", url: "/callback#frag" })).toBe(true);
  });

  it("agrees with the callback URL that buildBridgeUrl hands the browser", () => {
    // The drift this pins: the page POSTs where buildBridgeUrl told it to, and
    // the listener accepts only BRIDGE_CALLBACK_PATH. If those two ever
    // disagreed the ceremony would fail at the very last step.
    const url = new URL(
      buildBridgeUrl({ hubUrl: "http://localhost:8765", mode: "login", callbackPort: 1, state: STATE })
    );
    const callbackPath = new URL(url.searchParams.get("callback") ?? "").pathname;
    expect(callbackPath).toBe(BRIDGE_CALLBACK_PATH);
    expect(bridgeCallbackRequestIsAcceptable({ method: "POST", url: callbackPath })).toBe(true);
  });
});

describe("bridge limits", () => {
  it("bounds the wait and the buffered body", () => {
    // Both exist so an abandoned or hostile flow cannot leave a socket open
    // forever or stream unbounded data into the client.
    expect(BRIDGE_FLOW_TIMEOUT_MS).toBeGreaterThan(0);
    expect(BRIDGE_FLOW_TIMEOUT_MS).toBeLessThanOrEqual(10 * 60 * 1000);
    expect(MAX_BRIDGE_CALLBACK_BYTES).toBeGreaterThan(0);
    expect(MAX_BRIDGE_CALLBACK_BYTES).toBeLessThanOrEqual(1024 * 1024);
  });
});

describe("generateBridgeState", () => {
  it("produces a 32-char hex string from 16 random bytes", () => {
    const state = generateBridgeState((n) => new Uint8Array(n).fill(0xab));
    expect(state).toBe("ab".repeat(16));
    expect(state).toMatch(/^[0-9a-f]{32}$/);
  });

  it("pads single-digit bytes so the encoding stays fixed-width", () => {
    // A naive toString(16) would render 0x0a as "a", shortening the nonce and
    // making distinct byte sequences collide.
    const state = generateBridgeState((n) => new Uint8Array(n).fill(0x0a));
    expect(state).toBe("0a".repeat(16));
  });
});

describe("parseBridgeCallback", () => {
  const okLogin = {
    state: STATE,
    status: "ok",
    session: {
      session_id: "sess-1",
      account_id: "acct-1",
      assurance_level: "aal2",
      access_secret: "access-value",
      refresh_secret: "refresh-value"
    }
  };

  it("accepts a well-formed login reply and maps it to camelCase", () => {
    const outcome = parseBridgeCallback(okLogin, STATE, "login");
    expect(outcome).toEqual<BridgeOutcome>({
      status: "ok",
      mode: "login",
      session: {
        sessionId: "sess-1",
        accountId: "acct-1",
        assuranceLevel: "aal2",
        accessSecret: "access-value",
        refreshSecret: "refresh-value"
      }
    });
  });

  it("rejects a reply whose state does not match the attempt", () => {
    // Another local process racing the loopback port must not be able to feed
    // this client a session.
    expect(parseBridgeCallback({ ...okLogin, state: "different" }, STATE, "login")).toBeNull();
    expect(parseBridgeCallback({ ...okLogin, state: undefined }, STATE, "login")).toBeNull();
  });

  it("surfaces an error reply with its message", () => {
    const outcome = parseBridgeCallback(
      { state: STATE, status: "error", message: "The passkey prompt was dismissed." },
      STATE,
      "login"
    );
    expect(outcome).toEqual({ status: "error", message: "The passkey prompt was dismissed." });
  });

  it("gives an error reply a fallback message when none is supplied", () => {
    const outcome = parseBridgeCallback({ state: STATE, status: "error" }, STATE, "login");
    expect(outcome).toMatchObject({ status: "error" });
  });

  it("treats a success with a missing or incomplete session as an error, never a success", () => {
    // The failure mode this guards: reporting "signed in" while holding no
    // usable session.
    expect(parseBridgeCallback({ state: STATE, status: "ok" }, STATE, "login")).toEqual({
      status: "error",
      message: "The hub reported success but returned no session."
    });
    for (const missing of ["session_id", "account_id", "access_secret", "refresh_secret"]) {
      const session: Record<string, unknown> = { ...okLogin.session };
      delete session[missing];
      const outcome = parseBridgeCallback(
        { state: STATE, status: "ok", session },
        STATE,
        "login"
      );
      expect(outcome, `missing ${missing}`).toEqual({
        status: "error",
        message: "The hub returned an incomplete session."
      });
    }
  });

  it("treats an empty-string secret as incomplete rather than usable", () => {
    const outcome = parseBridgeCallback(
      { state: STATE, status: "ok", session: { ...okLogin.session, access_secret: "" } },
      STATE,
      "login"
    );
    expect(outcome).toEqual({
      status: "error",
      message: "The hub returned an incomplete session."
    });
  });

  it("accepts a register reply and never expects a session on it", () => {
    const outcome = parseBridgeCallback(
      { state: STATE, status: "ok", credential_id: "cred-1" },
      STATE,
      "register"
    );
    expect(outcome).toEqual({ status: "ok", mode: "register", credentialId: "cred-1" });
  });

  it("accepts a register reply without a credential id", () => {
    const outcome = parseBridgeCallback({ state: STATE, status: "ok" }, STATE, "register");
    expect(outcome).toEqual({ status: "ok", mode: "register", credentialId: null });
  });

  it("accepts a step-up reply as the raw assertion, never a session", () => {
    const assertion = { id: "cred-1", response: { authenticatorData: "..." }, type: "public-key" };
    const outcome = parseBridgeCallback({ state: STATE, status: "ok", credential: assertion }, STATE, "step-up");
    expect(outcome).toEqual({ status: "ok", mode: "step-up", credential: assertion });
  });

  it("treats a step-up success with no assertion as an error, and still enforces state", () => {
    expect(parseBridgeCallback({ state: STATE, status: "ok" }, STATE, "step-up")).toEqual({
      status: "error",
      message: "The hub reported success but returned no assertion."
    });
    // State mismatch is rejected for step-up exactly like the other modes.
    expect(parseBridgeCallback({ state: "different", status: "ok", credential: {} }, STATE, "step-up")).toBeNull();
  });

  it("rejects non-object bodies and unknown statuses", () => {
    for (const body of [null, undefined, "ok", 42, []]) {
      expect(parseBridgeCallback(body, STATE, "login")).toBeNull();
    }
    expect(parseBridgeCallback({ state: STATE, status: "weird" }, STATE, "login")).toBeNull();
  });
});
