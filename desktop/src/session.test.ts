import { describe, expect, it } from "vitest";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  decodeCreationOptions,
  decodeRequestOptions,
  encodeAssertionCredential,
  encodeRegistrationCredential,
  passkeyOriginAdvice,
  passkeySupportError,
  TauriSessionCredentialStore
} from "./session";
import type { DesktopTransport } from "./api";

class RecordingTransport implements DesktopTransport {
  readonly calls: Array<{ command: string; args?: Record<string, unknown> }> = [];
  private readonly responses = new Map<string, unknown[]>();

  respond(command: string, ...values: unknown[]) {
    this.responses.set(command, [...values]);
    return this;
  }

  async invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
    this.calls.push(args ? { command, args } : { command });
    const queue = this.responses.get(command) ?? [];
    if (queue.length === 0) return undefined as T;
    const value = queue.shift();
    if (value instanceof Error) throw value;
    return value as T;
  }
}

describe("TauriSessionCredentialStore", () => {
  it("maps camelCase SessionSecrets onto the snake_case native command shape", async () => {
    const transport = new RecordingTransport();
    const store = new TauriSessionCredentialStore(transport);
    await store.set("profile-a", {
      sessionId: "sess-1",
      accessSecret: "access-secret-value",
      refreshSecret: "refresh-secret-value"
    });
    expect(transport.calls).toEqual([
      {
        command: "save_session_secrets",
        args: {
          profileId: "profile-a",
          secrets: {
            session_id: "sess-1",
            access_secret: "access-secret-value",
            refresh_secret: "refresh-secret-value"
          }
        }
      }
    ]);
  });

  it("maps the native snake_case response back to camelCase SessionSecrets", async () => {
    const transport = new RecordingTransport().respond("load_session_secrets", {
      session_id: "sess-1",
      access_secret: "access-secret-value",
      refresh_secret: "refresh-secret-value"
    });
    const store = new TauriSessionCredentialStore(transport);
    await expect(store.get("profile-a")).resolves.toEqual({
      sessionId: "sess-1",
      accessSecret: "access-secret-value",
      refreshSecret: "refresh-secret-value"
    });
  });

  it("treats a missing or partial stored entry as no session rather than a broken one", async () => {
    const missing = new TauriSessionCredentialStore(
      new RecordingTransport().respond("load_session_secrets", null)
    );
    await expect(missing.get("profile-a")).resolves.toBeUndefined();

    // A half-written entry must not surface as a usable session -- the
    // caller's correct response is to sign in again.
    const partial = new TauriSessionCredentialStore(
      new RecordingTransport().respond("load_session_secrets", {
        session_id: "sess-1",
        access_secret: "",
        refresh_secret: "refresh-secret-value"
      })
    );
    await expect(partial.get("profile-a")).resolves.toBeUndefined();
  });

  it("clears by profile id", async () => {
    const transport = new RecordingTransport();
    await new TauriSessionCredentialStore(transport).delete("profile-a");
    expect(transport.calls).toEqual([
      { command: "clear_session_secrets", args: { profileId: "profile-a" } }
    ]);
  });
});

describe("passkeySupportError", () => {
  const win = (origin: string, overrides: Record<string, unknown> = {}) =>
    ({
      isSecureContext: true,
      PublicKeyCredential: class {},
      location: { origin },
      ...overrides
    }) as never;

  it("accepts the Windows Tauri origin (http://tauri.localhost)", () => {
    // Verified against tauri 2.11's manager::tauri_protocol_url: Windows
    // serves the webview from this origin, and `.localhost` is a
    // potentially-trustworthy origin, so ceremonies work.
    expect(passkeySupportError(win("http://tauri.localhost"))).toBeNull();
  });

  it("accepts the dev-server origin", () => {
    expect(passkeySupportError(win("http://localhost:5173"))).toBeNull();
  });

  it("rejects the macOS/Linux custom scheme with a platform explanation", () => {
    const error = passkeySupportError(win("tauri://localhost"));
    expect(error).toMatch(/not available on this platform/i);
    // Must point at the supported platform rather than just failing.
    expect(error).toMatch(/windows/i);
  });

  it("rejects a non-secure context and names the offending origin", () => {
    const error = passkeySupportError(win("http://192.168.1.50:1420", { isSecureContext: false }));
    expect(error).toMatch(/secure context/i);
    expect(error).toContain("192.168.1.50");
  });

  it("rejects a webview without WebAuthn at all", () => {
    expect(passkeySupportError(win("http://tauri.localhost", { PublicKeyCredential: undefined })))
      .toMatch(/does not support/i);
  });
});

describe("passkeyOriginAdvice", () => {
  it("reports the live page origin, not a hardcoded guess", () => {
    const advice = passkeyOriginAdvice({ location: { origin: "http://tauri.localhost" } } as never);
    expect(advice.origin).toBe("http://tauri.localhost");
  });

  it("suggests `localhost` as the RP id for any .localhost origin so one id spans dev and prod", () => {
    expect(
      passkeyOriginAdvice({ location: { origin: "http://tauri.localhost" } } as never).suggestedRpId
    ).toBe("localhost");
    expect(
      passkeyOriginAdvice({ location: { origin: "http://localhost:5173" } } as never).suggestedRpId
    ).toBe("localhost");
  });

  it("suggests the host itself for a real domain origin", () => {
    expect(
      passkeyOriginAdvice({ location: { origin: "https://fabric.example" } } as never).suggestedRpId
    ).toBe("fabric.example");
  });
});

describe("base64url conversions", () => {
  it("round-trips arbitrary bytes including ones needing padding", () => {
    for (const raw of [[0], [0, 1, 2], [255, 254, 253, 252], [1, 2, 3, 4, 5]]) {
      const bytes = new Uint8Array(raw);
      const encoded = bytesToBase64Url(bytes.buffer);
      expect(Array.from(base64UrlToBytes(encoded))).toEqual(raw);
    }
  });

  it("emits url-safe alphabet with no padding", () => {
    // 0xFB 0xFF encodes to "+/8" in standard base64 -- both chars must be
    // translated, and the "=" padding dropped.
    const encoded = bytesToBase64Url(new Uint8Array([251, 255]).buffer);
    expect(encoded).not.toMatch(/[+/=]/);
  });
});

describe("ceremony option decoding", () => {
  it("decodes challenge, user id, and excludeCredentials ids to buffers", () => {
    const decoded = decodeCreationOptions({
      challenge: "AAEC",
      rp: { id: "localhost", name: "Test" },
      user: { id: "AwQF", name: "alice", displayName: "Alice" },
      pubKeyCredParams: [],
      excludeCredentials: [{ type: "public-key", id: "BgcI" }]
    });
    expect(Array.from(new Uint8Array(decoded.challenge as ArrayBuffer))).toEqual([0, 1, 2]);
    expect(Array.from(new Uint8Array(decoded.user.id as ArrayBuffer))).toEqual([3, 4, 5]);
    expect(
      Array.from(new Uint8Array(decoded.excludeCredentials![0].id as ArrayBuffer))
    ).toEqual([6, 7, 8]);
    // Non-buffer fields pass through untouched.
    expect(decoded.rp.id).toBe("localhost");
  });

  it("decodes request options without requiring allowCredentials", () => {
    const decoded = decodeRequestOptions({ challenge: "AAEC", rpId: "localhost" });
    expect(Array.from(new Uint8Array(decoded.challenge as ArrayBuffer))).toEqual([0, 1, 2]);
    expect(decoded.allowCredentials).toBeUndefined();
  });
});

describe("credential encoding", () => {
  const buffer = (values: number[]) => new Uint8Array(values).buffer;

  it("encodes a registration credential into the hub's JSON shape", () => {
    const encoded = encodeRegistrationCredential({
      id: "cred-id",
      rawId: buffer([1, 2, 3]),
      type: "public-key",
      response: {
        attestationObject: buffer([4, 5, 6]),
        clientDataJSON: buffer([7, 8, 9])
      }
    } as unknown as PublicKeyCredential) as Record<string, Record<string, string>>;
    expect(encoded.id).toBe("cred-id");
    expect(encoded.type).toBe("public-key");
    expect(encoded.rawId).toBe(bytesToBase64Url(buffer([1, 2, 3])));
    expect(encoded.response.attestationObject).toBe(bytesToBase64Url(buffer([4, 5, 6])));
    expect(encoded.response.clientDataJSON).toBe(bytesToBase64Url(buffer([7, 8, 9])));
  });

  it("encodes an assertion credential, carrying a null userHandle through as null", () => {
    const encoded = encodeAssertionCredential({
      id: "cred-id",
      rawId: buffer([1]),
      type: "public-key",
      response: {
        authenticatorData: buffer([2]),
        clientDataJSON: buffer([3]),
        signature: buffer([4]),
        userHandle: null
      }
    } as unknown as PublicKeyCredential) as Record<string, Record<string, unknown>>;
    expect(encoded.response.signature).toBe(bytesToBase64Url(buffer([4])));
    expect(encoded.response.userHandle).toBeNull();
  });

  it("encodes a present userHandle as base64url", () => {
    const encoded = encodeAssertionCredential({
      id: "cred-id",
      rawId: buffer([1]),
      type: "public-key",
      response: {
        authenticatorData: buffer([2]),
        clientDataJSON: buffer([3]),
        signature: buffer([4]),
        userHandle: buffer([9, 9])
      }
    } as unknown as PublicKeyCredential) as Record<string, Record<string, unknown>>;
    expect(encoded.response.userHandle).toBe(bytesToBase64Url(buffer([9, 9])));
  });
});
