/**
 * VS Code side of the hub-served WebAuthn bridge (114C.6 Slice 5c).
 *
 * The extension host has no DOM -- no `navigator.credentials`, nowhere to
 * run a ceremony -- so it opens the hub's bridge page (114C.6 Slice 5b) in
 * the system browser and listens on an ephemeral loopback port for the
 * result. Everything that decides what a request or a reply *means* (is this
 * even a candidate request? does the state nonce match? is the payload
 * well-formed?) lives in `@forgewire/fabric-client-core` and is exercised by
 * its vitest suite; this file only wires that logic to Node's `http` module
 * and `vscode.env.openExternal`, since the extension host has no test runner
 * of its own (`npm run compile` here is typecheck + bundle, nothing else).
 */

import * as http from "http";
import type { AddressInfo } from "net";
import * as vscode from "vscode";
import {
  BRIDGE_CALLBACK_ACK_HTML,
  BRIDGE_FLOW_TIMEOUT_MS,
  MAX_BRIDGE_CALLBACK_BYTES,
  bridgeCallbackRequestIsAcceptable,
  buildBridgeUrl,
  generateBridgeState,
  parseBridgeCallback,
  type BridgeMode,
  type BridgeOutcome,
} from "@forgewire/fabric-client-core";

/** Distinguishes "the ceremony failed" (a `BridgeOutcome` with status "error",
 *  which is a normal, expected result) from "the flow itself never
 *  completed" -- timeout, a declined browser-open prompt, or a listener that
 *  could not start. Callers branch on this rather than a status string. */
export class WebauthnBridgeFlowError extends Error {}

/**
 * Run one bridge flow: generate a state nonce, start a loopback listener,
 * open the bridge page, and resolve with whatever it reports.
 *
 * Always tears the listener down -- on success, on timeout, and on any
 * error -- so an abandoned or failed flow cannot leave a port open.
 */
export function runWebauthnBridgeFlow(
  hubUrl: string,
  mode: BridgeMode,
  token?: vscode.CancellationToken,
  /**
   * 114C.7 Slice 4c-3: only step-up mode sets this -- the JSON-stringified
   * WebAuthn request options (`public_key` from `step_up_options`) the bridge
   * page runs the authenticator on. Not a secret; the session bearer never
   * enters the browser (see webauthnBridge.ts's BridgeOutcome step-up note).
   */
  challenge?: string
): Promise<BridgeOutcome> {
  // Matches the Web Crypto global already used for the same purpose in
  // extension.ts's generateToken(), rather than adding a second RNG source.
  const state = generateBridgeState((n) => {
    const bytes = new Uint8Array(n);
    globalThis.crypto.getRandomValues(bytes);
    return bytes;
  });

  return new Promise<BridgeOutcome>((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let cancelSub: vscode.Disposable | undefined;

    const server = http.createServer((req, res) => {
      if (!bridgeCallbackRequestIsAcceptable({ method: req.method, url: req.url })) {
        res.writeHead(404).end();
        return;
      }

      let total = 0;
      const chunks: Buffer[] = [];
      let overLimit = false;
      req.on("data", (chunk: Buffer) => {
        if (overLimit) return;
        total += chunk.length;
        if (total > MAX_BRIDGE_CALLBACK_BYTES) {
          overLimit = true;
          res.writeHead(413).end();
          req.destroy();
        } else {
          chunks.push(chunk);
        }
      });
      req.on("end", () => {
        if (overLimit) return;
        let body: unknown;
        try {
          body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        } catch {
          res.writeHead(400).end();
          return;
        }
        // A state mismatch or malformed body returns null -- that means
        // "not the reply this flow is waiting for," not "the flow failed,"
        // so the listener stays open rather than settling the promise.
        const outcome = parseBridgeCallback(body, state, mode);
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }).end(BRIDGE_CALLBACK_ACK_HTML);
        if (outcome !== null) finish(outcome);
      });
      req.on("error", () => {
        /* the client retries or the flow times out; nothing to do here */
      });
    });

    function finish(outcome: BridgeOutcome): void;
    function finish(outcome: undefined, error: Error): void;
    function finish(outcome: BridgeOutcome | undefined, error?: Error): void {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      cancelSub?.dispose();
      server.close();
      if (error) reject(error);
      else resolve(outcome as BridgeOutcome);
    }

    server.on("error", (err) => finish(undefined, err));

    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo | null;
      if (address === null) {
        finish(undefined, new WebauthnBridgeFlowError("Could not start the loopback listener."));
        return;
      }

      const url = buildBridgeUrl({ hubUrl, mode, callbackPort: address.port, state, challenge });
      vscode.env.openExternal(vscode.Uri.parse(url)).then(
        (opened) => {
          if (!opened) {
            finish(undefined, new WebauthnBridgeFlowError("The system browser was not opened."));
          }
        },
        (err) => finish(undefined, err instanceof Error ? err : new Error(String(err)))
      );

      timer = setTimeout(() => {
        finish(undefined, new WebauthnBridgeFlowError("Timed out waiting for the browser to report back."));
      }, BRIDGE_FLOW_TIMEOUT_MS);

      if (token) {
        cancelSub = token.onCancellationRequested(() => {
          finish(undefined, new WebauthnBridgeFlowError("Cancelled."));
        });
      }
    });
  });
}
