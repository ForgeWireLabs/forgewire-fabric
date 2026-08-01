"use strict";
/**
 * ForgeWire Fabric WebAuthn bridge (114C.6 Slice 5b).
 *
 * Runs a real passkey ceremony in the system browser, same-origin with the
 * hub, then reports the outcome to a loopback URL the calling client (VS Code
 * extension or Desktop app) is listening on.
 *
 * Reads its own query string rather than receiving server-interpolated
 * values, so the served HTML/JS are fully static and there is no template
 * injection surface. See the Rust module's doc comment for the full rationale.
 */

(function () {
  var params = new URLSearchParams(location.search);
  var mode = params.get("mode");
  var callback = params.get("callback");
  var state = params.get("state") || "";

  var challenge = params.get("challenge") || "";

  var form = document.getElementById("form");
  var submit = document.getElementById("submit");
  var statusEl = document.getElementById("status");
  var subtitle = document.getElementById("subtitle");
  var usernameField = document.getElementById("username-field");
  var passwordField = document.getElementById("password-field");
  var usernameEl = document.getElementById("username");
  var passwordEl = document.getElementById("password");

  function setStatus(message, kind) {
    statusEl.textContent = message;
    statusEl.className = kind || "";
  }

  /**
   * Re-check the callback is loopback, independently of the server's check.
   * Defense that exists on only one side of a trust boundary is one bug away
   * from not existing -- and this side is what actually transmits secrets.
   */
  function callbackIsLoopback(raw) {
    var url;
    try {
      url = new URL(raw);
    } catch (_) {
      return false;
    }
    if (url.protocol !== "http:") return false;
    var host = url.hostname.toLowerCase();
    if (host === "localhost" || host === "::1" || host === "[::1]") return true;
    if (host.endsWith(".localhost")) return true;
    return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
  }

  // base64url <-> bytes. The hub speaks WebAuthn JSON; the browser API speaks
  // ArrayBuffers.
  function b64uToBytes(value) {
    var padded = value.replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4 !== 0) padded += "=";
    var binary = atob(padded);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function bytesToB64u(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = "";
    for (var i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function decodeCreation(publicKey) {
    var options = Object.assign({}, publicKey);
    options.challenge = b64uToBytes(publicKey.challenge);
    options.user = Object.assign({}, publicKey.user);
    options.user.id = b64uToBytes(publicKey.user.id);
    if (Array.isArray(publicKey.excludeCredentials)) {
      options.excludeCredentials = publicKey.excludeCredentials.map(function (entry) {
        return Object.assign({}, entry, { id: b64uToBytes(entry.id) });
      });
    }
    return options;
  }

  function decodeRequest(publicKey) {
    var options = Object.assign({}, publicKey);
    options.challenge = b64uToBytes(publicKey.challenge);
    if (Array.isArray(publicKey.allowCredentials)) {
      options.allowCredentials = publicKey.allowCredentials.map(function (entry) {
        return Object.assign({}, entry, { id: b64uToBytes(entry.id) });
      });
    }
    return options;
  }

  function encodeRegistration(credential) {
    return {
      id: credential.id,
      rawId: bytesToB64u(credential.rawId),
      type: credential.type,
      response: {
        attestationObject: bytesToB64u(credential.response.attestationObject),
        clientDataJSON: bytesToB64u(credential.response.clientDataJSON)
      }
    };
  }

  function encodeAssertion(credential) {
    return {
      id: credential.id,
      rawId: bytesToB64u(credential.rawId),
      type: credential.type,
      response: {
        authenticatorData: bytesToB64u(credential.response.authenticatorData),
        clientDataJSON: bytesToB64u(credential.response.clientDataJSON),
        signature: bytesToB64u(credential.response.signature),
        userHandle: credential.response.userHandle
          ? bytesToB64u(credential.response.userHandle)
          : null
      }
    };
  }

  function postJson(path, body, bearer) {
    var headers = { "Content-Type": "application/json" };
    if (bearer) headers["Authorization"] = "Bearer " + bearer;
    return fetch(path, {
      method: "POST",
      headers: headers,
      body: JSON.stringify(body)
    }).then(function (response) {
      return response
        .json()
        .catch(function () {
          return {};
        })
        .then(function (payload) {
          if (!response.ok) {
            var code = payload && payload.error && payload.error.code;
            var message = (payload && payload.error && payload.error.message) || response.statusText;
            var err = new Error(code ? code + ": " + message : message);
            err.code = code;
            throw err;
          }
          return payload;
        });
    });
  }

  /**
   * Report the outcome to the client's loopback listener.
   *
   * Always a POST with a JSON body -- never a URL/query string, even for the
   * status-only register flow. Session secrets in a URL would land in browser
   * history, the listener's access log, and the Referer header; keeping one
   * transport for both modes means there is no "the other path was fine to be
   * sloppy on" exception to maintain.
   *
   * `state` is echoed back so the client can reject a reply that did not
   * originate from the flow it started (a different local process racing the
   * loopback port).
   */
  function report(payload) {
    return fetch(callback, {
      method: "POST",
      mode: "no-cors",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(Object.assign({ state: state }, payload))
    });
  }

  function fail(message) {
    setStatus(message, "error");
    submit.disabled = false;
    report({ status: "error", message: message }).catch(function () {
      /* the user still sees the error on screen */
    });
  }

  function finishOk(message, payload) {
    setStatus(message, "ok");
    form.hidden = true;
    report(Object.assign({ status: "ok" }, payload)).catch(function () {
      setStatus(
        message + " -- but the app could not be notified. Return to it and try again.",
        "error"
      );
    });
  }

  // ---- flows --------------------------------------------------------------

  function runLogin(username) {
    return postJson("/auth/passkeys/options", { username: username })
      .then(function (options) {
        setStatus("Waiting for your passkey…");
        // `public_key` is the whole webauthn-rs `RequestChallengeResponse`,
        // which itself serializes as `{ publicKey: {...} }` (the shape
        // `navigator.credentials.get` expects as its own argument) -- one
        // more level of nesting than `decodeRequest` operates on.
        return navigator.credentials
          .get({ publicKey: decodeRequest(options.public_key.publicKey) })
          .then(function (credential) {
            return postJson("/auth/passkeys/verify", {
              challenge_id: options.challenge_id,
              options_token: options.options_token,
              client_kind: "other",
              credential: encodeAssertion(credential)
            });
          });
      })
      .then(function (session) {
        // The client needs these to actually hold the session; they cross
        // only the loopback POST body.
        finishOk("Signed in. You can close this tab.", {
          session: {
            session_id: session.session_id,
            account_id: session.account_id,
            assurance_level: session.assurance_level,
            access_secret: session.access_secret,
            refresh_secret: session.refresh_secret
          }
        });
      });
  }

  function runRegister(username, password) {
    // Registration is an authenticated operation, so the page signs in first
    // rather than the client passing a session secret through the URL.
    return postJson("/auth/login", {
      username: username,
      password: password,
      client_kind: "other",
      client_label: "passkey bridge"
    })
      .then(function (session) {
        setStatus("Signed in. Creating your passkey…");
        return postJson("/auth/passkeys/register/options", {}, session.access_secret).then(
          function (options) {
            // Same one-extra-level-of-nesting shape as runLogin's
            // `options.public_key.publicKey` -- see that comment.
            return navigator.credentials
              .create({ publicKey: decodeCreation(options.public_key.publicKey) })
              .then(function (credential) {
                return postJson(
                  "/auth/passkeys/register/verify",
                  {
                    challenge_id: options.challenge_id,
                    options_token: options.options_token,
                    label: navigator.platform || "Passkey",
                    credential: encodeRegistration(credential)
                  },
                  session.access_secret
                );
              });
          }
        );
      })
      .then(function (passkey) {
        // Status only: the client does not need (and must not receive) the
        // session this page used to perform the registration.
        finishOk("Passkey registered. You can close this tab.", {
          credential_id: passkey.credential_id
        });
      });
  }

  function runStepUp() {
    // Step-up is a credential relay (114C.7 Slice 4c-3): the client already
    // holds the session bearer and made the step_up_options call, passing the
    // resulting public_key challenge in the query. This page only runs the
    // authenticator and returns the (public, single-use) assertion; it makes
    // no hub call and never sees a session secret. The client feeds the
    // assertion to step_up_verify itself.
    var publicKey;
    try {
      publicKey = JSON.parse(challenge);
    } catch (_) {
      return Promise.reject(new Error("The step-up challenge was malformed. Start again from the app."));
    }
    setStatus("Waiting for your passkey…");
    // The client embeds the whole `step_up_options` `public_key` field
    // verbatim in the URL -- same one-extra-level-of-nesting shape as
    // runLogin's `options.public_key.publicKey` -- see that comment.
    return navigator.credentials
      .get({ publicKey: decodeRequest(publicKey.publicKey) })
      .then(function (credential) {
        finishOk("Verified. You can close this tab.", {
          credential: encodeAssertion(credential)
        });
      });
  }

  // ---- wiring -------------------------------------------------------------

  if (mode !== "login" && mode !== "register" && mode !== "step-up") {
    setStatus("This link is malformed (unknown mode). Start again from the app.", "error");
    form.hidden = true;
    return;
  }
  if (mode === "step-up" && !challenge) {
    setStatus("This link is malformed (no step-up challenge). Start again from the app.", "error");
    form.hidden = true;
    return;
  }
  if (!callback || !callbackIsLoopback(callback)) {
    setStatus(
      "This link is malformed (its callback is not a loopback address). Start again from the app.",
      "error"
    );
    form.hidden = true;
    return;
  }
  if (!window.PublicKeyCredential || !navigator.credentials) {
    setStatus("This browser does not support passkeys.", "error");
    form.hidden = true;
    return;
  }
  if (!window.isSecureContext) {
    setStatus(
      "Passkeys need a secure context. Reach this hub over HTTPS or at localhost.",
      "error"
    );
    form.hidden = true;
    return;
  }

  // Every precondition passed, so it is now safe to show the form. The HTML
  // ships it hidden and seeds #status with a failure message, so a page whose
  // script never loaded shows an explanation rather than an inert credential
  // prompt. This is the only place either of those is undone.
  setStatus("");
  form.hidden = false;

  if (mode === "register") {
    subtitle.textContent = "Register a passkey";
    passwordField.hidden = false;
    passwordEl.required = true;
    submit.textContent = "Register passkey";
    usernameEl.focus();
  } else if (mode === "step-up") {
    // No username/password: step-up re-proves the already-signed-in session,
    // so the only input is the authenticator itself.
    subtitle.textContent = "Verify with your passkey";
    usernameField.hidden = true;
    usernameEl.required = false;
    submit.textContent = "Verify";
    submit.focus();
  } else {
    subtitle.textContent = "Sign in with a passkey";
    submit.textContent = "Sign in";
    usernameEl.focus();
  }

  form.addEventListener("submit", function (event) {
    event.preventDefault();
    submit.disabled = true;
    setStatus("Working…");
    var username = usernameEl.value.trim();
    var run =
      mode === "step-up"
        ? runStepUp()
        : mode === "register"
          ? runRegister(username, passwordEl.value)
          : runLogin(username);
    run.catch(function (error) {
      // NotAllowedError is what the browser reports for both a user-cancelled
      // prompt and a timeout; neither is an application fault.
      if (error && error.name === "NotAllowedError") {
        fail("The passkey prompt was dismissed or timed out.");
      } else {
        fail((error && error.message) || "The ceremony failed.");
      }
    });
  });
})();
