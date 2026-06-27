(function () {
  "use strict";

  const CREDENTIAL_KEY = "goblinpass_yubikey_credential_id_v1";
  const MODE_KEY = "goblinpass_yubikey_mode_v2";
  const CAPABILITY_KEY = "goblinpass_yubikey_capability_v1";
  const status = document.getElementById("registrationStatus");

  function setStatus(message, type = "info") {
    if (!status) return;
    status.textContent = `Status: ${message}`;
    status.dataset.status = type;
  }

  function rpId() {
    return location.hostname || "localhost";
  }

  function bytesToBase64Url(bytes) {
    let binary = "";
    bytes.forEach(byte => { binary += String.fromCharCode(byte); });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function base64UrlToBytes(value) {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
    return Uint8Array.from(atob(padded), char => char.charCodeAt(0));
  }

  function credentialIdBuffer(id) {
    const bytes = base64UrlToBytes(id);
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  }

  async function sha256Bytes(text) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  }

  function prfOutput(results, credentialId = "") {
    const prf = results?.prf?.results;
    return prf?.first || (credentialId ? prf?.[credentialId]?.first : null) || null;
  }

  function extensionSummary(results) {
    const prf = results?.prf;
    const first = prfOutput(results);
    const hmac = results?.hmacCreateSecret;
    return `prf.enabled=${typeof prf?.enabled === "boolean" ? prf.enabled : "not returned"}; prf.first=${first ? `${first.byteLength || 0} bytes` : "not returned"}; hmacCreateSecret=${typeof hmac === "boolean" ? hmac : "not returned"}`;
  }

  function requireWebAuthn() {
    if (!window.isSecureContext) {
      throw new Error("WebAuthn needs HTTPS or localhost. Open this from GitHub Pages or localhost.");
    }
    if (!navigator.credentials?.create || !navigator.credentials?.get || !window.PublicKeyCredential) {
      throw new Error("This browser does not support the WebAuthn features GoblinPass needs.");
    }
  }

  async function createGenerationCredential() {
    requireWebAuthn();
    return navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: "GoblinPass Password Generation", id: rpId() },
        user: {
          id: crypto.getRandomValues(new Uint8Array(32)),
          name: "goblinpass-password-generation",
          displayName: "GoblinPass Password Generation"
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 }
        ],
        authenticatorSelection: {
          authenticatorAttachment: "cross-platform",
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "preferred"
        },
        timeout: 60000,
        extensions: {
          prf: {},
          hmacCreateSecret: true
        }
      }
    });
  }

  async function verifyStoredCredential(credentialId) {
    const salt = await sha256Bytes("GoblinPass YubiKey registration stored verification v1");
    const base = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: rpId(),
      allowCredentials: [{ type: "public-key", id: credentialIdBuffer(credentialId), transports: ["usb", "nfc", "ble"] }],
      userVerification: "preferred",
      timeout: 60000
    };
    const first = await navigator.credentials.get({
      publicKey: {
        ...base,
        extensions: { prf: { eval: { first: salt } } }
      }
    });
    const firstResults = first.getClientExtensionResults?.() || {};
    let output = prfOutput(firstResults, credentialId);
    let requestShape = "eval";
    let results = firstResults;
    if (!output || output.byteLength !== 32) {
      const second = await navigator.credentials.get({
        publicKey: {
          ...base,
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          extensions: { prf: { evalByCredential: { [credentialId]: { first: salt } } } }
        }
      });
      results = second.getClientExtensionResults?.() || {};
      output = prfOutput(results, credentialId);
      requestShape = "evalByCredential";
    }
    return { ok: !!output && output.byteLength === 32, requestShape, results };
  }

  async function verifyDiscoverableCredential(expectedCredentialId = "") {
    const salt = await sha256Bytes("GoblinPass YubiKey registration discoverable verification v1");
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: rpId(),
        userVerification: "preferred",
        timeout: 60000,
        hints: ["security-key"],
        extensions: { prf: { eval: { first: salt } } }
      }
    });
    const results = credential.getClientExtensionResults?.() || {};
    const output = prfOutput(results);
    const credentialId = bytesToBase64Url(new Uint8Array(credential.rawId));
    return {
      ok: !!output && output.byteLength === 32 && (!expectedCredentialId || credentialId === expectedCredentialId),
      credentialId,
      results
    };
  }

  function saveCapability(capability) {
    localStorage.setItem(CAPABILITY_KEY, JSON.stringify({
      prfAvailable: !!capability.prfAvailable,
      hmacSecretAvailable: !!capability.hmacSecretAvailable,
      touchGateAvailable: true,
      authenticatorAttachment: capability.authenticatorAttachment || "",
      createResults: capability.createResults || "",
      getResults: capability.getResults || "",
      prfRequestShape: capability.prfRequestShape || "",
      rpId: rpId(),
      storedCredentialIdLength: capability.storedCredentialIdLength || 0,
      allowCredentialsSupplied: true,
      prfResultReturned: !!capability.prfResultReturned,
      browserUserAgent: navigator.userAgent || "",
      updated: new Date().toISOString()
    }));
  }

  async function registerKey() {
    try {
      requireWebAuthn();
      const existing = localStorage.getItem(CREDENTIAL_KEY);
      if (existing) {
        const replace = confirm("A YubiKey is already registered for password generation on this browser. Replace it with the key you touch next?");
        if (!replace) return;
      }
      setStatus("waiting for your browser and YubiKey. Complete any PIN or touch prompt.");
      const credential = await createGenerationCredential();
      const credentialId = bytesToBase64Url(new Uint8Array(credential.rawId));
      const createResults = credential.getClientExtensionResults?.() || {};

      setStatus("registered. Verifying stored and discoverable password-generation paths.");
      const stored = await verifyStoredCredential(credentialId);
      const discoverable = await verifyDiscoverableCredential(credentialId);
      if (!stored.ok || !discoverable.ok) {
        throw new Error("The new key was not selected for both verification prompts, or it did not return usable PRF data. The previous local registration was kept.");
      }

      localStorage.setItem(CREDENTIAL_KEY, credentialId);
      localStorage.setItem(MODE_KEY, "prf");
      saveCapability({
        prfAvailable: true,
        hmacSecretAvailable: createResults.hmacCreateSecret === true,
        authenticatorAttachment: credential.authenticatorAttachment || "",
        createResults: extensionSummary(createResults),
        getResults: `stored: ${extensionSummary(stored.results)}; discoverable: ${extensionSummary(discoverable.results)}`,
        prfRequestShape: `${stored.requestShape}; discoverable eval`,
        storedCredentialIdLength: credentialId.length,
        prfResultReturned: true
      });
      setStatus("YubiKey registered and verified for GoblinPass password generation. Secure Notes registration was not changed.", "success");
    } catch (error) {
      setStatus(error.message || "registration failed.", "warning");
    }
  }

  async function verifyKey() {
    try {
      requireWebAuthn();
      const credentialId = localStorage.getItem(CREDENTIAL_KEY) || "";
      if (!credentialId) {
        setStatus("no password-generation YubiKey is registered in this browser yet.", "warning");
        return;
      }
      setStatus("verifying the registered password-generation key.");
      const stored = await verifyStoredCredential(credentialId);
      const discoverable = await verifyDiscoverableCredential(credentialId);
      if (!stored.ok || !discoverable.ok) throw new Error("Verification did not return PRF data from the registered key.");
      saveCapability({
        prfAvailable: true,
        hmacSecretAvailable: false,
        getResults: `stored: ${extensionSummary(stored.results)}; discoverable: ${extensionSummary(discoverable.results)}`,
        prfRequestShape: `${stored.requestShape}; discoverable eval`,
        storedCredentialIdLength: credentialId.length,
        prfResultReturned: true
      });
      setStatus("registered key verified for 1.0 stored credential use and 2.0 discoverable generation use.", "success");
    } catch (error) {
      setStatus(error.message || "verification failed.", "warning");
    }
  }

  function forgetKey() {
    const ok = confirm("Forget the password-generation YubiKey registration stored in this browser? This does not remove credentials from the physical YubiKey.");
    if (!ok) return;
    localStorage.removeItem(CREDENTIAL_KEY);
    localStorage.removeItem(CAPABILITY_KEY);
    localStorage.setItem(MODE_KEY, "prf");
    setStatus("forgot local password-generation YubiKey registration. Secure Notes registration was not changed.");
  }

  function updateInitialStatus() {
    try {
      const credentialId = localStorage.getItem(CREDENTIAL_KEY) || "";
      setStatus(credentialId
        ? `password-generation YubiKey registration found for ${rpId()}. Use Verify key to test it.`
        : `no password-generation YubiKey registration found for ${rpId()}.`);
    } catch {
      setStatus("local storage is blocked, so this browser cannot remember a password-generation YubiKey.", "warning");
    }
  }

  document.getElementById("registerGenerationKey")?.addEventListener("click", registerKey);
  document.getElementById("verifyGenerationKey")?.addEventListener("click", verifyKey);
  document.getElementById("forgetGenerationKey")?.addEventListener("click", forgetKey);
  updateInitialStatus();
})();
