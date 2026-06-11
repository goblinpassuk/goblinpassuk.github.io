(function () {
  "use strict";

  const STORAGE_KEY = "GOBLINPASS_GOOGLE_BACKUP_CODES_V1";
  const CREDENTIAL_KEY = "GOBLINPASS_BACKUP_CODES_CREDENTIAL_ID";
  const RP_USER_ID_KEY = "GOBLINPASS_BACKUP_CODES_USER_ID";
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const setupButton = document.getElementById("setupBackupKey");
  const signInButton = document.getElementById("signInBackupKey");
  const saveButton = document.getElementById("saveBackupCodes");
  const unlockButton = document.getElementById("unlockBackupCodes");
  const deleteButton = document.getElementById("deleteBackupCodes");
  const clearButton = document.getElementById("clearBackupInput");
  const removeUsedButton = document.getElementById("removeUsedCodes");
  const input = document.getElementById("backupCodesInput");
  const output = document.getElementById("backupCodesOutput");
  const codeList = document.getElementById("backupCodeList");
  const status = document.getElementById("backupKeyStatus");
  const hoverHint = document.getElementById("encryptedHoverHint");
  let unlockedCodes = [];
  let sessionKey = null;

  if (!setupButton) return;

  function setStatus(message, kind = "info") {
    status.textContent = message;
    status.dataset.kind = kind;
  }

  function bytesToBase64Url(bytes) {
    let binary = "";
    bytes.forEach(byte => { binary += String.fromCharCode(byte); });
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function base64UrlToBytes(value) {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (value.length % 4)) % 4);
    return Uint8Array.from(atob(padded), char => char.charCodeAt(0));
  }

  function randomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  async function sha256Bytes(text) {
    return new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(text)));
  }

  function requireWebAuthnPrf() {
    if (!window.isSecureContext) {
      throw new Error("WebAuthn needs a secure context. Use the HTTPS GitHub Pages version, not a plain local file.");
    }
    if (!navigator.credentials || !window.PublicKeyCredential) {
      throw new Error("This browser does not support WebAuthn.");
    }
  }

  function rpId() {
    return location.hostname || undefined;
  }

  function getCredentialId() {
    return localStorage.getItem(CREDENTIAL_KEY) || "";
  }

  function saveCredentialId(id) {
    localStorage.setItem(CREDENTIAL_KEY, id);
    updateSetupButton();
  }

  function updateSetupButton() {
    setupButton.textContent = "Register YubiKey";
  }

  function getOrCreateUserId() {
    const saved = localStorage.getItem(RP_USER_ID_KEY);
    if (saved) return base64UrlToBytes(saved);
    const id = randomBytes(32);
    localStorage.setItem(RP_USER_ID_KEY, bytesToBase64Url(id));
    return id;
  }

  function extensionSummary(results) {
    const prf = results?.prf;
    const first = prf?.results?.first;
    return `prf.enabled=${typeof prf?.enabled === "boolean" ? prf.enabled : "not returned"}; prf.first=${first ? `${first.byteLength || 0} bytes` : "not returned"}`;
  }

  function prfOutputFromResults(results, credentialId = "") {
    const first = results?.prf?.results?.first;
    if (first) return first;
    if (credentialId && results?.prf?.results) {
      const byCredential = results.prf.results[credentialId]?.first;
      if (byCredential) return byCredential;
    }
    return null;
  }

  async function prfSalt() {
    return sha256Bytes(`GoblinPass Google Backup Codes v1|${location.origin}`);
  }

  async function requestPrfWithStoredCredential() {
    requireWebAuthnPrf();
    const credentialId = getCredentialId();
    if (!credentialId) return requestPrfWithDiscoverableCredential();
    const idBytes = base64UrlToBytes(credentialId);
    const salt = await prfSalt();

    const firstAssertion = await navigator.credentials.get({
      publicKey: {
        challenge: randomBytes(32),
        rpId: rpId(),
        userVerification: "preferred",
        allowCredentials: [{ type: "public-key", id: idBytes }],
        extensions: { prf: { eval: { first: salt } } }
      }
    });
    let results = firstAssertion.getClientExtensionResults?.();
    let outputBytes = prfOutputFromResults(results, credentialId);
    if (outputBytes?.byteLength === 32) return new Uint8Array(outputBytes);

    const secondAssertion = await navigator.credentials.get({
      publicKey: {
        challenge: randomBytes(32),
        rpId: rpId(),
        userVerification: "preferred",
        allowCredentials: [{ type: "public-key", id: idBytes }],
        extensions: { prf: { evalByCredential: { [credentialId]: { first: salt } } } }
      }
    });
    results = secondAssertion.getClientExtensionResults?.();
    outputBytes = prfOutputFromResults(results, credentialId);
    if (outputBytes?.byteLength !== 32) {
      throw new Error(`Your browser or YubiKey did not return PRF data. ${extensionSummary(results)}`);
    }
    return new Uint8Array(outputBytes);
  }

  async function requestPrfWithDiscoverableCredential() {
    const salt = await prfSalt();
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: randomBytes(32),
        rpId: rpId(),
        userVerification: "preferred",
        extensions: { prf: { eval: { first: salt } } }
      }
    });
    const discoveredId = bytesToBase64Url(new Uint8Array(assertion.rawId));
    if (discoveredId) saveCredentialId(discoveredId);
    const results = assertion.getClientExtensionResults?.();
    const outputBytes = prfOutputFromResults(results, discoveredId);
    if (outputBytes?.byteLength !== 32) {
      throw new Error(`YubiKey sign-in worked, but this browser/key did not return PRF data. ${extensionSummary(results)}`);
    }
    return new Uint8Array(outputBytes);
  }

  async function deriveAesKey(prfOutput) {
    const baseKey = await crypto.subtle.importKey("raw", prfOutput, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: encoder.encode("GoblinPass Backup Codes AES-GCM salt v1"),
        info: encoder.encode(`Google backup codes vault|${location.origin}`)
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  function codesToLines(codes) {
    return String(codes || "")
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(Boolean);
  }

  function linesToCodes(lines) {
    return lines.join("\n");
  }

  function renderCodeList(lines = []) {
    unlockedCodes = [...lines];
    if (!codeList) return;
    if (!lines.length) {
      codeList.textContent = "No unlocked codes to manage.";
      return;
    }
    codeList.innerHTML = "";
    lines.forEach((code, index) => {
      const label = document.createElement("label");
      label.className = "backup-code-row";

      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = String(index);
      checkbox.addEventListener("change", () => {
        label.classList.toggle("is-used", checkbox.checked);
      });

      const value = document.createElement("span");
      value.textContent = code;

      label.append(checkbox, value);
      codeList.appendChild(label);
    });
  }

  function setOutputMode(mode, text) {
    output.classList.toggle("is-sealed", mode === "sealed");
    output.classList.toggle("is-unlocked", mode === "unlocked");
    if (hoverHint) hoverHint.classList.toggle("hidden", mode !== "sealed");
    output.textContent = text;
  }

  async function getSessionKey() {
    if (sessionKey) return sessionKey;
    await signInYubiKey({ autoUnlock: false });
    if (!sessionKey) throw new Error("YubiKey sign-in did not create an encryption key.");
    return sessionKey;
  }

  async function encryptAndStoreCodes(codes) {
    const key = await getSessionKey();
    const iv = randomBytes(12);
    const payload = {
      label: "Google backup codes",
      codes,
      savedAt: new Date().toISOString()
    };
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(JSON.stringify(payload)));
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      version: 1,
      alg: "AES-GCM",
      kdf: "WebAuthn-PRF-HKDF-SHA256",
      credentialId: getCredentialId(),
      iv: bytesToBase64Url(iv),
      data: bytesToBase64Url(new Uint8Array(ciphertext)),
      updated: new Date().toISOString()
    }));
  }

  async function decryptStoredCodes(key) {
    const record = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
    if (!record?.data || !record?.iv) throw new Error("No encrypted backup codes are saved in this browser.");
    if (record.credentialId && record.credentialId !== getCredentialId()) saveCredentialId(record.credentialId);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64UrlToBytes(record.iv) },
      key,
      base64UrlToBytes(record.data)
    );
    const payload = JSON.parse(decoder.decode(plaintext));
    return codesToLines(payload.codes);
  }

  async function setupYubiKey() {
    try {
      requireWebAuthnPrf();
      if (getCredentialId()) {
        const ok = confirm("Registering a new YubiKey will replace the saved credential for this browser. Existing encrypted codes may not decrypt unless they were encrypted with the same key. Continue?");
        if (!ok) return;
      }
      setStatus("Status: creating YubiKey credential. Follow the browser prompt.", "info");
      const credential = await navigator.credentials.create({
        publicKey: {
          challenge: randomBytes(32),
          rp: { name: "GoblinPass Backup Codes", id: rpId() },
          user: {
            id: getOrCreateUserId(),
            name: "goblinpass-backup-codes-local-user",
            displayName: "GoblinPass Backup Codes"
          },
          pubKeyCredParams: [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -257 }
          ],
          authenticatorSelection: {
            residentKey: "required",
            requireResidentKey: true,
            userVerification: "preferred"
          },
          timeout: 120000,
          attestation: "none",
          extensions: { prf: {}, hmacCreateSecret: true }
        }
      });
      const credentialId = bytesToBase64Url(new Uint8Array(credential.rawId));
      saveCredentialId(credentialId);
      const createResults = credential.getClientExtensionResults?.();
      setStatus(`Status: credential saved. Testing PRF now. ${extensionSummary(createResults)}`, "info");
      sessionKey = null;
      await signInYubiKey({ autoUnlock: false });
      setStatus("Status: YubiKey registered and signed in. You can now encrypt or show saved codes.", "success");
    } catch (error) {
      setStatus(`Status: ${error.message}`, "warning");
    }
  }

  async function signInYubiKey(options = {}) {
    const autoUnlock = options.autoUnlock !== false;
    setStatus(getCredentialId()
      ? "Status: signing in with your saved YubiKey credential. Follow the browser prompt."
      : "Status: no local credential ID found. Trying to sign in with the discoverable credential on your YubiKey.", "info");
    const prfOutput = await requestPrfWithStoredCredential();
    sessionKey = await deriveAesKey(prfOutput);
    const record = localStorage.getItem(STORAGE_KEY);
    if (record && autoUnlock) {
      const lines = await decryptStoredCodes(sessionKey);
      setOutputMode("unlocked", lines.length ? linesToCodes(lines) : "No codes found in encrypted record.");
      renderCodeList(lines);
      setStatus("Status: signed in. Saved backup codes unlocked automatically.", "success");
      return;
    }
    setOutputMode("sealed", record ? "Signed in. Encrypted backup codes are saved locally. Press Show Codes to reveal them." : "Signed in. No encrypted backup codes are saved yet.");
    renderCodeList([]);
    setStatus("Status: signed in. Paste codes and press Encrypt when ready.", "success");
  }

  async function saveCodes() {
    const codes = input.value.trim();
    if (!codes) {
      setStatus("Status: paste your backup codes before saving.", "warning");
      return;
    }
    try {
      setStatus("Status: sign in with your YubiKey to encrypt backup codes.", "info");
      await encryptAndStoreCodes(linesToCodes(codesToLines(codes)));
      input.value = "";
      setOutputMode("sealed", "Backup codes are encrypted and stored locally. Sign in and press Show Codes to reveal them.");
      renderCodeList([]);
      setStatus("Status: encrypted backup codes saved in this browser.", "success");
    } catch (error) {
      setStatus(`Status: ${error.message}`, "warning");
    }
  }

  async function unlockCodes() {
    try {
      const key = await getSessionKey();
      const lines = await decryptStoredCodes(key);
      setOutputMode("unlocked", lines.length ? linesToCodes(lines) : "No codes found in encrypted record.");
      renderCodeList(lines);
      setStatus("Status: decrypted locally. Keep the screen private while the codes are visible.", "success");
    } catch (error) {
      setOutputMode("", "Encrypted backup codes will appear here after YubiKey sign-in.");
      renderCodeList([]);
      setStatus(`Status: ${error.message}`, "warning");
    }
  }

  async function removeUsedCodes() {
    try {
      if (!unlockedCodes.length) {
        setStatus("Status: sign in and show your backup codes before removing used codes.", "warning");
        return;
      }
      const selected = Array.from(codeList.querySelectorAll("input[type='checkbox']:checked"))
        .map(box => Number(box.value));
      if (!selected.length) {
        setStatus("Status: tick at least one used code before removing.", "warning");
        return;
      }
      const selectedSet = new Set(selected);
      const remaining = unlockedCodes.filter((_, index) => !selectedSet.has(index));
      const ok = confirm(`Remove ${selected.length} used backup code${selected.length === 1 ? "" : "s"} and re-save ${remaining.length} remaining code${remaining.length === 1 ? "" : "s"}?`);
      if (!ok) return;
      setStatus("Status: sign in with your YubiKey to re-encrypt the remaining codes.", "info");
      await encryptAndStoreCodes(linesToCodes(remaining));
      setOutputMode("unlocked", remaining.length ? linesToCodes(remaining) : "All backup codes have been marked used and removed.");
      renderCodeList(remaining);
      setStatus("Status: selected used codes removed and remaining codes re-encrypted locally.", "success");
    } catch (error) {
      setStatus(`Status: ${error.message}`, "warning");
    }
  }

  function deleteCodes() {
    const ok = confirm("Purge all encrypted backup codes from this browser? This cannot be undone.");
    if (!ok) return;
    localStorage.removeItem(STORAGE_KEY);
    setOutputMode("", "Encrypted backup codes will appear here after YubiKey sign-in.");
    renderCodeList([]);
    setStatus("Status: encrypted backup codes purged from this browser.", "warning");
  }

  setupButton.addEventListener("click", setupYubiKey);
  signInButton.addEventListener("click", () => {
    signInYubiKey().catch(error => setStatus(`Status: ${error.message}`, "warning"));
  });
  saveButton.addEventListener("click", saveCodes);
  unlockButton.addEventListener("click", unlockCodes);
  deleteButton.addEventListener("click", deleteCodes);
  clearButton.addEventListener("click", () => { input.value = ""; });
  removeUsedButton.addEventListener("click", removeUsedCodes);

  const savedRecord = localStorage.getItem(STORAGE_KEY);
  const savedCredential = getCredentialId();
  updateSetupButton();
  if (!window.isSecureContext) setStatus("Status: WebAuthn may not work from a local file. Use the HTTPS GitHub Pages page.", "warning");
  else if (savedCredential && savedRecord) setStatus("Status: encrypted backup codes found. Sign in with your YubiKey to unlock them.", "success");
  else if (savedCredential) setStatus("Status: YubiKey set up. No backup codes saved yet.", "info");
})();
