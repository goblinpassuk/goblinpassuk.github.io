(function () {
  "use strict";

  const STORAGE_KEY = "GOBLINPASS_GOOGLE_BACKUP_CODES_V1";
  const CREDENTIAL_KEY = "GOBLINPASS_BACKUP_CODES_CREDENTIAL_ID";
  const RP_USER_ID_KEY = "GOBLINPASS_BACKUP_CODES_USER_ID";
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const setupButton = document.getElementById("setupBackupKey");
  const saveButton = document.getElementById("saveBackupCodes");
  const unlockButton = document.getElementById("unlockBackupCodes");
  const hideButton = document.getElementById("hideBackupCodes");
  const deleteButton = document.getElementById("deleteBackupCodes");
  const clearButton = document.getElementById("clearBackupInput");
  const removeUsedButton = document.getElementById("removeUsedCodes");
  const input = document.getElementById("backupCodesInput");
  const output = document.getElementById("backupCodesOutput");
  const codeList = document.getElementById("backupCodeList");
  const status = document.getElementById("backupKeyStatus");
  let unlockedCodes = [];

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
    setupButton.textContent = getCredentialId() ? "Test YubiKey sign-in" : "Set up YubiKey";
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
    if (!credentialId) throw new Error("No saved YubiKey credential found in this browser. Set up the YubiKey once, then future saves and unlocks will use sign-in/authentication.");
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

  async function encryptAndStoreCodes(codes) {
    const prfOutput = await requestPrfWithStoredCredential();
    const key = await deriveAesKey(prfOutput);
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

  async function setupYubiKey() {
    try {
      requireWebAuthnPrf();
      if (getCredentialId()) {
        setStatus("Status: signing in with your saved YubiKey credential. Follow the browser prompt.", "info");
        await requestPrfWithStoredCredential();
        setStatus("Status: YubiKey sign-in worked. This saved credential can encrypt and decrypt backup codes.", "success");
        return;
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
      await requestPrfWithStoredCredential();
      setStatus("Status: YubiKey ready. Future saves and unlocks will use sign-in/authentication, not setup.", "success");
    } catch (error) {
      setStatus(`Status: ${error.message}`, "warning");
    }
  }

  async function saveCodes() {
    const codes = input.value.trim();
    if (!codes) {
      setStatus("Status: paste your backup codes before saving.", "warning");
      return;
    }
    try {
      setStatus("Status: touch or unlock your YubiKey to encrypt backup codes.", "info");
      await encryptAndStoreCodes(linesToCodes(codesToLines(codes)));
      input.value = "";
      output.textContent = "Backup codes encrypted and saved locally.";
      renderCodeList([]);
      setStatus("Status: encrypted backup codes saved in this browser.", "success");
    } catch (error) {
      setStatus(`Status: ${error.message}`, "warning");
    }
  }

  async function unlockCodes() {
    try {
      const record = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
      if (!record?.data || !record?.iv) throw new Error("No encrypted backup codes are saved in this browser.");
      if (record.credentialId && record.credentialId !== getCredentialId()) saveCredentialId(record.credentialId);
      setStatus("Status: touch or unlock your YubiKey to decrypt backup codes.", "info");
      const prfOutput = await requestPrfWithStoredCredential();
      const key = await deriveAesKey(prfOutput);
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: base64UrlToBytes(record.iv) },
        key,
        base64UrlToBytes(record.data)
      );
      const payload = JSON.parse(decoder.decode(plaintext));
      const lines = codesToLines(payload.codes);
      output.textContent = lines.length ? linesToCodes(lines) : "No codes found in encrypted record.";
      renderCodeList(lines);
      setStatus("Status: decrypted locally. Hide the codes when you are finished.", "success");
    } catch (error) {
      output.textContent = "Encrypted backup codes will appear here after YubiKey unlock.";
      renderCodeList([]);
      setStatus(`Status: ${error.message}`, "warning");
    }
  }

  function hideCodes() {
    output.textContent = "Encrypted backup codes will appear here after YubiKey unlock.";
    renderCodeList([]);
    setStatus(getCredentialId() ? "Status: YubiKey credential saved. Codes hidden." : "Status: not set up.");
  }

  async function removeUsedCodes() {
    try {
      if (!unlockedCodes.length) {
        setStatus("Status: unlock your backup codes before removing used codes.", "warning");
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
      setStatus("Status: touch or unlock your YubiKey to re-encrypt the remaining codes.", "info");
      await encryptAndStoreCodes(linesToCodes(remaining));
      output.textContent = remaining.length ? linesToCodes(remaining) : "All backup codes have been marked used and removed.";
      renderCodeList(remaining);
      setStatus("Status: selected used codes removed and remaining codes re-encrypted locally.", "success");
    } catch (error) {
      setStatus(`Status: ${error.message}`, "warning");
    }
  }

  function deleteCodes() {
    const ok = confirm("Delete encrypted backup codes from this browser? This cannot be undone.");
    if (!ok) return;
    localStorage.removeItem(STORAGE_KEY);
    output.textContent = "Encrypted backup codes will appear here after YubiKey unlock.";
    renderCodeList([]);
    setStatus("Status: encrypted backup codes deleted from this browser.", "warning");
  }

  setupButton.addEventListener("click", setupYubiKey);
  saveButton.addEventListener("click", saveCodes);
  unlockButton.addEventListener("click", unlockCodes);
  hideButton.addEventListener("click", hideCodes);
  deleteButton.addEventListener("click", deleteCodes);
  clearButton.addEventListener("click", () => { input.value = ""; });
  removeUsedButton.addEventListener("click", removeUsedCodes);

  const savedRecord = localStorage.getItem(STORAGE_KEY);
  const savedCredential = getCredentialId();
  updateSetupButton();
  if (!window.isSecureContext) setStatus("Status: WebAuthn may not work from a local file. Use the HTTPS GitHub Pages page.", "warning");
  else if (savedCredential && savedRecord) setStatus("Status: encrypted backup codes found. Unlock with your YubiKey.", "success");
  else if (savedCredential) setStatus("Status: YubiKey set up. No backup codes saved yet.", "info");
})();
