(function () {
  "use strict";

  const STORAGE_KEY = "GOBLINPASS_GOOGLE_BACKUP_CODES_V1";
  const CREDENTIAL_KEY = "GOBLINPASS_BACKUP_CODES_CREDENTIAL_ID";
  const RP_USER_ID_KEY = "GOBLINPASS_BACKUP_CODES_USER_ID";
  const EXPORT_TYPE = "goblinpass-google-backup-codes";
  const RECORD_VERSION = 2;
  const KDF_NAME = "WebAuthn-PRF-HKDF-SHA256";
  const KDF_CONTEXT = "GoblinPass-GoogleBackupCodes-v1";
  const RECORD_AAD = "goblinpass-google-backup-codes";
  const LEGACY_KDF_SALT = "GoblinPass Backup Codes AES-GCM salt v1";
  const LEGACY_KDF_INFO_PREFIX = "Google backup codes vault|";
  const encoder = new TextEncoder();
  const decoder = new TextDecoder();

  const setupButton = document.getElementById("setupBackupKey");
  const signInButton = document.getElementById("signInBackupKey");
  const saveButton = document.getElementById("saveBackupCodes");
  const unlockButton = document.getElementById("unlockBackupCodes");
  const deleteButton = document.getElementById("deleteBackupCodes");
  const clearButton = document.getElementById("clearBackupInput");
  const removeUsedButton = document.getElementById("removeUsedCodes");
  const exportButton = document.getElementById("exportBackupCodes");
  const importButton = document.getElementById("importBackupCodes");
  const importFile = document.getElementById("backupImportFile");
  const emailInput = document.getElementById("backupAccountEmail");
  const accountDisplay = document.getElementById("backupAccountDisplay");
  const input = document.getElementById("backupCodesInput");
  const output = document.getElementById("backupCodesOutput");
  const codeList = document.getElementById("backupCodeList");
  const status = document.getElementById("backupKeyStatus");
  const hoverHint = document.getElementById("encryptedHoverHint");
  let unlockedCodes = [];
  let sessionKey = null;
  let sessionPrfOutput = null;

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

  function getSavedRecord() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
    } catch {
      return null;
    }
  }

  function ensureBackupCredentialId() {
    const localId = getCredentialId();
    if (localId) return localId;
    const recordId = getSavedRecord()?.credentialId || "";
    if (recordId) {
      saveCredentialId(recordId);
      return recordId;
    }
    throw new Error("No Backup Codes YubiKey credential is saved in this browser. Press Register YubiKey for this Backup Codes tool first.");
  }

  function physicalKeyDescriptor(idBytes) {
    return {
      type: "public-key",
      id: idBytes,
      transports: ["usb", "nfc", "ble", "hybrid"]
    };
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

  function prfSalt() {
    return new Uint8Array([
      0x47, 0x50, 0x2d, 0x42, 0x41, 0x43, 0x4b, 0x55,
      0x50, 0x2d, 0x43, 0x4f, 0x44, 0x45, 0x53, 0x2d,
      0x59, 0x55, 0x42, 0x49, 0x4b, 0x45, 0x59, 0x2d,
      0x50, 0x52, 0x46, 0x2d, 0x56, 0x31, 0x21, 0x21
    ]);
  }

  async function requestPrfWithStoredCredential() {
    requireWebAuthnPrf();
    const credentialId = ensureBackupCredentialId();
    const idBytes = base64UrlToBytes(credentialId);
    const salt = prfSalt();

    const firstAssertion = await navigator.credentials.get({
      publicKey: {
        challenge: randomBytes(32),
        rpId: rpId(),
        userVerification: "preferred",
        allowCredentials: [physicalKeyDescriptor(idBytes)],
        hints: ["security-key"],
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
        allowCredentials: [physicalKeyDescriptor(idBytes)],
        hints: ["security-key"],
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

  function recordKdfContext(record) {
    return record?.version === 1 ? LEGACY_KDF_SALT : record?.kdfContext || KDF_CONTEXT;
  }

  function recordKdfInfo(record) {
    return record?.version === 1
      ? `${LEGACY_KDF_INFO_PREFIX}${location.origin}`
      : `${recordKdfContext(record)}|${record?.aad || RECORD_AAD}|${location.origin}`;
  }

  function recordAad(record) {
    return record?.version === 1 ? undefined : encoder.encode(record?.aad || RECORD_AAD);
  }

  function validateEncryptedRecord(record) {
    if (!record || typeof record !== "object" || !record.data || !record.iv) {
      throw new Error("This does not look like a GoblinPass encrypted backup-code file.");
    }
    if (![1, 2].includes(Number(record.version))) {
      throw new Error("This backup-code file uses an unsupported format version.");
    }
    if (record.alg !== "AES-GCM") {
      throw new Error("Unsupported encryption algorithm. Expected AES-GCM.");
    }
    if (record.kdf !== KDF_NAME) {
      throw new Error("Unsupported key derivation method. Expected WebAuthn PRF with HKDF-SHA256.");
    }
    if (Number(record.version) >= 2) {
      if (record.kdfContext !== KDF_CONTEXT) {
        throw new Error("Unsupported backup-code key context.");
      }
      if (record.aad !== RECORD_AAD) {
        throw new Error("Backup-code purpose binding does not match.");
      }
    }
  }

  async function deriveAesKey(prfOutput, record = null) {
    const baseKey = await crypto.subtle.importKey("raw", prfOutput, "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: encoder.encode(recordKdfContext(record)),
        info: encoder.encode(recordKdfInfo(record))
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

  function normalizeStoredCodes(codes) {
    if (Array.isArray(codes)) {
      return codes.map(code => String(code || "").trim()).filter(Boolean);
    }
    return codesToLines(codes);
  }

  function linesToCodes(lines) {
    return lines.join("\n");
  }

  function normalizeEmail(value) {
    return String(value || "").trim();
  }

  function isBasicEmail(value) {
    if (!value) return true;
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
  }

  function setAccountDisplay(email = "") {
    if (!accountDisplay) return;
    accountDisplay.textContent = `Account: ${email || "No email specified"}`;
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

  function setBusy(button, isBusy, text) {
    if (!button) return;
    if (isBusy) {
      button.dataset.originalText = button.textContent;
      button.textContent = text;
      button.disabled = true;
      return;
    }
    button.textContent = button.dataset.originalText || button.textContent;
    button.disabled = false;
    delete button.dataset.originalText;
  }

  async function getSessionKey(options = {}) {
    const fresh = options.fresh === true;
    if (sessionKey && !fresh) return sessionKey;
    if (fresh) sessionKey = null;
    await signInYubiKey({ autoUnlock: false, purpose: options.purpose });
    if (!sessionKey) throw new Error("YubiKey sign-in did not create an encryption key.");
    return sessionKey;
  }

  async function encryptAndStoreCodes(codes, email = "", options = {}) {
    const key = await getSessionKey(options);
    const iv = randomBytes(12);
    const now = new Date().toISOString();
    const recordMeta = {
      version: RECORD_VERSION,
      alg: "AES-GCM",
      kdf: KDF_NAME,
      kdfContext: KDF_CONTEXT,
      aad: RECORD_AAD,
      credentialId: getCredentialId(),
      updated: now
    };
    const payload = {
      label: "Google backup codes",
      service: "Google",
      email,
      codes,
      createdAt: now,
      updatedAt: now
    };
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: recordAad(recordMeta) },
      key,
      encoder.encode(JSON.stringify(payload))
    );
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      ...recordMeta,
      iv: bytesToBase64Url(iv),
      data: bytesToBase64Url(new Uint8Array(ciphertext))
    }));
  }

  async function decryptRecord(record, prfOutput = sessionPrfOutput) {
    validateEncryptedRecord(record);
    if (!prfOutput) throw new Error("Sign in with your YubiKey before decrypting backup codes.");
    const key = await deriveAesKey(prfOutput, record);
    if (record.credentialId && record.credentialId !== getCredentialId()) saveCredentialId(record.credentialId);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64UrlToBytes(record.iv), additionalData: recordAad(record) },
      key,
      base64UrlToBytes(record.data)
    );
    const payload = JSON.parse(decoder.decode(plaintext));
    return {
      codes: normalizeStoredCodes(payload.codes),
      email: normalizeEmail(payload.email)
    };
  }

  async function decryptStoredCodes() {
    const record = JSON.parse(localStorage.getItem(STORAGE_KEY) || "null");
    if (!record?.data || !record?.iv) throw new Error("No encrypted backup codes are saved in this browser.");
    return decryptRecord(record);
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
            authenticatorAttachment: "cross-platform",
            residentKey: "required",
            requireResidentKey: true,
            userVerification: "preferred"
          },
          hints: ["security-key"],
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
    const purpose = options.purpose === "encrypt"
      ? "Status: confirm with your YubiKey to encrypt and save these backup codes."
      : "";
    try {
      ensureBackupCredentialId();
    } catch (error) {
      setOutputMode("", error.message);
      throw error;
    }
    setStatus(purpose || "Status: signing in with the saved Backup Codes YubiKey credential. Follow the browser prompt.", "info");
    const prfOutput = await requestPrfWithStoredCredential();
    sessionPrfOutput = prfOutput;
    sessionKey = await deriveAesKey(prfOutput);
    const record = localStorage.getItem(STORAGE_KEY);
    if (record && autoUnlock) {
      const decrypted = await decryptStoredCodes();
      setAccountDisplay(decrypted.email);
      setOutputMode("unlocked", decrypted.codes.length ? linesToCodes(decrypted.codes) : "No codes found in encrypted record.");
      renderCodeList(decrypted.codes);
      setStatus("Status: signed in. Saved backup codes unlocked automatically.", "success");
      return;
    }
    setAccountDisplay("");
    setOutputMode("sealed", record ? "Signed in. Encrypted backup codes are saved locally. Press Show Codes to reveal them." : "Signed in. No encrypted backup codes are saved yet.");
    renderCodeList([]);
    setStatus("Status: signed in. Paste codes and press Encrypt when ready.", "success");
  }

  async function saveCodes() {
    const codes = input.value.trim();
    const email = normalizeEmail(emailInput?.value);
    if (!codes) {
      setOutputMode("", "Paste your Google backup codes first, then press Encrypt.");
      setStatus("Status: paste your backup codes before saving.", "warning");
      return;
    }
    if (!isBasicEmail(email)) {
      setOutputMode("", "The email field is optional. If you use it, enter something like user@gmail.com.");
      setStatus("Status: email is optional, but if entered it should look like user@gmail.com.", "warning");
      return;
    }
    try {
      setBusy(saveButton, true, "Waiting for YubiKey...");
      setStatus("Status: confirm with your YubiKey to encrypt backup codes. Choose Security key if Windows offers options.", "info");
      setOutputMode("sealed", "Waiting for YubiKey confirmation. Your codes will be encrypted locally after sign-in succeeds.");
      await encryptAndStoreCodes(codesToLines(codes), email, { fresh: true, purpose: "encrypt" });
      input.value = "";
      if (emailInput) emailInput.value = "";
      setAccountDisplay("");
      setOutputMode("sealed", "Backup codes are encrypted and stored locally. Sign in and press Show Codes to reveal them.");
      renderCodeList([]);
      setStatus("Status: encrypted backup codes saved in this browser.", "success");
    } catch (error) {
      setOutputMode("", `Encryption did not complete: ${error.message}`);
      setStatus(`Status: ${error.message}`, "warning");
    } finally {
      setBusy(saveButton, false);
    }
  }

  async function unlockCodes() {
    try {
      await getSessionKey();
      const decrypted = await decryptStoredCodes();
      setAccountDisplay(decrypted.email);
      setOutputMode("unlocked", decrypted.codes.length ? linesToCodes(decrypted.codes) : "No codes found in encrypted record.");
      renderCodeList(decrypted.codes);
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
      const currentEmail = accountDisplay?.textContent?.replace(/^Account:\s*/, "") === "No email specified"
        ? ""
        : accountDisplay.textContent.replace(/^Account:\s*/, "");
      await encryptAndStoreCodes(remaining, currentEmail, { fresh: true, purpose: "encrypt" });
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
    setAccountDisplay("");
    setStatus("Status: encrypted backup codes purged from this browser.", "warning");
  }

  function exportEncryptedBackup() {
    const record = localStorage.getItem(STORAGE_KEY);
    if (!record) {
      setStatus("Status: no encrypted backup codes are saved to export.", "warning");
      return;
    }
    const parsedRecord = JSON.parse(record);
    validateEncryptedRecord(parsedRecord);
    const blob = new Blob([JSON.stringify({
      type: EXPORT_TYPE,
      exportedAt: new Date().toISOString(),
      encryptedRecord: parsedRecord
    }, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "goblinpass-google-backup-codes-encrypted.json";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    setStatus("Status: encrypted backup file exported. Email and codes remain encrypted inside it.", "success");
  }

  async function importEncryptedBackup(file) {
    if (!file) return;
    const previousCredentialId = getCredentialId();
    try {
      const parsed = JSON.parse(await file.text());
      const record = parsed.encryptedRecord || parsed;
      if (parsed.type && parsed.type !== EXPORT_TYPE) {
        throw new Error("This is not a GoblinPass Google backup-code export.");
      }
      validateEncryptedRecord(record);
      setStatus("Status: verifying imported backup with your YubiKey before saving.", "info");
      if (record.credentialId) saveCredentialId(record.credentialId);
      await getSessionKey({ fresh: true, purpose: "encrypt" });
      const decrypted = await decryptRecord(record);
      localStorage.setItem(STORAGE_KEY, JSON.stringify(record));
      if (record.credentialId) saveCredentialId(record.credentialId);
      setOutputMode("unlocked", decrypted.codes.length ? linesToCodes(decrypted.codes) : "No codes found in encrypted record.");
      renderCodeList(decrypted.codes);
      setAccountDisplay(decrypted.email);
      setStatus("Status: imported file verified, decrypted, and saved locally.", "success");
    } catch (error) {
      if (previousCredentialId) saveCredentialId(previousCredentialId);
      else localStorage.removeItem(CREDENTIAL_KEY);
      setStatus(`Status: ${error.message}`, "warning");
    } finally {
      importFile.value = "";
    }
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
  exportButton.addEventListener("click", exportEncryptedBackup);
  importButton.addEventListener("click", () => importFile.click());
  importFile.addEventListener("change", () => importEncryptedBackup(importFile.files?.[0]));

  const savedRecord = localStorage.getItem(STORAGE_KEY);
  const savedCredential = getCredentialId();
  updateSetupButton();
  if (!window.isSecureContext) setStatus("Status: WebAuthn may not work from a local file. Use the HTTPS GitHub Pages page.", "warning");
  else if (savedCredential && savedRecord) setStatus("Status: encrypted backup codes found. Sign in with your YubiKey to unlock them.", "success");
  else if (savedCredential) setStatus("Status: YubiKey set up. No backup codes saved yet.", "info");
  setAccountDisplay("");
})();
