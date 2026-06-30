(function (root, factory) {
  "use strict";
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  if (root) root.GoblinPassGen3MapCrypto = api;
})(typeof window !== "undefined" ? window : globalThis, function () {
  "use strict";

  const MAGIC = "GPASS3";
  const TYPE = "goblinpass-gen3-map";
  const VERSION = 1;
  const ENCRYPTION = "AES-GCM";
  const KDF = "HKDF-SHA256";
  const PROTECTED_MAGIC = "GPASS3-LOCKED";
  const PROTECTED_TYPE = "goblinpass-gen3-protected-map";
  const PROTECTED_VERSION = 1;
  const PROTECTED_KDF = "PBKDF2-SHA256";
  const PROTECTED_ITERATIONS = 600000;
  const UNLOCK_TYPES = new Set(["google", "yubikey", "biometric"]);

  function bytesToBase64(bytes) {
    let binary = "";
    new Uint8Array(bytes).forEach(byte => { binary += String.fromCharCode(byte); });
    return btoa(binary);
  }

  function base64ToBytes(value) {
    const binary = atob(String(value || ""));
    return Uint8Array.from(binary, char => char.charCodeAt(0));
  }

  function validCipherBlock(block) {
    if (!block || typeof block.iv !== "string" || typeof block.data !== "string") return false;
    try {
      return base64ToBytes(block.iv).byteLength === 12 && base64ToBytes(block.data).byteLength >= 16;
    } catch {
      return false;
    }
  }

  function validateUnlockMethod(method) {
    if (!method || !UNLOCK_TYPES.has(method.type) || !validCipherBlock(method.wrappedKey)) return false;
    if (method.type === "google") return typeof method.subjectHash === "string" && typeof method.salt === "string";
    return typeof method.credentialId === "string" && method.credentialId.length > 0;
  }

  function validateEnvelope(record) {
    if (!record || record.magic !== MAGIC || record.type !== TYPE || record.version !== VERSION) {
      throw new Error("This is not a GoblinPass Gen 3.0 encrypted map file.");
    }
    if (record.encryption !== ENCRYPTION || record.kdf !== KDF) {
      throw new Error("This GoblinPass Security Map uses an unsupported encryption format.");
    }
    if (!Array.isArray(record.unlockMethods) || !record.unlockMethods.length || !record.unlockMethods.every(validateUnlockMethod)) {
      throw new Error("This GoblinPass Security Map has invalid unlock methods.");
    }
    if (!validCipherBlock(record.payload)) throw new Error("This GoblinPass Security Map has an invalid encrypted payload.");
    return record;
  }

  function protectedAdditionalData() {
    return new TextEncoder().encode(`${PROTECTED_MAGIC}|${PROTECTED_VERSION}|${PROTECTED_KDF}|${PROTECTED_ITERATIONS}`);
  }

  function validateProtectedEnvelope(record) {
    if (!record || record.magic !== PROTECTED_MAGIC || record.type !== PROTECTED_TYPE || record.version !== PROTECTED_VERSION) {
      throw new Error("This is not a protected GoblinPass Gen 3.0 map file.");
    }
    if (record.encryption !== ENCRYPTION || record.kdf?.name !== PROTECTED_KDF || record.kdf?.iterations !== PROTECTED_ITERATIONS) {
      throw new Error("This protected GoblinPass map uses an unsupported encryption format.");
    }
    try {
      if (base64ToBytes(record.kdf.salt).byteLength !== 16) throw new Error();
    } catch {
      throw new Error("This protected GoblinPass map has an invalid encryption salt.");
    }
    if (!validCipherBlock(record.payload)) throw new Error("This protected GoblinPass map has an invalid encrypted payload.");
    return record;
  }

  function isProtectedEnvelope(record) {
    return Boolean(record && record.magic === PROTECTED_MAGIC);
  }

  async function deriveProtectionKey(passphrase, salt) {
    if (typeof passphrase !== "string" || !passphrase.length) throw new Error("Enter the file passphrase.");
    const saltBytes = typeof salt === "string" ? base64ToBytes(salt) : new Uint8Array(salt);
    if (saltBytes.byteLength !== 16) throw new Error("The protected map encryption salt is invalid.");
    const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations: PROTECTED_ITERATIONS
    }, material, { name: ENCRYPTION, length: 256 }, false, ["encrypt", "decrypt"]);
  }

  async function protectEnvelope(record, protectionKey, salt) {
    validateEnvelope(record);
    const saltBytes = typeof salt === "string" ? base64ToBytes(salt) : new Uint8Array(salt);
    if (saltBytes.byteLength !== 16) throw new Error("The protected map encryption salt is invalid.");
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(record));
    const data = await crypto.subtle.encrypt({ name: ENCRYPTION, iv, additionalData: protectedAdditionalData() }, protectionKey, plaintext);
    return validateProtectedEnvelope({
      magic: PROTECTED_MAGIC,
      type: PROTECTED_TYPE,
      version: PROTECTED_VERSION,
      encryption: ENCRYPTION,
      kdf: { name: PROTECTED_KDF, iterations: PROTECTED_ITERATIONS, salt: bytesToBase64(saltBytes) },
      payload: { iv: bytesToBase64(iv), data: bytesToBase64(data) }
    });
  }

  async function createProtectedEnvelope(record, passphrase) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveProtectionKey(passphrase, salt);
    return { envelope: await protectEnvelope(record, key, salt), key, salt };
  }

  async function openProtectedEnvelope(record, passphrase) {
    const validated = validateProtectedEnvelope(record);
    const salt = base64ToBytes(validated.kdf.salt);
    const key = await deriveProtectionKey(passphrase, salt);
    try {
      const plaintext = await crypto.subtle.decrypt({
        name: ENCRYPTION,
        iv: base64ToBytes(validated.payload.iv),
        additionalData: protectedAdditionalData()
      }, key, base64ToBytes(validated.payload.data));
      return { record: validateEnvelope(JSON.parse(new TextDecoder().decode(plaintext))), key, salt };
    } catch {
      throw new Error("The file passphrase is incorrect or the protected map is damaged.");
    }
  }

  function createEnvelope(unlockMethods, payload) {
    return validateEnvelope({
      magic: MAGIC,
      type: TYPE,
      version: VERSION,
      encryption: ENCRYPTION,
      kdf: KDF,
      unlockMethods: unlockMethods.map(method => ({ ...method })),
      payload: { iv: payload.iv, data: payload.data }
    });
  }

  function buildPayload(rows, settings = {}) {
    return {
      schema: 1,
      updatedAt: new Date().toISOString(),
      settings: settings && typeof settings === "object" && !Array.isArray(settings) ? { ...settings } : {},
      entries: rows.map(row => ({
        id: String(row.id || ""),
        website: String(row.website ?? row.site ?? ""),
        username: String(row.username ?? row.login ?? ""),
        securityMethod: String(row.securityMethod || "Master Password"),
        passwordHint: String(row.passwordHint ?? row.hint ?? ""),
        notes: String(row.notes || "")
      }))
    };
  }

  function restoreRows(parsed) {
    if (!parsed || parsed.schema !== 1 || !Array.isArray(parsed.entries) || !parsed.settings || typeof parsed.settings !== "object") {
      throw new Error("The decrypted GoblinPass Security Map is invalid.");
    }
    const updatedAt = typeof parsed.updatedAt === "string" ? parsed.updatedAt : "";
    return parsed.entries.map(entry => ({
      key: crypto.randomUUID(),
      id: String(entry?.id || ""),
      site: String(entry?.website || ""),
      login: String(entry?.username || ""),
      length: 16,
      counter: 1,
      hint: String(entry?.passwordHint || ""),
      securityMethod: String(entry?.securityMethod || ""),
      notes: String(entry?.notes || ""),
      updated: updatedAt
    }));
  }

  function restoreLegacyRows(record) {
    const source = Array.isArray(record?.entries) ? record.entries : Array.isArray(record?.rows) ? record.rows : null;
    if (!source) return null;
    const updatedAt = String(record.updatedAt || "");
    return source.map(entry => ({
      key: String(entry?.key || crypto.randomUUID()),
      id: String(entry?.id || ""),
      site: String(entry?.website ?? entry?.site ?? ""),
      login: String(entry?.username ?? entry?.login ?? ""),
      length: Number(entry?.length) || 16,
      counter: Number(entry?.counter) || 1,
      hint: String(entry?.passwordHint ?? entry?.hint ?? ""),
      securityMethod: String(entry?.securityMethod || "Master Password"),
      notes: String(entry?.notes || ""),
      updated: String(entry?.updated || updatedAt)
    }));
  }

  function isLegacyEncrypted(record) {
    return Boolean(record && !record.magic && record.type === TYPE && record.version === VERSION && Array.isArray(record.unlockMethods) && validCipherBlock(record.payload));
  }

  function normalizeLegacyUnlockMethods(methods) {
    return methods.map(method => method.type === "google"
      ? { ...method, kdf: method.kdf || "PBKDF2-SHA256" }
      : { ...method });
  }

  async function encryptPayload(dataKey, payloadObject) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(payloadObject));
    const data = await crypto.subtle.encrypt({ name: ENCRYPTION, iv }, dataKey, plaintext);
    return { iv: bytesToBase64(iv), data: bytesToBase64(data) };
  }

  async function decryptPayload(dataKey, payload) {
    if (!validCipherBlock(payload)) throw new Error("The encrypted GoblinPass Security Map payload is invalid.");
    const plaintext = await crypto.subtle.decrypt({ name: ENCRYPTION, iv: base64ToBytes(payload.iv) }, dataKey, base64ToBytes(payload.data));
    return JSON.parse(new TextDecoder().decode(plaintext));
  }

  return {
    MAGIC,
    TYPE,
    VERSION,
    ENCRYPTION,
    KDF,
    PROTECTED_MAGIC,
    PROTECTED_TYPE,
    PROTECTED_VERSION,
    PROTECTED_KDF,
    PROTECTED_ITERATIONS,
    buildPayload,
    createProtectedEnvelope,
    createEnvelope,
    decryptPayload,
    deriveProtectionKey,
    encryptPayload,
    isLegacyEncrypted,
    isProtectedEnvelope,
    normalizeLegacyUnlockMethods,
    openProtectedEnvelope,
    protectEnvelope,
    restoreLegacyRows,
    restoreRows,
    validateEnvelope,
    validateProtectedEnvelope
  };
});
