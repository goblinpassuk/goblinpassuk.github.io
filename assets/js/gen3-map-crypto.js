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
    buildPayload,
    createEnvelope,
    decryptPayload,
    encryptPayload,
    isLegacyEncrypted,
    normalizeLegacyUnlockMethods,
    restoreLegacyRows,
    restoreRows,
    validateEnvelope
  };
});
