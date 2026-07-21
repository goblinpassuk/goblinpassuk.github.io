import {
  aad, base64url, canonicalJson, constantTimeEqual, decodeUtf8, decryptAesGcm, encryptAesGcm,
  fromBase64url, hkdfBytes, hkdfKey, importAesKey, importHmacKey, randomBytes, utf8, wipe
} from "./crypto.js";
import { VaultStorage } from "./storage.js";
import { VAULT_FORMAT, VAULT_SCHEMA, type AeadEnvelope, type PasskeyWrap, type VaultPayload, type VaultRecordV2 } from "./types.js";
import { credentialIdString, evaluatePasskey, registerPasskey } from "./webauthn.js";

const WRAP_INFO = utf8("GoblinPass/v5/passkey-key-wrap/AES-256-GCM");
const INTEGRITY_INFO = utf8("GoblinPass/v5/vault-record-integrity/HMAC-SHA-256");

function envelope(iv: Uint8Array, ciphertext: Uint8Array): AeadEnvelope {
  return { algorithm: "AES-256-GCM", iv: base64url(iv), ciphertext: base64url(ciphertext) };
}

function payloadMetadata(record: Pick<VaultRecordV2, "format" | "schema" | "vaultId" | "profileSalt" | "createdAt">) {
  return {
    format: record.format, schema: record.schema, vaultId: record.vaultId,
    profileSalt: record.profileSalt, createdAt: record.createdAt, purpose: "vault-payload"
  };
}

function wrapMetadata(vaultId: string, wrap: Omit<PasskeyWrap, "wrappedKey">) {
  return { vaultId, ...wrap, purpose: "vault-data-key-wrap" };
}

async function recordIntegrity(dataKeyBytes: Uint8Array, record: VaultRecordV2): Promise<Uint8Array> {
  const integrityKeyBytes = await hkdfBytes(dataKeyBytes, fromBase64url(record.profileSalt), INTEGRITY_INFO);
  try {
    const key = await importHmacKey(integrityKeyBytes);
    const { integrity: _ignored, ...authenticatedRecord } = record;
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(canonicalJson(authenticatedRecord))));
  } finally { wipe(integrityKeyBytes); }
}

async function wrapDataKey(vaultId: string, dataKeyBytes: Uint8Array, label: string, existing: PasskeyWrap[]): Promise<PasskeyWrap> {
  const prfSalt = randomBytes(32);
  const hkdfSalt = randomBytes(32);
  let registered: Awaited<ReturnType<typeof registerPasskey>> | undefined;
  try {
    registered = await registerPasskey(prfSalt, existing.map(item => fromBase64url(item.credentialId)));
    const now = new Date().toISOString();
    const partial = {
      id: base64url(randomBytes(16)),
      credentialId: credentialIdString(registered.credentialId),
      label: label.normalize("NFKC").trim().slice(0, 80) || "Platform passkey",
      transports: registered.transports,
      prfSalt: base64url(prfSalt),
      hkdfSalt: base64url(hkdfSalt),
      createdAt: now,
      lastUsedAt: null
    } satisfies Omit<PasskeyWrap, "wrappedKey">;
    const kek = await hkdfKey(registered.prfOutput, hkdfSalt, WRAP_INFO, ["encrypt"]);
    const wrapped = await encryptAesGcm(kek, dataKeyBytes, aad("GP5-WRAP-1", wrapMetadata(vaultId, partial)));
    return { ...partial, wrappedKey: envelope(wrapped.iv, wrapped.ciphertext) };
  } finally {
    wipe(prfSalt, hkdfSalt, registered?.credentialId, registered?.prfOutput);
  }
}

async function unwrapDataKey(vaultId: string, wrap: PasskeyWrap): Promise<Uint8Array> {
  const credentialId = fromBase64url(wrap.credentialId);
  const prfSalt = fromBase64url(wrap.prfSalt);
  const hkdfSalt = fromBase64url(wrap.hkdfSalt);
  let prfOutput: Uint8Array | undefined;
  try {
    prfOutput = await evaluatePasskey(credentialId, prfSalt);
    const { wrappedKey: _ignored, ...partial } = wrap;
    const kek = await hkdfKey(prfOutput, hkdfSalt, WRAP_INFO, ["decrypt"]);
    return decryptAesGcm(
      kek,
      fromBase64url(wrap.wrappedKey.iv),
      fromBase64url(wrap.wrappedKey.ciphertext),
      aad("GP5-WRAP-1", wrapMetadata(vaultId, partial))
    );
  } finally {
    wipe(credentialId, prfSalt, hkdfSalt, prfOutput);
  }
}

export class UnlockedVault {
  #record: VaultRecordV2;
  #dataKeyBytes: Uint8Array | null;
  #masterPassword: Uint8Array | null;

  constructor(record: VaultRecordV2, dataKeyBytes: Uint8Array, masterPassword: Uint8Array) {
    this.#record = structuredClone(record);
    this.#dataKeyBytes = dataKeyBytes;
    this.#masterPassword = masterPassword;
  }

  get record(): VaultRecordV2 { return structuredClone(this.#record); }
  takeMasterPassword(): Uint8Array {
    if (!this.#masterPassword) throw new DOMException("Vault is locked.", "InvalidStateError");
    const copy = this.#masterPassword.slice();
    wipe(this.#masterPassword);
    this.#masterPassword = null;
    return copy;
  }

  async readMasterPassword(): Promise<Uint8Array> {
    if (!this.#dataKeyBytes) throw new DOMException("Vault is locked.", "InvalidStateError");
    const key = await importAesKey(this.#dataKeyBytes, ["decrypt"]);
    const plaintext = await decryptAesGcm(
      key, fromBase64url(this.#record.payload.iv), fromBase64url(this.#record.payload.ciphertext),
      aad("GP5-PAYLOAD-1", payloadMetadata(this.#record))
    );
    try {
      const payload = JSON.parse(decodeUtf8(plaintext)) as VaultPayload;
      if (payload.format !== "goblinpass-vault-payload" || payload.schema !== 1) throw new DOMException("Vault payload is invalid.", "DataError");
      return fromBase64url(payload.masterPassword);
    } finally {
      wipe(plaintext);
    }
  }

  async addPasskey(storage: VaultStorage, label: string): Promise<void> {
    if (!this.#dataKeyBytes) throw new DOMException("Vault is locked.", "InvalidStateError");
    const added = await wrapDataKey(this.#record.vaultId, this.#dataKeyBytes, label, this.#record.credentials);
    const previousRevision = this.#record.revision;
    const candidate = structuredClone(this.#record);
    candidate.credentials.push(added);
    candidate.revision += 1;
    candidate.updatedAt = new Date().toISOString();
    const tag = await recordIntegrity(this.#dataKeyBytes, candidate);
    try { candidate.integrity.tag = base64url(tag); } finally { wipe(tag); }
    await storage.writeAtomic(candidate, previousRevision);
    this.#record = candidate;
  }

  async removePasskey(storage: VaultStorage, passkeyId: string): Promise<void> {
    if (this.#record.credentials.length <= 1) throw new Error("Add another passkey before removing the last one.");
    const previousRevision = this.#record.revision;
    const removed = this.#record.credentials.find(item => item.id === passkeyId);
    const next = this.#record.credentials.filter(item => item.id !== passkeyId);
    if (next.length === this.#record.credentials.length) throw new Error("Passkey not found.");
    if (!this.#dataKeyBytes) throw new DOMException("Vault is locked.", "InvalidStateError");
    const candidate = structuredClone(this.#record);
    candidate.credentials = next;
    candidate.revision += 1;
    candidate.updatedAt = new Date().toISOString();
    const tag = await recordIntegrity(this.#dataKeyBytes, candidate);
    try { candidate.integrity.tag = base64url(tag); } finally { wipe(tag); }
    await storage.writeAtomic(candidate, previousRevision);
    this.#record = candidate;
    const credentialSignals = PublicKeyCredential as typeof PublicKeyCredential & {
      signalUnknownCredential?: (options: { rpId: string; credentialId: string }) => Promise<void>;
    };
    if (removed && typeof credentialSignals.signalUnknownCredential === "function") {
      await credentialSignals.signalUnknownCredential({ rpId: location.hostname, credentialId: removed.credentialId }).catch(() => undefined);
    }
  }

  destroy(): void {
    wipe(this.#dataKeyBytes ?? undefined, this.#masterPassword ?? undefined);
    this.#dataKeyBytes = null;
    this.#masterPassword = null;
  }
}

export class SecureVault {
  constructor(readonly storage = new VaultStorage()) {}

  async setup(masterPassword: Uint8Array, label = "Primary platform passkey", restoredProfileSalt?: Uint8Array): Promise<UnlockedVault> {
    if (masterPassword.length < 12) throw new Error("Use a master password of at least 12 UTF-8 bytes.");
    if (await this.storage.read()) throw new DOMException("A vault already exists.", "InvalidStateError");
    const dataKeyBytes = randomBytes(32);
    const profileSalt = restoredProfileSalt?.slice() ?? randomBytes(32);
    if (profileSalt.length !== 32) throw new Error("Generator profile salt must be 256 bits.");
    const vaultId = base64url(randomBytes(32));
    const now = new Date().toISOString();
    let payloadBytes: Uint8Array | undefined;
    try {
      const wrap = await wrapDataKey(vaultId, dataKeyBytes, label, []);
      const record: VaultRecordV2 = {
        format: VAULT_FORMAT, schema: VAULT_SCHEMA, revision: 1, vaultId,
        profileSalt: base64url(profileSalt), payload: { algorithm: "AES-256-GCM", iv: "", ciphertext: "" },
        integrity: { algorithm: "HMAC-SHA-256", tag: "" },
        credentials: [wrap], createdAt: now, updatedAt: now
      };
      const key = await importAesKey(dataKeyBytes, ["encrypt"]);
      const payload: VaultPayload = {
        format: "goblinpass-vault-payload", schema: 1,
        masterPassword: base64url(masterPassword), payloadId: base64url(randomBytes(16))
      };
      payloadBytes = utf8(JSON.stringify(payload));
      const encrypted = await encryptAesGcm(key, payloadBytes, aad("GP5-PAYLOAD-1", payloadMetadata(record)));
      record.payload = envelope(encrypted.iv, encrypted.ciphertext);
      const tag = await recordIntegrity(dataKeyBytes, record);
      try { record.integrity.tag = base64url(tag); } finally { wipe(tag); }
      await this.storage.writeAtomic(record, null);
      return new UnlockedVault(record, dataKeyBytes, masterPassword.slice());
    } catch (error) {
      wipe(dataKeyBytes);
      throw error;
    } finally {
      wipe(profileSalt, payloadBytes);
    }
  }

  async unlock(record?: VaultRecordV2): Promise<UnlockedVault> {
    record ??= await this.storage.read();
    validateVaultRecord(record);
    let lastError: unknown = new Error("No passkey could unlock the vault.");
    for (const wrap of record.credentials) {
      let dataKeyBytes: Uint8Array | undefined;
      try {
        dataKeyBytes = await unwrapDataKey(record.vaultId, wrap);
        const expectedTag = await recordIntegrity(dataKeyBytes, record);
        const storedTag = fromBase64url(record.integrity.tag);
        const validIntegrity = constantTimeEqual(expectedTag, storedTag);
        wipe(expectedTag, storedTag);
        if (!validIntegrity) throw new DOMException("Vault record integrity check failed.", "DataError");
        const key = await importAesKey(dataKeyBytes, ["decrypt"]);
        const plaintext = await decryptAesGcm(
          key, fromBase64url(record.payload.iv), fromBase64url(record.payload.ciphertext),
          aad("GP5-PAYLOAD-1", payloadMetadata(record))
        );
        try {
          const payload = JSON.parse(decodeUtf8(plaintext)) as VaultPayload;
          if (payload.format !== "goblinpass-vault-payload" || payload.schema !== 1) throw new Error("Vault payload format mismatch.");
          return new UnlockedVault(record, dataKeyBytes, fromBase64url(payload.masterPassword));
        } finally {
          wipe(plaintext);
        }
      } catch (error) {
        wipe(dataKeyBytes);
        lastError = error;
        if ((error as DOMException).name === "NotAllowedError") break;
      }
    }
    throw lastError;
  }

  async migrateLegacy(): Promise<UnlockedVault> {
    if (await this.storage.read()) throw new DOMException("A current vault already exists.", "InvalidStateError");
    const legacy = await this.storage.readLegacy();
    if (!legacy || legacy.version !== 1) throw new DOMException("No legacy vault was found.", "NotFoundError");
    const credentialId = Uint8Array.from(legacy.credentialId);
    const prfSalt = Uint8Array.from(legacy.prfSalt);
    const kdfSalt = Uint8Array.from(legacy.kdfSalt);
    const legacyAad = utf8("GoblinPass Gen 5 master-password vault v1");
    let prfOutput: Uint8Array | undefined;
    let plaintext: Uint8Array | undefined;
    let masterBytes: Uint8Array | undefined;
    try {
      prfOutput = await evaluatePasskey(credentialId, prfSalt);
      const key = await hkdfKey(prfOutput, kdfSalt, legacyAad, ["decrypt"]);
      plaintext = await decryptAesGcm(
        key, Uint8Array.from(legacy.iv), Uint8Array.from(legacy.ciphertext), legacyAad
      );
      masterBytes = utf8(decodeUtf8(plaintext));
      const migrated = await this.setup(masterBytes, "Migrated platform passkey");
      await this.storage.removeLegacy();
      return migrated;
    } finally {
      wipe(credentialId, prfSalt, kdfSalt, prfOutput, legacyAad, plaintext, masterBytes);
    }
  }
}

export function validateVaultRecord(value: VaultRecordV2 | undefined): asserts value is VaultRecordV2 {
  const validEncodedLength = (encoded: unknown, bytes: number, maximumCharacters = 22_000): boolean => {
    if (typeof encoded !== "string" || encoded.length > maximumCharacters) return false;
    try { return fromBase64url(encoded).length === bytes; } catch { return false; }
  };
  const validEnvelope = (candidate: unknown, expectedCiphertextBytes?: number): candidate is AeadEnvelope => {
    if (!candidate || typeof candidate !== "object") return false;
    const item = candidate as AeadEnvelope;
    if (item.algorithm !== "AES-256-GCM" || !validEncodedLength(item.iv, 12, 32) ||
        typeof item.ciphertext !== "string" || item.ciphertext.length > 22_000) return false;
    try {
      const length = fromBase64url(item.ciphertext).length;
      return expectedCiphertextBytes === undefined ? length >= 16 : length === expectedCiphertextBytes;
    } catch { return false; }
  };
  const validWrap = (candidate: unknown): candidate is PasskeyWrap => {
    if (!candidate || typeof candidate !== "object") return false;
    const item = candidate as PasskeyWrap;
    return validEncodedLength(item.id, 16, 32) &&
      typeof item.credentialId === "string" && item.credentialId.length <= 1_400 && (() => {
        try { const length = fromBase64url(item.credentialId).length; return length >= 1 && length <= 1_024; } catch { return false; }
      })() &&
      typeof item.label === "string" && item.label.length <= 80 &&
      Array.isArray(item.transports) && item.transports.length <= 8 && item.transports.every(entry => typeof entry === "string") &&
      validEncodedLength(item.prfSalt, 32, 64) && validEncodedLength(item.hkdfSalt, 32, 64) &&
      validEnvelope(item.wrappedKey, 48) && typeof item.createdAt === "string" && item.createdAt.length <= 40 &&
      (item.lastUsedAt === null || typeof item.lastUsedAt === "string");
  };
  const candidate = value as Partial<VaultRecordV2> | undefined;
  if (!candidate || candidate.format !== VAULT_FORMAT || candidate.schema !== VAULT_SCHEMA ||
      !Number.isSafeInteger(candidate.revision) || (candidate.revision ?? 0) < 1 ||
      !Array.isArray(candidate.credentials) || candidate.credentials.length < 1 || candidate.credentials.length > 8 ||
      !candidate.credentials.every(validWrap) || candidate.integrity?.algorithm !== "HMAC-SHA-256" ||
      !validEncodedLength(candidate.integrity.tag, 32, 64) || !validEncodedLength(candidate.profileSalt, 32, 64) ||
      !validEncodedLength(candidate.vaultId, 32, 64) || !validEnvelope(candidate.payload) ||
      typeof candidate.createdAt !== "string" || candidate.createdAt.length > 40 ||
      typeof candidate.updatedAt !== "string" || candidate.updatedAt.length > 40) {
    throw new DOMException("Vault record is missing, corrupted, or unsupported.", "DataError");
  }
}
