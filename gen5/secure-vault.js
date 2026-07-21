(function (root) {
  "use strict";

  const DB_NAME = "goblinpass-gen5";
  const STORE_NAME = "vault";
  const RECORD_KEY = "master-password";
  const SCHEMA_VERSION = 1;
  const AAD = new TextEncoder().encode("GoblinPass Gen 5 master-password vault v1");

  function randomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
  }

  function toBytes(value) {
    return value instanceof Uint8Array ? value : new Uint8Array(value);
  }

  function openDatabase() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, 1);
      request.onupgradeneeded = () => {
        if (!request.result.objectStoreNames.contains(STORE_NAME)) request.result.createObjectStore(STORE_NAME);
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("Secure local storage could not be opened."));
    });
  }

  async function databaseRequest(mode, operation) {
    const database = await openDatabase();
    return new Promise((resolve, reject) => {
      const transaction = database.transaction(STORE_NAME, mode);
      const request = operation(transaction.objectStore(STORE_NAME));
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error || new Error("Secure local storage failed."));
      transaction.oncomplete = () => database.close();
      transaction.onabort = () => {
        database.close();
        reject(transaction.error || new Error("Secure local storage was interrupted."));
      };
    });
  }

  function getRecord() {
    return databaseRequest("readonly", store => store.get(RECORD_KEY));
  }

  function saveRecord(record) {
    return databaseRequest("readwrite", store => store.put(record, RECORD_KEY));
  }

  function deleteRecord() {
    return databaseRequest("readwrite", store => store.delete(RECORD_KEY));
  }

  async function support() {
    const baseSupport = Boolean(
      root.isSecureContext && root.PublicKeyCredential && navigator.credentials &&
      crypto?.subtle && root.indexedDB
    );
    if (!baseSupport) return { available: false, reason: "WebAuthn secure storage requires HTTPS and a compatible browser." };

    if (typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
      try {
        const platformAvailable = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        if (!platformAvailable) return { available: false, reason: "No Windows Hello or biometric device authenticator is available." };
      } catch {
        return { available: false, reason: "This browser could not check the device authenticator." };
      }
    }

    if (typeof PublicKeyCredential.getClientCapabilities === "function") {
      try {
        const capabilities = await PublicKeyCredential.getClientCapabilities();
        if (capabilities["extension:prf"] === false) {
          return { available: false, reason: "This browser does not support passkey PRF encryption." };
        }
      } catch {
        // Older implementations can support PRF without capability discovery.
      }
    }
    return { available: true };
  }

  async function deriveEncryptionKey(prfOutput, kdfSalt) {
    const material = await crypto.subtle.importKey("raw", toBytes(prfOutput), "HKDF", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({
      name: "HKDF",
      hash: "SHA-256",
      salt: toBytes(kdfSalt),
      info: AAD
    }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  async function evaluatePrf(credentialId, prfSalt) {
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: randomBytes(32),
        allowCredentials: [{ id: toBytes(credentialId), type: "public-key" }],
        userVerification: "required",
        timeout: 120000,
        extensions: { prf: { eval: { first: toBytes(prfSalt) } } }
      }
    });
    const output = assertion?.getClientExtensionResults?.().prf?.results?.first;
    if (!output) throw new Error("This passkey did not provide the encryption secret. Try a current Chromium-based browser and Windows Hello.");
    return output;
  }

  async function create(masterPassword) {
    if (!masterPassword) throw new Error("Enter a master password before protecting it.");
    const supportResult = await support();
    if (!supportResult.available) throw new Error(supportResult.reason);

    const prfSalt = randomBytes(32);
    const kdfSalt = randomBytes(32);
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: randomBytes(32),
        rp: { name: "GoblinPass" },
        user: {
          id: randomBytes(32),
          name: "goblinpass-local-vault",
          displayName: "GoblinPass local master password"
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 }
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "required"
        },
        attestation: "none",
        timeout: 120000,
        extensions: { prf: { eval: { first: prfSalt } }, credProps: true }
      }
    });

    const registrationPrf = credential?.getClientExtensionResults?.().prf;
    if (!registrationPrf?.enabled) {
      throw new Error("Windows Hello created a passkey, but it cannot protect local data with PRF in this browser. Nothing was saved.");
    }
    const credentialId = new Uint8Array(credential.rawId);
    const prfOutput = registrationPrf.results?.first || await evaluatePrf(credentialId, prfSalt);
    const key = await deriveEncryptionKey(prfOutput, kdfSalt);
    const iv = randomBytes(12);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: AAD, tagLength: 128 },
      key,
      new TextEncoder().encode(masterPassword)
    );
    const record = {
      version: SCHEMA_VERSION,
      credentialId: Array.from(credentialId),
      prfSalt: Array.from(prfSalt),
      kdfSalt: Array.from(kdfSalt),
      iv: Array.from(iv),
      ciphertext: Array.from(new Uint8Array(ciphertext)),
      createdAt: new Date().toISOString()
    };
    await saveRecord(record);
    return record;
  }

  async function unlock(record) {
    const saved = record || await getRecord();
    if (!saved || saved.version !== SCHEMA_VERSION) throw new Error("No compatible saved master password was found.");
    const prfOutput = await evaluatePrf(saved.credentialId, saved.prfSalt);
    const key = await deriveEncryptionKey(prfOutput, saved.kdfSalt);
    try {
      const plaintext = await crypto.subtle.decrypt({
        name: "AES-GCM",
        iv: toBytes(saved.iv),
        additionalData: AAD,
        tagLength: 128
      }, key, toBytes(saved.ciphertext));
      return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
    } catch {
      throw new Error("The saved master password could not be decrypted. The passkey or stored data may no longer match.");
    }
  }

  root.GoblinPassSecureVault = { support, getRecord, create, unlock, deleteRecord };
}(window));
