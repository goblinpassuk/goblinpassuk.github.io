"use strict";

const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");

if (!global.crypto) Object.defineProperty(global, "crypto", { value: webcrypto });
global.window = global;
global.isSecureContext = true;

const records = new Map();
function requestFor(operation) {
  const request = {};
  queueMicrotask(() => {
    try {
      request.result = operation();
      request.onsuccess?.();
    } catch (error) {
      request.error = error;
      request.onerror?.();
    }
  });
  return request;
}

global.indexedDB = {
  open() {
    const request = {};
    const database = {
      objectStoreNames: { contains: () => true },
      createObjectStore() {},
      close() {},
      transaction() {
        return {
          objectStore() {
            return {
              get: key => requestFor(() => records.get(key)),
              put: (value, key) => requestFor(() => records.set(key, value)),
              delete: key => requestFor(() => records.delete(key))
            };
          }
        };
      }
    };
    queueMicrotask(() => {
      request.result = database;
      request.onsuccess?.();
    });
    return request;
  }
};

global.PublicKeyCredential = {
  isUserVerifyingPlatformAuthenticatorAvailable: async () => true,
  getClientCapabilities: async () => ({ "extension:prf": true })
};

const credentialId = webcrypto.getRandomValues(new Uint8Array(32));
const correctPrf = webcrypto.getRandomValues(new Uint8Array(32));
let assertionPrf = correctPrf;
Object.defineProperty(global, "navigator", { configurable: true, value: {
  credentials: {
    create: async () => ({
      rawId: credentialId.buffer,
      getClientExtensionResults: () => ({ prf: { enabled: true, results: { first: correctPrf.buffer } } })
    }),
    get: async () => ({
      getClientExtensionResults: () => ({ prf: { results: { first: assertionPrf.buffer } } })
    })
  }
} });

require("../gen5/secure-vault.js");

(async () => {
  const masterPassword = "correct horse battery staple";
  const saved = await GoblinPassSecureVault.create(masterPassword);
  assert.equal(saved.version, 1);
  assert.equal(Object.values(saved).includes(masterPassword), false, "plaintext must not be stored in the record");
  assert.notDeepEqual(saved.ciphertext, Array.from(new TextEncoder().encode(masterPassword)));
  assert.equal(await GoblinPassSecureVault.unlock(), masterPassword);

  assertionPrf = webcrypto.getRandomValues(new Uint8Array(32));
  await assert.rejects(() => GoblinPassSecureVault.unlock(), /could not be decrypted/);

  await GoblinPassSecureVault.deleteRecord();
  assert.equal(await GoblinPassSecureVault.getRecord(), undefined);
  console.log("Gen 5 secure vault tests passed.");
})().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
