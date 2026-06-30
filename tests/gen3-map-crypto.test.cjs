"use strict";

const assert = require("node:assert/strict");
const { webcrypto } = require("node:crypto");

if (!global.crypto) Object.defineProperty(global, "crypto", { value: webcrypto });
global.btoa = value => Buffer.from(value, "binary").toString("base64");
global.atob = value => Buffer.from(value, "base64").toString("binary");

const MapCrypto = require("../assets/js/gen3-map-crypto.js");

function toBase64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

(async () => {
  const sample = {
    id: "site-id-42",
    website: "private.example.test",
    username: "sample-user@example.test",
    passwordHint: "hint-ALPHA",
    notes: "private note 7z"
  };
  const rows = [{
    id: sample.id,
    site: sample.website,
    login: sample.username,
    length: 16,
    counter: 1,
    selectedKeys: ["lower", "upper", "nums"],
    hint: sample.passwordHint,
    notes: sample.notes,
    securityMethod: "Master Password"
  }];

  const dataKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
  const wrappingKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const rawDataKey = await crypto.subtle.exportKey("raw", dataKey);
  const wrapIv = crypto.getRandomValues(new Uint8Array(12));
  const wrappedDataKey = await crypto.subtle.encrypt({ name: "AES-GCM", iv: wrapIv }, wrappingKey, rawDataKey);

  const payloadObject = MapCrypto.buildPayload(rows);
  const payload = await MapCrypto.encryptPayload(dataKey, payloadObject);
  const envelope = MapCrypto.createEnvelope([{
    type: "google",
    subjectHash: "safe-account-hash",
    salt: toBase64(crypto.getRandomValues(new Uint8Array(24))),
    wrappedKey: { iv: toBase64(wrapIv), data: toBase64(wrappedDataKey) }
  }], payload);
  const exported = JSON.stringify(envelope);

  Object.values(sample).forEach(value => assert.equal(exported.includes(value), false));
  assert.deepEqual(Object.keys(envelope), ["magic", "type", "version", "encryption", "kdf", "unlockMethods", "payload"]);
  assert.equal("updatedAt" in envelope, false);
  assert.equal("entries" in envelope, false);

  const imported = MapCrypto.validateEnvelope(JSON.parse(exported));
  const unwrappedRaw = await crypto.subtle.decrypt({ name: "AES-GCM", iv: wrapIv }, wrappingKey, Buffer.from(imported.unlockMethods[0].wrappedKey.data, "base64"));
  const unwrappedKey = await crypto.subtle.importKey("raw", unwrappedRaw, { name: "AES-GCM" }, false, ["decrypt"]);
  const decrypted = await MapCrypto.decryptPayload(unwrappedKey, imported.payload);
  assert.deepEqual(Object.keys(decrypted), ["schema", "updatedAt", "settings", "entries"]);
  assert.deepEqual(Object.keys(decrypted.entries[0]), ["id", "website", "username", "length", "counter", "selectedKeys", "securityMethod", "passwordHint", "notes"]);
  const restored = MapCrypto.restoreRows(decrypted);

  assert.equal(restored.length, 1);
  assert.equal(restored[0].id, sample.id);
  assert.equal(restored[0].site, sample.website);
  assert.equal(restored[0].login, sample.username);
  assert.deepEqual(restored[0].selectedKeys, ["lower", "upper", "nums"]);
  assert.equal(restored[0].hint, sample.passwordHint);
  assert.equal(restored[0].notes, sample.notes);

  const restoredOlderEntry = MapCrypto.restoreRows({
    schema: 1,
    settings: {},
    entries: [{ id: "older-entry", website: "", username: "", securityMethod: "Master Password", passwordHint: "", notes: "" }]
  });
  assert.deepEqual(restoredOlderEntry[0].selectedKeys, ["lower", "upper", "nums", "symbols"]);

  const filePassphrase = "correct horse battery staple";
  const protectedResult = await MapCrypto.createProtectedEnvelope(envelope, filePassphrase);
  const protectedExport = JSON.stringify(protectedResult.envelope);
  assert.equal(MapCrypto.isProtectedEnvelope(protectedResult.envelope), true);
  assert.deepEqual(Object.keys(protectedResult.envelope), ["magic", "type", "version", "encryption", "kdf", "payload"]);
  assert.equal(protectedExport.includes("unlockMethods"), false);
  assert.equal(protectedExport.includes("credentialId"), false);
  assert.equal(protectedExport.includes("safe-account-hash"), false);
  Object.values(sample).forEach(value => assert.equal(protectedExport.includes(value), false));

  const openedProtected = await MapCrypto.openProtectedEnvelope(protectedResult.envelope, filePassphrase);
  assert.deepEqual(openedProtected.record, envelope);
  await assert.rejects(
    MapCrypto.openProtectedEnvelope(protectedResult.envelope, "wrong passphrase"),
    /incorrect or the protected map is damaged/
  );

  const resavedProtected = await MapCrypto.protectEnvelope(openedProtected.record, openedProtected.key, openedProtected.salt);
  assert.notEqual(resavedProtected.payload.iv, protectedResult.envelope.payload.iv);
  assert.deepEqual((await MapCrypto.openProtectedEnvelope(resavedProtected, filePassphrase)).record, envelope);

  const secondPayload = await MapCrypto.encryptPayload(dataKey, payloadObject);
  assert.notEqual(secondPayload.iv, payload.iv);
  assert.notEqual(secondPayload.data, payload.data);

  assert.throws(() => MapCrypto.validateEnvelope({ ...envelope, magic: "NOT-GPASS3" }));
  assert.equal(MapCrypto.isLegacyEncrypted({ type: MapCrypto.TYPE, version: 1, unlockMethods: envelope.unlockMethods, payload }), true);
  assert.equal(MapCrypto.restoreLegacyRows({ entries: payloadObject.entries }).length, 1);

  console.log("Gen 3 map encryption tests passed.");
})().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
