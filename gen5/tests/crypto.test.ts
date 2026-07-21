import test from "node:test";
import assert from "node:assert/strict";
import { constantTimeEqual, decryptAesGcm, encryptAesGcm, importAesKey } from "../src/crypto.js";

test("AES-256-GCM matches the NIST zero-key vector", async () => {
  const key = await importAesKey(new Uint8Array(32), ["encrypt", "decrypt"]);
  const plaintext = new Uint8Array(16);
  const iv = new Uint8Array(12);
  const result = await encryptAesGcm(key, plaintext, new Uint8Array(), iv);
  assert.equal(Buffer.from(result.ciphertext).toString("hex"), "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919");
  assert.deepEqual(await decryptAesGcm(key, iv, result.ciphertext, new Uint8Array()), plaintext);
  result.ciphertext[0] ^= 1;
  await assert.rejects(() => decryptAesGcm(key, iv, result.ciphertext, new Uint8Array()));
});

test("constant-time comparison handles equal, unequal, and unequal-length values", () => {
  assert.equal(constantTimeEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 2)), true);
  assert.equal(constantTimeEqual(Uint8Array.of(1, 2), Uint8Array.of(1, 3)), false);
  assert.equal(constantTimeEqual(Uint8Array.of(1), Uint8Array.of(1, 0)), false);
  assert.equal(constantTimeEqual(new Uint8Array(), new Uint8Array()), true);
});
