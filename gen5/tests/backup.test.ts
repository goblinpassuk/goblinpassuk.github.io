import test from "node:test";
import assert from "node:assert/strict";
import { backupQrParts, combineBackupQrParts, createBackup, openBackup } from "../src/backup.js";
import { base64url, utf8 } from "../src/crypto.js";

test("Argon2id backup round-trips and rejects tampering", { timeout: 30_000 }, async () => {
  const payload = {
    format: "goblinpass-recovery-payload" as const,
    schema: 1 as const,
    masterPassword: base64url(utf8("correct horse battery staple")),
    profileSalt: base64url(new Uint8Array(32).fill(7)),
    generatorVersion: "GP4-GPIDV2" as const
  };
  const encoded = await createBackup(payload, utf8("separate backup passphrase 2026"));
  assert.deepEqual(await openBackup(encoded, utf8("separate backup passphrase 2026")), payload);
  const replacement = encoded.endsWith("A") ? "B" : "A";
  await assert.rejects(() => openBackup(encoded.slice(0, -1) + replacement, utf8("separate backup passphrase 2026")));
});

test("multipart backup QR framing rejects missing parts", () => {
  const source = "GPB1." + "A".repeat(1800);
  const parts = backupQrParts(source, 600);
  assert.equal(combineBackupQrParts([...parts].reverse()), source);
  assert.throws(() => combineBackupQrParts(parts.slice(1)));
});
