import test from "node:test";
import assert from "node:assert/strict";
import { GeneratorSession } from "../src/generator.js";
import { base64url, utf8 } from "../src/crypto.js";

test("GP5 deterministic generator is stable, Unicode-normalized, and policy complete", async () => {
  const profileSalt = base64url(Uint8Array.from({ length: 32 }, (_, index) => index));
  const first = await GeneratorSession.create(utf8("Tr0ub4dor&correct-horse"), profileSalt);
  const second = await GeneratorSession.create(utf8("Tr0ub4dor&correct-horse"), profileSalt);
  const options = { length: 24, counter: 7, lower: true, upper: true, numbers: true, symbols: true };
  const passwordA = await first.generate("éxample.com", options);
  const passwordB = await second.generate("e\u0301xample.com", options);
  assert.equal(passwordA, "SbWU#QfyhmsI51r!mT5WhM@S");
  assert.equal(passwordA, passwordB);
  assert.equal(passwordA.length, 24);
  assert.match(passwordA, /[a-z]/u);
  assert.match(passwordA, /[A-Z]/u);
  assert.match(passwordA, /[0-9]/u);
  assert.match(passwordA, /[%!@#$_-]/u);
  first.destroy();
  second.destroy();
});
