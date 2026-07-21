import test from "node:test";
import assert from "node:assert/strict";
import { GENERATOR_VERSION, GeneratorSession } from "../src/generator.js";
import { utf8 } from "../src/crypto.js";

test("Gen 5 exactly reproduces Gen 4 GPIDV2 password vectors", async () => {
  assert.equal(GENERATOR_VERSION, "GP4-GPIDV2");
  const session = GeneratorSession.create(utf8("Tr0ub4dor&correct-horse"));
  const allSets = { length: 24, counter: 7, lower: true, upper: true, numbers: true, symbols: true };
  assert.equal(await session.generate("Example.com", allSets), "d46hD@k6T!0w3!#!qEpP2K-S");
  assert.equal(await session.generate("  EXAMPLE.COM  ", allSets), "d46hD@k6T!0w3!#!qEpP2K-S");
  session.destroy();
});

test("Gen 4 compatibility covers every character-set combination", async () => {
  const session = GeneratorSession.create(utf8("Master Password 123"));
  const base = { length: 8, counter: 999, lower: false, upper: false, numbers: false, symbols: false };
  assert.equal(await session.generate("Sub.Domain", { ...base, lower: true }), "kawrqkri");
  assert.equal(await session.generate("Sub.Domain", { ...base, upper: true, numbers: true }), "5B2M7GN6");
  assert.equal(await session.generate("Sub.Domain", { ...base, symbols: true }), "@_%$$%$@");
  assert.equal(await session.generate("Sub.Domain", { ...base, lower: true, upper: true, numbers: true }), "9g3SDg8a");
  session.destroy();
});

test("master password bytes remain case and Unicode sensitive", async () => {
  const session = GeneratorSession.create(utf8("päss Wörd"));
  assert.equal(await session.generate("  ÉXAMPLE.com  ", {
    length: 16, counter: 1, lower: true, upper: true, numbers: true, symbols: true
  }), "n#r_$_S730U6IToj");
  session.destroy();
});
