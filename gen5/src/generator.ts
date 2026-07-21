import { deriveArgon2id, fromBase64url, importHmacKey, utf8, wipe } from "./crypto.js";
import type { GeneratorOptions } from "./types.js";

const VERSION = "GP5-PWD-1";
const SETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  numbers: "0123456789",
  symbols: "%!@#$_-"
} as const;

export class GeneratorSession {
  #rootKey: CryptoKey | null;
  private constructor(rootKey: CryptoKey) { this.#rootKey = rootKey; }

  static async create(masterPassword: Uint8Array, profileSaltBase64url: string): Promise<GeneratorSession> {
    const profileSalt = fromBase64url(profileSaltBase64url);
    let hardened: Uint8Array | undefined;
    try {
      hardened = await deriveArgon2id(masterPassword, profileSalt);
      return new GeneratorSession(await importHmacKey(hardened));
    } finally {
      wipe(masterPassword, profileSalt, hardened);
    }
  }

  async generate(siteId: string, options: GeneratorOptions): Promise<string> {
    if (!this.#rootKey) throw new DOMException("Generator session is locked.", "InvalidStateError");
    const normalizedSite = siteId.normalize("NFKC").trim().toLowerCase();
    const siteBytes = utf8(normalizedSite);
    if (!normalizedSite || siteBytes.length > 512) {
      wipe(siteBytes);
      throw new Error("Website ID must contain 1–512 UTF-8 bytes.");
    }
    wipe(siteBytes);
    const length = Math.trunc(options.length);
    const counter = Math.trunc(options.counter);
    if (length < 12 || length > 64 || counter < 1 || counter > 999_999) throw new RangeError("Invalid password options.");
    const selected = [
      options.lower ? SETS.lower : "", options.upper ? SETS.upper : "",
      options.numbers ? SETS.numbers : "", options.symbols ? SETS.symbols : ""
    ].filter(Boolean);
    if (selected.length === 0 || length < selected.length) throw new Error("Select a valid character set.");
    const alphabet = selected.join("");
    const recipe = utf8(JSON.stringify({ v: VERSION, site: normalizedSite, counter, sets: selected }));
    const stream = new DeterministicStream(this.#rootKey, recipe);
    try {
      const characters: string[] = [];
      for (const set of selected) characters.push(set[await stream.index(set.length)]!);
      while (characters.length < length) characters.push(alphabet[await stream.index(alphabet.length)]!);
      for (let index = characters.length - 1; index > 0; index -= 1) {
        const swap = await stream.index(index + 1);
        [characters[index], characters[swap]] = [characters[swap]!, characters[index]!];
      }
      return characters.join("");
    } finally {
      wipe(recipe);
      stream.destroy();
    }
  }

  destroy(): void { this.#rootKey = null; }
}

class DeterministicStream {
  #key: CryptoKey | null;
  #context: Uint8Array;
  #block = new Uint8Array(0);
  #offset = 0;
  #counter = 0;
  constructor(key: CryptoKey, context: Uint8Array) { this.#key = key; this.#context = context.slice(); }

  async #refill(): Promise<void> {
    if (!this.#key) throw new Error("Destroyed stream.");
    const input = new Uint8Array(this.#context.length + 4);
    input.set(this.#context);
    new DataView(input.buffer).setUint32(this.#context.length, this.#counter, false);
    this.#counter += 1;
    wipe(this.#block);
    this.#block = new Uint8Array(await crypto.subtle.sign("HMAC", this.#key, input));
    this.#offset = 0;
    wipe(input);
  }

  async #uint32(): Promise<number> {
    if (this.#offset + 4 > this.#block.length) await this.#refill();
    const value = new DataView(this.#block.buffer, this.#block.byteOffset + this.#offset, 4).getUint32(0, false);
    this.#offset += 4;
    return value;
  }

  async index(range: number): Promise<number> {
    if (!Number.isSafeInteger(range) || range < 1 || range > 0xffff) throw new RangeError("Invalid deterministic range.");
    const limit = 0x1_0000_0000 - (0x1_0000_0000 % range);
    for (;;) {
      const candidate = await this.#uint32();
      if (candidate < limit) return candidate % range;
    }
  }

  destroy(): void { wipe(this.#context, this.#block); this.#key = null; this.#counter = 0; this.#offset = 0; }
}
