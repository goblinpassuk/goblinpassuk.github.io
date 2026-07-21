import { decodeUtf8, sha256, utf8, wipe } from "./crypto.js";
import type { GeneratorOptions } from "./types.js";

export const GENERATOR_VERSION = "GP4-GPIDV2" as const;

const CHARACTER_SETS = [
  { key: "lower", chars: "abcdefghijklmnopqrstuvwxyz" },
  { key: "upper", chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZ" },
  { key: "nums", chars: "0123456789" },
  { key: "symbols", chars: "%!@#$_-" }
] as const;

type CharacterSet = (typeof CHARACTER_SETS)[number];

async function sha256Hex(value: string): Promise<string> {
  const bytes = utf8(value);
  try {
    const digest = await sha256(bytes);
    try { return Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join(""); }
    finally { wipe(digest); }
  } finally { wipe(bytes); }
}

async function characterFromSet(seed: string, set: CharacterSet, round: number): Promise<string> {
  const hash = await sha256Hex(`${seed}|required|${set.key}|${round}`);
  return set.chars[Number.parseInt(hash.slice(0, 8), 16) % set.chars.length]!;
}

async function deterministicSetOrder(sets: CharacterSet[], seed: string, round: number): Promise<CharacterSet[]> {
  const scored = await Promise.all(sets.map(async set => ({
    value: set,
    score: await sha256Hex(`${seed}|set-order|${round}|${set.key}`)
  })));
  return scored.sort((left, right) => left.score.localeCompare(right.score)).map(item => item.value);
}

async function deterministicShuffle(characters: string[], seed: string): Promise<string> {
  const scored = await Promise.all(characters.map(async (character, index) => ({
    value: character,
    score: await sha256Hex(`${seed}|shuffle|${index}|${character}`)
  })));
  return scored.sort((left, right) => left.score.localeCompare(right.score)).map(item => item.value).join("");
}

export class GeneratorSession {
  #masterPassword: Uint8Array | null;

  private constructor(masterPassword: Uint8Array) {
    this.#masterPassword = masterPassword.slice();
  }

  static create(masterPassword: Uint8Array): GeneratorSession {
    if (masterPassword.length === 0 || masterPassword.length > 4_096) throw new RangeError("Invalid master password length.");
    return new GeneratorSession(masterPassword);
  }

  async generate(siteId: string, options: GeneratorOptions): Promise<string> {
    if (!this.#masterPassword) throw new DOMException("Generator session is locked.", "InvalidStateError");
    const normalizedSite = siteId.trim().toLowerCase();
    const siteBytes = utf8(normalizedSite);
    if (!normalizedSite || siteBytes.length > 512) {
      wipe(siteBytes);
      throw new Error("Website ID must contain 1–512 UTF-8 bytes.");
    }
    wipe(siteBytes);

    const length = Math.trunc(options.length);
    const counter = Math.trunc(options.counter);
    if (length < 8 || length > 64 || counter < 1 || counter > 999) throw new RangeError("Invalid password options.");
    const selectedKeys = [
      options.lower ? "lower" : "",
      options.upper ? "upper" : "",
      options.numbers ? "nums" : "",
      options.symbols ? "symbols" : ""
    ].filter(Boolean);
    const sets = CHARACTER_SETS.filter(set => selectedKeys.includes(set.key));
    if (sets.length === 0) throw new Error("Select at least one password character group.");

    const masterPassword = decodeUtf8(this.#masterPassword);
    const optionKey = sets.map(set => set.key).join(",");
    const seed = `GPIDV2|${normalizedSite}|${counter}|${masterPassword}|${optionKey}`;
    const output: string[] = [];
    const minimumPerSet = Math.max(1, Math.min(2, Math.floor(length / sets.length)));
    for (const set of sets) {
      for (let round = 0; round < minimumPerSet && output.length < length; round += 1) {
        output.push(await characterFromSet(seed, set, round));
      }
    }
    let round = 0;
    while (output.length < length) {
      const orderedSets = await deterministicSetOrder(sets, seed, round);
      for (const set of orderedSets) {
        if (output.length >= length) break;
        output.push(await characterFromSet(seed, set, minimumPerSet + round));
      }
      round += 1;
    }
    return deterministicShuffle(output, seed);
  }

  destroy(): void {
    wipe(this.#masterPassword ?? undefined);
    this.#masterPassword = null;
  }
}
