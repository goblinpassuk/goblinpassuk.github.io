import { argon2idAsync } from "@noble/hashes/argon2.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export const ARGON2_BROWSER_PROFILE = Object.freeze({
  version: 19 as const,
  memoryKiB: 65_536,
  iterations: 3,
  parallelism: 1,
  outputBytes: 32
});

export function randomBytes(length: number): Uint8Array {
  if (!Number.isSafeInteger(length) || length < 1 || length > 65_536) throw new RangeError("Invalid random length.");
  return crypto.getRandomValues(new Uint8Array(length));
}

export function utf8(value: string): Uint8Array {
  return encoder.encode(value);
}

export function decodeUtf8(value: BufferSource): string {
  return decoder.decode(value);
}

export function wipe(...values: Array<Uint8Array | undefined>): void {
  for (const value of values) value?.fill(0);
}

export function concat(...values: Uint8Array[]): Uint8Array {
  const length = values.reduce((sum, value) => sum + value.length, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.length;
  }
  return output;
}

export function base64url(value: BufferSource): string {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value as ArrayBuffer);
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function fromBase64url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/u.test(value)) throw new Error("Invalid base64url data.");
  const padding = "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + padding);
  return Uint8Array.from(binary, character => character.charCodeAt(0));
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object") {
    const input = value as Record<string, unknown>;
    const output: Record<string, unknown> = {};
    for (const key of Object.keys(input).sort()) output[key] = canonicalValue(input[key]);
    return output;
  }
  if (typeof value === "number" && !Number.isFinite(value)) throw new TypeError("Non-finite JSON number.");
  return value;
}

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

export function aad(label: string, metadata: unknown): Uint8Array {
  return utf8(`${label}\u0000${canonicalJson(metadata)}`);
}

export function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  let difference = left.length ^ right.length;
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (left[index % Math.max(left.length, 1)] ?? 0) ^ (right[index % Math.max(right.length, 1)] ?? 0);
  }
  return difference === 0;
}

export async function sha256(value: BufferSource): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", value));
}

export async function hkdfKey(
  inputKeyMaterial: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  usages: KeyUsage[]
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey("raw", inputKeyMaterial, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt, info },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    usages
  );
}

export async function hkdfBytes(inputKeyMaterial: Uint8Array, salt: Uint8Array, info: Uint8Array, length = 32): Promise<Uint8Array> {
  const material = await crypto.subtle.importKey("raw", inputKeyMaterial, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info }, material, length * 8
  ));
}

export async function importAesKey(raw: Uint8Array, usages: KeyUsage[]): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, usages);
}

export async function importHmacKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256", length: 256 }, false, ["sign"]);
}

export async function encryptAesGcm(key: CryptoKey, plaintext: Uint8Array, additionalData: Uint8Array, iv = randomBytes(12)) {
  if (iv.length !== 12) throw new Error("AES-GCM IV must be 96 bits.");
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData, tagLength: 128 }, key, plaintext
  ));
  return { iv, ciphertext };
}

export async function decryptAesGcm(
  key: CryptoKey,
  iv: Uint8Array,
  ciphertext: Uint8Array,
  additionalData: Uint8Array
): Promise<Uint8Array> {
  if (iv.length !== 12 || ciphertext.length < 16) throw new Error("Invalid AES-GCM envelope.");
  return new Uint8Array(await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData, tagLength: 128 }, key, ciphertext
  ));
}

export async function deriveArgon2id(password: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
  if (salt.length !== 32) throw new Error("Argon2id salt must be 256 bits.");
  return argon2idAsync(password, salt, {
    t: ARGON2_BROWSER_PROFILE.iterations,
    m: ARGON2_BROWSER_PROFILE.memoryKiB,
    p: ARGON2_BROWSER_PROFILE.parallelism,
    version: ARGON2_BROWSER_PROFILE.version,
    dkLen: ARGON2_BROWSER_PROFILE.outputBytes,
    maxmem: 80 * 1024 * 1024,
    asyncTick: 8
  });
}
