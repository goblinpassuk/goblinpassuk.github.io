import qrcode from "qrcode-generator";
import {
  ARGON2_BROWSER_PROFILE, aad, base64url, canonicalJson, decodeUtf8, decryptAesGcm,
  deriveArgon2id, encryptAesGcm, fromBase64url, importAesKey, randomBytes, utf8, wipe
} from "./crypto.js";
import { BACKUP_FORMAT, BACKUP_SCHEMA, type BackupDocument, type BackupPayload } from "./types.js";

const BACKUP_PREFIX = "GPB1.";

function backupMetadata(document: Omit<BackupDocument, "encryption">) {
  return { ...document, purpose: "encrypted-recovery-backup" };
}

export async function createBackup(payload: BackupPayload, passphrase: Uint8Array): Promise<string> {
  if (passphrase.length < 16) throw new Error("Backup passphrase must contain at least 16 UTF-8 bytes.");
  const salt = randomBytes(32);
  let derived: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    derived = await deriveArgon2id(passphrase, salt);
    const key = await importAesKey(derived, ["encrypt"]);
    const header = {
      format: BACKUP_FORMAT, schema: BACKUP_SCHEMA,
      kdf: {
        name: "Argon2id" as const, version: ARGON2_BROWSER_PROFILE.version,
        memoryKiB: ARGON2_BROWSER_PROFILE.memoryKiB, iterations: ARGON2_BROWSER_PROFILE.iterations,
        parallelism: ARGON2_BROWSER_PROFILE.parallelism, salt: base64url(salt)
      },
      createdAt: new Date().toISOString()
    };
    plaintext = utf8(canonicalJson(payload));
    const encrypted = await encryptAesGcm(key, plaintext, aad("GP5-BACKUP-1", backupMetadata(header)));
    const document: BackupDocument = {
      ...header,
      encryption: { algorithm: "AES-256-GCM", iv: base64url(encrypted.iv), ciphertext: base64url(encrypted.ciphertext) }
    };
    return BACKUP_PREFIX + base64url(utf8(canonicalJson(document)));
  } finally {
    wipe(passphrase, salt, derived, plaintext);
  }
}

export async function openBackup(encoded: string, passphrase: Uint8Array): Promise<BackupPayload> {
  if (!encoded.startsWith(BACKUP_PREFIX)) throw new DOMException("Unknown backup format.", "DataError");
  if (encoded.length > 1_000_000) throw new DOMException("Backup is too large.", "DataError");
  const documentBytes = fromBase64url(encoded.slice(BACKUP_PREFIX.length));
  let document: BackupDocument;
  try { document = JSON.parse(decodeUtf8(documentBytes)) as BackupDocument; }
  finally { wipe(documentBytes); }
  if (!document || typeof document !== "object" || document.format !== BACKUP_FORMAT || document.schema !== BACKUP_SCHEMA ||
      !document.kdf || document.kdf.name !== "Argon2id" ||
      document.kdf.version !== 19 || document.kdf.memoryKiB !== ARGON2_BROWSER_PROFILE.memoryKiB ||
      document.kdf.iterations !== ARGON2_BROWSER_PROFILE.iterations || document.kdf.parallelism !== ARGON2_BROWSER_PROFILE.parallelism ||
      document.encryption?.algorithm !== "AES-256-GCM") {
    throw new DOMException("Unsupported or weakened backup parameters.", "DataError");
  }
  const salt = fromBase64url(document.kdf.salt);
  const iv = fromBase64url(document.encryption.iv);
  const ciphertext = fromBase64url(document.encryption.ciphertext);
  if (salt.length !== 32 || iv.length !== 12 || ciphertext.length < 16 || ciphertext.length > 65_536) {
    wipe(salt, iv, ciphertext);
    throw new DOMException("Backup envelope is invalid.", "DataError");
  }
  const { encryption: _ignored, ...header } = document;
  let derived: Uint8Array | undefined;
  let plaintext: Uint8Array | undefined;
  try {
    derived = await deriveArgon2id(passphrase, salt);
    const key = await importAesKey(derived, ["decrypt"]);
    plaintext = await decryptAesGcm(
      key, iv, ciphertext,
      aad("GP5-BACKUP-1", backupMetadata(header))
    );
    const payload = JSON.parse(decodeUtf8(plaintext)) as BackupPayload;
    if (!payload || typeof payload.profileSalt !== "string" || typeof payload.masterPassword !== "string") {
      throw new DOMException("Backup payload is invalid.", "DataError");
    }
    const profileSalt = fromBase64url(payload.profileSalt);
    const masterPassword = fromBase64url(payload.masterPassword);
    try {
      if (payload.format !== "goblinpass-recovery-payload" || payload.schema !== 1 || payload.generatorVersion !== "GP5-PWD-1" ||
          profileSalt.length !== 32 || masterPassword.length < 12 || masterPassword.length > 4_096) {
        throw new DOMException("Backup payload is invalid.", "DataError");
      }
    } finally { wipe(profileSalt, masterPassword); }
    return payload;
  } finally {
    wipe(passphrase, salt, iv, ciphertext, derived, plaintext);
  }
}

export function downloadBackup(encoded: string, filename = "goblinpass-recovery.gpb"): void {
  const blob = new Blob([encoded], { type: "application/vnd.goblinpass.backup" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function backupQrParts(encoded: string, chunkLength = 600): string[] {
  if (chunkLength < 128 || chunkLength > 900) throw new RangeError("Invalid QR chunk size.");
  const id = base64url(randomBytes(8));
  const chunks = Array.from({ length: Math.ceil(encoded.length / chunkLength) }, (_, index) => encoded.slice(index * chunkLength, (index + 1) * chunkLength));
  if (chunks.length > 99) throw new Error("Backup is too large for QR export.");
  return chunks.map((chunk, index) => `GPBQ1/${id}/${index + 1}/${chunks.length}/${chunk}`);
}

export function drawBackupQr(canvas: HTMLCanvasElement, part: string): void {
  const qr = qrcode(0, "Q");
  qr.addData(part, "Byte");
  qr.make();
  const count = qr.getModuleCount();
  const quiet = 4;
  const size = count + quiet * 2;
  canvas.width = size;
  canvas.height = size;
  const context = canvas.getContext("2d", { alpha: false });
  if (!context) throw new Error("Canvas is unavailable.");
  context.fillStyle = "#fff";
  context.fillRect(0, 0, size, size);
  context.fillStyle = "#000";
  for (let row = 0; row < count; row += 1) for (let column = 0; column < count; column += 1) {
    if (qr.isDark(row, column)) context.fillRect(column + quiet, row + quiet, 1, 1);
  }
}

export function combineBackupQrParts(parts: string[]): string {
  const parsed = parts.map(part => {
    const match = /^GPBQ1\/([A-Za-z0-9_-]+)\/(\d{1,2})\/(\d{1,2})\/(.+)$/u.exec(part);
    if (!match) throw new DOMException("Invalid backup QR part.", "DataError");
    return { id: match[1]!, index: Number(match[2]), total: Number(match[3]), chunk: match[4]! };
  });
  const first = parsed[0];
  if (!first || parsed.some(item => item.id !== first.id || item.total !== first.total) || parsed.length !== first.total) {
    throw new DOMException("Backup QR set is incomplete or mixed.", "DataError");
  }
  parsed.sort((left, right) => left.index - right.index);
  if (parsed.some((item, index) => item.index !== index + 1)) throw new DOMException("Backup QR parts are duplicated or missing.", "DataError");
  return parsed.map(item => item.chunk).join("");
}
