export const VAULT_FORMAT = "goblinpass-vault" as const;
export const VAULT_SCHEMA = 2 as const;
export const BACKUP_FORMAT = "goblinpass-backup" as const;
export const BACKUP_SCHEMA = 1 as const;

export interface AeadEnvelope {
  algorithm: "AES-256-GCM";
  iv: string;
  ciphertext: string;
}

export interface PasskeyWrap {
  id: string;
  credentialId: string;
  label: string;
  transports: AuthenticatorTransport[];
  prfSalt: string;
  hkdfSalt: string;
  wrappedKey: AeadEnvelope;
  createdAt: string;
  lastUsedAt: string | null;
}

export interface VaultRecordV2 {
  format: typeof VAULT_FORMAT;
  schema: typeof VAULT_SCHEMA;
  revision: number;
  vaultId: string;
  profileSalt: string;
  payload: AeadEnvelope;
  integrity: { algorithm: "HMAC-SHA-256"; tag: string };
  credentials: PasskeyWrap[];
  createdAt: string;
  updatedAt: string;
}

export interface VaultPayload {
  format: "goblinpass-vault-payload";
  schema: 1;
  masterPassword: string;
  payloadId: string;
}

export interface BackupDocument {
  format: typeof BACKUP_FORMAT;
  schema: typeof BACKUP_SCHEMA;
  kdf: {
    name: "Argon2id";
    version: 19;
    memoryKiB: number;
    iterations: number;
    parallelism: number;
    salt: string;
  };
  encryption: AeadEnvelope;
  createdAt: string;
}

export interface BackupPayload {
  format: "goblinpass-recovery-payload";
  schema: 1;
  masterPassword: string;
  profileSalt: string;
  generatorVersion: "GP5-PWD-1";
}

export interface GeneratorOptions {
  length: number;
  counter: number;
  lower: boolean;
  upper: boolean;
  numbers: boolean;
  symbols: boolean;
}

export interface LegacyVaultV1 {
  version: 1;
  credentialId: number[];
  prfSalt: number[];
  kdfSalt: number[];
  iv: number[];
  ciphertext: number[];
  createdAt: string;
}
