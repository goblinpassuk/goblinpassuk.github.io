# Gen 5.0 Encryption and Generation Specification

All integers are unsigned. All randomness comes exclusively from `crypto.getRandomValues`. Binary JSON fields use unpadded base64url. JSON used as AEAD metadata is recursively key-sorted canonical JSON encoded as UTF-8.

## Vault format

- Format: `goblinpass-vault`, schema `2`.
- Vault ID: 32 random bytes.
- Generator profile salt: 32 random bytes.
- Vault data-encryption key (DEK): 32 random bytes.
- Payload encryption: AES-256-GCM, random 12-byte IV, 128-bit tag.
- Payload AAD domain: `GP5-PAYLOAD-1 NUL canonical(metadata)`.
- Authenticated payload metadata: format, schema, vault ID, profile salt, creation time, purpose.
- Payload: format identifier, schema, base64url master bytes, random payload ID.

## Per-passkey DEK wrapping

For every passkey:

1. Generate independent 32-byte PRF input and 32-byte HKDF salt.
2. Evaluate WebAuthn `prf` after required user verification.
3. HKDF-SHA-256 with PRF output as input key material, the credential HKDF salt, and info `GoblinPass/v5/passkey-key-wrap/AES-256-GCM` produces a non-extractable AES-256-GCM KEK.
4. Encrypt the DEK with a fresh 12-byte IV.
5. AAD domain `GP5-WRAP-1` authenticates the vault ID, wrapper ID, credential ID, label, transports, both salts, creation/last-use values and purpose.

Each passkey can independently unwrap the same DEK. Removing a wrapper does not require payload re-encryption. Rotating the DEK requires decrypting and re-encrypting the payload plus every wrapper in one atomic transaction.

## Generator root derivation

- Master password input: NFKC-normalized UTF-8 bytes.
- Argon2id version: `0x13`.
- Salt: 32-byte stable profile salt.
- Memory: 65,536 KiB.
- Iterations: 3.
- Parallelism: 1.
- Output: 32 bytes.
- Output is immediately imported as a non-extractable HMAC-SHA-256 key and the byte array is wiped.

## Deterministic generation `GP5-PWD-1`

1. Normalize Website ID with NFKC, trim, and lowercase; encode UTF-8.
2. Canonically serialize version, normalized site, counter and ordered selected character sets.
3. Generate 32-byte blocks with HMAC-SHA-256(generator root, recipe || uint32be(block counter)).
4. Select characters with 32-bit rejection sampling, avoiding modulo bias.
5. Emit one character from every selected set, fill from the combined alphabet, then perform a deterministic Fisher–Yates shuffle using the same stream.
6. Supported lengths are 12–64 and counters 1–999,999.

### Cryptographic vector

```text
Version:       GP5-PWD-1
Master:        Tr0ub4dor&correct-horse
Profile salt:  AA...Af (base64url of bytes 00 through 1f)
Website ID:    éxample.com (equivalent to e + combining acute)
Counter:       7
Length:        24
Sets:          lower, upper, numbers, %!@#$_-
Output:        SbWU#QfyhmsI51r!mT5WhM@S
```

This version is intentionally incompatible with earlier generators. Existing passwords must continue using their recorded algorithm version until deliberately rotated.

## Recovery backup `GPB1`

- Plaintext: master bytes, 32-byte profile salt and generator version.
- KDF: same Argon2id profile, independent 32-byte random salt.
- Encryption: AES-256-GCM with random 12-byte IV and 128-bit tag.
- AAD domain: `GP5-BACKUP-1` authenticating format, schema, full KDF parameters, creation time and purpose.
- File encoding: ASCII `GPB1.` followed by base64url canonical JSON.
- QR framing: `GPBQ1/<random-set-id>/<part>/<total>/<chunk>`. Integrity is verified by the final AEAD decryption; incomplete or mixed sets are rejected before KDF work.

## Constant-time and erasure statement

Web Crypto implementations are used for AES-GCM, HKDF, HMAC and SHA-256. Application equality uses fixed-work byte comparison. Argon2id is algorithmically side-channel resistant. Neither ECMAScript nor a JIT/garbage-collected browser provides guarantees of constant-time execution, `CryptoKey` destruction, or physical-memory erasure. The implementation overwrites owned byte arrays and drops non-extractable key references; it makes no stronger claim.
