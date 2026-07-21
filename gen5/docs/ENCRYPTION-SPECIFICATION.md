# Gen 5.0 Encryption and Generation Specification

All integers are unsigned. All randomness comes exclusively from `crypto.getRandomValues`. Binary JSON fields use unpadded base64url. JSON used as authenticated metadata is recursively key-sorted canonical JSON encoded as UTF-8.

## Vault format

- Format: `goblinpass-vault`, schema `2`.
- Vault ID: 32 random bytes.
- Record-integrity salt: 32 random bytes in the `profileSalt` schema field.
- Vault data-encryption key (DEK): 32 random bytes.
- Payload encryption: AES-256-GCM, random 12-byte IV, 128-bit tag.
- Payload AAD domain: `GP5-PAYLOAD-1 NUL canonical(metadata)`.
- Authenticated payload metadata: format, schema, vault ID, integrity salt, creation time, and purpose.
- Payload: format identifier, schema, base64url master bytes, and random payload ID.

## Per-passkey DEK wrapping

For every passkey:

1. Generate independent 32-byte PRF input and 32-byte HKDF salt.
2. Evaluate WebAuthn `prf` after required user verification.
3. HKDF-SHA-256 with PRF output as input key material, the credential HKDF salt, and info `GoblinPass/v5/passkey-key-wrap/AES-256-GCM` produces a non-extractable AES-256-GCM KEK.
4. Encrypt the DEK with a fresh 12-byte IV.
5. AAD domain `GP5-WRAP-1` authenticates the vault ID, wrapper ID, credential ID, label, transports, both salts, creation/last-use values, and purpose.

Each passkey can independently unwrap the same DEK. Removing a wrapper does not require payload re-encryption. Wrapper updates and record-integrity updates commit atomically.

## Generator compatibility and memory

Exact Gen 4 output compatibility requires the original master-password value because `GPIDV2` hashes it directly into every site recipe. While unlocked, Gen 5 retains one owned UTF-8 master-password buffer in memory. It never writes that plaintext to storage. Locking overwrites the buffer and drops its reference.

Replacing the master value with an Argon2id or HMAC-derived root would change every generated password. Argon2id is therefore used for encrypted recovery backups, where it strengthens passphrases without changing deterministic site passwords.

## Deterministic generation `GP4-GPIDV2`

1. Trim and lowercase the Website ID exactly as Gen 4 does. Do not Unicode-normalize either input.
2. Preserve selected-set order: `lower`, `upper`, `nums`, `symbols`; construct the comma-separated option key.
3. Construct `GPIDV2|<site>|<counter>|<master>|<option-key>`.
4. Emit up to two required characters per selected set. Each index is the first 32 bits of SHA-256 over `<seed>|required|<set-key>|<round>`, reduced modulo the set length.
5. Fill remaining positions by sorting selected sets on SHA-256 of `<seed>|set-order|<round>|<set-key>` and applying the same required-character rule.
6. Shuffle by assigning each character the SHA-256 score of `<seed>|shuffle|<index>|<character>` and sorting by that score.
7. Supported lengths are 8–64 and counters 1–999, exactly matching Gen 4.

### Compatibility vector

```text
Version:       GP4-GPIDV2
Master:        Tr0ub4dor&correct-horse
Website ID:    Example.com
Counter:       7
Length:        24
Sets:          lower, upper, numbers, %!@#$_-
Output:        d46hD@k6T!0w3!#!qEpP2K-S
```

This vector is pinned from the original Gen 4 implementation. Identical supported inputs must produce identical Gen 4 and Gen 5 passwords; a mismatch is a release-blocking defect.

## Recovery backup `GPB1`

- Plaintext: master bytes, 32-byte record-integrity salt, and generator version.
- KDF: Argon2id version `0x13`, 65,536 KiB, three iterations, parallelism one, 32-byte output, and an independent 32-byte random salt.
- Encryption: AES-256-GCM with random 12-byte IV and 128-bit tag.
- AAD domain: `GP5-BACKUP-1` authenticating format, schema, full KDF parameters, creation time, and purpose.
- File encoding: ASCII `GPB1.` followed by base64url canonical JSON.
- QR framing: `GPBQ1/<random-set-id>/<part>/<total>/<chunk>`. Final AEAD decryption verifies integrity; incomplete or mixed sets are rejected before KDF work.

## Constant-time and erasure statement

Web Crypto implementations are used for AES-GCM, HKDF, HMAC, and SHA-256. Application equality uses fixed-work byte comparison. Neither ECMAScript nor a JIT/garbage-collected browser guarantees constant-time execution, `CryptoKey` destruction, or physical-memory erasure. The implementation overwrites owned byte arrays and drops non-extractable key references; it makes no stronger claim.
