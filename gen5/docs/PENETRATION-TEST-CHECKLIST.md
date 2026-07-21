# Penetration-Test Checklist

## Static and supply-chain review

- Search source and bundle for `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `Function`, dynamic import URLs and inline event handlers.
- Audit every dependency and transitive dependency; compare installed files to registry integrity hashes and provenance.
- Verify no secret, key, PRF result or passphrase appears in logs, exceptions, URLs, DOM attributes, analytics or service-worker caches.
- Inspect bundle for accidentally embedded test secrets or source maps.

## XSS and browser policy

- Inject HTML/JS payloads into Website ID, passkey label, filenames, QR scan/import content, error text and every restored metadata field.
- Attempt DOM clobbering with IDs/names matching application globals.
- Verify Trusted Types blocks all script sinks and CSP reports zero unexpected allowances.
- Frame the app from same-origin and cross-origin pages; verify both CSP `frame-ancestors` and `X-Frame-Options`.
- Test opener/XS-Leak isolation, MIME sniffing, referrer leakage and forbidden feature APIs.
- Test CSP under service-worker control and after an intentionally stale worker/cache.

## WebAuthn

- Use virtual authenticators to test UV false, resident key false, PRF absent, wrong credential ID and duplicated credentials.
- Replay prior assertions and mutate challenge, origin, type and `crossOrigin` client-data fields.
- Test cancellation and timeout at registration, unlock, migration and second-passkey creation.
- Verify concurrent tabs cannot overwrite a newer vault revision.
- Remove the passkey in OS settings and verify failure is clear and recovery remains possible.
- Confirm cross-origin iframes cannot invoke the ceremony under Permissions Policy.

## Cryptography and storage

- Flip every field and ciphertext byte independently; all authenticated changes must fail closed.
- Swap payloads/wrappers between vault IDs and swap wrappers within records.
- Truncate, extend and non-canonically encode base64url fields.
- Fuzz schema, revision, lengths, timestamps, KDF parameters, JSON depth and Unicode.
- Verify IVs/salts/IDs never repeat over at least one million generated samples in instrumented tests.
- Compare AES, HKDF, HMAC, Argon2id and generator results with independent implementations and published vectors.
- Profile Argon2 memory/time and attempt resource exhaustion with hostile backups; parameter validation must happen before KDF execution.
- Restore an older valid IndexedDB snapshot and document rollback behavior.

## Lifecycle, memory and UI

- Inspect heap snapshots before unlock, during generation and after every lock trigger.
- Confirm owned arrays are overwritten and key references become unreachable; document unavoidable JS string/GC copies.
- Trigger blur, hide, freeze, bfcache, pagehide, unload, crash, suspend/resume, OS lock and long sleep.
- Attempt generation/copy/backup from stale event handlers after lock.
- Test rapid copy, clipboard replacement before timeout, denied clipboard read/write and OS clipboard history.
- Test shoulder-surfing defaults, focus restoration, password-manager save prompts and browser autofill behavior.
- Test screen reader/accessibility APIs for unintended secret exposure.

## Recovery and destructive actions

- Test wrong backup passphrase, tampered header/ciphertext, mixed QR sets, duplicate/missing/reordered frames and huge files.
- Confirm backup import cannot overwrite an existing vault.
- Confirm vault removal requires explicit confirmation and does not claim to delete the OS passkey.
- Complete full disaster recovery on a clean browser profile and compare deterministic vectors.
