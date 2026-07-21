# STRIDE Threat Model

## Assets

Master password, generated passwords, in-memory generator session, vault data key, passkey PRF outputs, recovery payload, backup passphrase, site identifiers, clipboard contents, and the integrity/availability of the deterministic algorithm.

## Adversaries

Remote web attacker, malicious site, network attacker, dependency publisher compromise, malicious/over-privileged extension, local user without OS unlock, thief with copied browser storage, malware with user privileges, attacker with developer-tools access, shoulder surfer, and attacker controlling the entire device.

## STRIDE analysis

| Category | Realistic threats | Controls | Residual risk |
|---|---|---|---|
| Spoofing | Fake GoblinPass origin, lookalike PWA, clickjacked unlock UI, substituted passkey | HTTPS, origin-bound WebAuthn, RP ID, `frame-ancestors 'none'`, COOP, displayed origin guidance, exact credential-ID validation | Users can still approve a lookalike origin; compromised DNS/CA/device defeats origin assurance |
| Tampering | Edited IndexedDB, swapped credential wrappers, altered metadata, service-worker replacement, corrupted backup | AES-GCM authenticated metadata, per-wrapper AAD, schema validation, strict atomic revisions, SRI, CSP, pinned lockfile, backup AEAD | Revision/timestamps are advisory; an attacker can delete or roll back the entire record, causing denial or old-state restoration |
| Repudiation | User disputes passkey addition/deletion/export | Local timestamps and revision counters; explicit ceremonies | No server or trusted audit log exists; non-repudiation is intentionally out of scope |
| Information disclosure | XSS, extension reads DOM/clipboard, process-memory inspection, devtools, Spectre, shoulder surfing, clipboard history, autofill | No secret DOM insertion after setup, Trusted Types, CSP, COOP/COEP, non-extractable keys, short sessions, hidden outputs, clipboard timeout, autocomplete controls, zeroisation attempts | Compromised browser/OS, privileged extensions, devtools after unlock, display observation, and clipboard managers can disclose secrets |
| Denial of service | IndexedDB deletion/corruption, passkey deletion, quota eviction, malicious cache, Argon2 resource exhaustion | Encrypted backup, multiple passkeys, validation before expensive operations, fixed Argon2 parameters, bounded inputs, atomic updates | Local storage is not durable; backups are mandatory for recovery |
| Elevation of privilege | XSS invokes WebAuthn and uses PRF, hostile extension bypasses UI, clickjacking tricks verification | No inline/eval scripts, Trusted Types enforcement, frame blocking, UV required, least Permissions Policy, dependency isolation | User verification does not attest benign JavaScript; same-origin code compromise remains catastrophic |

## Attack-vector register

| Vector | Assessment and mitigation |
|---|---|
| XSS | Highest-impact application threat. Any same-origin script running during unlock can use the PRF result or generated password. The build removes dynamic HTML sinks, inline script, `eval`, external runtime code and enables strict CSP plus Trusted Types. CSP is defense in depth, not a substitute for review. |
| Supply chain | Dependencies are exact-version pinned with a lockfile and bundled locally. No runtime CDN exists. CI should use `npm ci`, verify provenance and review lockfile diffs. Argon2 dependency code requires continued review because its Argon2 path was not covered by the historic independent audit. |
| Clipboard attacks | Other apps/extensions and OS history can read copied passwords. Copy is explicit/gesture-bound, rate-limited, scheduled for conditional clearing, and warns when clearing cannot be verified. OS clipboard history may retain earlier values despite clearing. |
| Memory inspection | Master bytes are short-lived and wiped; generator keys are non-extractable. JS strings, GC copies, browser internals, crash dumps and swapped pages cannot be reliably erased. A process-memory attacker wins after unlock. |
| Browser extensions | Privileged extensions can read DOM, clipboard or alter page behavior and are outside CSP. Recommend a clean browser profile with no untrusted extensions. |
| Replay | 256-bit challenges are fresh for every ceremony and client data is checked for challenge, type, origin and cross-origin state. PRF salts are random and credential-bound. No network assertion session exists to fixate. |
| WebAuthn misuse | UV and resident platform credentials are required; RP ID is explicit; unexpected credential IDs and missing PRF results are rejected; attestation is `none` to reduce fingerprinting. Windows may satisfy UV with PIN rather than biometrics. |
| Timing attacks | Web Crypto handles AES/HMAC/HKDF. Equality checks are algorithmically constant-work. Argon2id reduces password side channels. JavaScript JIT/GC and rejection sampling prevent a strict constant-time claim; observable variation does not expose a practical key-recovery oracle in this local design. |
| Side channels | COOP/COEP reduce cross-origin process sharing and high-resolution cross-origin observation. Power, EM, cache attacks and local performance instrumentation are outside browser control. |
| Offline IndexedDB theft | Stolen data contains AEAD ciphertext and independently wrapped random data keys. Unlock requires a matching passkey PRF. Metadata such as timestamps and credential count remains visible. Deletion and rollback remain possible. |
| Device compromise | Admin/root malware, injected accessibility software, hostile browser binaries or kernel compromise can capture inputs and outputs. No web application control can solve this. |
| Malicious websites | Same-origin policy and origin-bound credentials block direct access. COOP, frame blocking and no-referrer reduce cross-site leaks. Homograph/phishing risk remains human-facing. |
| Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY` are required headers. Meta CSP alone cannot enforce `frame-ancestors`. |
| CSRF | No authenticated server state or cross-origin write endpoint exists. WebAuthn ceremonies are origin-bound. CSRF is effectively not applicable, though clickjacking and same-origin compromise remain. |
| CSP bypasses | No allowlisted third-party hosts, inline scripts, nonces, wildcards, `unsafe-inline`, `unsafe-eval` or dynamic Trusted Types policies. Browser bugs and compromised same-origin assets remain. |
| Spectre-class attacks | Cross-origin isolation headers reduce process-sharing exposure, but cannot eliminate same-process/JIT microarchitectural leakage or a compromised browser. Secrets are retained briefly. |
| Shoulder surfing | Fields default hidden, QR is opt-in, generated output is hidden, and page-hide/blur locks. A visible output or QR can still be photographed. |
| Session fixation | There is no server session. Every unlock derives a fresh in-memory session and lifecycle instance. IndexedDB rollback can restore an older valid local record. |
| Browser autofill leakage | Master/backup inputs use password types and controlled autocomplete values; decrypted master is never placed in an input. Password managers may ignore hints; users should disable save prompts for this origin. |
| Developer tools abuse | Devtools in the active profile can inspect DOM, patch functions and intercept Web Crypto calls. Treat devtools access as device compromise. Production bundles omit source maps. |
| Clipboard history | Clearing the current clipboard does not guarantee removal from Windows clipboard history or cloud clipboard. UI warnings and a no-copy/manual typing option are necessary. |
| Cache persistence | Service worker caches only public immutable application assets, never vault responses or secrets. Old Gen 5 caches are scoped and removed. Browser HTTP caches never contain secret POST responses because none exist. |
| Malicious service worker | A previously compromised worker controls the origin until replaced. Versioned cache, update-on-navigation, SRI and deployment integrity help; users may need to clear site data after an incident. |
| Rollback | A copied older valid vault can be restored because there is no trusted monotonic server counter. Revision control prevents concurrent-tab lost updates, not offline rollback. Display last-updated metadata and rely on recovery discipline. |
| Unicode confusion | For exact Gen 4 compatibility, Website IDs are trimmed and lowercased but are not Unicode-normalized; master-password code points remain unchanged. Visually equivalent Unicode strings can intentionally produce different passwords. Compatibility vectors pin this behavior. |
