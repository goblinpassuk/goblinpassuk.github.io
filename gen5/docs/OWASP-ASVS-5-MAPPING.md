# OWASP ASVS 5.0 Mapping

This is an applicability mapping, not a certification. Gen 5 is a local static web application with no server account, authorization layer, API, uploaded server content, or server session. Controls requiring deployment headers are only satisfied when the host applies `security-headers.conf`.

| ASVS 5.0 area | Applicability and implementation | Status |
|---|---|---|
| V1 Encoding and Sanitization | Text is assigned through `textContent`/form values; no application HTML sinks; canonical structured encoding for AEAD | Implemented |
| V2 Validation and Business Logic | Bounded lengths/counters, strict schemas, KDF parameter allowlist, base64url validation, one-vault import rule | Implemented |
| V3 Web Frontend Security | Strict CSP, Trusted Types, SRI, framing denial, COOP/COEP/CORP, Permissions Policy, no-referrer, lifecycle clearing | Host-dependent |
| V4 API and Web Service | No remote API or server data flow | Not applicable |
| V5 File Handling | Backup import size/type/format validation; no server upload; QR framing validation | Implemented |
| V6 Authentication | WebAuthn resident credential, UV required, PRF required, exact credential and client-data checks | Implemented within local-app model |
| V7 Session Management | No server session; short local cryptographic session with comprehensive lifecycle lock | Implemented |
| V8 Authorization | Single local user, no protected server resources or roles | Not applicable |
| V9 Self-contained Tokens | No bearer/session tokens | Not applicable |
| V10 OAuth and OIDC | Not used | Not applicable |
| V11 Cryptography | Web Crypto AES-256-GCM/HKDF/HMAC, Argon2id, 256-bit salts, 96-bit IVs, domain/key separation, authenticated metadata | Implemented; independent review required |
| V12 Secure Communication | HTTPS-only WebAuthn, HSTS recommendation, no outbound secret traffic | Host-dependent |
| V13 Configuration | Locked dependency versions, reproducible build expectations, restrictive policy file | Partially host/CI-dependent |
| V14 Data Protection | Encrypted IndexedDB, no generated-password storage, short-lived secrets, clipboard controls, no telemetry | Implemented with documented platform limits |
| V15 Secure Coding and Architecture | Explicit threat model/trust boundaries, fail-closed design, atomic storage and migrations | Implemented |
| V16 Security Logging and Error Handling | Minimal user-facing errors; no secret logging. No remote audit log by design | Implemented / audit logging not applicable |
| V17 WebRTC | Not used and denied by feature policy where applicable | Not applicable |

## Selected requirement-level mapping

Identifiers are pinned to ASVS 5.0.0. This is the subset most directly applicable to the local browser security boundary; it does not turn this document into a certification.

| ASVS identifier | Evidence | Result |
|---|---|---|
| v5.0.0-3.1.1, 3.7.5 | `webAuthnSupport()` documents and blocks unsupported secure-context, UV, and PRF configurations | Pass |
| v5.0.0-3.2.2, 3.2.3 | DOM output uses `textContent`, form values, explicit module scope, and Trusted Types; no application HTML sink | Pass |
| v5.0.0-3.4.1, 3.4.3-3.4.6, 3.4.8 | `_headers` supplies HSTS, CSP, nosniff, no-referrer, frame denial, and COOP | Deployment gate |
| v5.0.0-3.4.7 | No remote CSP reporting endpoint is configured because the app intentionally sends no telemetry | Documented deviation |
| v5.0.0-3.5.4 | Architecture requires Gen 5 to be the only application on its dedicated hostname | Deployment gate |
| v5.0.0-3.5.6, 3.5.7 | No JSONP and no sensitive script-resource responses | Pass |
| v5.0.0-3.5.8 | CORP `same-origin` and COEP `require-corp` | Deployment gate |
| v5.0.0-3.6.1 | No externally hosted runtime resource; bundled script has SRI and exact dependency versions | Pass |
| v5.0.0-3.7.4 | HSTS preload is recommended only after the dedicated parent domain is operationally ready | Not yet claimed |
| v5.0.0-11.1.1-11.1.4 | Encryption specification inventories keys, purposes, lifecycle, versions, and migration boundaries | Pass; ongoing review required |
| v5.0.0-11.2.1-11.2.3, 11.2.5 | Web Crypto plus pinned Argon2id implementation, versioned formats, 256-bit keys, fail-closed AEAD | Pass; independent audit required |
| v5.0.0-11.2.4 | Fixed-work comparisons and Web Crypto are used, but ECMAScript/JIT cannot guarantee constant-time execution | Platform-limited partial |
| v5.0.0-11.3.2-11.3.4 | AES-256-GCM only, authenticated metadata, fresh 96-bit IV per operation | Pass |
| v5.0.0-11.4.1, 11.4.4 | SHA-256/HMAC/HKDF and Argon2id with fixed reviewed parameters | Pass |
| v5.0.0-11.5.1 | All security randomness uses Web Crypto and provides at least 128 bits of entropy | Pass |
| v5.0.0-11.7.2 | Minimal plaintext lifetime, owned-buffer wiping, non-extractable keys, lifecycle lock | Best effort pass with GC limitation |
| v5.0.0-14.1.1, 14.1.2 | Threat model identifies sensitive assets and their protection/retention requirements | Pass |
| v5.0.0-14.2.3, 14.2.4, 14.2.6, 14.2.7 | No trackers or secret network flow; minimal exposure; generated passwords are not retained | Pass |
| v5.0.0-14.3.1 | UI secrets and application byte buffers are cleared on lock/lifecycle events | Best effort pass with GC limitation |
| v5.0.0-14.3.2 | HTTP responses contain no dynamic secrets; static responses are revalidated; secrets exist only in local API data and user exports | Pass for this architecture |
| v5.0.0-14.3.3 | IndexedDB intentionally contains an authenticated encrypted master-password vault; plaintext and generated passwords are prohibited | Documented product-model deviation |

Evidence is in `src/`, `tests/`, the other documents in this directory, `_headers`, and `security-headers.conf`. Runtime header evidence must still be collected from the production origin.
