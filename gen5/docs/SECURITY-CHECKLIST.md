# Release Security Checklist

## Build and supply chain

- [ ] Use `npm ci`, never an unlocked install, in a clean runner.
- [ ] Review every `package-lock.json` change and verify npm provenance where available.
- [ ] Run `npm audit`, dependency-license review and malware scanning; treat findings contextually.
- [ ] Run `npm run verify` and all repository regression tests.
- [ ] Confirm `dist/app.js` is reproducible from the tagged source and lockfile.
- [ ] Recalculate and update the script SHA-384 SRI value after every bundle change.
- [ ] Confirm there are no source maps, external runtime scripts, inline handlers, `eval`, dynamic `Function`, or HTML string sinks.
- [ ] Sign the release/tag and retain build hashes.

## Deployment

- [ ] Deploy Gen 5 on a dedicated HTTPS origin where all headers in `security-headers.conf` are enforced.
- [ ] Verify CSP and Trusted Types in enforcement mode, not report-only.
- [ ] Verify COOP `same-origin`, COEP `require-corp`, CORP `same-origin`, frame denial and no-referrer.
- [ ] Enable HSTS only after every subdomain is HTTPS-ready; add `preload` only after meeting preload requirements.
- [ ] Serve JavaScript as `text/javascript`, JSON manifests correctly, and `nosniff` all responses.
- [ ] Confirm service-worker scope is `/gen5/` and it caches only public static assets.
- [ ] Confirm no analytics, telemetry, crash reporter, CSP report body, or logs receive secret-bearing values.

## Functional security

- [ ] First use cannot generate before passkey-protected setup finishes.
- [ ] Unlock rejects cancelled UV, wrong credential, missing PRF, wrong origin/challenge and corrupted ciphertext.
- [ ] App locks on timeout, hidden, blur, freeze, pagehide, unload and sleep drift.
- [ ] Password/master fields and QR canvases clear on lock.
- [ ] Clipboard clears after timeout or warns clearly when it cannot.
- [ ] A second passkey can unlock before the first is removed.
- [ ] Last-passkey removal is rejected.
- [ ] Backup export/import works using a different passphrase; wrong passwords and bit flips fail closed.
- [ ] Legacy migration preserves the old record on every failure and deletes it only after the new atomic commit.
- [ ] Every supported Gen 4 input vector produces the identical Gen 5 `GPIDV2` password on current Chrome, Edge, Firefox, and Safari where WebAuthn PRF is supported.

## User guidance

- [ ] Explain that Windows Hello PIN may satisfy user verification when biometrics are unavailable.
- [ ] Warn that privileged extensions, malware, devtools, screen capture and clipboard history defeat browser-level controls.
- [ ] Require a tested backup before destructive credential removal.
- [ ] Show the `GP4-GPIDV2` algorithm version and explain that Website IDs are trimmed/lowercased but not Unicode-normalized.
