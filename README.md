# GoblinPass

GoblinPass is a local-first password tools website built around stateless password generation, YubiKey/security-key support, encrypted local state, and secure notes.

The main idea is simple:

```text
Website ID + Master Password + Unlock Factor + Optional Factors
    -> GoblinPass
    = Generated Password
    -> Security Map metadata is recorded locally
```

GoblinPass does not aim to be a cloud password manager. The password generator is designed so the same inputs recreate the same password, while avoiding storage of the generated password itself.

## Current Focus

The most important part of the project is **Stateless Gen 2.0 (Beta)**:

- Stateless password generation.
- YubiKey/security-key unlock support using WebAuthn PRF where available.
- A local encrypted Security Map state file.
- Auto-recording of password metadata after generation.
- Hidden Security Map rows by default for screen privacy.
- Search and paging for larger Security Map lists.
- Secure Notes with YubiKey-backed encryption.
- Planned support for Windows Hello passkeys and biometric routes.

## Live Pages

Main pages in the current site:

- `index.html` - homepage and overview.
- `app.html` - Stateless Gen 1.0, the original generator.
- `stateless-gen2.html` - Stateless Gen 2.0 unlock-method chooser.
- `stateless-gen2-yubikey.html` - current Gen 2.0 YubiKey/security-key beta.
- `backup-codes.html` - Secure Notes unlock-method chooser.
- `secure-notes-yubikey.html` - current YubiKey-backed Secure Notes tool.
- `checker.html` - password strength checker.
- `security.html` - security overview.
- `security-model.html` - security model details.
- `guide.html` - Guide 1.0.
- `guide2.html` - Guide 2.0.
- `faq.html` - frequently asked questions.

## Stateless Gen 1.0

Stateless Gen 1.0 is the original GoblinPass generator.

It uses user-provided inputs such as a Website ID and Master Password to deterministically generate a password. If the same recipe is entered again, the same password can be recreated.

Gen 1.0 remains linked as the stable/original tool while Gen 2.0 is being tested.

## Stateless Gen 2.0 Beta

Stateless Gen 2.0 is the next-generation workflow.

It is built around a clearer separation:

- **Inputs**: Website ID, website name, optional login/account, master password, length, counter, and selected security methods.
- **Unlock Factor**: currently YubiKey/security-key.
- **Generated Password**: copied for use, not stored as a saved password.
- **Security Map**: local encrypted metadata that helps remember how each password was generated.

The Gen 2.0 chooser currently presents three routes:

- **YubiKey / Security Key**: available now.
- **Windows Hello Passkey**: planned.
- **Biometrics**: planned.

Only the YubiKey route is currently active.

## YubiKey / Security Key Support

The Gen 2.0 YubiKey beta uses the browser's WebAuthn support to involve a physical security key during generation.

The current YubiKey route is intended for users who want a hardware-backed unlock step as part of their password-generation recipe.

Important notes:

- The same YubiKey/security key may be required to regenerate the same passwords when YubiKey is part of the recipe.
- If the browser or operating system shows a passkey picker, choose the physical security key route when using the YubiKey version.
- If a security key is lost and there is no recovery design in place for that factor, affected passwords may not be recoverable.

## Security Map

The Security Map is the Gen 2.0 companion to the password generator.

It records metadata about how a password was generated, without saving the generated password itself.

Current Security Map entries can include:

- ID / Website ID.
- Site / website name.
- Security method icons.
- Password hint.
- Password length.
- Counter.

The hint is designed to help identify the generated password without saving the full password.

The Security Map is designed to answer questions like:

- Which security method did I use for this site?
- What length did I use?
- What counter did I use?
- Did I use a master password, YubiKey, Google factor, trusted device, or copy-only setting?

## Security Map Privacy

Security Map entries are hidden by default so someone nearby cannot quickly read the screen.

Current privacy controls include:

- Hide all entries.
- Show all entries.
- Reveal individual rows.
- Edit selected entry metadata.
- Delete entries.
- Site-name search filter.
- Entries-per-page paging.

This is meant to reduce casual shoulder-surfing and screenshot risk. It does not protect against a fully compromised device after data is unlocked and visible.

## Encrypted State File

Gen 2.0 uses a local encrypted state file for the Security Map.

The user can:

- Create a beta state.
- Open an existing state file.
- Reconnect a remembered state file when supported by the browser.
- Save changes.
- Save as a new file.
- Export a copy.

The current model is local-first. The user keeps control of the exported state file. There is no required GoblinPass server account for the Gen 2.0 beta.

## Auto-Record

Auto-record is designed to reduce manual work.

When a password is generated, GoblinPass can add or update the matching Security Map row with the current metadata:

- Website ID.
- Site.
- Security methods.
- Hint.
- Length.
- Counter.

This means the user should not need to separately save an entry after generating a password.

## Secure Notes

Secure Notes is a local encrypted notes tool.

The current available route is:

- **YubiKey / Security Key Secure Notes**.

Planned routes are:

- Windows Hello Passkey.
- Biometrics.

The YubiKey Secure Notes tool lets the user:

- Register a PRF-capable YubiKey/security key.
- Unlock notes with that key.
- Save encrypted notes locally.
- Export an encrypted file.
- Import an encrypted file.
- Lock the notes again.
- Purge local note entries.

Secure Notes are local-only. They are not sent to GoblinPass, Google, or a server by the static site.

## Planned Support

The interface already shows future unlock routes so the product direction is clear:

- Windows Hello passkey support.
- Biometric confirmation support.
- Possible trusted-device or phone-assisted flows.
- More polished recovery and migration flows.
- Continued improvements to Security Map filtering, paging, and editing.

These routes are shown as planned paths, not finished features.

## Privacy Model

GoblinPass is designed as a static, local-first website.

The core privacy goals are:

- Do not store generated passwords.
- Keep generation inputs under the user's control.
- Keep state files local and encrypted.
- Keep Secure Notes local and encrypted.
- Avoid requiring a cloud account for password generation.

Some optional factors, such as Google Security Factor, may involve signing in to a third-party identity provider if enabled. Those factors should be treated as part of the user's chosen password recipe.

## Security Boundaries

GoblinPass can help reduce several common risks:

- Password reuse.
- Weak passwords.
- Cloud vault breach risk.
- Forgetting which method was used for a site.
- Casual screen-watching of Security Map entries.

GoblinPass cannot protect against every situation:

- A fully compromised computer can read data after it is unlocked or displayed.
- Losing a required unlock factor can make affected passwords or notes unrecoverable.
- Incorrectly typed inputs can generate a different password.
- Users must keep exported state and note files backed up safely.

## Running Locally

This is a static website.

Open `index.html` in a browser, or open any page directly.

For the YubiKey/WebAuthn features, browser support and local security context rules may apply. Some browsers restrict WebAuthn or file access when pages are opened directly from `file://`. If a feature does not work from a direct file open, use a local static server during testing.

Example local server:

```powershell
python -m http.server 8000
```

Then open:

```text
http://localhost:8000/
```

## Project Structure

Key files and folders:

- `index.html` - homepage.
- `app.html` - Stateless Gen 1.0.
- `stateless-gen2.html` - Gen 2.0 method chooser.
- `stateless-gen2-yubikey.html` - active Gen 2.0 YubiKey beta.
- `backup-codes.html` - Secure Notes method chooser.
- `secure-notes-yubikey.html` - active YubiKey Secure Notes tool.
- `assets/css/style.css` - main website styling.
- `assets/js/goblinpass-engine.js` - shared password engine logic.
- `assets/js/level2-test.js` - Gen 2.0 YubiKey beta logic.
- `assets/js/backup-codes.js` - Secure Notes logic.
- `assets/img/security-icons/` - icons used across the security pages and tools.
- `goblinpass/` - included mobile/PWA-style app assets.

## Status

GoblinPass is actively evolving.

Current stable/original route:

- Stateless Gen 1.0.

Current beta routes:

- Stateless Gen 2.0 with YubiKey/security-key.
- Secure Notes with YubiKey/security-key.

Planned routes:

- Windows Hello passkeys.
- Biometrics.
- Expanded unlock-method support.

## License

Copyright (c) 2026 Carl Hatton.

GoblinPass is created and maintained by Carl Hatton.

See `LICENSE` for the full license terms.

