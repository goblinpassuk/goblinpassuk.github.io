# GoblinPass Strength Checker

GoblinPass Strength Checker is a simple local-only password strength checker and password safety guide built with HTML, CSS, and vanilla JavaScript.

## How to use

Open `index.html` directly in a web browser. No install step is needed.

## Privacy

The password checker runs entirely in your browser. Password data entered into the checker is not sent, saved, stored, logged, placed in localStorage, written to cookies, written to sessionStorage, or sent to any external service.

The included GoblinPass app under `goblinpass/` is a separate local-first ID-based vault app. If a user chooses to save vault entries, that app encrypts vault metadata in the browser's localStorage using a key derived from the vault PIN. It does not save the master password or full generated passwords.

GoblinPass also includes an optional Additional Secret setting. When disabled, existing users keep generating the same passwords as before. When enabled, the full Additional Secret is added during generation as a second secret, but the key itself is not saved in the vault, exported, transmitted, or stored. Users can enter it with a normal keyboard, a desktop shuffled on-screen keyboard, or a mobile combination lock. GoblinPass does not use partial or random character prompts for the Additional Secret.

GoblinPass supports two password styles. Maximum Security is the default and keeps existing complex password generation unchanged. Memorable Password mode is optional and generates deterministic word-based passwords, with Easy, Standard, and Strong strength choices.

The vault can optionally avoid saving Website IDs. When this setting is off, users must remember or enter the Website ID themselves when regenerating a password.

Trusted Device Protection is a separate optional setting. When enabled, GoblinPass adds a hidden local Trusted Device Key to password generation. Save the Recovery Key offline before relying on this mode; without it, passwords made with Trusted Device Protection cannot be recreated on another device.

Optional Google Sign-In support uses Google Identity Services with a hardcoded frontend Client ID only. It does not request Gmail, Drive, Calendar, or other sensitive scopes. Do not add a Google client secret to this static site. Google Sign-In can be used for future sync/import/export convenience without changing passwords.

Google Security Factor is a separate optional setting. When disabled, password generation remains unchanged. When enabled, users must sign in with Google and GoblinPass uses the stable Google account subject ID, not the email address, as an extra password generation input. The subject ID is kept in memory for generation and is not saved in plain text. If access to that Google account is lost, the same passwords may not be recoverable.

## Content

The page includes:

- A responsive navigation bar
- A local password strength checker
- Password security guidance
- Password tips and common mistakes
- Email alias and forwarding guidance
- A short DuckDuckGo privacy tools mention
- A GoblinPass overview
- GoblinPass vault preview screens
- A link to the live GoblinPass demo
- An included GoblinPass mobile PWA under `goblinpass/`
- Optional Additional Secret settings for the included app and generated forks
- Optional Memorable Password mode for the included app and generated forks
- A link to the GoblinPass GitHub repository
- Master password and regeneration guidance
- A GoblinPass and LessPass comparison table
- A Create Your Own Pass fork package builder
- An expanded About GoblinPass section
- A Why GitHub transparency section

## Files

- `index.html`
- `assets/css/style.css`
- `assets/js/app.js`
- `README.md`
- `goblinpass/`

## License

Copyright (c) 2026 Carl Hatton

GoblinPass is a project created and maintained by Carl Hatton.

All rights reserved.

This project is publicly viewable for personal and educational purposes only.

Modification, redistribution, commercial use, and derivative works are prohibited without prior written permission.

See the LICENSE file for full terms.

## Support the Project

If you find GoblinPass useful and would like to support future development, testing hardware, hosting costs, and new features, voluntary tips are appreciated.

Tips are optional and do not grant any additional rights to use, modify, redistribute, or commercialize the software.
