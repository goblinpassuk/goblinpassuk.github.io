(function () {
  "use strict";

  const passwordInput = document.getElementById("passwordInput");
  const togglePassword = document.getElementById("togglePassword");
  const strengthLabel = document.getElementById("strengthLabel");
  const strengthSummary = document.getElementById("strengthSummary");
  const scoreValue = document.getElementById("scoreValue");
  const meterFill = document.getElementById("meterFill");
  const crackTime = document.getElementById("crackTime");
  const warningsList = document.getElementById("warnings");
  const navToggle = document.getElementById("navToggle");
  const navLinks = document.getElementById("navLinks");
  const checklistItems = Array.from(document.querySelectorAll("[data-check]"));
  const ENGINE_VERSION = "2.0.0";
  const brandFields = {
    siteName: document.getElementById("brandSiteName"),
    tagline: document.getElementById("brandTagline"),
    primary: document.getElementById("brandPrimary"),
    secondary: document.getElementById("brandSecondary"),
    logo: document.getElementById("brandLogo"),
    theme: document.getElementById("brandTheme"),
    about: document.getElementById("brandAbout")
  };
  const previewName = document.getElementById("previewName");
  const previewTagline = document.getElementById("previewTagline");
  const previewLogo = document.getElementById("previewLogo");
  const brandPreview = document.getElementById("brandPreview");
  const configOutput = document.getElementById("configOutput");
  const downloadFork = document.getElementById("downloadFork");
  const engineVersion = document.getElementById("engineVersion");
  let uploadedLogo = null;

  const commonPasswords = new Set([
    "password",
    "password1",
    "password123",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "welcome1",
    "qwerty",
    "qwerty123",
    "abc123",
    "123456",
    "12345678",
    "123456789",
    "111111",
    "iloveyou",
    "dragon",
    "monkey",
    "football",
    "baseball",
    "sunshine",
    "princess",
    "charlie",
    "trustno1",
    "passw0rd",
    "p@ssword",
    "p@ssw0rd"
  ]);

  const keyboardPatterns = [
    "qwerty",
    "asdf",
    "zxcv",
    "123456",
    "654321",
    "abcdef",
    "fedcba",
    "qazwsx",
    "1q2w3e",
    "poiuy",
    "lkjhg",
    "mnbvc"
  ];

  const commonWords = [
    "account",
    "admin",
    "apple",
    "computer",
    "dragon",
    "football",
    "google",
    "hello",
    "letmein",
    "login",
    "master",
    "money",
    "monkey",
    "password",
    "princess",
    "qwerty",
    "secret",
    "summer",
    "welcome",
    "winter"
  ];

  const substitutions = {
    "@": "a",
    "4": "a",
    "0": "o",
    "1": "i",
    "!": "i",
    "3": "e",
    "$": "s",
    "5": "s",
    "7": "t"
  };

  function normalizeLeetspeak(value) {
    return value
      .toLowerCase()
      .split("")
      .map((char) => substitutions[char] || char)
      .join("");
  }

  function hasRepeatedCharacters(value) {
    return /(.)\1{2,}/.test(value) || /(.{2,4})\1{2,}/i.test(value);
  }

  function getRepeatedChunk(value) {
    const lower = value.toLowerCase();
    for (let size = 2; size <= Math.floor(lower.length / 2); size += 1) {
      if (lower.length % size !== 0) continue;
      const chunk = lower.slice(0, size);
      if (chunk.repeat(lower.length / size) === lower) return chunk;
    }
    return "";
  }

  function getCommonWordMatch(value) {
    const normalized = normalizeLeetspeak(value);
    return commonWords.find((word) => normalized.includes(word)) || "";
  }

  function countCommonWordRepeats(value, commonWord) {
    if (!commonWord) return 0;
    const matches = normalizeLeetspeak(value).match(new RegExp(commonWord, "g"));
    return matches ? matches.length : 0;
  }

  function hasKeyboardPattern(value) {
    const lower = value.toLowerCase();
    return keyboardPatterns.some((pattern) => lower.includes(pattern));
  }

  function estimateGuessesPerSecond() {
    return 10000000000;
  }

  function getPoolSize(value) {
    let pool = 0;
    if (/[a-z]/.test(value)) pool += 26;
    if (/[A-Z]/.test(value)) pool += 26;
    if (/[0-9]/.test(value)) pool += 10;
    if (/[^A-Za-z0-9]/.test(value)) pool += 33;
    return pool || 1;
  }

  function estimateEffectiveLength(value, repeatedChunk, commonWord, commonWordRepeats) {
    if (!value) return 0;
    if (repeatedChunk) return repeatedChunk.length + 2;
    if (commonWordRepeats > 1) return commonWord.length + Math.min(commonWordRepeats, 4);
    if (commonWord && value.length <= commonWord.length + 6) return Math.max(4, value.length - commonWord.length + 5);
    return value.length;
  }

  function applyScoreBasedTimeCap(seconds, score) {
    if (score < 20) return Math.min(seconds, 60);
    if (score < 40) return Math.min(seconds, 60 * 60 * 24);
    if (score < 60) return Math.min(seconds, 60 * 60 * 24 * 365);
    if (score < 80) return Math.min(seconds, 60 * 60 * 24 * 365 * 1000);
    return seconds;
  }

  function formatTime(seconds) {
    if (seconds <= 0) return "No time";
    if (seconds < 1) return "Instantly";

    const units = [
      ["years", 60 * 60 * 24 * 365],
      ["months", 60 * 60 * 24 * 30],
      ["days", 60 * 60 * 24],
      ["hours", 60 * 60],
      ["minutes", 60],
      ["seconds", 1]
    ];

    for (const [unit, unitSeconds] of units) {
      if (seconds >= unitSeconds) {
        const amount = Math.floor(seconds / unitSeconds);
        if (amount > 999999999999 && unit === "years") return "More than 999 billion years";
        const label = amount === 1 ? unit.slice(0, -1) : unit;
        return `${amount.toLocaleString()} ${label}`;
      }
    }

    return "Instantly";
  }

  function getLabel(score, length) {
    if (length === 0) return "Empty";
    if (score < 20) return "Very weak";
    if (score < 40) return "Weak";
    if (score < 60) return "Okay";
    if (score < 80) return "Strong";
    return "Very strong";
  }

  function getMeterColor(score) {
    if (score < 20) return "#ff6b6b";
    if (score < 40) return "#f8961e";
    if (score < 60) return "#ffd166";
    if (score < 80) return "#8bd450";
    return "#77f05a";
  }

  function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "\"": "&quot;",
      "'": "&#39;"
    })[char]);
  }

  function getBrandConfig() {
    return {
      engineVersion: ENGINE_VERSION,
      siteName: brandFields.siteName.value.trim() || "MyPass",
      tagline: brandFields.tagline.value.trim() || "Private passwords, your way.",
      primaryColour: brandFields.primary.value,
      secondaryColour: brandFields.secondary.value,
      theme: brandFields.theme.value,
      logoPath: "assets/logo.png",
      hasCustomLogo: Boolean(uploadedLogo),
      aboutText: brandFields.about.value.trim(),
      coreFiles: [
        "core/password-generator.js",
        "core/security.js"
      ],
      securityNote: "Branding settings must not modify the GoblinPass password generation engine."
    };
  }

  function renderBrandPreview() {
    if (!brandFields.siteName) return;
    const config = getBrandConfig();
    previewName.textContent = config.siteName;
    previewTagline.textContent = config.tagline;
    brandPreview.style.setProperty("--accent", config.primaryColour);
    brandPreview.style.setProperty("--brand-primary", config.primaryColour);
    brandPreview.style.setProperty("--brand-secondary", config.secondaryColour);
    brandPreview.style.backgroundColor = config.theme === "light" ? "#f7fff8" : "rgba(16, 25, 20, 0.88)";
    const previewShell = brandPreview.querySelector(".preview-shell");
    if (previewShell) previewShell.style.backgroundColor = config.secondaryColour;

    if (uploadedLogo && uploadedLogo.dataUrl) {
      previewLogo.innerHTML = `<img src="${uploadedLogo.dataUrl}" alt="">`;
    } else {
      previewLogo.textContent = getLogoInitials(config.siteName);
    }

    configOutput.textContent = JSON.stringify(config, null, 2);
  }

  function getLogoInitials(siteName) {
    return siteName
      .split(/\s+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((word) => word[0].toUpperCase())
      .join("") || "GP";
  }

  function makeLogoMarkup(config) {
    if (config.hasCustomLogo) return `<img id="brandLogoMark" src="assets/logo.png" alt="" class="logo">`;
    return `<div id="brandLogoMark" class="logo logo-fallback" aria-hidden="true">${escapeHtml(getLogoInitials(config.siteName))}</div>`;
  }

  function makeGeneratedIndex(config) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>${escapeHtml(config.siteName)}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="theme-color" content="${config.secondaryColour}">
  <link rel="manifest" href="manifest.webmanifest">
  <link rel="stylesheet" href="style.css">
  ${makeGeneratedStyleFallback(config)}
</head>
<body>
  <main class="app">
    <header class="brand">
      ${makeLogoMarkup(config)}
      <div>
        <h1 id="brandTitle">${escapeHtml(config.siteName)}</h1>
        <p id="brandTagline">${escapeHtml(config.tagline)}</p>
      </div>
      <button id="themeEditToggle" class="theme-edit-toggle" type="button">Edit theme</button>
    </header>

    <nav class="app-menu" aria-label="Main menu">
      <button id="generatorTab" class="active" type="button" data-page-target="generatorPage">Generator</button>
      <button id="vaultTab" type="button" data-page-target="vaultPage">Vault</button>
      <button id="settingsTab" type="button" data-page-target="settingsPage">Settings</button>
    </nav>

    <div class="mode-toggle" aria-label="Interface mode">
      <button id="simpleMode" type="button">Simple</button>
      <button id="advancedMode" type="button">Advanced</button>
    </div>

    <section id="themeEditor" class="card theme-editor hidden">
      <label>Site name</label>
      <input id="themeSiteName" type="text" value="${escapeHtml(config.siteName)}">
      <label>Tagline</label>
      <input id="themeTagline" type="text" value="${escapeHtml(config.tagline)}">
      <label>Primary colour</label>
      <div class="swatch-row">
        <input id="themePrimary" type="color" value="${config.primaryColour}">
        <button data-colour="#74ff9d" type="button"></button>
        <button data-colour="#ec4bdd" type="button"></button>
        <button data-colour="#4da3ff" type="button"></button>
        <button data-colour="#ffd166" type="button"></button>
      </div>
      <label>Secondary colour</label>
      <div class="swatch-row">
        <input id="themeSecondary" type="color" value="${config.secondaryColour}">
        <button data-secondary="#09160f" type="button"></button>
        <button data-secondary="#161026" type="button"></button>
        <button data-secondary="#101827" type="button"></button>
        <button data-secondary="#f7fff8" type="button"></button>
      </div>
      <label>Font colour</label>
      <div class="swatch-row">
        <input id="themeText" type="color" value="${config.theme === "light" ? "#0b160f" : "#effff2"}">
        <button data-text="#effff2" type="button"></button>
        <button data-text="#0b160f" type="button"></button>
        <button data-text="#ffd166" type="button"></button>
        <button data-text="#ffffff" type="button"></button>
      </div>
      <label>Muted text colour</label>
      <div class="swatch-row">
        <input id="themeMuted" type="color" value="${config.theme === "light" ? "#4d6355" : "#9fc7aa"}">
        <button data-muted="#9fc7aa" type="button"></button>
        <button data-muted="#4d6355" type="button"></button>
        <button data-muted="#c7f9cc" type="button"></button>
        <button data-muted="#f4d35e" type="button"></button>
      </div>
      <button id="themeReset" type="button">Reset theme</button>
    </section>

    <section id="generatorPage" class="page-section">
    <section class="card">
      <label>Website ID</label>
      <input id="siteId" type="text" placeholder="Unique ID" autocomplete="off" autocapitalize="none" spellcheck="false">

      <div class="advanced-only">
        <label>Site (optional)</label>
        <input id="site" type="text" placeholder="example.com" autocomplete="off" autocapitalize="none" spellcheck="false">

        <label>Login (optional)</label>
        <input id="login" type="text" placeholder="username or email" autocomplete="off" autocapitalize="none" spellcheck="false">

        <label class="save-full-row">
          <input id="storeFullLogin" type="checkbox">
          Store full login for this entry
        </label>
      </div>

      <label>Master Password</label>
      <div class="input-row">
        <input id="master" type="password" placeholder="Never saved" autocomplete="off" autocapitalize="none" spellcheck="false">
        <button id="toggleMaster" class="icon-btn" type="button" aria-label="Show master password">Show</button>
      </div>

      <div id="securityKeyBox" class="security-key-box hidden" data-entry-mode="keyboard">
        <label>Additional Secret</label>
        <input id="securityKey" type="password" placeholder="Example: GP4837" autocomplete="off" autocapitalize="characters" spellcheck="false">
        <p class="muted">The full Additional Secret is required every time. ${escapeHtml(config.siteName)} does not store it.</p>
        <div id="securityInputPanel" class="security-input-panel hidden" aria-live="polite"></div>
      </div>

      <label for="passwordStyle">Password Style</label>
      <select id="passwordStyle">
        <option value="maximum">Maximum Security</option>
        <option value="memorable">Memorable Password</option>
      </select>
      <div id="memorableOptions" class="hidden">
        <label for="memorableStrength">Memorable Strength</label>
        <select id="memorableStrength">
          <option value="easy">Easy - 3 words</option>
          <option value="standard" selected>Standard - 4 words</option>
          <option value="strong">Strong - 4 words + number + symbol</option>
        </select>
      </div>
      <p class="muted">Memorable passwords are easier to enter on consoles, TVs, handheld devices, and controllers. Maximum Security remains recommended for email, banking, and important accounts.</p>

      <div class="options-grid advanced-only">
        <label class="check"><input id="lower" type="checkbox" checked> a-z</label>
        <label class="check"><input id="upper" type="checkbox" checked> A-Z</label>
        <label class="check"><input id="nums" type="checkbox" checked> 0-9</label>
        <label class="check"><input id="symbols" type="checkbox" checked> %!@</label>
      </div>

      <div class="number-row">
        <div>
          <label>Length</label>
          <input id="length" type="number" min="8" max="64" value="16">
        </div>
        <div>
          <label>Counter</label>
          <input id="counter" type="number" min="1" max="999" value="1">
        </div>
      </div>

      <div class="button-row">
        <button id="generate" class="primary" type="button">Generate & copy</button>
        <button id="save" type="button">Save</button>
      </div>

      <div id="result" class="result hidden">
        <span id="resultText"></span>
        <button id="copyGenerated" class="icon-btn small" type="button" aria-label="Copy generated password">Copy</button>
        <button id="toggleGenerated" class="icon-btn small" type="button" aria-label="Show generated password">Show</button>
      </div>
    </section>
    </section>

    <section id="vaultPage" class="page-section hidden">
    <section class="card">
      <div class="vault-head">
        <h2>Vault</h2>
        <button id="vaultBtn" type="button">Show vault</button>
      </div>
      <p class="muted">Saved encrypted on this device. Your vault PIN is required to decrypt saved entries.</p>

      <div id="pinBox" class="pin-box hidden">
        <p class="muted">Create or enter your vault PIN to decrypt your local vault.</p>
        <div class="pin-row">
          <input id="vaultPin" type="password" maxlength="4" inputmode="numeric" placeholder="Vault PIN">
          <button id="setOrUnlockPin" type="button">Unlock</button>
        </div>
      </div>

      <div id="vaultArea" class="hidden">
        <input id="filter" class="filter" type="text" placeholder="Filter vault..." autocomplete="off">
        <div class="vault-actions">
          <button id="exportBtn" type="button">Export</button>
          <label class="import-label">
            Import
            <input id="importFile" type="file" accept="application/json">
          </label>
        </div>
        <div id="entries" class="entries"></div>
      </div>
    </section>
    </section>

    <section id="settingsPage" class="page-section hidden">
      <section class="card">
        <div class="vault-head">
          <h2>Settings</h2>
        </div>
        <select id="defaultPasswordStyle" class="hidden" aria-hidden="true" tabindex="-1">
          <option value="maximum" selected>Maximum Security</option>
          <option value="memorable">Memorable Password</option>
        </select>
        <div class="settings-stack">
          <section class="settings-card">
            <h3>Vault</h3>
            <label class="setting-row">
              <input id="saveWebsiteIds" type="checkbox" checked>
              Save Website IDs in vault
            </label>
            <p class="muted">Keeps saved entries easier to reuse. Turn this off if you prefer to remember IDs yourself.</p>
          </section>
          <section class="settings-card">
            <h3>Security</h3>
            <label class="setting-row">
              <input id="enableSecurityKey" type="checkbox">
              Enable Additional Secret
            </label>
            <div id="securityKeyMethodGroup" class="settings-reveal hidden">
              <label for="securityKeyInputMethod">Additional Secret Input Method</label>
              <select id="securityKeyInputMethod">
                <option value="normal">Normal Keyboard</option>
                <option value="desktop-shuffled">Desktop Shuffled Keyboard</option>
                <option value="mobile-combo">Mobile Combination Lock</option>
              </select>
              <details class="more-info">
                <summary>More info</summary>
                <p>Recommended formats include G48372, DOG123, CAT456, or GP4837. Suggested format: 2 letters + 4 digits, for example GP4837.</p>
              </details>
              <p id="securityKeyWarning" class="notice">The Additional Secret adds another private input to password generation. It may reduce risk from basic keyloggers, but it cannot protect against a fully compromised device, screen recording, or advanced malware.</p>
            </div>
            <label class="setting-row">
              <input id="enableTrustedDevice" type="checkbox">
              Enable Trusted Device Protection
            </label>
            <div id="trustedDeviceDetails" class="settings-reveal hidden">
              <p id="trustedDeviceStatus" class="status-line">Trusted Device Protection: Disabled</p>
              <div class="settings-actions">
                <button id="showRecoveryKey" type="button">Show Recovery Key</button>
                <button id="restoreTrustedDevice" type="button">Restore Trusted Device</button>
              </div>
              <details class="more-info">
                <summary>More info</summary>
                <p>Trusted Device Protection adds a hidden local key to password generation. Passwords created with it enabled need the same trusted key restored on another device.</p>
              </details>
              <p id="trustedDeviceWarning" class="notice">If the Trusted Device Key is lost and no recovery key was saved, passwords generated with Trusted Device Protection cannot be recovered.</p>
            </div>
          </section>
          <section class="settings-card">
            <h3>Privacy</h3>
            <label class="setting-row">
              <input id="copyPasswordOnly" type="checkbox">
              Copy Password Only
            </label>
            <p class="muted">Copies the generated password without showing it on screen.</p>
          </section>
          <section class="settings-card google-account-card">
            <h3>Google Sign-In</h3>
            <p class="muted">Optional. Google Sign-In can identify the user for future encrypted vault sync/import/export convenience. It is not used for password generation unless Google Security Factor is enabled.</p>
            <label class="setting-row">
              <input id="googleSecurityFactor" type="checkbox">
              Google Security Factor
            </label>
            <p class="muted">When enabled, GoblinPass requires Google Sign-In and uses the stable Google account subject ID as an extra password ingredient. It does not use your email address.</p>
            <p id="googleSecurityWarning" class="notice">If you lose access to this Google account, you may not be able to regenerate the same passwords.</p>
            <div class="settings-actions">
              <button id="setupGoogleSignIn" type="button">Set up Google Sign-In</button>
              <button id="googleSignOut" type="button">Sign out</button>
            </div>
            <div id="googleSignInButton" class="google-button-area"></div>
            <p id="googleSignInStatus" class="status-line">Google Sign-In: Not signed in</p>
            <details class="more-info">
              <summary>More info</summary>
              <p>Google Sign-In uses basic identity only. Do not add a Google client secret to this static site. The Google Subject ID is kept in memory for generation and is not saved in plain text.</p>
            </details>
          </section>
        </div>
      </section>
    </section>
  </main>
  <footer>Powered by the GoblinPass Engine. Review the GoblinPass license before publishing or redistributing.</footer>
  <script src="core/security.js"></script>
  <script src="core/password-generator.js"></script>
  <script src="app.js"></script>
</body>
</html>`;
  }

  function makeGeneratedAbout(config) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>About ${escapeHtml(config.siteName)}</title>
  <link rel="stylesheet" href="style.css">
  ${makeGeneratedStyleFallback(config)}
</head>
<body>
  <main class="app">
    <header class="brand">
      ${makeLogoMarkup(config)}
      <div>
        <h1>About ${escapeHtml(config.siteName)}</h1>
        <p>${escapeHtml(config.tagline)}</p>
      </div>
    </header>
    <section class="card">
      <p>${escapeHtml(config.aboutText || "This branded package uses the GoblinPass Engine with separate theme settings. Review the GoblinPass license before using, modifying, redistributing, or publishing it.")}</p>
      <p>The password generation engine is kept separate from branding settings. Branding lives in config.json, themes/config.json, style.css, and logo assets.</p>
    </section>
  </main>
  <footer>Powered by the GoblinPass Engine. Review the GoblinPass license before publishing or redistributing.</footer>
</body>
</html>`;
  }

  function makeGeneratedReadmeMarkdown(config) {
    return `# ${config.siteName}

${config.tagline}

This package is powered by the GoblinPass Engine. Review the GoblinPass license before using, modifying, redistributing, or publishing it.

## Use in a browser

Open \`index.html\` directly in a browser. No server, database, account, or install step is required.

## Publish on GitHub Pages

1. Create a new GitHub repository.
2. Upload all files from this package into the repository.
3. Open the repository settings.
4. Go to Pages.
5. Choose the main branch and root folder.
6. Save and wait for GitHub Pages to publish the site.

Your app will usually be available at:

\`https://your-username.github.io/your-repository-name/\`

## Install on mobile

1. Open the published GitHub Pages URL on your phone.
2. Use your browser menu.
3. Choose Add to Home Screen or Install App.

Install support depends on the mobile browser. The app includes a web manifest and icons for PWA-style installation.

## Security notes

- The master password is not saved.
- Full generated passwords are not saved.
- If you use the vault, saved ID/site/login metadata is stored locally in the browser.
- Optional full login storage may expose the email or username you used for an entry.
- The optional Additional Secret setting is saved locally, but the Additional Secret itself is never saved, exported, or transmitted.
- The Additional Secret input method preference is saved locally. The actual Additional Secret is cleared on refresh, app close, or Clear.
- The full Additional Secret is required every time. This fork does not use partial or random character prompts for the Additional Secret.
- Maximum Security is the default password style and keeps existing complex generation unchanged.
- Memorable Password mode is optional and creates deterministic word-based passwords with Easy, Standard, and Strong choices.
- The vault can optionally avoid saving Website IDs. If Website ID saving is off, users must remember or enter the ID themselves when regenerating a password.
- Trusted Device Protection is optional. Save the Recovery Key offline before relying on it on another device.
- If the Trusted Device Key is lost and no Recovery Key was saved, passwords generated with Trusted Device Protection cannot be recovered.
- Optional Google Sign-In uses a hardcoded frontend Client ID only. It does not request Gmail, Drive, Calendar, or other sensitive scopes. Do not add a client secret to this static site.
- Google Sign-In can be used for future sync/import/export convenience without changing passwords.
- Google Security Factor is separate and optional. When enabled, it requires Google Sign-In and adds the stable Google account subject ID, not the email address, to password generation.
- The Google Subject ID is kept in memory for generation and is not saved in plain text.
- If you lose access to the chosen Google account, passwords made with Google Security Factor may not be recoverable.
- If Additional Secret is disabled, password generation remains compatible with standard mode.
- The password engine lives in \`/core\`; branding files should not need to modify it.

## Files

- \`index.html\`
- \`about.html\`
- \`readme.html\`
- \`README.md\`
- \`app.js\`
- \`style.css\`
- \`manifest.webmanifest\`
- \`config.json\`
- \`themes/config.json\`
- \`core/password-generator.js\`
- \`core/security.js\`
- logo and icon files

Powered by the GoblinPass Engine. Review the GoblinPass license before publishing or redistributing.
`;
  }

  function makeGeneratedReadmeHtml(config) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Setup ${escapeHtml(config.siteName)}</title>
  <link rel="stylesheet" href="style.css">
  ${makeGeneratedStyleFallback(config)}
</head>
<body>
  <main class="app">
    <header class="brand">
      ${makeLogoMarkup(config)}
      <div>
        <h1>Setup ${escapeHtml(config.siteName)}</h1>
        <p>${escapeHtml(config.tagline)}</p>
      </div>
    </header>
    <section class="card">
      <h2>Use directly</h2>
      <p>Open index.html in a browser. No server, database, account, or install step is required.</p>
    </section>
    <section class="card">
      <h2>Publish on GitHub Pages</h2>
      <ol>
        <li>Create a new GitHub repository.</li>
        <li>Upload every file from this package.</li>
        <li>Open Settings, then Pages.</li>
        <li>Select the main branch and root folder.</li>
        <li>Save and wait for GitHub Pages to publish.</li>
      </ol>
    </section>
    <section class="card">
      <h2>Install on mobile</h2>
      <p>Open the published URL on your phone, then choose Add to Home Screen or Install App from your browser menu.</p>
    </section>
    <section class="card">
      <h2>Security notes</h2>
      <ul>
        <li>The master password is not saved.</li>
        <li>Full generated passwords are not saved.</li>
        <li>Vault metadata is saved locally only if you use the vault.</li>
        <li>The optional Additional Secret setting is saved locally, but the Additional Secret itself is never saved or exported.</li>
        <li>The Additional Secret input method preference is saved locally. The actual Additional Secret is cleared on refresh, app close, or Clear.</li>
        <li>The full Additional Secret is required every time. This fork does not use partial or random character prompts.</li>
        <li>Maximum Security is the default password style and keeps existing complex generation unchanged.</li>
        <li>Memorable Password mode is optional and creates deterministic word-based passwords with Easy, Standard, and Strong choices.</li>
        <li>The vault can optionally avoid saving Website IDs. If Website ID saving is off, users must remember or enter the ID themselves when regenerating a password.</li>
        <li>Trusted Device Protection is optional. Save the Recovery Key offline before relying on it on another device.</li>
        <li>If the Trusted Device Key is lost and no Recovery Key was saved, passwords generated with Trusted Device Protection cannot be recovered.</li>
        <li>Optional Google Sign-In uses a hardcoded frontend Client ID only. It does not request Gmail, Drive, Calendar, or other sensitive scopes. Do not add a client secret to this static site.</li>
        <li>Google Sign-In can be used for future sync/import/export convenience without changing passwords.</li>
        <li>Google Security Factor is separate and optional. When enabled, it requires Google Sign-In and adds the stable Google account subject ID, not the email address, to password generation.</li>
        <li>The Google Subject ID is kept in memory for generation and is not saved in plain text.</li>
        <li>If you lose access to the chosen Google account, passwords made with Google Security Factor may not be recoverable.</li>
        <li>When Additional Secret is disabled, standard password generation remains unchanged.</li>
        <li>The password engine lives in /core.</li>
      </ul>
    </section>
  </main>
  <footer>Powered by the GoblinPass Engine. Review the GoblinPass license before publishing or redistributing.</footer>
</body>
</html>`;
  }

  function makeGeneratedCss(config) {
    const light = config.theme === "light";
    return `:root{--bg:${light ? "#f7fff8" : "#06100c"};--card:${config.secondaryColour};--card2:${config.secondaryColour};--border:${config.primaryColour};--border2:${config.primaryColour};--text:${light ? "#0b160f" : "#effff2"};--muted:${light ? "#4d6355" : "#9fc7aa"};--input:${light ? "#ffffff" : "#06120d"};--green:${config.primaryColour};--green2:${config.primaryColour};--danger:#ff6672;--shadow:0 14px 34px rgba(0,0,0,.38)}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font:15px/1.4 system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif}.app{width:min(100%,520px);margin:0 auto;padding:calc(12px + env(safe-area-inset-top)) 12px calc(24px + env(safe-area-inset-bottom))}.brand{display:flex;align-items:center;gap:12px;padding:8px 4px 14px}.brand>div{flex:1}.theme-edit-toggle{width:auto;min-height:38px;padding:9px 12px}.mode-toggle{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:0 0 14px}.mode-toggle button.active{background:var(--green);color:#041009;border-color:var(--green)}body.simple-mode .advanced-only{display:none!important}.logo{width:48px;height:48px;display:grid;place-items:center;border-radius:15px;background:var(--input);border:1px solid var(--green);color:var(--green);font-weight:950;box-shadow:0 0 20px rgba(116,255,157,.18);object-fit:cover}.logo-fallback{display:grid}h1{font-size:25px;line-height:1;margin:0;font-weight:950;letter-spacing:.01em}.brand p{margin:4px 0 0;color:var(--muted);font-size:12px}.app-menu{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:0 0 14px}.app-menu button.active{background:var(--green);color:#041009;border-color:var(--green)}.page-section{display:block}.card{background:linear-gradient(180deg,var(--card),var(--card2));border:1px solid var(--border);border-radius:20px;padding:16px;box-shadow:var(--shadow);margin-bottom:14px}.theme-editor{display:grid;gap:10px}.swatch-row{display:grid;grid-template-columns:1fr repeat(4,42px);gap:8px;align-items:center}.swatch-row input{height:42px;padding:5px}.swatch-row button{height:42px;padding:0;border-color:var(--border)}.swatch-row button[data-colour="#74ff9d"]{background:#74ff9d}.swatch-row button[data-colour="#ec4bdd"]{background:#ec4bdd}.swatch-row button[data-colour="#4da3ff"]{background:#4da3ff}.swatch-row button[data-colour="#ffd166"]{background:#ffd166}.swatch-row button[data-secondary="#09160f"]{background:#09160f}.swatch-row button[data-secondary="#161026"]{background:#161026}.swatch-row button[data-secondary="#101827"]{background:#101827}.swatch-row button[data-secondary="#f7fff8"]{background:#f7fff8}.swatch-row button[data-text="#effff2"]{background:#effff2}.swatch-row button[data-text="#0b160f"]{background:#0b160f}.swatch-row button[data-text="#ffd166"]{background:#ffd166}.swatch-row button[data-text="#ffffff"]{background:#ffffff}.swatch-row button[data-muted="#9fc7aa"]{background:#9fc7aa}.swatch-row button[data-muted="#4d6355"]{background:#4d6355}.swatch-row button[data-muted="#c7f9cc"]{background:#c7f9cc}.swatch-row button[data-muted="#f4d35e"]{background:#f4d35e}label{display:block;font-weight:800;margin:0 0 8px}input,select{width:100%;border:1px solid var(--border2);background:var(--input);color:var(--text);border-radius:12px;padding:13px;outline:none;font-size:16px}select{margin-bottom:12px}input:focus,select:focus{border-color:var(--green);box-shadow:0 0 0 3px color-mix(in srgb,var(--green) 18%,transparent)}input::placeholder{color:var(--muted)}.card>input{margin-bottom:16px}.advanced-only{margin-bottom:16px}.advanced-only>input{margin-bottom:16px}.advanced-only>input:last-of-type{margin-bottom:10px}.input-row{display:flex;gap:9px;margin-bottom:16px}.input-row input{flex:1}.icon-btn{width:58px;min-width:58px;border:1px solid var(--border2);background:var(--input);color:var(--text);border-radius:12px;cursor:pointer}.icon-btn.small{height:42px;width:72px;min-width:72px;padding:9px 12px;white-space:nowrap}.save-full-row{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px;margin:6px 0 0;font-weight:750}.check{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:13px;margin:0;font-weight:750}.save-full-row input,.check input{width:16px;height:16px;padding:0;accent-color:var(--green2);flex:0 0 16px}.options-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin-bottom:14px}.check{justify-content:center;background:var(--input);border:1px solid var(--border);border-radius:12px;padding:10px 6px}.number-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px}.button-row{display:grid;grid-template-columns:1fr .55fr;gap:9px}button,.import-label{border:1px solid var(--border2);background:var(--input);color:var(--text);border-radius:12px;padding:13px 12px;font-weight:850;cursor:pointer;text-align:center;font-size:14px}.primary{background:var(--green);color:#041009;border:0}.result{margin-top:14px;border:1px dashed var(--border2);border-radius:12px;padding:12px;display:grid;grid-template-columns:minmax(0,1fr) 72px 72px;align-items:center;gap:10px;background:var(--input);color:var(--text)}.result span{min-width:0;overflow-wrap:anywhere;line-height:1.35}.hidden{display:none!important}.security-key-box{margin-bottom:16px}.security-key-box input[readonly]{cursor:pointer}.security-input-panel{margin-top:10px;padding:12px;border:1px solid var(--border);border-radius:15px;background:var(--input)}.security-panel-title{margin:0 0 10px;color:var(--muted);font-size:12px;font-weight:850}.security-progress{margin:0 0 10px;color:var(--text);font-size:13px;font-weight:850}.security-key-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:7px}.security-key-grid button,.security-actions button{min-height:46px;padding:10px 6px}.security-actions{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-top:10px}.combo-slots{display:grid;grid-template-columns:repeat(6,1fr);gap:7px}.combo-slots button{min-height:50px;padding:10px 4px;font-size:18px}.combo-choice-panel{margin-top:10px;padding-top:10px;border-top:1px solid var(--border)}.combo-actions{grid-template-columns:repeat(3,1fr)}.notice{margin:12px 0 0;padding:12px;border:1px solid #6a5b20;border-radius:12px;background:#1b1909;color:#ffe58a;font-size:13px}.setting-row{display:flex;align-items:center;gap:10px;margin:14px 0 10px;color:var(--text)}.setting-row input{width:18px;height:18px;padding:0;accent-color:var(--green2);flex:0 0 18px}.status-line{margin:10px 0;padding:10px 12px;border:1px solid var(--border);border-radius:12px;background:var(--input);color:var(--text);font-weight:800;font-size:13px}.settings-stack{display:grid;gap:12px;margin-top:12px}.settings-card{border:1px solid var(--border);border-radius:16px;background:color-mix(in srgb,var(--input) 76%,transparent);padding:14px}.settings-card h3{margin:0 0 10px;font-size:16px}.settings-reveal{margin:8px 0 14px;padding:12px;border:1px solid var(--border);border-radius:14px;background:var(--input)}.more-info{margin:8px 0;color:var(--muted);font-size:12px}.more-info summary{cursor:pointer;color:var(--green);font-weight:850}.more-info p{margin:8px 0 0}.settings-actions{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin:10px 0}.settings-actions.single-action{grid-template-columns:1fr}.settings-subtitle{margin:22px 0 8px;font-size:16px}.google-button-area{min-height:44px;display:flex;align-items:center;margin:10px 0}.google-button-area:empty{display:none}.google-account-card input:disabled{opacity:.55}.vault-head{display:flex;align-items:center;justify-content:space-between;gap:10px}h2{margin:0;font-size:18px}.muted{color:var(--muted);font-size:12px;margin:7px 0 12px}.pin-row{display:grid;grid-template-columns:1fr 96px;gap:8px}.filter{margin:4px 0 10px}.vault-actions{display:flex;gap:8px;margin-bottom:10px}.import-label{position:relative;overflow:hidden}.import-label input{position:absolute;inset:0;opacity:0}.entry{border:1px solid var(--border);border-radius:15px;padding:13px;margin-bottom:10px;background:var(--input)}.entry-title{font-weight:950;margin-bottom:7px}.entry-line{color:var(--text);font-size:13px;margin:4px 0}.entry-actions{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin-top:10px}.entry-actions button{padding:10px 8px}.danger{color:#ffe3e6;border-color:#70424a;background:#211014}.sensitive-note{color:var(--muted);font-size:11px;margin-left:5px}footer{width:min(100%,520px);margin:0 auto;padding:8px 12px 28px;color:var(--muted)}@media(max-width:380px){.security-key-grid{grid-template-columns:repeat(4,1fr)}.combo-slots{grid-template-columns:repeat(6,1fr)}.security-actions{grid-template-columns:1fr}.combo-actions{grid-template-columns:1fr}.options-grid{grid-template-columns:repeat(2,1fr)}.button-row{grid-template-columns:1fr}.result{grid-template-columns:1fr}.result .icon-btn.small{width:100%}.settings-actions{grid-template-columns:1fr}}`;
  }

  function makeGeneratedStyleFallback(config) {
    return `<style>${makeGeneratedCss(config)}</style>`;
  }

  function makeCoreGenerator() {
    return `"use strict";
const GOBLINPASS_ENGINE_VERSION = "${ENGINE_VERSION}";
const GP_CHARSETS = [
  { key: "lower", chars: "abcdefghijklmnopqrstuvwxyz" },
  { key: "upper", chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZ" },
  { key: "nums", chars: "0123456789" },
  { key: "symbols", chars: "%!@#$_-" }
];
const GP_MEMORABLE_WORDS = [
  "Amber", "Anchor", "Aspen", "Atlas", "Autumn", "Beacon", "Berry", "Blossom",
  "Bridge", "Bronze", "Canyon", "Cedar", "Cherry", "Cloud", "Comet", "Copper",
  "Crystal", "Daisy", "Delta", "Echo", "Ember", "Falcon", "Forest", "Frost",
  "Galaxy", "Garden", "Harbor", "Hazel", "Hidden", "Indigo", "Island", "Jasper",
  "Juniper", "Kernel", "Lagoon", "Lantern", "Maple", "Marble", "Meadow", "Meteor",
  "Midnight", "Mint", "Mountain", "Nectar", "Nova", "Ocean", "Olive", "Onyx",
  "Orbit", "Pebble", "Pepper", "Phoenix", "Pine", "Pixel", "Planet", "Purple",
  "Quartz", "River", "Rocket", "Saffron", "Shadow", "Silver", "Solstice", "Spark",
  "Stone", "Storm", "Summit", "Sunset", "Thistle", "Thunder", "Topaz", "Tulip",
  "Velvet", "Violet", "Willow", "Winter", "Zephyr", "Hammer", "Compass", "Puzzle",
  "Signal", "Castle", "Engine", "Voyage", "Button", "Cobalt"
];

async function gpSha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function gpCharFromSet(seed, set, round) {
  const hex = await gpSha256Hex(seed + "|required|" + set.key + "|" + round);
  const n = parseInt(hex.slice(0, 8), 16);
  return set.chars[n % set.chars.length];
}

async function gpDeterministicShuffle(items, seed) {
  const scored = [];
  for (let i = 0; i < items.length; i++) {
    scored.push({ value: items[i], score: await gpSha256Hex(seed + "|shuffle|" + i + "|" + items[i]) });
  }
  return scored.sort((a, b) => a.score.localeCompare(b.score)).map(item => item.value).join("");
}

async function gpDeterministicSetOrder(sets, seed, round) {
  const scored = [];
  for (let i = 0; i < sets.length; i++) {
    scored.push({ value: sets[i], score: await gpSha256Hex(seed + "|set-order|" + round + "|" + sets[i].key) });
  }
  return scored.sort((a, b) => a.score.localeCompare(b.score)).map(item => item.value);
}

async function gpDistributedCharacters(seed, sets, length) {
  const out = [];
  const minimumPerSet = Math.max(1, Math.min(2, Math.floor(length / sets.length)));

  for (const set of sets) {
    for (let i = 0; i < minimumPerSet && out.length < length; i++) {
      out.push(await gpCharFromSet(seed, set, i));
    }
  }

  let round = 0;
  while (out.length < length) {
    const orderedSets = await gpDeterministicSetOrder(sets, seed, round);
    for (const set of orderedSets) {
      if (out.length >= length) break;
      out.push(await gpCharFromSet(seed, set, minimumPerSet + round));
    }
    round++;
  }

  return out;
}

async function gpMemorableWord(seed, round) {
  const hex = await gpSha256Hex(seed + "|word|" + round);
  return GP_MEMORABLE_WORDS[parseInt(hex.slice(0, 8), 16) % GP_MEMORABLE_WORDS.length];
}

async function gpMemorablePassword(seed, strength) {
  const wordCount = strength === "easy" ? 3 : 4;
  const words = [];
  for (let i = 0; i < wordCount; i++) words.push(await gpMemorableWord(seed, i));
  if (strength === "strong") {
    const digitHex = await gpSha256Hex(seed + "|digit");
    const symbolHex = await gpSha256Hex(seed + "|symbol");
    const symbols = "!@#$%";
    return \`\${words.join("-")}\${symbols[parseInt(symbolHex.slice(0, 8), 16) % symbols.length]}\${parseInt(digitHex.slice(0, 8), 16) % 10}\`;
  }
  return words.join("-");
}

async function goblinPassGenerate(siteId, masterPassword, options = {}) {
  const length = Math.max(8, Math.min(64, parseInt(options.length || "16", 10)));
  const counter = Math.max(1, Math.min(999, parseInt(options.counter || "1", 10)));
  const selectedKeys = options.selectedKeys && options.selectedKeys.length ? options.selectedKeys : ["lower", "upper", "nums", "symbols"];
  const sets = GP_CHARSETS.filter(set => selectedKeys.includes(set.key));
  const optionKey = sets.map(set => set.key).join(",");
  const normalizedSiteId = String(siteId).trim().toLowerCase();
  const securityKey = String(options.securityKey || "");
  const trustedDeviceKey = String(options.trustedDeviceKey || "");
  const googleSubjectId = String(options.googleSubjectId || "");
  const passwordStyle = options.passwordStyle === "memorable" ? "memorable" : "maximum";
  const memorableStrength = ["easy", "standard", "strong"].includes(options.memorableStrength) ? options.memorableStrength : "standard";
  if (passwordStyle === "memorable") {
    const memorableSeed = \`GPMEMV1|\${normalizedSiteId}|\${counter}|\${masterPassword}|\${securityKey}|\${trustedDeviceKey}|\${googleSubjectId}|\${memorableStrength}\`;
    return gpMemorablePassword(memorableSeed, memorableStrength);
  }
  const seed = googleSubjectId && trustedDeviceKey
    ? \`GPIDV2TG|\${normalizedSiteId}|\${counter}|\${masterPassword}|\${securityKey}|\${trustedDeviceKey}|\${googleSubjectId}|\${optionKey}\`
    : googleSubjectId
    ? \`GPIDV2G|\${normalizedSiteId}|\${counter}|\${masterPassword}|\${securityKey}|\${googleSubjectId}|\${optionKey}\`
    : trustedDeviceKey
    ? \`GPIDV2T|\${normalizedSiteId}|\${counter}|\${masterPassword}|\${securityKey}|\${trustedDeviceKey}|\${optionKey}\`
    : securityKey
    ? \`GPIDV2K|\${normalizedSiteId}|\${counter}|\${masterPassword}|\${securityKey}|\${optionKey}\`
    : \`GPIDV2|\${normalizedSiteId}|\${counter}|\${masterPassword}|\${optionKey}\`;
  const out = await gpDistributedCharacters(seed, sets, length);
  return await gpDeterministicShuffle(out, seed);
}
window.goblinPassGenerate = goblinPassGenerate;`;
  }

  function makeCoreSecurity() {
    return `"use strict";
const GOBLINPASS_CORE_FILE_WARNING = "If core/password-generator.js or core/security.js changes, review the fork before trusting generated passwords.";
window.GOBLINPASS_ENGINE_VERSION = "${ENGINE_VERSION}";`;
  }

  function makeGeneratedAppJs(config) {
    return `"use strict";
const $ = (id) => document.getElementById(id);
let generatedPassword = "";
let generatedVisible = false;
let vaultUnlocked = false;
let vaultCryptoKey = null;
let securityKeyMemory = "";
let securityKeyRevealTimer = 0;
let securityKeyRevealVisible = false;
let googleUser = null;
let googleScriptPromise = null;
let lastGeneratedMeta = null;
const STORAGE_KEY = "goblinpass_mobile_entries_v1";
const PIN_KEY = "goblinpass_mobile_pin_v1";
const VAULT_ENCRYPTION_VERSION = "vault-aes-gcm-v1";
const VAULT_KDF_ITERATIONS = 250000;
const THEME_KEY = "goblinpass_brand_theme_v1";
const MODE_KEY = "goblinpass_interface_mode_v1";
const SETTINGS_KEY = "goblinpass_mobile_settings_v1";
const TRUSTED_DEVICE_KEY = "goblinpass_trusted_device_key_v1";
const GOOGLE_CLIENT_ID = "908605927082-sne248f74g829ek1kh1mh11gumjj411m.apps.googleusercontent.com";
const CHARSET_KEYS = ["lower", "upper", "nums", "symbols"];
const SECURITY_INPUT_METHODS = ["normal", "desktop-shuffled", "mobile-combo"];
const PASSWORD_STYLES = ["maximum", "memorable"];
const MEMORABLE_STRENGTHS = ["easy", "standard", "strong"];
const DEFAULT_THEME = {
  siteName: "${escapeHtml(config.siteName)}",
  tagline: "${escapeHtml(config.tagline)}",
  primary: "${config.primaryColour}",
  secondary: "${config.secondaryColour}",
  text: "${config.theme === "light" ? "#0b160f" : "#effff2"}",
  muted: "${config.theme === "light" ? "#4d6355" : "#9fc7aa"}"
};

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}
function maskText(value) {
  const s = String(value || "");
  if (!s) return "";
  if (s.length <= 4) return s[0] + "***";
  if (s.includes("@")) {
    const [name, domain] = s.split("@");
    return (name.length <= 4 ? name[0] + "***" : name.slice(0, 4) + "***" + name.slice(-2)) + "@" + domain;
  }
  return s.slice(0, 4) + "***" + s.slice(-2);
}
function selectedKeys() {
  const keys = CHARSET_KEYS.filter(key => $(key).checked);
  return keys.length ? keys : CHARSET_KEYS;
}
function loadSettings() {
  try {
    return {
      securityKeyEnabled: false,
      securityKeyInputMethod: "",
      trustedDeviceEnabled: false,
      trustedDeviceBackedUp: false,
      copyPasswordOnly: false,
      defaultPasswordStyle: "maximum",
      saveWebsiteIds: true,
      googleSecurityFactorEnabled: false,
      ...JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}")
    };
  }
  catch {
    return {
      securityKeyEnabled: false,
      securityKeyInputMethod: "",
      trustedDeviceEnabled: false,
      trustedDeviceBackedUp: false,
      copyPasswordOnly: false,
      defaultPasswordStyle: "maximum",
      saveWebsiteIds: true,
      googleSecurityFactorEnabled: false
    };
  }
}
function saveSettings(settings) {
  const next = { ...loadSettings(), ...settings };
  const method = SECURITY_INPUT_METHODS.includes(next.securityKeyInputMethod) ? next.securityKeyInputMethod : "";
  localStorage.setItem(SETTINGS_KEY, JSON.stringify({
    securityKeyEnabled: !!next.securityKeyEnabled,
    securityKeyInputMethod: method,
    trustedDeviceEnabled: !!next.trustedDeviceEnabled,
    trustedDeviceBackedUp: !!next.trustedDeviceBackedUp,
    copyPasswordOnly: !!next.copyPasswordOnly,
    defaultPasswordStyle: PASSWORD_STYLES.includes(next.defaultPasswordStyle) ? next.defaultPasswordStyle : "maximum",
    saveWebsiteIds: next.saveWebsiteIds !== false,
    googleSecurityFactorEnabled: !!next.googleSecurityFactorEnabled
  }));
}
function isSecurityKeyEnabled() { return !!loadSettings().securityKeyEnabled; }
function getDefaultPasswordStyle() {
  const style = loadSettings().defaultPasswordStyle;
  return PASSWORD_STYLES.includes(style) ? style : "maximum";
}
function getQuickPasswordStyle() {
  return PASSWORD_STYLES.includes($("passwordStyle")?.value) ? $("passwordStyle").value : getDefaultPasswordStyle();
}
function getMemorableStrength() {
  return MEMORABLE_STRENGTHS.includes($("memorableStrength")?.value) ? $("memorableStrength").value : "standard";
}
function clearGeneratedResult() {
  generatedPassword = "";
  generatedVisible = false;
  lastGeneratedMeta = null;
  if ($("result")) $("result").classList.add("hidden");
}
function updatePasswordStyleUi() {
  const style = getQuickPasswordStyle();
  if ($("memorableOptions")) $("memorableOptions").classList.toggle("hidden", style !== "memorable");
}
function isMobileDevice() { return window.matchMedia("(pointer: coarse), (max-width: 640px)").matches; }
function getDefaultSecurityInputMethod() { return isMobileDevice() ? "mobile-combo" : "desktop-shuffled"; }
function getSecurityInputMethod() {
  const settings = loadSettings();
  return SECURITY_INPUT_METHODS.includes(settings.securityKeyInputMethod) ? settings.securityKeyInputMethod : getDefaultSecurityInputMethod();
}
function getSecurityKeyInputValue() {
  if (!$("securityKey")) return "";
  if (getSecurityInputMethod() === "normal") return $("securityKey").value;
  return securityKeyMemory.length === 6 && !securityKeyMemory.includes(" ") ? securityKeyMemory : "";
}
function maskSecurityKeyDisplay() {
  const value = getSecurityInputMethod() === "normal" ? $("securityKey").value : securityKeyMemory;
  return value ? "\\u2022".repeat([...value].filter(char => char && char !== " ").length) : "";
}
function getSecurityProgressText() {
  return \`\${securityKeyMemory.split("").filter(char => char && char !== " ").length} of 6 characters selected\`;
}
function updateSecurityKeyDisplay() {
  if (!$("securityKey")) return;
  if (getSecurityInputMethod() === "normal") return;
  $("securityKey").value = securityKeyRevealVisible ? securityKeyMemory : maskSecurityKeyDisplay();
  const progress = document.querySelector("[data-security-progress]");
  if (progress) progress.textContent = getSecurityProgressText();
  document.querySelectorAll("[data-combo-slot]").forEach((button, index) => {
    const char = securityKeyMemory[index];
    if (securityKeyRevealVisible && char && char !== " ") button.textContent = char;
    else if (char && char !== " ") button.textContent = "*";
    else button.textContent = index < 2 ? "L" : "#";
  });
}
function setSecurityKeyMemory(value) {
  const limit = getSecurityInputMethod() === "normal" ? 64 : 6;
  securityKeyMemory = String(value || "").toUpperCase().slice(0, limit);
  updateSecurityKeyDisplay();
}
function applySecurityKeySetting() {
  const settings = loadSettings();
  let method = settings.securityKeyInputMethod;
  if (settings.securityKeyEnabled && !SECURITY_INPUT_METHODS.includes(method)) {
    method = getDefaultSecurityInputMethod();
    saveSettings({ ...settings, securityKeyInputMethod: method });
  }
  const enabled = !!settings.securityKeyEnabled;
  $("enableSecurityKey").checked = enabled;
  $("securityKeyInputMethod").value = SECURITY_INPUT_METHODS.includes(method) ? method : getDefaultSecurityInputMethod();
  $("securityKeyBox").classList.toggle("hidden", !enabled);
  if ($("securityKeyMethodGroup")) $("securityKeyMethodGroup").classList.toggle("hidden", !enabled);
  if ($("securityKeyWarning")) $("securityKeyWarning").classList.toggle("hidden", !enabled);
  $("securityKeyInputMethod").disabled = !enabled;
  $("securityKey").readOnly = enabled && getSecurityInputMethod() !== "normal";
  $("securityKey").placeholder = getSecurityInputMethod() === "mobile-combo" ? "[L] [L] [#] [#] [#] [#]" : "Example: GP4837";
  if (!enabled) clearSecurityKey();
  else if (getSecurityInputMethod() !== "normal") $("securityKey").value = maskSecurityKeyDisplay();
  else securityKeyMemory = "";
}
function showPage(pageId) {
  document.querySelectorAll("[data-page-target]").forEach(item => item.classList.toggle("active", item.dataset.pageTarget === pageId));
  document.querySelectorAll(".page-section").forEach(section => section.classList.toggle("hidden", section.id !== pageId));
}
function clearSecurityKey() {
  securityKeyMemory = "";
  securityKeyRevealVisible = false;
  clearTimeout(securityKeyRevealTimer);
  if ($("securityKey")) $("securityKey").value = "";
  closeSecurityInputPanel();
}
function bytesToBase64Url(bytes) {
  let binary = "";
  bytes.forEach(byte => { binary += String.fromCharCode(byte); });
  return btoa(binary).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/g, "");
}
function base64UrlToBytes(value) {
  const padded = String(value || "").replace(/-/g, "+").replace(/_/g, "/") + "===".slice((String(value || "").length + 3) % 4);
  return Uint8Array.from(atob(padded), char => char.charCodeAt(0));
}
function randomSalt() {
  return [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function deriveVaultKey(pin, salt) {
  const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(\`GOBLINPASS-VAULT-v1|\${salt}\`),
      iterations: VAULT_KDF_ITERATIONS,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
async function encryptVaultEntries(entries) {
  if (!vaultCryptoKey) throw new Error("Vault is locked.");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(entries || []));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, vaultCryptoKey, plaintext);
  return {
    version: VAULT_ENCRYPTION_VERSION,
    alg: "AES-GCM",
    kdf: "PBKDF2-SHA256",
    iterations: VAULT_KDF_ITERATIONS,
    iv: bytesToBase64Url(iv),
    data: bytesToBase64Url(new Uint8Array(ciphertext)),
    updated: new Date().toISOString()
  };
}
async function decryptVaultEntries(record) {
  if (!vaultCryptoKey) throw new Error("Vault is locked.");
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64UrlToBytes(record.iv || "") },
    vaultCryptoKey,
    base64UrlToBytes(record.data || "")
  );
  const entries = JSON.parse(new TextDecoder().decode(plaintext));
  return Array.isArray(entries) ? entries : [];
}
function createTrustedDeviceKey() {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}
function getTrustedDeviceKey() {
  return localStorage.getItem(TRUSTED_DEVICE_KEY) || "";
}
function setTrustedDeviceKey(key) {
  localStorage.setItem(TRUSTED_DEVICE_KEY, key);
}
function ensureTrustedDeviceKey() {
  let key = getTrustedDeviceKey();
  if (!key) {
    key = createTrustedDeviceKey();
    setTrustedDeviceKey(key);
    saveSettings({ trustedDeviceBackedUp: false });
  }
  return key;
}
function getTrustedDeviceGenerationKey() {
  return loadSettings().trustedDeviceEnabled ? ensureTrustedDeviceKey() : "";
}
function recoveryKeyFromTrustedKey(key) {
  return \`GP-TRUSTED-\${key}\`;
}
function trustedKeyFromRecoveryKey(value) {
  const clean = String(value || "").trim();
  const key = clean.startsWith("GP-TRUSTED-") ? clean.slice("GP-TRUSTED-".length) : clean;
  return /^[A-Za-z0-9_-]{32,}$/.test(key) ? key : "";
}
function updateTrustedDeviceStatus() {
  const settings = loadSettings();
  if ($("enableTrustedDevice")) $("enableTrustedDevice").checked = !!settings.trustedDeviceEnabled;
  if ($("copyPasswordOnly")) $("copyPasswordOnly").checked = !!settings.copyPasswordOnly;
  if ($("trustedDeviceDetails")) $("trustedDeviceDetails").classList.toggle("hidden", !settings.trustedDeviceEnabled);
  if ($("trustedDeviceWarning")) $("trustedDeviceWarning").classList.toggle("hidden", !settings.trustedDeviceEnabled);
  if (!$("trustedDeviceStatus")) return;
  if (!settings.trustedDeviceEnabled) {
    $("trustedDeviceStatus").textContent = "Trusted Device Protection: Disabled";
    return;
  }
  $("trustedDeviceStatus").textContent = \`Trusted Device Protection: Enabled - Recovery Key: \${settings.trustedDeviceBackedUp ? "Backed up" : "Not backed up"}\`;
}
async function showRecoveryKey() {
  const settings = loadSettings();
  if (!settings.trustedDeviceEnabled) return alert("Enable Trusted Device Protection first.");
  const ok = confirm("Anyone with this recovery key, your master password, and your Additional Secret can recreate your passwords. Store it safely offline.");
  if (!ok) return;
  const recoveryKey = recoveryKeyFromTrustedKey(ensureTrustedDeviceKey());
  try { await navigator.clipboard.writeText(recoveryKey); } catch {}
  prompt("Recovery Key. Store it safely offline.", recoveryKey);
  saveSettings({ trustedDeviceBackedUp: true });
  updateTrustedDeviceStatus();
}
function restoreTrustedDevice() {
  const value = prompt("Paste your Recovery Key:");
  if (value === null) return;
  const key = trustedKeyFromRecoveryKey(value);
  if (!key) return alert("That Recovery Key does not look valid.");
  setTrustedDeviceKey(key);
  saveSettings({ trustedDeviceEnabled: true, trustedDeviceBackedUp: true });
  updateTrustedDeviceStatus();
  alert("Trusted Device restored. Passwords using this Trusted Device Key can now be recreated here.");
}
function decodeJwtPayload(token) {
  try {
    const payload = token.split(".")[1];
    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const json = decodeURIComponent(atob(base64).split("").map(char => \`%\${char.charCodeAt(0).toString(16).padStart(2, "0")}\`).join(""));
    return JSON.parse(json);
  } catch {
    return null;
  }
}
function loadGoogleIdentityScript() {
  if (window.google?.accounts?.id) return Promise.resolve();
  if (googleScriptPromise) return googleScriptPromise;
  googleScriptPromise = new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = "https://accounts.google.com/gsi/client";
    script.async = true;
    script.defer = true;
    script.onload = resolve;
    script.onerror = () => reject(new Error("Could not load Google Identity Services."));
    document.head.appendChild(script);
  });
  return googleScriptPromise;
}
function updateGoogleStatus() {
  const settings = loadSettings();
  if ($("googleSecurityFactor")) $("googleSecurityFactor").checked = !!settings.googleSecurityFactorEnabled;
  if ($("googleSecurityWarning")) $("googleSecurityWarning").classList.toggle("hidden", !settings.googleSecurityFactorEnabled);
  if (!$("googleSignInStatus")) return;
  if (googleUser) {
    $("googleSignInStatus").textContent = settings.googleSecurityFactorEnabled
      ? \`Google Security Factor: Ready as \${googleUser.email || googleUser.name || "signed in"}\`
      : \`Google Sign-In: Signed in as \${googleUser.email || googleUser.name || "signed in"}\`;
    return;
  }
  $("googleSignInStatus").textContent = settings.googleSecurityFactorEnabled
    ? "Google Security Factor: Sign in required before generating"
    : "Google Sign-In: Not signed in";
}
function isGoogleSecurityFactorEnabled() {
  return !!loadSettings().googleSecurityFactorEnabled;
}
function getGoogleSubjectForGeneration() {
  return isGoogleSecurityFactorEnabled() && googleUser?.sub ? googleUser.sub : "";
}
function handleGoogleCredential(response) {
  const payload = decodeJwtPayload(response.credential || "");
  if (!payload) return alert("Google sign-in response could not be read.");
  googleUser = {
    sub: payload.sub || "",
    email: payload.email || "",
    name: payload.name || ""
  };
  updateGoogleStatus();
}
async function setupGoogleSignIn() {
  updateGoogleStatus();
  try {
    await loadGoogleIdentityScript();
    google.accounts.id.initialize({
      client_id: GOOGLE_CLIENT_ID,
      callback: handleGoogleCredential,
      auto_select: false
    });
    $("googleSignInButton").innerHTML = "";
    google.accounts.id.renderButton($("googleSignInButton"), {
      theme: "outline",
      size: "large",
      text: "signin_with",
      shape: "rectangular"
    });
  } catch (error) {
    alert(error.message);
  }
}
function googleSignOut() {
  googleUser = null;
  if (window.google?.accounts?.id) google.accounts.id.disableAutoSelect();
  updateGoogleStatus();
}
function closeSecurityInputPanel() {
  if ($("securityInputPanel")) {
    $("securityInputPanel").classList.add("hidden");
    $("securityInputPanel").innerHTML = "";
  }
}
function shuffleValues(values) {
  const copy = [...values];
  for (let i = copy.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}
function openDesktopSecurityKeyboard() {
  const panel = $("securityInputPanel");
  const keys = shuffleValues("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".split(""));
  panel.innerHTML = \`
    <p class="security-panel-title">Enter the full Additional Secret</p>
    <p class="security-progress" data-security-progress>\${getSecurityProgressText()}</p>
    <div class="security-key-grid">
      \${keys.map(key => \`<button type="button" data-security-key="\${key}">\${key}</button>\`).join("")}
    </div>
    <div class="security-actions">
      <button type="button" data-security-backspace>Backspace</button>
      <button type="button" data-security-clear>Clear</button>
      <button type="button" data-security-reveal>Reveal</button>
      <button type="button" data-security-done>Done</button>
    </div>\`;
  panel.classList.remove("hidden");
  panel.querySelectorAll("[data-security-key]").forEach(button => {
    button.onclick = () => setSecurityKeyMemory(securityKeyMemory + button.dataset.securityKey);
  });
  panel.querySelector("[data-security-backspace]").onclick = () => setSecurityKeyMemory(securityKeyMemory.slice(0, -1));
  panel.querySelector("[data-security-clear]").onclick = clearSecurityKey;
  panel.querySelector("[data-security-reveal]").onclick = revealSecurityKey;
  panel.querySelector("[data-security-done]").onclick = closeSecurityInputPanel;
  updateSecurityKeyDisplay();
}
function optionList(values) {
  return values.map(value => \`<option value="\${value}">\${value}</option>\`).join("");
}
function openMobileCombinationLock() {
  const panel = $("securityInputPanel");
  panel.innerHTML = \`
    <p class="security-panel-title">Choose 2 letters and 4 digits</p>
    <p class="security-progress" data-security-progress>\${getSecurityProgressText()}</p>
    <div class="combo-slots">
      \${[0, 1, 2, 3, 4, 5].map(index => \`<button type="button" data-combo-slot="\${index}">\${securityKeyMemory[index] && securityKeyMemory[index] !== " " ? "*" : (index < 2 ? "L" : "#")}</button>\`).join("")}
    </div>
    <div class="combo-choice-panel hidden" data-combo-choices></div>
    <div class="security-actions combo-actions">
      <button type="button" data-security-clear>Clear</button>
      <button type="button" data-security-reveal>Reveal</button>
      <button type="button" data-security-done>Done</button>
    </div>\`;
  panel.querySelectorAll("[data-combo-slot]").forEach(button => {
    button.onclick = () => openComboChoices(parseInt(button.dataset.comboSlot, 10));
  });
  panel.classList.remove("hidden");
  panel.querySelector("[data-security-clear]").onclick = clearSecurityKey;
  panel.querySelector("[data-security-reveal]").onclick = revealSecurityKey;
  panel.querySelector("[data-security-done]").onclick = closeSecurityInputPanel;
  updateSecurityKeyDisplay();
}
function openComboChoices(index) {
  const choices = document.querySelector("[data-combo-choices]");
  const values = (index < 2 ? "ABCDEFGHIJKLMNOPQRSTUVWXYZ" : "0123456789").split("");
  choices.innerHTML = \`
    <p class="security-panel-title">\${index < 2 ? "Choose a letter" : "Choose a digit"}</p>
    <div class="security-key-grid combo-choice-grid">
      \${values.map(value => \`<button type="button" data-combo-choice="\${value}">\${value}</button>\`).join("")}
    </div>\`;
  choices.classList.remove("hidden");
  choices.querySelectorAll("[data-combo-choice]").forEach(button => {
    button.onclick = () => {
      const chars = securityKeyMemory.padEnd(6, " ").split("");
      chars[index] = button.dataset.comboChoice;
      securityKeyMemory = chars.join("").trimEnd();
      securityKeyRevealVisible = false;
      choices.classList.add("hidden");
      choices.innerHTML = "";
      updateSecurityKeyDisplay();
    };
  });
}
function revealSecurityKey() {
  if (!securityKeyMemory) return;
  securityKeyRevealVisible = true;
  updateSecurityKeyDisplay();
  clearTimeout(securityKeyRevealTimer);
  securityKeyRevealTimer = setTimeout(() => {
    securityKeyRevealVisible = false;
    updateSecurityKeyDisplay();
  }, 3000);
}
function openSecurityInputMethod() {
  if (!isSecurityKeyEnabled()) return;
  const method = getSecurityInputMethod();
  if (method === "normal") return;
  if (method === "mobile-combo") openMobileCombinationLock();
  else openDesktopSecurityKeyboard();
}
function previewPassword(pw) {
  if (!pw) return "";
  if (pw.length <= 8) return pw[0] + "****" + pw.slice(-1);
  return pw.slice(0, 4) + "********" + pw.slice(-4);
}
function showResultMessage(message, allowShow = false) {
  if (!$("result") || !$("resultText")) return;
  $("resultText").textContent = message;
  $("result").classList.remove("hidden");
  if ($("toggleGenerated")) {
    $("toggleGenerated").classList.toggle("hidden", !allowShow);
    if (allowShow) $("toggleGenerated").textContent = generatedVisible ? "Hide" : "Show";
  }
}
async function copyGeneratedPassword() {
  if (!generatedPassword) return alert("Generate a password first.");
  try {
    await navigator.clipboard.writeText(generatedPassword);
    const visibleText = generatedVisible && !loadSettings().copyPasswordOnly ? generatedPassword : previewPassword(generatedPassword);
    $("resultText").textContent = "Copied: " + visibleText;
  } catch {
    alert("Clipboard copy was blocked. Use Show and copy it manually.");
  }
}
function getEntryId(entry) { return entry.siteId || ""; }
function getEntryKey(entry) { return entry.entryKey || entry.siteId || entry.site || entry.maskedLogin || entry.updated || ""; }
function getEntryTitle(entry) { return getEntryId(entry) || entry.site || getEntryLogin(entry) || "Saved entry"; }
function getEntryLogin(entry) { return entry.fullLogin || entry.maskedLogin || ""; }
async function loadEntries() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (!raw) return [];
  const parsed = JSON.parse(raw);
  if (Array.isArray(parsed)) {
    if (vaultCryptoKey) await saveEntries(parsed);
    return parsed;
  }
  if (parsed?.version === VAULT_ENCRYPTION_VERSION) return await decryptVaultEntries(parsed);
  if (Array.isArray(parsed?.entries)) {
    if (vaultCryptoKey) await saveEntries(parsed.entries);
    return parsed.entries;
  }
  return [];
}
async function saveEntries(entries) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(await encryptVaultEntries(entries)));
}
function getLogoInitials(value) {
  const words = String(value || "").trim().split(/\\s+/).filter(Boolean);
  if (!words.length) return "GP";
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[1][0]).toUpperCase();
}
function loadTheme() {
  try { return { ...DEFAULT_THEME, ...JSON.parse(localStorage.getItem(THEME_KEY) || "{}") }; }
  catch { return { ...DEFAULT_THEME }; }
}
function saveTheme(theme) { localStorage.setItem(THEME_KEY, JSON.stringify(theme)); }
function applyTheme(theme) {
  document.documentElement.style.setProperty("--green", theme.primary);
  document.documentElement.style.setProperty("--green2", theme.primary);
  document.documentElement.style.setProperty("--border", theme.primary);
  document.documentElement.style.setProperty("--border2", theme.primary);
  document.documentElement.style.setProperty("--card", theme.secondary);
  document.documentElement.style.setProperty("--card2", theme.secondary);
  document.documentElement.style.setProperty("--text", theme.text);
  document.documentElement.style.setProperty("--muted", theme.muted);
  document.getElementById("brandTitle").textContent = theme.siteName;
  document.getElementById("brandTagline").textContent = theme.tagline;
  const logoMark = document.getElementById("brandLogoMark");
  if (logoMark && logoMark.tagName !== "IMG") logoMark.textContent = getLogoInitials(theme.siteName);
  document.title = theme.siteName;
}
function syncThemeInputs(theme) {
  $("themeSiteName").value = theme.siteName;
  $("themeTagline").value = theme.tagline;
  $("themePrimary").value = theme.primary;
  $("themeSecondary").value = theme.secondary;
  $("themeText").value = theme.text;
  $("themeMuted").value = theme.muted;
}
function currentThemeFromInputs() {
  return {
    siteName: $("themeSiteName").value.trim() || DEFAULT_THEME.siteName,
    tagline: $("themeTagline").value.trim() || DEFAULT_THEME.tagline,
    primary: $("themePrimary").value,
    secondary: $("themeSecondary").value,
    text: $("themeText").value,
    muted: $("themeMuted").value
  };
}
function updateThemeFromInputs() {
  const theme = currentThemeFromInputs();
  saveTheme(theme);
  applyTheme(theme);
}
function applyMode(mode) {
  const simple = mode !== "advanced";
  document.body.classList.toggle("simple-mode", simple);
  $("simpleMode").classList.toggle("active", simple);
  $("advancedMode").classList.toggle("active", !simple);
}
function saveMode(mode) {
  localStorage.setItem(MODE_KEY, mode);
  applyMode(mode);
}
async function hashPin(pin, salt) { return await sha256Hex("GOBLINPASS-PIN-v1|" + pin + "|" + salt); }
async function getPinRecord() {
  const raw = localStorage.getItem(PIN_KEY) || "";
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed?.salt && parsed?.hash) return parsed;
  } catch {}
  return { legacyHash: raw };
}
async function savePinRecord(record) { localStorage.setItem(PIN_KEY, JSON.stringify(record)); }
async function setPin(pin) {
  const salt = randomSalt();
  const hash = await hashPin(pin, salt);
  await savePinRecord({ salt, hash, created: new Date().toISOString() });
  vaultCryptoKey = await deriveVaultKey(pin, salt);
}
async function checkPin(pin, record = null) {
  const saved = record || await getPinRecord();
  if (!saved) return false;
  if (saved.legacyHash) {
    const ok = await sha256Hex("GOBLINPASS-PIN-v1|" + pin) === saved.legacyHash;
    if (ok) {
      const salt = randomSalt();
      const hash = await hashPin(pin, salt);
      await savePinRecord({ salt, hash, migrated: new Date().toISOString() });
      vaultCryptoKey = await deriveVaultKey(pin, salt);
    }
    return ok;
  }
  const ok = await hashPin(pin, saved.salt) === saved.hash;
  if (ok) vaultCryptoKey = await deriveVaultKey(pin, saved.salt);
  return ok;
}
async function verifyPin(message) {
  const saved = await getPinRecord();
  if (!saved) {
    alert("Create a vault PIN first.");
    showPage("vaultPage");
    showVault();
    return false;
  }
  const pin = prompt(message || "Enter vault PIN:");
  if (pin === null) return false;
  const ok = await checkPin(pin, saved);
  if (!ok) alert("Wrong PIN.");
  return ok;
}
async function deterministicPassword(style = getQuickPasswordStyle(), strength = getMemorableStrength()) {
  return await window.goblinPassGenerate($("siteId").value, $("master").value, {
    length: $("length").value,
    counter: $("counter").value,
    selectedKeys: selectedKeys(),
    securityKey: isSecurityKeyEnabled() ? getSecurityKeyInputValue() : "",
    trustedDeviceKey: getTrustedDeviceGenerationKey(),
    googleSubjectId: getGoogleSubjectForGeneration(),
    passwordStyle: style,
    memorableStrength: strength
  });
}
async function generate() {
  if (!$("siteId").value.trim() || !$("master").value) return alert("Enter website ID and master password.");
  if (isSecurityKeyEnabled() && !getSecurityKeyInputValue()) return alert("Enter your Additional Secret, or turn it off in Settings.");
  if (isGoogleSecurityFactorEnabled() && !getGoogleSubjectForGeneration()) return alert("Sign in with Google before generating passwords, or turn off Google Security Factor in Settings.");
  const style = getQuickPasswordStyle();
  const strength = getMemorableStrength();
  generatedPassword = await deterministicPassword(style, strength);
  lastGeneratedMeta = { style, strength };
  generatedVisible = false;
  try { await navigator.clipboard.writeText(generatedPassword); } catch {}
  if (loadSettings().copyPasswordOnly) {
    $("resultText").textContent = "Password copied. Hidden by Copy Password Only mode.";
    $("toggleGenerated").classList.add("hidden");
  } else {
    $("resultText").textContent = "Generated and copied: " + previewPassword(generatedPassword);
    $("toggleGenerated").textContent = "Show";
    $("toggleGenerated").classList.remove("hidden");
  }
  $("result").classList.remove("hidden");
}
async function saveCurrent() {
  try {
    if (!vaultUnlocked && !(await verifyPin("Save requires your vault PIN."))) return;
    if (!$("siteId").value.trim()) return alert("Enter website ID before saving.");
    const savedStyle = getQuickPasswordStyle();
    const savedStrength = getMemorableStrength();
    let pw = generatedPassword;
    if (pw && (!lastGeneratedMeta || lastGeneratedMeta.style !== savedStyle || lastGeneratedMeta.strength !== savedStrength)) pw = "";
    if (!pw && isSecurityKeyEnabled() && !getSecurityKeyInputValue()) return alert("Enter your Additional Secret, or turn it off in Settings.");
    if (!pw && isGoogleSecurityFactorEnabled() && !getGoogleSubjectForGeneration()) return alert("Sign in with Google before saving this entry, or turn off Google Security Factor in Settings.");
    if (!pw && $("master").value) pw = await deterministicPassword(savedStyle, savedStrength);
    const login = $("login").value.trim();
    const settings = loadSettings();
    const siteId = $("siteId").value.trim().toLowerCase();
    const entry = {
      entryKey: "entry-" + bytesToBase64Url(crypto.getRandomValues(new Uint8Array(12))),
      siteId: settings.saveWebsiteIds ? siteId : "",
      idSaved: settings.saveWebsiteIds,
      site: $("site").value.trim().toLowerCase(),
      maskedLogin: maskText(login),
      fullLogin: $("storeFullLogin").checked ? login : "",
      fullLoginStored: $("storeFullLogin").checked,
      passwordHint: pw ? pw.slice(0, 5) : "",
      memorableStrength: getMemorableStrength(),
      length: parseInt($("length").value || "16", 10),
      counter: parseInt($("counter").value || "1", 10),
      options: {
        lower: $("lower").checked,
        upper: $("upper").checked,
        nums: $("nums").checked,
        symbols: $("symbols").checked
      },
      updated: new Date().toISOString()
    };
    const entries = await loadEntries();
    const existing = settings.saveWebsiteIds ? entries.findIndex(item => item.siteId === siteId) : -1;
    const updatedExisting = existing >= 0;
    if (updatedExisting) {
      entry.entryKey = entries[existing].entryKey || entry.entryKey;
      entries[existing] = entry;
    }
    else entries.unshift(entry);
    await saveEntries(entries);
    renderEntries();
    showResultMessage(updatedExisting ? "Updated vault entry." : "Saved to vault.", !!generatedPassword && !loadSettings().copyPasswordOnly);
  } catch (error) {
    alert("Could not save to vault: " + (error.message || error));
  }
}
async function setOrUnlockPin() {
  const pin = $("vaultPin").value.trim();
  if (!/^\\d{4}$/.test(pin)) return alert("Use a 4 digit PIN.");
  const saved = await getPinRecord();
  if (!saved) {
    const confirmPin = prompt("Confirm new vault PIN:");
    if (confirmPin !== pin) return alert("PINs did not match.");
    await setPin(pin);
    const existing = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    if (Array.isArray(existing)) await saveEntries(existing);
    vaultUnlocked = true;
    openVault();
    return;
  }
  if (!(await checkPin(pin, saved))) return alert("Wrong PIN.");
  vaultUnlocked = true;
  openVault();
}
function openVault() {
  $("pinBox").classList.add("hidden");
  $("vaultArea").classList.remove("hidden");
  $("vaultBtn").textContent = "Lock vault";
  $("vaultPin").value = "";
  renderEntries();
}
async function showVault() {
  if (vaultUnlocked) {
    vaultUnlocked = false;
    vaultCryptoKey = null;
    $("vaultArea").classList.add("hidden");
    $("pinBox").classList.add("hidden");
    $("vaultBtn").textContent = "Show vault";
    return;
  }
  $("vaultArea").classList.add("hidden");
  $("pinBox").classList.remove("hidden");
  $("vaultBtn").textContent = "Cancel";
  $("setOrUnlockPin").textContent = await getPinRecord() ? "Unlock" : "Set PIN";
}
function applyEntry(entry) {
  $("siteId").value = entry.siteId || "";
  $("site").value = entry.site || "";
  $("login").value = entry.fullLogin || entry.maskedLogin || "";
  $("storeFullLogin").checked = !!entry.fullLoginStored;
  $("passwordStyle").value = getDefaultPasswordStyle();
  $("memorableStrength").value = MEMORABLE_STRENGTHS.includes(entry.memorableStrength) ? entry.memorableStrength : "standard";
  $("length").value = entry.length || 16;
  $("counter").value = entry.counter || 1;
  $("lower").checked = !!entry.options?.lower;
  $("upper").checked = !!entry.options?.upper;
  $("nums").checked = !!entry.options?.nums;
  $("symbols").checked = !!entry.options?.symbols;
  updatePasswordStyleUi();
  window.scrollTo({ top: 0, behavior: "smooth" });
}
async function renderEntries() {
  if (!vaultUnlocked) return;
  const box = $("entries");
  const filter = ($("filter").value || "").toLowerCase();
  const entries = (await loadEntries()).filter(entry => (getEntryTitle(entry) + " " + entry.site + " " + getEntryLogin(entry)).toLowerCase().includes(filter));
  box.innerHTML = entries.length ? "" : '<p class="muted">No matching vault entries.</p>';
  entries.forEach(entry => {
    const div = document.createElement("div");
    div.className = "entry";
    div.innerHTML = \`<div class="entry-title">\${escapeHtml(getEntryTitle(entry))}</div>
      <div class="entry-line">Website ID: \${getEntryId(entry) ? escapeHtml(getEntryId(entry)) : "not saved"}</div>
      \${entry.site ? \`<div class="entry-line">Site: \${escapeHtml(entry.site)}</div>\` : ""}
      <div class="entry-line">Login: <span data-login>\${escapeHtml(entry.maskedLogin || "not saved")}</span>\${entry.fullLoginStored ? '<span class="sensitive-note">full stored</span>' : ""}</div>
      <div class="entry-line">Password hint: <span data-hint>*****</span></div>
      <div class="entry-line">Length: \${entry.length} - Counter: \${entry.counter}</div>
      <div class="entry-actions"><button data-use>Use</button><button data-show>Show hint</button><button data-copy>Copy login</button><button class="danger" data-delete>Delete</button></div>\`;
    div.querySelector("[data-use]").onclick = () => applyEntry(entry);
    div.querySelector("[data-show]").onclick = async () => {
      if (await verifyPin("Enter vault PIN to reveal hint.")) div.querySelector("[data-hint]").textContent = entry.passwordHint || "not saved";
    };
    div.querySelector("[data-copy]").onclick = async () => {
      if (await verifyPin("Enter vault PIN to copy login.")) {
        try { await navigator.clipboard.writeText(entry.fullLogin || entry.maskedLogin || ""); } catch {}
      }
    };
    div.querySelector("[data-delete]").onclick = async () => {
      if (!(await verifyPin("Enter vault PIN to delete."))) return;
      await saveEntries((await loadEntries()).filter(item => getEntryKey(item) !== getEntryKey(entry)));
      renderEntries();
    };
    box.appendChild(div);
  });
}
function escapeHtml(value) {
  return String(value || "").replace(/[&<>"']/g, ch => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[ch]));
}
async function exportVault() {
  if (!vaultUnlocked && !(await verifyPin("Export requires your vault PIN."))) return;
  const blob = new Blob([JSON.stringify({ version: "mobile-2", exported: new Date().toISOString(), entries: await loadEntries() }, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "goblinpass-mobile-export.json";
  a.click();
  URL.revokeObjectURL(url);
}
async function importVault(file) {
  if (!vaultUnlocked && !(await verifyPin("Import requires your vault PIN."))) return;
  const data = JSON.parse(await file.text());
  const incoming = Array.isArray(data) ? data : data.entries;
  if (!Array.isArray(incoming)) throw new Error("Invalid export file.");
  await saveEntries([...incoming, ...await loadEntries()]);
  renderEntries();
}
document.addEventListener("DOMContentLoaded", () => {
  const savedTheme = loadTheme();
  applyTheme(savedTheme);
  syncThemeInputs(savedTheme);
  applySecurityKeySetting();
  updateTrustedDeviceStatus();
  updateGoogleStatus();
  $("defaultPasswordStyle").value = getDefaultPasswordStyle();
  $("passwordStyle").value = getDefaultPasswordStyle();
  $("saveWebsiteIds").checked = loadSettings().saveWebsiteIds !== false;
  $("memorableStrength").value = "standard";
  updatePasswordStyleUi();
  applyMode(localStorage.getItem(MODE_KEY) || "simple");
  $("generate").onclick = generate;
  $("save").onclick = saveCurrent;
  $("vaultBtn").onclick = showVault;
  $("setOrUnlockPin").onclick = setOrUnlockPin;
  $("filter").oninput = renderEntries;
  $("exportBtn").onclick = exportVault;
  $("importFile").onchange = async event => {
    try { if (event.target.files[0]) await importVault(event.target.files[0]); }
    catch (error) { alert(error.message); }
  };
  $("toggleGenerated").onclick = () => {
    if (loadSettings().copyPasswordOnly) return;
    generatedVisible = !generatedVisible;
    $("resultText").textContent = generatedVisible ? "Generated and copied: " + generatedPassword : "Generated and copied: " + previewPassword(generatedPassword);
    $("toggleGenerated").textContent = generatedVisible ? "Hide" : "Show";
  };
  if ($("copyGenerated")) $("copyGenerated").onclick = copyGeneratedPassword;
  $("toggleMaster").onclick = () => {
    const visible = $("master").type === "password";
    $("master").type = visible ? "text" : "password";
    $("toggleMaster").textContent = visible ? "Hide" : "Show";
  };
  $("securityKey").onclick = openSecurityInputMethod;
  $("securityKey").oninput = () => {
    if (getSecurityInputMethod() === "normal") securityKeyMemory = "";
  };
  $("passwordStyle").onchange = () => {
    clearGeneratedResult();
    updatePasswordStyleUi();
  };
  $("memorableStrength").onchange = () => {
    clearGeneratedResult();
    updatePasswordStyleUi();
  };
  $("defaultPasswordStyle").onchange = () => {
    saveSettings({ defaultPasswordStyle: $("defaultPasswordStyle").value });
    clearGeneratedResult();
    updatePasswordStyleUi();
  };
  $("saveWebsiteIds").onchange = () => {
    saveSettings({ saveWebsiteIds: $("saveWebsiteIds").checked });
  };
  $("themeEditToggle").onclick = () => $("themeEditor").classList.toggle("hidden");
  document.querySelectorAll("[data-page-target]").forEach(button => {
    button.onclick = () => {
      showPage(button.dataset.pageTarget);
    };
  });
  $("enableSecurityKey").onchange = () => {
    const enabled = $("enableSecurityKey").checked;
    const existingMethod = loadSettings().securityKeyInputMethod;
    saveSettings({
      securityKeyEnabled: enabled,
      securityKeyInputMethod: enabled ? existingMethod || getDefaultSecurityInputMethod() : $("securityKeyInputMethod").value
    });
    applySecurityKeySetting();
  };
  $("securityKeyInputMethod").onchange = () => {
    clearSecurityKey();
    saveSettings({
      securityKeyEnabled: $("enableSecurityKey").checked,
      securityKeyInputMethod: $("securityKeyInputMethod").value
    });
    applySecurityKeySetting();
  };
  $("enableTrustedDevice").onchange = () => {
    const enabled = $("enableTrustedDevice").checked;
    if (enabled) ensureTrustedDeviceKey();
    saveSettings({
      trustedDeviceEnabled: enabled,
      trustedDeviceBackedUp: loadSettings().trustedDeviceBackedUp
    });
    updateTrustedDeviceStatus();
  };
  $("showRecoveryKey").onclick = showRecoveryKey;
  $("restoreTrustedDevice").onclick = restoreTrustedDevice;
  $("copyPasswordOnly").onchange = () => {
    saveSettings({ copyPasswordOnly: $("copyPasswordOnly").checked });
    updateTrustedDeviceStatus();
  };
  $("setupGoogleSignIn").onclick = setupGoogleSignIn;
  $("googleSignOut").onclick = googleSignOut;
  $("googleSecurityFactor").onchange = () => {
    const enabled = $("googleSecurityFactor").checked;
    if (enabled) {
      const ok = confirm("If you lose access to this Google account, you may not be able to regenerate the same passwords.");
      if (!ok) {
        $("googleSecurityFactor").checked = false;
        saveSettings({ googleSecurityFactorEnabled: false });
        updateGoogleStatus();
        return;
      }
    }
    saveSettings({ googleSecurityFactorEnabled: enabled });
    updateGoogleStatus();
  };
  ["themeSiteName", "themeTagline", "themePrimary", "themeSecondary", "themeText", "themeMuted"].forEach(id => {
    $(id).addEventListener("input", updateThemeFromInputs);
  });
  document.querySelectorAll("[data-colour]").forEach(button => {
    button.onclick = () => {
      $("themePrimary").value = button.dataset.colour;
      updateThemeFromInputs();
    };
  });
  document.querySelectorAll("[data-secondary]").forEach(button => {
    button.onclick = () => {
      $("themeSecondary").value = button.dataset.secondary;
      updateThemeFromInputs();
    };
  });
  document.querySelectorAll("[data-text]").forEach(button => {
    button.onclick = () => {
      $("themeText").value = button.dataset.text;
      updateThemeFromInputs();
    };
  });
  document.querySelectorAll("[data-muted]").forEach(button => {
    button.onclick = () => {
      $("themeMuted").value = button.dataset.muted;
      updateThemeFromInputs();
    };
  });
  $("themeReset").onclick = () => {
    localStorage.removeItem(THEME_KEY);
    syncThemeInputs(DEFAULT_THEME);
    applyTheme(DEFAULT_THEME);
  };
  $("simpleMode").onclick = () => saveMode("simple");
  $("advancedMode").onclick = () => saveMode("advanced");
});`;
  }

  function makeGeneratedManifest(config) {
    return JSON.stringify({
      name: config.siteName,
      short_name: config.siteName.slice(0, 12) || "GoblinPass",
      description: `${config.siteName} - local-first ID-based deterministic password helper.`,
      start_url: "./index.html",
      display: "standalone",
      background_color: config.theme === "light" ? "#f7fff8" : "#06100c",
      theme_color: config.secondaryColour,
      icons: [
        { src: "icon-192.png", sizes: "192x192", type: "image/png" },
        { src: "icon-512.png", sizes: "512x512", type: "image/png" }
      ]
    }, null, 2);
  }

  function textBytes(value) {
    return new TextEncoder().encode(value);
  }

  function makeCrcTable() {
    const table = [];
    for (let n = 0; n < 256; n += 1) {
      let c = n;
      for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      table[n] = c >>> 0;
    }
    return table;
  }

  const crcTable = makeCrcTable();

  function crc32(bytes) {
    let crc = 0 ^ -1;
    for (const byte of bytes) crc = (crc >>> 8) ^ crcTable[(crc ^ byte) & 0xff];
    return (crc ^ -1) >>> 0;
  }

  function u16(value) {
    return [value & 255, (value >>> 8) & 255];
  }

  function u32(value) {
    return [value & 255, (value >>> 8) & 255, (value >>> 16) & 255, (value >>> 24) & 255];
  }

  function makeZip(files) {
    const parts = [];
    const central = [];
    let offset = 0;

    files.forEach((file) => {
      const name = textBytes(file.name);
      const data = file.bytes;
      const crc = crc32(data);
      const local = new Uint8Array([
        ...u32(0x04034b50), ...u16(20), ...u16(0), ...u16(0), ...u16(0), ...u16(0),
        ...u32(crc), ...u32(data.length), ...u32(data.length), ...u16(name.length), ...u16(0)
      ]);
      parts.push(local, name, data);
      central.push(new Uint8Array([
        ...u32(0x02014b50), ...u16(20), ...u16(20), ...u16(0), ...u16(0), ...u16(0), ...u16(0),
        ...u32(crc), ...u32(data.length), ...u32(data.length), ...u16(name.length), ...u16(0), ...u16(0),
        ...u16(0), ...u16(0), ...u32(0), ...u32(offset)
      ]), name);
      offset += local.length + name.length + data.length;
    });

    const centralSize = central.reduce((sum, part) => sum + part.length, 0);
    const end = new Uint8Array([
      ...u32(0x06054b50), ...u16(0), ...u16(0), ...u16(files.length), ...u16(files.length),
      ...u32(centralSize), ...u32(offset), ...u16(0)
    ]);
    return new Blob([...parts, ...central, end], { type: "application/zip" });
  }

  function transparentPngBytes() {
    const binary = atob("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/p9sAAAAASUVORK5CYII=");
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  }

  function bytesToBase64(bytes) {
    let binary = "";
    for (let index = 0; index < bytes.length; index += 8192) {
      binary += String.fromCharCode(...bytes.slice(index, index + 8192));
    }
    return btoa(binary);
  }

  function downloadForkPackage() {
    const config = getBrandConfig();
    const logoBytes = uploadedLogo ? uploadedLogo.bytes : transparentPngBytes();
    const configJson = JSON.stringify(config, null, 2);
    const generatedCss = makeGeneratedCss(config);
    const files = [
      { name: "index.html", bytes: textBytes(makeGeneratedIndex(config)) },
      { name: "about.html", bytes: textBytes(makeGeneratedAbout(config)) },
      { name: "readme.html", bytes: textBytes(makeGeneratedReadmeHtml(config)) },
      { name: "README.md", bytes: textBytes(makeGeneratedReadmeMarkdown(config)) },
      { name: "app.js", bytes: textBytes(makeGeneratedAppJs(config)) },
      { name: "style.css", bytes: textBytes(generatedCss) },
      { name: "assets/css/style.css", bytes: textBytes(generatedCss) },
      { name: "manifest.webmanifest", bytes: textBytes(makeGeneratedManifest(config)) },
      { name: "config.json", bytes: textBytes(configJson) },
      { name: "themes/config.json", bytes: textBytes(configJson) },
      { name: "logo.png", bytes: logoBytes },
      { name: "assets/logo.png", bytes: logoBytes },
      { name: "icon-192.png", bytes: logoBytes },
      { name: "icon-512.png", bytes: logoBytes },
      { name: "core/password-generator.js", bytes: textBytes(makeCoreGenerator()) },
      { name: "core/security.js", bytes: textBytes(makeCoreSecurity()) }
    ];
    try {
      const blob = makeZip(files);
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `${config.siteName.toLowerCase().replace(/[^a-z0-9]+/g, "-") || "goblinpass-fork"}.zip`;
      document.body.appendChild(link);
      link.click();
      setTimeout(() => {
        URL.revokeObjectURL(link.href);
        link.remove();
      }, 1000);
    } catch (error) {
      alert("Could not build the fork package. Please refresh the page and try again.");
    }
  }

  function analyzePassword(value) {
    if (!value) {
      return {
        checks: {
          length: false,
          uppercase: false,
          lowercase: false,
          numbers: false,
          symbols: false,
          notCommon: false,
          notRepeated: false,
          notKeyboard: false
        },
        warnings: [],
        score: 0,
        label: "Empty",
        crackEstimate: "No password yet"
      };
    }

    const normalized = normalizeLeetspeak(value);
    const exactCommon = commonPasswords.has(value.toLowerCase()) || commonPasswords.has(normalized);
    const repeatedChunk = getRepeatedChunk(value);
    const commonWord = getCommonWordMatch(value);
    const commonWordRepeats = countCommonWordRepeats(value, commonWord);
    const checks = {
      length: value.length >= 12,
      uppercase: /[A-Z]/.test(value),
      lowercase: /[a-z]/.test(value),
      numbers: /[0-9]/.test(value),
      symbols: /[^A-Za-z0-9]/.test(value),
      notCommon: !exactCommon && !commonWord,
      notRepeated: !hasRepeatedCharacters(value) && !repeatedChunk,
      notKeyboard: !hasKeyboardPattern(value)
    };

    const warnings = [];
    if (value.length > 0 && value.length < 10) warnings.push("This password is short enough to be guessed quickly.");
    if (!checks.notCommon) warnings.push("This looks like a password attackers already expect.");
    if (repeatedChunk || commonWordRepeats > 1) warnings.push("Repeating the same word or block adds length without adding much surprise.");
    if (!checks.notRepeated && !repeatedChunk) warnings.push("Repeated letters, numbers, or blocks make the password easier to predict.");
    if (!checks.notKeyboard) warnings.push("Keyboard rows and counting sequences are common first guesses.");
    if (value && normalized !== value.toLowerCase() && commonPasswords.has(normalized)) {
      warnings.push("Symbol swaps such as @, 0, and 1 do not hide a familiar word well.");
    }
    if (commonWord && !commonPasswords.has(normalized)) {
      warnings.push("A familiar word inside the password makes it easier to narrow down.");
    }

    let score = 0;
    score += Math.min(value.length * 4, 48);
    score += checks.uppercase ? 8 : 0;
    score += checks.lowercase ? 8 : 0;
    score += checks.numbers ? 10 : 0;
    score += checks.symbols ? 12 : 0;
    score += value.length >= 16 ? 8 : 0;
    score += checks.notCommon ? 6 : -24;
    score += checks.notRepeated ? 4 : -14;
    score += checks.notKeyboard ? 4 : -14;

    if (value.length > 0 && value.length < 8) score -= 18;
    if (exactCommon) score = Math.min(score, 18);
    if (repeatedChunk || commonWordRepeats > 1) score = Math.min(score, repeatedChunk.length <= 5 ? 28 : 36);
    if (commonWord && !checks.numbers && !checks.symbols) score = Math.min(score, 45);
    if (commonWord && value.length <= commonWord.length + 4) score = Math.min(score, 34);
    score = Math.max(0, Math.min(100, Math.round(score)));

    const poolSize = getPoolSize(value);
    const effectiveLength = estimateEffectiveLength(value, repeatedChunk, commonWord, commonWordRepeats);
    const guesses = Math.pow(poolSize, Math.min(effectiveLength, 32)) / 2;
    const seconds = value.length ? applyScoreBasedTimeCap(guesses / estimateGuessesPerSecond(), score) : 0;

    return {
      checks,
      warnings,
      score,
      label: getLabel(score, value.length),
      crackEstimate: value.length ? formatTime(seconds) : "No password yet"
    };
  }

  function renderChecklist(checks) {
    checklistItems.forEach((item) => {
      const key = item.dataset.check;
      item.classList.toggle("pass", Boolean(checks[key]));
    });
  }

  function renderWarnings(warnings) {
    warningsList.innerHTML = "";

    if (warnings.length === 0) {
      const item = document.createElement("li");
      item.textContent = "No obvious warning signs found.";
      warningsList.appendChild(item);
      return;
    }

    warnings.forEach((warning) => {
      const item = document.createElement("li");
      item.textContent = warning;
      warningsList.appendChild(item);
    });
  }

  function update() {
    const value = passwordInput.value;
    const result = analyzePassword(value);

    strengthLabel.textContent = result.label;
    strengthSummary.textContent = value
      ? "Score updates as the password changes."
      : "Start typing to see a local score.";
    scoreValue.textContent = `${result.score} / 100`;
    crackTime.textContent = result.crackEstimate;
    meterFill.style.width = `${result.score}%`;
    meterFill.style.minWidth = value && result.score > 0 ? "28px" : "0";
    meterFill.style.backgroundColor = getMeterColor(result.score);

    renderChecklist(result.checks);
    renderWarnings(value ? result.warnings : ["Enter a password to see warning signs."]);
  }

  if (togglePassword && passwordInput) {
    togglePassword.addEventListener("click", () => {
      const shouldShow = passwordInput.type === "password";
      passwordInput.type = shouldShow ? "text" : "password";
      togglePassword.setAttribute("aria-label", shouldShow ? "Hide password" : "Show password");
      togglePassword.querySelector("span").textContent = shouldShow ? "Hide" : "Show";
      passwordInput.focus();
    });
  }

  if (navToggle && navLinks) {
    navToggle.addEventListener("click", () => {
      const isOpen = navLinks.classList.toggle("open");
      navToggle.setAttribute("aria-expanded", String(isOpen));
      navToggle.setAttribute("aria-label", isOpen ? "Close navigation menu" : "Open navigation menu");
    });

    navLinks.addEventListener("click", (event) => {
      if (event.target.matches("a")) {
        const openDropdown = navLinks.querySelector("details[open]");
        if (openDropdown) openDropdown.removeAttribute("open");
        navLinks.classList.remove("open");
        navToggle.setAttribute("aria-expanded", "false");
        navToggle.setAttribute("aria-label", "Open navigation menu");
      }
    });
  }

  if (engineVersion) engineVersion.textContent = ENGINE_VERSION;

  if (brandFields.siteName && brandFields.logo && downloadFork) {
    Object.values(brandFields).forEach((field) => {
      if (!field || field.type === "file") return;
      field.addEventListener("input", renderBrandPreview);
      field.addEventListener("change", renderBrandPreview);
    });

    brandFields.logo.addEventListener("change", () => {
      const file = brandFields.logo.files[0];
      if (!file) {
        uploadedLogo = null;
        renderBrandPreview();
        return;
      }

      const reader = new FileReader();
      reader.addEventListener("load", () => {
        const bytes = new Uint8Array(reader.result);
        uploadedLogo = {
          bytes,
          dataUrl: `data:${file.type || "image/png"};base64,${bytesToBase64(bytes)}`
        };
        renderBrandPreview();
      });
      reader.readAsArrayBuffer(file);
    });

    downloadFork.addEventListener("click", downloadForkPackage);
    renderBrandPreview();
  }

  if (passwordInput) {
    passwordInput.addEventListener("input", update);
    update();
  }
})();
