const $ = (id) => document.getElementById(id);

let generatedPassword = "";
let generatedVisible = false;
let vaultUnlocked = false;
let vaultCryptoKey = null;
let pinFailCount = 0;
let pinLockedUntil = 0;
let securityKeyMemory = "";
let securityKeyRevealTimer = 0;
let securityKeyRevealVisible = false;
let googleUser = null;
let googleScriptPromise = null;
let lastGeneratedMeta = null;
let currentYubiKeyFactor = "";

const STORAGE_KEY = "goblinpass_mobile_entries_v1";
const PIN_KEY = "goblinpass_mobile_pin_v1";
const VAULT_ENCRYPTION_VERSION = "vault-aes-gcm-v1";
const VAULT_KDF_ITERATIONS = 250000;
const SETTINGS_KEY = "goblinpass_mobile_settings_v1";
const TRUSTED_DEVICE_KEY = "goblinpass_trusted_device_key_v1";
const YUBIKEY_CREDENTIAL_KEY = "goblinpass_yubikey_credential_id_v1";
const YUBIKEY_MODE_KEY = "goblinpass_yubikey_mode_v2";
const YUBIKEY_CAPABILITY_KEY = "goblinpass_yubikey_capability_v1";
const GOOGLE_CLIENT_ID = "908605927082-sne248f74g829ek1kh1mh11gumjj411m.apps.googleusercontent.com";
const PRIVATE_BROWSING_YUBIKEY_WARNING = "YubiKey mode may not work in private/incognito browsing because the registered credential cannot be reused. Please use normal browser mode.";
const MOBILE_YUBIKEY_PRF_WARNING = "Mobile browsers may register a YubiKey but fail to reuse it for WebAuthn PRF. If PRF mode fails on this phone, use a desktop browser in normal mode.";

const CHARSETS = [
  { key: "lower", chars: "abcdefghijklmnopqrstuvwxyz" },
  { key: "upper", chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZ" },
  { key: "nums", chars: "0123456789" },
  { key: "symbols", chars: "%!@#$_-" }
];
const SECURITY_INPUT_METHODS = ["normal", "desktop-shuffled", "mobile-combo"];
const PASSWORD_STYLES = ["maximum", "memorable"];
const MEMORABLE_STRENGTHS = ["easy", "standard", "strong"];
const MEMORABLE_WORDS = [
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
  "Signal", "Castle", "Engine", "Lantern", "Voyage", "Harbor", "Button", "Cobalt"
];

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function randomSalt() {
  return [...crypto.getRandomValues(new Uint8Array(16))]
    .map(b => b.toString(16).padStart(2, "0")).join("");
}

async function getPinRecord() {
  const raw = localStorage.getItem(PIN_KEY) || "";
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (parsed?.salt && parsed?.hash) return parsed;
  } catch {}
  return { legacyHash: raw };
}

async function savePinRecord(record) {
  localStorage.setItem(PIN_KEY, JSON.stringify(record));
}

async function hashPin(pin, salt) {
  return await sha256Hex("GOBLINPASS-PIN-v1|" + pin + "|" + salt);
}

async function deriveVaultKey(pin, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(pin),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(`GOBLINPASS-VAULT-v1|${salt}`),
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
  const iv = base64UrlToBytes(record.iv || "");
  const data = base64UrlToBytes(record.data || "");
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, vaultCryptoKey, data);
  const entries = JSON.parse(new TextDecoder().decode(plaintext));
  return Array.isArray(entries) ? entries : [];
}

function maskText(s) {
  if (!s) return "";
  if (s.length <= 4) return s[0] + "***";
  if (s.includes("@")) {
    const [name, domain] = s.split("@");
    const left = name.length <= 4 ? name[0] + "***" : name.slice(0, 4) + "***" + name.slice(-2);
    return left + "@" + domain;
  }
  return s.slice(0, 4) + "***" + s.slice(-2);
}

function storedLoginObject(login, storeFull) {
  return { maskedLogin: maskText(login), fullLogin: storeFull ? login : "", fullLoginStored: !!storeFull };
}

function getEntryId(e) { return e.siteId || e.id || ""; }
function getEntryKey(e) { return e.entryKey || e.siteId || e.id || e.site || e.maskedLogin || e.updated || ""; }
function getEntryTitle(e) { return getEntryId(e) || e.site || getEntryLoginForDisplay(e) || "Saved entry"; }
function getEntrySite(e) { return e.site || ""; }
function getEntryLoginForDisplay(e) { return e.maskedLogin || maskText(e.login || ""); }
function getEntryFullLogin(e) { return e.fullLogin || e.login || ""; }
function canRevealFullLogin(e) { return !!(e.fullLogin || e.login); }

function selectedCharsets() {
  const selected = CHARSETS.filter(set => $(set.key).checked);
  return selected.length ? selected : CHARSETS;
}

function loadSettings() {
  try {
    const saved = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}");
    return {
      securityKeyEnabled: false,
      securityKeyInputMethod: "",
      trustedDeviceEnabled: false,
      trustedDeviceBackedUp: false,
      copyPasswordOnly: false,
      defaultPasswordStyle: "maximum",
      saveWebsiteIds: true,
      useMasterPassword: true,
      googleSecurityFactorEnabled: false,
      offlineDeviceMode: false,
      ...saved
    };
  } catch {
    return {
      securityKeyEnabled: false,
      securityKeyInputMethod: "",
      trustedDeviceEnabled: false,
      trustedDeviceBackedUp: false,
      copyPasswordOnly: false,
      defaultPasswordStyle: "maximum",
      saveWebsiteIds: true,
      useMasterPassword: true,
      googleSecurityFactorEnabled: false,
      offlineDeviceMode: false
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
    useMasterPassword: next.useMasterPassword !== false,
    googleSecurityFactorEnabled: !!next.googleSecurityFactorEnabled,
    offlineDeviceMode: !!next.offlineDeviceMode
  }));
}

function isMasterPasswordEnabled() {
  return loadSettings().useMasterPassword !== false;
}

function isSecurityKeyEnabled() {
  return !!loadSettings().securityKeyEnabled;
}

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
  hidePasswordQr();
}

function applyMasterPasswordSetting() {
  const enabled = isMasterPasswordEnabled();
  if ($("useMasterPassword")) $("useMasterPassword").checked = enabled;
  if ($("masterPasswordGroup")) $("masterPasswordGroup").classList.toggle("hidden", !enabled);
  if ($("masterPasswordWarning")) $("masterPasswordWarning").classList.toggle("hidden", enabled);
  if (!enabled && $("master")) {
    $("master").value = "";
    $("master").type = "password";
    if ($("toggleMaster")) $("toggleMaster").textContent = "Show";
  }
  clearGeneratedResult();
}

function updatePasswordStyleUi() {
  const style = getQuickPasswordStyle();
  if ($("memorableOptions")) $("memorableOptions").classList.toggle("hidden", style !== "memorable");
}

function getSecurityKeyInputValue() {
  if (!$("securityKey")) return "";
  if (getSecurityInputMethod() === "normal") return $("securityKey").value;
  return securityKeyMemory.length === 6 && !securityKeyMemory.includes(" ") ? securityKeyMemory : "";
}

function isMobileDevice() {
  return window.matchMedia("(pointer: coarse), (max-width: 640px)").matches;
}

function getDefaultSecurityInputMethod() {
  return isMobileDevice() ? "mobile-combo" : "desktop-shuffled";
}

function getSecurityInputMethod() {
  const settings = loadSettings();
  return SECURITY_INPUT_METHODS.includes(settings.securityKeyInputMethod)
    ? settings.securityKeyInputMethod
    : getDefaultSecurityInputMethod();
}

function maskSecurityKeyDisplay() {
  const value = getSecurityInputMethod() === "normal" ? $("securityKey").value : securityKeyMemory;
  return value ? "\u2022".repeat([...value].filter(char => char && char !== " ").length) : "";
}

function getSecurityProgressText() {
  return `${securityKeyMemory.split("").filter(char => char && char !== " ").length} of 6 characters selected`;
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
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  return Uint8Array.from(atob(padded), char => char.charCodeAt(0));
}

const QR_VERSION = 4;
const QR_SIZE = 33;
const QR_DATA_CODEWORDS = 80;
const QR_ECC_CODEWORDS = 20;

function initQrGf() {
  const exp = new Array(512);
  const log = new Array(256);
  let x = 1;
  for (let i = 0; i < 255; i++) {
    exp[i] = x;
    log[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) exp[i] = exp[i - 255];
  return { exp, log };
}

const QR_GF = initQrGf();

function qrGfMul(a, b) {
  if (!a || !b) return 0;
  return QR_GF.exp[QR_GF.log[a] + QR_GF.log[b]];
}

function qrGeneratorPoly(degree) {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= qrGfMul(poly[j], QR_GF.exp[i]);
    }
    poly = next;
  }
  return poly;
}

function qrErrorCorrection(data, degree) {
  const gen = qrGeneratorPoly(degree);
  const ecc = new Array(degree).fill(0);
  data.forEach(byte => {
    const factor = byte ^ ecc.shift();
    ecc.push(0);
    for (let i = 0; i < degree; i++) ecc[i] ^= qrGfMul(gen[i + 1], factor);
  });
  return ecc;
}

function qrPushBits(bits, value, length) {
  for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1);
}

function qrDataCodewords(text) {
  const bytes = [...new TextEncoder().encode(text)];
  if (bytes.length > 78) throw new Error("QR transfer supports passwords up to 78 bytes.");
  const bits = [];
  qrPushBits(bits, 0b0100, 4);
  qrPushBits(bits, bytes.length, 8);
  bytes.forEach(byte => qrPushBits(bits, byte, 8));
  const maxBits = QR_DATA_CODEWORDS * 8;
  qrPushBits(bits, 0, Math.min(4, maxBits - bits.length));
  while (bits.length % 8) bits.push(0);
  const codewords = [];
  for (let i = 0; i < bits.length; i += 8) {
    codewords.push(bits.slice(i, i + 8).reduce((value, bit) => (value << 1) | bit, 0));
  }
  for (let pad = 0xec; codewords.length < QR_DATA_CODEWORDS; pad = pad === 0xec ? 0x11 : 0xec) {
    codewords.push(pad);
  }
  return codewords;
}

function qrFormatBits(mask) {
  let data = (0b01 << 3) | mask;
  let value = data << 10;
  for (let i = 14; i >= 10; i--) {
    if ((value >>> i) & 1) value ^= 0x537 << (i - 10);
  }
  return ((data << 10) | value) ^ 0x5412;
}

function makeQrMatrix(text) {
  const modules = Array.from({ length: QR_SIZE }, () => Array(QR_SIZE).fill(null));
  const set = (x, y, dark) => {
    if (x >= 0 && y >= 0 && x < QR_SIZE && y < QR_SIZE) modules[y][x] = !!dark;
  };

  function finder(x, y) {
    for (let yy = -1; yy <= 7; yy++) {
      for (let xx = -1; xx <= 7; xx++) {
        const edge = xx === -1 || yy === -1 || xx === 7 || yy === 7;
        const dark = !edge && (xx === 0 || yy === 0 || xx === 6 || yy === 6 || (xx >= 2 && xx <= 4 && yy >= 2 && yy <= 4));
        set(x + xx, y + yy, dark);
      }
    }
  }

  function alignment(cx, cy) {
    for (let yy = -2; yy <= 2; yy++) {
      for (let xx = -2; xx <= 2; xx++) {
        set(cx + xx, cy + yy, Math.max(Math.abs(xx), Math.abs(yy)) !== 1);
      }
    }
  }

  finder(0, 0);
  finder(QR_SIZE - 7, 0);
  finder(0, QR_SIZE - 7);
  alignment(26, 26);
  for (let i = 8; i < QR_SIZE - 8; i++) {
    set(i, 6, i % 2 === 0);
    set(6, i, i % 2 === 0);
  }
  set(8, QR_SIZE - 8, true);

  const reserveFormat = [
    ...Array.from({ length: 6 }, (_, i) => [8, i]),
    [8, 7], [8, 8], [7, 8],
    ...Array.from({ length: 6 }, (_, i) => [5 - i, 8]),
    ...Array.from({ length: 8 }, (_, i) => [QR_SIZE - 1 - i, 8]),
    ...Array.from({ length: 7 }, (_, i) => [8, QR_SIZE - 7 + i])
  ];
  reserveFormat.forEach(([x, y]) => set(x, y, false));

  const data = qrDataCodewords(text);
  const codewords = data.concat(qrErrorCorrection(data, QR_ECC_CODEWORDS));
  const bits = [];
  codewords.forEach(byte => qrPushBits(bits, byte, 8));

  let bitIndex = 0;
  let upward = true;
  for (let x = QR_SIZE - 1; x > 0; x -= 2) {
    if (x === 6) x--;
    for (let i = 0; i < QR_SIZE; i++) {
      const y = upward ? QR_SIZE - 1 - i : i;
      for (let dx = 0; dx < 2; dx++) {
        const xx = x - dx;
        if (modules[y][xx] !== null) continue;
        const bit = bits[bitIndex++] || 0;
        const masked = bit ^ (((xx + y) % 2) === 0 ? 1 : 0);
        set(xx, y, masked);
      }
    }
    upward = !upward;
  }

  const format = qrFormatBits(0);
  const formatBit = i => ((format >>> i) & 1) === 1;
  for (let i = 0; i < 6; i++) set(8, i, formatBit(i));
  set(8, 7, formatBit(6));
  set(8, 8, formatBit(7));
  set(7, 8, formatBit(8));
  for (let i = 9; i < 15; i++) set(14 - i, 8, formatBit(i));
  for (let i = 0; i < 8; i++) set(QR_SIZE - 1 - i, 8, formatBit(i));
  for (let i = 8; i < 15; i++) set(8, QR_SIZE - 15 + i, formatBit(i));

  return modules;
}

function drawQrToCanvas(text) {
  const panel = $("qrTransfer");
  const canvas = $("passwordQr");
  if (!panel || !canvas) return;
  try {
    const matrix = makeQrMatrix(text);
    const scale = 7;
    const quiet = 4;
    const size = (QR_SIZE + quiet * 2) * scale;
    canvas.width = size;
    canvas.height = size;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#ffffff";
    ctx.fillRect(0, 0, size, size);
    ctx.fillStyle = "#000000";
    matrix.forEach((row, y) => row.forEach((dark, x) => {
      if (dark) ctx.fillRect((x + quiet) * scale, (y + quiet) * scale, scale, scale);
    }));
    panel.classList.remove("hidden");
  } catch (error) {
    panel.classList.add("hidden");
    alert(error.message || "Could not create QR code.");
  }
}

function hidePasswordQr() {
  if ($("qrTransfer")) $("qrTransfer").classList.add("hidden");
}

function credentialIdBuffer(id) {
  const bytes = base64UrlToBytes(id);
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
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
  return `GP-TRUSTED-${key}`;
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
  $("trustedDeviceStatus").textContent = `Trusted Device Protection: Enabled - Recovery Key: ${settings.trustedDeviceBackedUp ? "Backed up" : "Not backed up"}`;
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
    const json = decodeURIComponent(atob(base64).split("").map(char => `%${char.charCodeAt(0).toString(16).padStart(2, "0")}`).join(""));
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
      ? `Google Security Factor: Ready as ${googleUser.email || googleUser.name || "signed in"}`
      : `Google Sign-In: Signed in as ${googleUser.email || googleUser.name || "signed in"}`;
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

function getYubiKeyCredentialId() {
  try {
    return localStorage.getItem(YUBIKEY_CREDENTIAL_KEY) || "";
  } catch {
    return "";
  }
}

function getYubiKeyMode() {
  return "prf";
}

function setYubiKeyMode(mode) {
  try { localStorage.setItem(YUBIKEY_MODE_KEY, "prf"); } catch {}
}

function getYubiKeyCapability() {
  try {
    return JSON.parse(localStorage.getItem(YUBIKEY_CAPABILITY_KEY) || "{}");
  } catch {
    return {};
  }
}

function saveYubiKeyCapability(capability) {
  try {
    localStorage.setItem(YUBIKEY_CAPABILITY_KEY, JSON.stringify({
      prfAvailable: !!capability.prfAvailable,
      hmacSecretAvailable: !!capability.hmacSecretAvailable,
      touchGateAvailable: !!capability.touchGateAvailable,
      authenticatorAttachment: capability.authenticatorAttachment || "",
      createResults: capability.createResults || "",
      getResults: capability.getResults || "",
      prfRequestShape: capability.prfRequestShape || "",
      rpId: capability.rpId || webAuthnRpId(),
      storedCredentialIdLength: capability.storedCredentialIdLength || 0,
      allowCredentialsSupplied: !!capability.allowCredentialsSupplied,
      prfResultReturned: !!capability.prfResultReturned,
      browserUserAgent: capability.browserUserAgent || navigator.userAgent || "",
      updated: new Date().toISOString()
    }));
  } catch {
    setYubiKeyMessage(PRIVATE_BROWSING_YUBIKEY_WARNING, "warning");
  }
}

function setYubiKeyMessage(message, type = "info") {
  const el = $("yubiKeyMessage");
  if (!el) return;
  el.textContent = message || "";
  el.dataset.messageType = type;
  el.classList.toggle("hidden", !message);
}

function setYubiKeyDebug(details = {}) {
  const el = $("yubiKeyDebug");
  if (!el) return;
  const hasDetails = Object.keys(details).length > 0;
  el.textContent = hasDetails ? [
    "Temporary YubiKey PRF debug",
    `PRF data present: ${details.prfPresent ? "yes" : "no"}`,
    `PRF result length: ${details.prfLength || 0} bytes`,
    `PRF result used in password generation: ${details.prfUsed ? "yes" : "no"}`,
    `Request shape: ${details.requestShape || "not tested"}`,
    `Result source: ${details.resultSource || "not found"}`
  ].join("\n") : "";
  el.classList.toggle("hidden", !hasDetails);
}

function localStorageWorks() {
  try {
    const key = "goblinpass_storage_test";
    localStorage.setItem(key, "1");
    const ok = localStorage.getItem(key) === "1";
    localStorage.removeItem(key);
    return ok;
  } catch {
    return false;
  }
}

function indexedDbWorks() {
  return new Promise(resolve => {
    if (!window.indexedDB) return resolve(false);
    const name = `goblinpass-idb-test-${Date.now()}`;
    let request;
    try {
      request = indexedDB.open(name, 1);
    } catch {
      resolve(false);
      return;
    }
    request.onerror = () => resolve(false);
    request.onblocked = () => resolve(false);
    request.onsuccess = () => {
      const db = request.result;
      db.close();
      try { indexedDB.deleteDatabase(name); } catch {}
      resolve(true);
    };
  });
}

async function yubiKeyStorageWarning() {
  return "";
}

async function warnIfYubiKeyStorageLooksTemporary() {
  if (!$("useYubiKey")?.checked) return;
  const warning = await yubiKeyStorageWarning();
  if (warning) setYubiKeyMessage(warning, "warning");
  else if (mobileYubiKeyWarning() && getYubiKeyMode() === "prf") setYubiKeyMessage(mobileYubiKeyWarning(), "warning");
}

function mobileYubiKeyWarning() {
  const ua = navigator.userAgent || "";
  const mobile = /Android|iPhone|iPad|iPod|Mobile/i.test(ua);
  return mobile ? MOBILE_YUBIKEY_PRF_WARNING : "";
}

async function browserPrfCapabilityText() {
  if (!window.PublicKeyCredential) return "WebAuthn is not available in this browser.";
  if (typeof PublicKeyCredential.getClientCapabilities !== "function") {
    return "This browser does not expose a PRF capability check. GoblinPass will test PRF during generation.";
  }
  try {
    const caps = await PublicKeyCredential.getClientCapabilities("public-key");
    const extensions = Array.isArray(caps.extensions) ? caps.extensions.join(", ") : "none reported";
    return caps.extensions?.includes("prf")
      ? `Browser reports WebAuthn PRF support. Browser extensions: ${extensions}.`
      : `Browser does not report WebAuthn PRF support. Browser extensions: ${extensions}.`;
  } catch {
    return "GoblinPass could not read the browser PRF capability. It will test PRF during generation.";
  }
}

function extensionSummary(results) {
  const prf = results?.prf;
  const first = prf?.results?.first;
  const hmac = results?.hmacCreateSecret;
  return `prf.enabled=${typeof prf?.enabled === "boolean" ? prf.enabled : "not returned"}; prf.first=${first ? `${first.byteLength || 0} bytes` : "not returned"}; hmacCreateSecret=${typeof hmac === "boolean" ? hmac : "not returned"}`;
}

function yubiKeyStatusText(extra = "") {
  const cap = getYubiKeyCapability();
  const browser = extra ? `${extra}\n` : "";
  return `${browser}PRF available: ${cap.prfAvailable ? "yes" : "no"}\n` +
    `hmac-secret available: ${cap.hmacSecretAvailable ? "yes" : "no"}\n` +
    `Touch-gate available: ${cap.touchGateAvailable ? "yes" : "no"}\n` +
    `RP ID: ${cap.rpId || webAuthnRpId()}\n` +
    `Stored credential ID length: ${cap.storedCredentialIdLength || getYubiKeyCredentialId().length || 0}\n` +
    `allowCredentials supplied: ${cap.allowCredentialsSupplied ? "yes" : "no"}\n` +
    `PRF result returned: ${cap.prfResultReturned ? "yes" : "no"}\n` +
    `Authenticator attachment: ${cap.authenticatorAttachment || "not reported"}\n` +
    `Create extension results: ${cap.createResults || "not tested"}\n` +
    `Get extension results: ${cap.getResults || "not tested"}\n` +
    `PRF request shape: ${cap.prfRequestShape || "not tested"}\n` +
    `Browser/userAgent: ${cap.browserUserAgent || navigator.userAgent || "not reported"}`;
}

function updateYubiKeyUi() {
  const enabled = !!$("useYubiKey")?.checked;
  const mode = getYubiKeyMode();
  const cap = getYubiKeyCapability();
  const hasCredential = !!getYubiKeyCredentialId();
  const registered = mode === "gate"
    ? hasCredential && !!cap.touchGateAvailable
    : hasCredential && (!!cap.prfAvailable || !!cap.hmacSecretAvailable);
  if ($("yubiKeyMode")) $("yubiKeyMode").value = mode;
  if ($("yubiKeyBox")) $("yubiKeyBox").classList.toggle("hidden", !enabled);
  if ($("yubiKeyStatus")) $("yubiKeyStatus").textContent = registered ? "Status: Registered" : "Status: Not registered";
  if (!enabled) setYubiKeyMessage("");
  else if (!hasCredential) setYubiKeyMessage("Register and test the YubiKey before generating a YubiKey-protected password.", "info");
  else if (!webAuthnPrfSupported()) setYubiKeyMessage("This browser does not expose WebAuthn PRF. Try a current Chromium-based browser over HTTPS with a YubiKey that supports hmac-secret.", "warning");
  else if (mode === "gate") setYubiKeyMessage(yubiKeyStatusText("YubiKey touch unlock only is active. This mode does not change the generated password."), "info");
  else if (registered) setYubiKeyMessage(yubiKeyStatusText("YubiKey is registered for this site origin."), "success");
  else setYubiKeyMessage("This key is not confirmed for PRF ingredient mode. Use Set up and test YubiKey PRF.", "warning");
}

function webAuthnPrfSupported() {
  return !!(navigator.credentials?.create && navigator.credentials?.get && window.PublicKeyCredential);
}

function webAuthnRpId() {
  return location.hostname || "localhost";
}

async function yubiKeySalt() {
  const siteId = $("siteId").value.trim().toLowerCase();
  const accountId = $("login").value.trim().toLowerCase();
  const masterPassword = isMasterPasswordEnabled() ? $("master").value : "";
  const material = `GoblinPass PRF v1|${siteId}|${accountId}|${masterPassword}`;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(material)));
}

function yubiKeyErrorMessage(error) {
  if (!webAuthnPrfSupported()) return "This browser does not support WebAuthn PRF.";
  const message = String(error?.message || "");
  if (message.includes("No passkeys available") || message.includes("couldn't find") || message.includes("could not find")) return "GoblinPass could not find a reusable passkey/security-key credential for this site. Make sure the YubiKey has a passkey for this site and choose it during authentication.";
  if (error?.name === "NotAllowedError") return "YubiKey prompt was cancelled, timed out, the wrong YubiKey was used, or touch/PIN was not completed.";
  if (error?.name === "InvalidStateError") return "This YubiKey may already be registered for this app.";
  if (error?.name === "NotReadableError") return "YubiKey not detected or could not be read.";
  if (error?.name === "SecurityError") return "WebAuthn is not available for this origin. Use HTTPS or GitHub Pages.";
  if (message.includes("PRF extension data")) return "This key registered successfully, but this browser/key combination did not return PRF data during generation. GoblinPass cannot use it as a password ingredient here.";
  return error?.message || "YubiKey failed. Check that the registered YubiKey is connected.";
}

function isUnusableStoredCredentialError(error) {
  const message = String(error?.message || "");
  return message.includes("No passkeys available") ||
    message.includes("couldn't find") ||
    message.includes("could not find") ||
    message.includes("not reusable");
}

function getPrfOutputDetails(results, credentialId = "") {
  const prfResults = results?.prf?.results;
  const directFirst = prfResults?.first;
  if (directFirst) return { output: directFirst, source: "prf.results.first" };
  const keyedFirst = credentialId ? prfResults?.[credentialId]?.first : null;
  if (keyedFirst) return { output: keyedFirst, source: "prf.results[credentialId].first" };
  const directSecond = prfResults?.second;
  if (directSecond) return { output: null, source: "prf.results.second present but ignored" };
  return { output: null, source: "not found" };
}

function getPrfOutput(results, credentialId = "") {
  return getPrfOutputDetails(results, credentialId).output;
}

async function requestYubiKeyPrf(id, salt) {
  const allowCredentials = [{ type: "public-key", id: credentialIdBuffer(id) }];
  const basePublicKey = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rpId: webAuthnRpId(),
    allowCredentials,
    userVerification: "preferred",
    timeout: 60000
  };

  const firstCredential = await navigator.credentials.get({
    publicKey: {
      ...basePublicKey,
      extensions: {
        prf: { eval: { first: salt } }
      }
    }
  });
  const firstResults = firstCredential.getClientExtensionResults?.();
  const firstOutput = getPrfOutput(firstResults, id);
  if (firstOutput?.byteLength === 32) {
    return { credential: firstCredential, results: firstResults, output: firstOutput, requestShape: "eval" };
  }

  const secondCredential = await navigator.credentials.get({
    publicKey: {
      ...basePublicKey,
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      extensions: {
        prf: { evalByCredential: { [id]: { first: salt } } }
      }
    }
  });
  const secondResults = secondCredential.getClientExtensionResults?.();
  const secondOutput = getPrfOutput(secondResults, id);
  return { credential: secondCredential, results: secondResults, output: secondOutput, requestShape: "evalByCredential", firstResults };
}

async function requestYubiKeyAuthenticationPrf(salt) {
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: webAuthnRpId(),
      userVerification: "preferred",
      timeout: 60000,
      hints: ["security-key"],
      extensions: {
        prf: { eval: { first: salt } }
      }
    }
  });
  const results = credential.getClientExtensionResults?.();
  const details = getPrfOutputDetails(results);
  return { credential, results, output: details.output, resultSource: details.source, requestShape: "discoverable-authentication" };
}

async function createYubiKeyCredential() {
  return navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: "GoblinPass", id: webAuthnRpId() },
      user: {
        id: crypto.getRandomValues(new Uint8Array(32)),
        name: "goblinpass-local-user",
        displayName: "GoblinPass Local User"
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 }
      ],
      authenticatorSelection: {
        authenticatorAttachment: "cross-platform",
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "preferred"
      },
      timeout: 60000,
      extensions: {
        prf: {},
        hmacCreateSecret: true
      }
    }
  });
}

function capabilityFromCreatedCredential(credential) {
  const results = credential.getClientExtensionResults?.();
  const credentialId = bytesToBase64Url(new Uint8Array(credential.rawId));
  return {
    credentialId,
    prfAvailable: results?.prf?.enabled === true,
    hmacSecretAvailable: results?.hmacCreateSecret === true,
    touchGateAvailable: true,
    authenticatorAttachment: credential.authenticatorAttachment || "",
    createResults: extensionSummary(results),
    getResults: "",
    prfRequestShape: "",
    rpId: webAuthnRpId(),
    storedCredentialIdLength: credentialId.length,
    allowCredentialsSupplied: false,
    prfResultReturned: false,
    browserUserAgent: navigator.userAgent || ""
  };
}

async function mixYubiKeyPrfOutput(output) {
  const mixKey = await crypto.subtle.importKey(
    "raw",
    output,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mixed = await crypto.subtle.sign("HMAC", mixKey, new TextEncoder().encode("GoblinPass-YubiKey-Mix-v1"));
  return bytesToBase64Url(new Uint8Array(mixed));
}

async function registerYubiKey() {
  if (!webAuthnPrfSupported()) {
    setYubiKeyMessage("This browser does not expose WebAuthn PRF. Try a current Chromium-based browser over HTTPS with a YubiKey that supports hmac-secret.", "warning");
    return;
  }
  const mode = getYubiKeyMode();
  const storageWarning = await yubiKeyStorageWarning();
  const mobileWarning = mode === "prf" ? mobileYubiKeyWarning() : "";
  setYubiKeyMessage(storageWarning || mobileWarning || "Waiting for the browser and YubiKey. Complete any touch or PIN prompt.", storageWarning || mobileWarning ? "warning" : "info");
  try {
    const credential = await createYubiKeyCredential();
    const capability = capabilityFromCreatedCredential(credential);
    const { credentialId, prfAvailable, hmacSecretAvailable } = capability;

    let savedMode = mode;
    if (mode === "prf" && !prfAvailable && !hmacSecretAvailable) {
      const ok = confirm("This key registered, but PRF/hmac-secret was not confirmed. Save it as touch unlock only instead? Touch unlock does not change generated passwords.");
      if (!ok) {
        setYubiKeyMessage(`Registration completed, but PRF ingredient mode was not enabled.\nCreate extension results: ${capability.createResults}\nPRF available: no\nhmac-secret available: no\nTouch-gate available: yes`, "warning");
        return;
      }
      setYubiKeyMode("gate");
      savedMode = "gate";
    }

    localStorage.setItem(YUBIKEY_CREDENTIAL_KEY, credentialId);
    setYubiKeyMessage("Registration created. Verifying the stored credential can be reused now.", "info");
    let verified;
    try {
      verified = await verifyRegisteredYubiKey(credentialId, savedMode);
    } catch (verifyError) {
      localStorage.removeItem(YUBIKEY_CREDENTIAL_KEY);
      localStorage.removeItem(YUBIKEY_CAPABILITY_KEY);
      updateYubiKeyUi();
      setYubiKeyMessage(`YubiKey registration could not be reused. Try normal browser mode or register again.${mobileWarning ? `\n${mobileWarning}` : ""}`, "warning");
      return;
    }

    if (savedMode === "prf" && !verified.prfAvailable) {
      localStorage.removeItem(YUBIKEY_CREDENTIAL_KEY);
      localStorage.removeItem(YUBIKEY_CAPABILITY_KEY);
      updateYubiKeyUi();
      setYubiKeyMessage(`YubiKey registration could not be reused. Try normal browser mode or register again.${mobileWarning ? `\n${mobileWarning}` : ""}`, "warning");
      return;
    }

    saveYubiKeyCapability({
      ...capability,
      prfAvailable: savedMode === "prf" ? verified.prfAvailable : prfAvailable,
      hmacSecretAvailable,
      touchGateAvailable: verified.touchGateAvailable,
      authenticatorAttachment: verified.authenticatorAttachment || capability.authenticatorAttachment,
      getResults: verified.getResults,
      prfRequestShape: verified.prfRequestShape || capability.prfRequestShape,
      rpId: webAuthnRpId(),
      storedCredentialIdLength: credentialId.length,
      allowCredentialsSupplied: verified.allowCredentialsSupplied,
      prfResultReturned: verified.prfResultReturned,
      browserUserAgent: navigator.userAgent || ""
    });
    updateYubiKeyUi();
    const registerMessage = `${storageWarning ? `${storageWarning}\n` : ""}${mobileWarning ? `${mobileWarning}\n` : ""}${savedMode === "prf" && verified.prfAvailable
      ? "YubiKey registered and verified for PRF ingredient mode."
      : "YubiKey registered for touch unlock only."}`;
    setYubiKeyMessage(yubiKeyStatusText(registerMessage), savedMode === "prf" && verified.prfAvailable ? "success" : "info");
  } catch (error) {
    setYubiKeyMessage(yubiKeyErrorMessage(error), "warning");
  }
}

async function setupAndTestYubiKeyPrf() {
  if (!webAuthnPrfSupported()) {
    setYubiKeyMessage("This browser does not expose WebAuthn PRF. Try a current Chromium-based browser over HTTPS with a YubiKey that supports hmac-secret.", "warning");
    return;
  }
  if (!$("siteId").value.trim() || (isMasterPasswordEnabled() && !$("master").value)) {
    setYubiKeyMessage(isMasterPasswordEnabled()
      ? "Enter Website ID and Master Password before setup so GoblinPass can generate a PRF test password."
      : "Enter Website ID before setup so GoblinPass can generate a PRF test password.", "warning");
    return;
  }

  if ($("useYubiKey")) $("useYubiKey").checked = true;
  setYubiKeyMode("prf");
  updateYubiKeyUi();

  const storageWarning = await yubiKeyStorageWarning();
  const mobileWarning = mobileYubiKeyWarning();
  const tapText = "Tap your YubiKey to the phone. You may need to remove it and tap again for the second step.";
  setYubiKeyMessage(`${storageWarning ? `${storageWarning}\n` : ""}${mobileWarning ? `${mobileWarning}\n` : ""}${tapText}\nStarting YubiKey PRF registration.`, storageWarning || mobileWarning ? "warning" : "info");

  try {
    const credential = await createYubiKeyCredential();
    const capability = capabilityFromCreatedCredential(credential);
    const credentialId = capability.credentialId;
    localStorage.setItem(YUBIKEY_CREDENTIAL_KEY, credentialId);
    saveYubiKeyCapability(capability);
    updateYubiKeyUi();

    setYubiKeyMessage(`Registration complete. Keep your YubiKey ready - now testing PRF authentication.\n${tapText}`, "info");
    const salt = await yubiKeySalt();
    const { credential: assertion, results, output, requestShape, firstResults } = await requestYubiKeyPrf(credentialId, salt);
    const ok = output?.byteLength === 32;
    const verifiedCapability = {
      ...capability,
      prfAvailable: ok,
      hmacSecretAvailable: !!capability.hmacSecretAvailable,
      touchGateAvailable: true,
      authenticatorAttachment: assertion.authenticatorAttachment || capability.authenticatorAttachment || "",
      getResults: `${firstResults ? `First try: ${extensionSummary(firstResults)}; ` : ""}Final try: ${extensionSummary(results)}`,
      prfRequestShape: requestShape,
      rpId: webAuthnRpId(),
      storedCredentialIdLength: credentialId.length,
      allowCredentialsSupplied: true,
      prfResultReturned: ok,
      browserUserAgent: navigator.userAgent || ""
    };

    if (!ok) {
      localStorage.removeItem(YUBIKEY_CREDENTIAL_KEY);
      localStorage.removeItem(YUBIKEY_CAPABILITY_KEY);
      updateYubiKeyUi();
      setYubiKeyMessage(`YubiKey registration could not be reused. Try normal browser mode or register again.\n${prfResultSummary(results)}`, "warning");
      return;
    }

    saveYubiKeyCapability(verifiedCapability);
    currentYubiKeyFactor = await mixYubiKeyPrfOutput(output);
    const style = getQuickPasswordStyle();
    const strength = getMemorableStrength();
    const testPassword = await deterministicPassword(style, strength);
    currentYubiKeyFactor = "";
    generatedPassword = testPassword;
    lastGeneratedMeta = { style, strength, useYubiKey: true, yubiKeyMode: "prf" };
    generatedVisible = false;
    if ($("resultText")) $("resultText").textContent = "YubiKey PRF test password generated: " + previewPassword(testPassword);
    if ($("toggleGenerated")) {
      $("toggleGenerated").textContent = "Show";
      $("toggleGenerated").classList.remove("hidden");
    }
    if ($("result")) $("result").classList.remove("hidden");
    updateYubiKeyUi();
    setYubiKeyMessage(yubiKeyStatusText("YubiKey PRF is ready for this browser and site. The test password used the saved credential ID and a real 32-byte PRF output."), "success");
  } catch (error) {
    currentYubiKeyFactor = "";
    localStorage.removeItem(YUBIKEY_CREDENTIAL_KEY);
    localStorage.removeItem(YUBIKEY_CAPABILITY_KEY);
    updateYubiKeyUi();
    const message = isUnusableStoredCredentialError(error)
      ? "GoblinPass could not find the saved YubiKey credential. Try clearing the saved credential and setting up again."
      : yubiKeyErrorMessage(error);
    setYubiKeyMessage(message, "warning");
  }
}

async function forgetYubiKey() {
  localStorage.removeItem(YUBIKEY_CREDENTIAL_KEY);
  localStorage.removeItem(YUBIKEY_CAPABILITY_KEY);
  currentYubiKeyFactor = "";
  generatedPassword = "";
  lastGeneratedMeta = null;
  updateYubiKeyUi();
  const capability = await browserPrfCapabilityText();
  setYubiKeyMessage(`Local key registration forgotten. Register the YubiKey again with the latest PRF setup. ${capability}`, "info");
}

function prfResultSummary(results) {
  const prf = results?.prf;
  const first = getPrfOutput(results);
  return [
    `PRF object returned: ${prf ? "yes" : "no"}`,
    `PRF enabled flag: ${typeof prf?.enabled === "boolean" ? prf.enabled : "not returned"}`,
    `PRF result returned: ${first ? "yes" : "no"}`,
    `PRF result bytes: ${first?.byteLength || 0}`
  ].join(" | ");
}

async function testYubiKeyPrf() {
  const id = getYubiKeyCredentialId();
  if (!id) {
    setYubiKeyMessage("Register a YubiKey before running the PRF test.", "warning");
    return;
  }
  setYubiKeyMessage("Testing browser PRF support. Complete the security key prompts.", "info");
  const capability = await browserPrfCapabilityText();
  try {
    const salt = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("GoblinPass-PRF-test-v1")));
    const { credential, results, output, requestShape, firstResults } = await requestYubiKeyPrf(id, salt);
    const summary = `${capability} ${firstResults ? `First try: ${prfResultSummary(firstResults)}. ` : ""}Final try: ${prfResultSummary(results)}. Shape: ${requestShape}`;
    const ok = output?.byteLength === 32;
    const cap = getYubiKeyCapability();
    saveYubiKeyCapability({
      ...cap,
      prfAvailable: ok || !!cap.prfAvailable,
      hmacSecretAvailable: !!cap.hmacSecretAvailable,
      touchGateAvailable: true,
      authenticatorAttachment: credential.authenticatorAttachment || cap.authenticatorAttachment || "",
      getResults: extensionSummary(results),
      prfRequestShape: requestShape,
      rpId: webAuthnRpId(),
      storedCredentialIdLength: id.length,
      allowCredentialsSupplied: true,
      prfResultReturned: ok,
      browserUserAgent: navigator.userAgent || ""
    });
    setYubiKeyMessage(ok ? `PRF test passed. ${summary}` : `PRF test failed. ${summary}`, ok ? "success" : "warning");
  } catch (error) {
    if (isUnusableStoredCredentialError(error)) {
      localStorage.removeItem(YUBIKEY_CREDENTIAL_KEY);
      localStorage.removeItem(YUBIKEY_CAPABILITY_KEY);
      updateYubiKeyUi();
    }
    setYubiKeyMessage(`PRF test failed. ${capability} ${yubiKeyErrorMessage(error)}`, "warning");
  }
}

async function verifyRegisteredYubiKey(id, mode) {
  if (mode === "gate") {
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: webAuthnRpId(),
        allowCredentials: [{ type: "public-key", id: credentialIdBuffer(id) }],
        userVerification: "preferred",
        timeout: 60000
      }
    });
    return {
      prfAvailable: false,
      hmacSecretAvailable: false,
      touchGateAvailable: true,
      authenticatorAttachment: credential.authenticatorAttachment || "",
      getResults: "Immediate touch-gate verification succeeded.",
      rpId: webAuthnRpId(),
      allowCredentialsSupplied: true,
      prfResultReturned: false
    };
  }

  const salt = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("GoblinPass-PRF-registration-verify-v1")));
  const { credential, results, output, requestShape, firstResults } = await requestYubiKeyPrf(id, salt);
  if (!output || output.byteLength !== 32) throw new Error("YubiKey registration could not be reused. Try normal browser mode or register again.");
  return {
    prfAvailable: true,
    hmacSecretAvailable: false,
    touchGateAvailable: true,
    authenticatorAttachment: credential.authenticatorAttachment || "",
    getResults: `${firstResults ? `First try: ${extensionSummary(firstResults)}; ` : ""}Final try: ${extensionSummary(results)}`,
    prfRequestShape: requestShape,
    rpId: webAuthnRpId(),
    allowCredentialsSupplied: true,
    prfResultReturned: true
  };
}

async function getYubiKeyFactor() {
  if (!$("useYubiKey")?.checked) return "";
  const id = getYubiKeyCredentialId();
  if (!id) throw new Error("Register and test a YubiKey before generating a YubiKey-protected password.");
  if (getYubiKeyMode() === "gate") {
    await verifyYubiKeyTouchGate(id);
    setYubiKeyMessage(yubiKeyStatusText("YubiKey touch unlock succeeded. The password was generated with the normal GoblinPass formula."), "success");
    return "";
  }
  if (!webAuthnPrfSupported()) throw new Error("This browser does not support WebAuthn PRF.");
  const salt = await yubiKeySalt();
  try {
    setYubiKeyMessage("Authenticate with the registered YubiKey now and complete its touch or PIN prompt.", "info");
    setYubiKeyDebug({ prfPresent: false, prfLength: 0, prfUsed: false, requestShape: "starting", resultSource: "waiting for authenticator" });
    const { credential, results, output, requestShape, firstResults } = await requestYubiKeyPrf(id, salt);
    const prfLength = output?.byteLength || 0;
    const resultSource = getPrfOutputDetails(results).source || "stored credential";
    const cap = getYubiKeyCapability();
    saveYubiKeyCapability({
      ...cap,
      touchGateAvailable: true,
      authenticatorAttachment: credential.authenticatorAttachment || cap.authenticatorAttachment || "",
      getResults: `${firstResults ? `First try: ${extensionSummary(firstResults)}; ` : ""}Final try: ${extensionSummary(results)}`,
      prfRequestShape: requestShape,
      rpId: webAuthnRpId(),
      prfAvailable: (!!output && output.byteLength === 32) || !!cap.prfAvailable,
      hmacSecretAvailable: !!cap.hmacSecretAvailable,
      storedCredentialIdLength: id.length,
      allowCredentialsSupplied: true,
      prfResultReturned: !!output,
      browserUserAgent: navigator.userAgent || ""
    });
    setYubiKeyDebug({ prfPresent: !!output, prfLength, prfUsed: false, requestShape, resultSource });
    if (!output || output.byteLength !== 32) throw new Error("This browser or YubiKey did not return PRF extension data.");
    const factor = await mixYubiKeyPrfOutput(output);
    setYubiKeyDebug({ prfPresent: true, prfLength, prfUsed: true, requestShape, resultSource });
    setYubiKeyMessage(yubiKeyStatusText("YubiKey authenticated and returned a real PRF password ingredient."), "success");
    return factor;
  } catch (error) {
    setYubiKeyDebug({ prfPresent: false, prfLength: 0, prfUsed: false, requestShape: "failed", resultSource: "not used" });
    throw new Error(yubiKeyErrorMessage(error));
  }
}

async function verifyYubiKeyTouchGate(id = getYubiKeyCredentialId()) {
  try {
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: webAuthnRpId(),
        allowCredentials: [{ type: "public-key", id: credentialIdBuffer(id) }],
        userVerification: "preferred",
        timeout: 60000
      }
    });
    const cap = getYubiKeyCapability();
    saveYubiKeyCapability({
      ...cap,
      touchGateAvailable: true,
      authenticatorAttachment: credential.authenticatorAttachment || cap.authenticatorAttachment || "",
      getResults: "Touch-gate WebAuthn get succeeded without PRF request.",
      rpId: webAuthnRpId(),
      storedCredentialIdLength: id.length,
      allowCredentialsSupplied: true,
      prfResultReturned: false,
      browserUserAgent: navigator.userAgent || ""
    });
  } catch (error) {
    throw new Error(yubiKeyErrorMessage(error));
  }
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
  panel.innerHTML = `
    <p class="security-panel-title">Enter the full Additional Secret</p>
    <p class="security-progress" data-security-progress>${getSecurityProgressText()}</p>
    <div class="security-key-grid">
      ${keys.map(key => `<button type="button" data-security-key="${key}">${key}</button>`).join("")}
    </div>
    <div class="security-actions">
      <button type="button" data-security-backspace>Backspace</button>
      <button type="button" data-security-clear>Clear</button>
      <button type="button" data-security-reveal>Reveal</button>
      <button type="button" data-security-done>Done</button>
    </div>`;
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
  return values.map(value => `<option value="${value}">${value}</option>`).join("");
}

function openMobileCombinationLock() {
  const panel = $("securityInputPanel");
  panel.innerHTML = `
    <p class="security-panel-title">Choose 2 letters and 4 digits</p>
    <p class="security-progress" data-security-progress>${getSecurityProgressText()}</p>
    <div class="combo-slots">
      ${[0, 1, 2, 3, 4, 5].map(index => `<button type="button" data-combo-slot="${index}">${securityKeyMemory[index] && securityKeyMemory[index] !== " " ? "*" : (index < 2 ? "L" : "#")}</button>`).join("")}
    </div>
    <div class="combo-choice-panel hidden" data-combo-choices></div>
    <div class="security-actions combo-actions">
      <button type="button" data-security-clear>Clear</button>
      <button type="button" data-security-reveal>Reveal</button>
      <button type="button" data-security-done>Done</button>
    </div>`;
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
  choices.innerHTML = `
    <p class="security-panel-title">${index < 2 ? "Choose a letter" : "Choose a digit"}</p>
    <div class="security-key-grid combo-choice-grid">
      ${values.map(value => `<button type="button" data-combo-choice="${value}">${value}</button>`).join("")}
    </div>`;
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

async function charFromSet(seed, set, round) {
  const hex = await sha256Hex(seed + "|required|" + set.key + "|" + round);
  const n = parseInt(hex.slice(0, 8), 16);
  return set.chars[n % set.chars.length];
}

async function deterministicShuffle(items, seed) {
  const scored = [];
  for (let i = 0; i < items.length; i++) {
    scored.push({ value: items[i], score: await sha256Hex(seed + "|shuffle|" + i + "|" + items[i]) });
  }
  return scored.sort((a, b) => a.score.localeCompare(b.score)).map(item => item.value).join("");
}

async function deterministicSetOrder(sets, seed, round) {
  const scored = [];
  for (let i = 0; i < sets.length; i++) {
    scored.push({ value: sets[i], score: await sha256Hex(seed + "|set-order|" + round + "|" + sets[i].key) });
  }
  return scored.sort((a, b) => a.score.localeCompare(b.score)).map(item => item.value);
}

async function distributedCharacters(seed, sets, length) {
  const out = [];
  const minimumPerSet = Math.max(1, Math.min(2, Math.floor(length / sets.length)));

  for (const set of sets) {
    for (let i = 0; i < minimumPerSet && out.length < length; i++) {
      out.push(await charFromSet(seed, set, i));
    }
  }

  let round = 0;
  while (out.length < length) {
    const orderedSets = await deterministicSetOrder(sets, seed, round);
    for (const set of orderedSets) {
      if (out.length >= length) break;
      out.push(await charFromSet(seed, set, minimumPerSet + round));
    }
    round++;
  }

  return out;
}

async function deterministicWord(seed, round) {
  const hex = await sha256Hex(seed + "|word|" + round);
  const n = parseInt(hex.slice(0, 8), 16);
  return MEMORABLE_WORDS[n % MEMORABLE_WORDS.length];
}

async function deterministicDigit(seed) {
  const hex = await sha256Hex(seed + "|digit");
  return String(parseInt(hex.slice(0, 8), 16) % 10);
}

async function deterministicSymbol(seed) {
  const symbols = "!@#$%";
  const hex = await sha256Hex(seed + "|symbol");
  return symbols[parseInt(hex.slice(0, 8), 16) % symbols.length];
}

async function deterministicMemorablePassword(seed, strength) {
  const wordCount = strength === "easy" ? 3 : 4;
  const words = [];
  for (let i = 0; i < wordCount; i++) words.push(await deterministicWord(seed, i));
  if (strength === "strong") return `${words.join("-")}${await deterministicSymbol(seed)}${await deterministicDigit(seed)}`;
  return words.join("-");
}

function getPasswordSeedParts() {
  const siteId = $("siteId").value.trim().toLowerCase();
  const master = isMasterPasswordEnabled() ? $("master").value : "";
  const securityKeyEnabled = isSecurityKeyEnabled();
  const securityKey = securityKeyEnabled ? getSecurityKeyInputValue() : "";
  const trustedDeviceKey = getTrustedDeviceGenerationKey();
  const googleSubjectId = getGoogleSubjectForGeneration();
  const yubiKeyFactor = $("useYubiKey")?.checked ? currentYubiKeyFactor : "";
  const counter = Math.max(1, Math.min(999, parseInt($("counter").value || "1", 10)));
  return { siteId, master, securityKey, trustedDeviceKey, googleSubjectId, yubiKeyFactor, counter };
}

function buildComplexSeed(parts, optionKey) {
  const { siteId, master, securityKey, trustedDeviceKey, googleSubjectId, yubiKeyFactor, counter } = parts;
  if (yubiKeyFactor) return `GPIDV2Y|${siteId}|${counter}|${master}|${securityKey}|${trustedDeviceKey}|${googleSubjectId}|${yubiKeyFactor}|${optionKey}`;
  return googleSubjectId && trustedDeviceKey
    ? `GPIDV2TG|${siteId}|${counter}|${master}|${securityKey}|${trustedDeviceKey}|${googleSubjectId}|${optionKey}`
    : googleSubjectId
    ? `GPIDV2G|${siteId}|${counter}|${master}|${securityKey}|${googleSubjectId}|${optionKey}`
    : trustedDeviceKey
    ? `GPIDV2T|${siteId}|${counter}|${master}|${securityKey}|${trustedDeviceKey}|${optionKey}`
    : securityKey
    ? `GPIDV2K|${siteId}|${counter}|${master}|${securityKey}|${optionKey}`
    : `GPIDV2|${siteId}|${counter}|${master}|${optionKey}`;
}

function buildMemorableSeed(parts, strength) {
  const { siteId, master, securityKey, trustedDeviceKey, googleSubjectId, yubiKeyFactor, counter } = parts;
  if (yubiKeyFactor) return `GPMEMV1Y|${siteId}|${counter}|${master}|${securityKey}|${trustedDeviceKey}|${googleSubjectId}|${yubiKeyFactor}|${strength}`;
  return `GPMEMV1|${siteId}|${counter}|${master}|${securityKey}|${trustedDeviceKey}|${googleSubjectId}|${strength}`;
}

async function deterministicComplexPassword() {
  const parts = getPasswordSeedParts();
  const length = Math.max(8, Math.min(64, parseInt($("length").value || "16", 10)));
  const sets = selectedCharsets();
  const optionKey = sets.map(set => set.key).join(",");
  const seed = buildComplexSeed(parts, optionKey);

  const out = await distributedCharacters(seed, sets, length);

  return await deterministicShuffle(out, seed);
}

async function deterministicPassword(style = getQuickPasswordStyle(), strength = getMemorableStrength()) {
  const parts = getPasswordSeedParts();
  if (style === "memorable") {
    return deterministicMemorablePassword(buildMemorableSeed(parts, strength), strength);
  }
  return deterministicComplexPassword();
}

function previewPassword(pw) {
  if (!pw) return "";
  if (pw.length <= 8) return pw[0] + "****" + pw.slice(-1);
  return pw.slice(0, 4) + "********" + pw.slice(-4);
}

function maskPasswordHint(hint) {
  return hint ? "*****" : "not saved";
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
    const visibleText = generatedVisible && !loadSettings().copyPasswordOnly
      ? generatedPassword
      : previewPassword(generatedPassword);
    $("resultText").textContent = "Copied: " + visibleText;
  } catch {
    alert("Clipboard copy was blocked. Use Show and copy it manually.");
  }
}

async function generate() {
  if (!$("siteId").value.trim()) return alert("Enter website ID.");
  if (isMasterPasswordEnabled() && !$("master").value) return alert("Enter master password, or turn it off in Settings.");
  if (isSecurityKeyEnabled() && !getSecurityKeyInputValue()) return alert("Enter your Additional Secret, or turn it off in Settings.");
  if (isGoogleSecurityFactorEnabled() && !getGoogleSubjectForGeneration()) return alert("Sign in with Google before generating passwords, or turn off Google Security Factor in Settings.");
  const style = getQuickPasswordStyle();
  const strength = getMemorableStrength();
  try {
    currentYubiKeyFactor = await getYubiKeyFactor();
  } catch (error) {
    currentYubiKeyFactor = "";
    if (isUnusableStoredCredentialError(error)) {
      localStorage.removeItem(YUBIKEY_CREDENTIAL_KEY);
      localStorage.removeItem(YUBIKEY_CAPABILITY_KEY);
      updateYubiKeyUi();
    }
    setYubiKeyMessage(error.message, "warning");
    return;
  }
  if ($("useYubiKey")?.checked && !currentYubiKeyFactor) {
    setYubiKeyDebug({ prfPresent: false, prfLength: 0, prfUsed: false, requestShape: "generation aborted", resultSource: "missing factor" });
    setYubiKeyMessage("YubiKey is enabled, but no PRF password ingredient was created. Password generation stopped.", "warning");
    return;
  }
  generatedPassword = await deterministicPassword(style, strength);
  lastGeneratedMeta = {
    style,
    strength,
    useYubiKey: !!$("useYubiKey")?.checked,
    yubiKeyMode: getYubiKeyMode(),
    useMasterPassword: isMasterPasswordEnabled(),
    googleSecurityFactorEnabled: isGoogleSecurityFactorEnabled(),
    trustedDeviceEnabled: !!loadSettings().trustedDeviceEnabled
  };
  currentYubiKeyFactor = "";
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
  if (loadSettings().offlineDeviceMode) {
    drawQrToCanvas(generatedPassword);
    await saveCurrent({ silent: true });
  } else {
    hidePasswordQr();
  }
}

function getEntryPayload(passwordHint) {
  const login = $("login").value.trim();
  const loginStore = storedLoginObject(login, $("storeFullLogin").checked);
  const settings = loadSettings();
  const siteId = $("siteId").value.trim().toLowerCase();
  return {
    entryKey: "entry-" + bytesToBase64Url(crypto.getRandomValues(new Uint8Array(12))),
    siteId: settings.saveWebsiteIds ? siteId : "",
    idSaved: settings.saveWebsiteIds,
    site: $("site").value.trim().toLowerCase(),
    maskedLogin: loginStore.maskedLogin,
    fullLogin: loginStore.fullLogin,
    fullLoginStored: loginStore.fullLoginStored,
    passwordHint: passwordHint || "",
    yubiKeyRequired: !!$("useYubiKey")?.checked,
    yubiKeyMode: getYubiKeyMode(),
    useMasterPassword: isMasterPasswordEnabled(),
    googleSecurityFactorRequired: isGoogleSecurityFactorEnabled(),
    trustedDeviceRequired: !!loadSettings().trustedDeviceEnabled,
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
}

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
  const encrypted = await encryptVaultEntries(entries);
  localStorage.setItem(STORAGE_KEY, JSON.stringify(encrypted));
}

async function checkPin(pin) {
  const record = await getPinRecord();
  if (!record) return false;

  const now = Date.now();
  if (pinLockedUntil && now < pinLockedUntil) {
    alert("PIN locked. Try again soon.");
    return false;
  }

  let ok = false;
  if (record.legacyHash) {
    ok = (await sha256Hex("GOBLINPASS-PIN-v1|" + pin)) === record.legacyHash;
    if (ok) {
      const salt = randomSalt();
      const hash = await hashPin(pin, salt);
      await savePinRecord({ salt, hash, migrated: new Date().toISOString() });
      vaultCryptoKey = await deriveVaultKey(pin, salt);
    }
  } else {
    ok = (await hashPin(pin, record.salt)) === record.hash;
    if (ok) vaultCryptoKey = await deriveVaultKey(pin, record.salt);
  }
  if (ok) {
    pinFailCount = 0;
    pinLockedUntil = 0;
    return true;
  }

  pinFailCount++;
  if (pinFailCount >= 5) {
    pinLockedUntil = Date.now() + 60000;
    pinFailCount = 0;
    alert("Too many wrong attempts. Vault locked for 60 seconds.");
  }
  return false;
}

async function ensureVaultUnlocked(message) {
  if (vaultUnlocked) return true;
  const record = await getPinRecord();
  if (!record) {
    alert("Create a vault PIN first.");
    showPage("vaultPage");
    await showVault();
    return false;
  }
  const pin = prompt(message || "Enter vault PIN:");
  if (pin === null) return false;
  const ok = await checkPin(pin);
  if (!ok) return alert("Wrong PIN."), false;
  vaultUnlocked = true;
  openUnlockedVault();
  return true;
}

async function saveCurrent(options = {}) {
  const silent = !!options.silent;
  try {
    if (!(await ensureVaultUnlocked("Save requires your vault PIN."))) return;

    const savedStyle = getQuickPasswordStyle();
    const savedStrength = getMemorableStrength();
    let pwForHint = generatedPassword;
    const usingYubiKey = !!$("useYubiKey")?.checked;
    const yubiKeyMode = getYubiKeyMode();
    if (pwForHint && (!lastGeneratedMeta || lastGeneratedMeta.style !== savedStyle || lastGeneratedMeta.strength !== savedStrength || lastGeneratedMeta.useYubiKey !== usingYubiKey || lastGeneratedMeta.yubiKeyMode !== yubiKeyMode || lastGeneratedMeta.useMasterPassword !== isMasterPasswordEnabled() || lastGeneratedMeta.googleSecurityFactorEnabled !== isGoogleSecurityFactorEnabled() || lastGeneratedMeta.trustedDeviceEnabled !== !!loadSettings().trustedDeviceEnabled)) {
      pwForHint = "";
    }
    if (!pwForHint && isSecurityKeyEnabled() && !getSecurityKeyInputValue()) return alert("Enter your Additional Secret, or turn it off in Settings.");
    if (!pwForHint && isGoogleSecurityFactorEnabled() && !getGoogleSubjectForGeneration()) return alert("Sign in with Google before saving this entry, or turn off Google Security Factor in Settings.");
    if (!pwForHint && $("siteId").value.trim() && (!isMasterPasswordEnabled() || $("master").value)) {
      try {
        currentYubiKeyFactor = await getYubiKeyFactor();
      } catch (error) {
        currentYubiKeyFactor = "";
        if (isUnusableStoredCredentialError(error)) {
          localStorage.removeItem(YUBIKEY_CREDENTIAL_KEY);
          localStorage.removeItem(YUBIKEY_CAPABILITY_KEY);
          updateYubiKeyUi();
        }
        setYubiKeyMessage(error.message, "warning");
        return;
      }
      pwForHint = await deterministicPassword(savedStyle, savedStrength);
      currentYubiKeyFactor = "";
    }

    const entry = getEntryPayload(pwForHint ? pwForHint.slice(0, 5) : "");
    if (!$("siteId").value.trim()) return alert("Enter website ID before saving.");

    const entries = await loadEntries();
    const idx = loadSettings().saveWebsiteIds
      ? entries.findIndex(e => getEntryId(e) === $("siteId").value.trim().toLowerCase())
      : -1;
    const updatedExisting = idx >= 0;
    if (updatedExisting) {
      if (!entry.passwordHint && entries[idx].passwordHint) entry.passwordHint = entries[idx].passwordHint;
      entry.entryKey = entries[idx].entryKey || entry.entryKey;
      entries[idx] = entry;
    } else entries.unshift(entry);

    await saveEntries(entries);
    renderEntries();
    if (!silent) {
      showResultMessage(updatedExisting ? "Updated vault entry." : "Saved to vault.", !!generatedPassword && !loadSettings().copyPasswordOnly);
    } else if ($("resultText")) {
      $("resultText").textContent += updatedExisting ? " Saved to vault." : " Saved to vault.";
    }
    return true;
  } catch (error) {
    alert(`Could not save to vault: ${error.message || error}`);
    return false;
  }
}

async function setOrUnlockPin() {
  const pin = $("vaultPin").value.trim();
  if (!/^\d{4}$/.test(pin)) return alert("Use a 4 digit PIN.");
  const record = await getPinRecord();

  if (!record) {
    const confirmPin = prompt("Confirm new vault PIN:");
    if (confirmPin !== pin) return alert("PINs did not match.");
    const salt = randomSalt();
    const hash = await hashPin(pin, salt);
    vaultCryptoKey = await deriveVaultKey(pin, salt);
    await savePinRecord({ salt, hash, created: new Date().toISOString() });
    vaultUnlocked = true;
    $("vaultPin").value = "";
    const existing = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    if (Array.isArray(existing)) await saveEntries(existing);
    openUnlockedVault();
    return;
  }

  const ok = await checkPin(pin);
  $("vaultPin").value = "";
  if (!ok) return alert("Wrong PIN.");
  vaultUnlocked = true;
  openUnlockedVault();
}

async function verifyPin() {
  const pin = prompt("Enter vault PIN:");
  if (pin === null) return false;
  return await checkPin(pin);
}

function openUnlockedVault() {
  $("pinBox").classList.add("hidden");
  $("vaultArea").classList.remove("hidden");
  $("vaultBtn").textContent = "Lock vault";
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

  const record = await getPinRecord();
  $("vaultArea").classList.add("hidden");
  $("pinBox").classList.remove("hidden");
  $("vaultBtn").textContent = "Cancel";
  $("setOrUnlockPin").textContent = record ? "Unlock" : "Set PIN";
  $("pinBox").querySelector(".muted").textContent = record
    ? "Enter your vault PIN to unlock saved IDs."
    : "Create a permanent 4 digit vault PIN. This PIN will be required to view saved IDs.";
}

function applyEntry(e) {
  $("siteId").value = getEntryId(e);
  $("site").value = getEntrySite(e);
  $("login").value = canRevealFullLogin(e) ? getEntryFullLogin(e) : getEntryLoginForDisplay(e);
  $("storeFullLogin").checked = !!e.fullLoginStored;
  $("passwordStyle").value = getDefaultPasswordStyle();
  $("memorableStrength").value = MEMORABLE_STRENGTHS.includes(e.memorableStrength) ? e.memorableStrength : "standard";
  $("length").value = e.length || 16;
  $("counter").value = e.counter || 1;
  $("lower").checked = !!e.options?.lower;
  $("upper").checked = !!e.options?.upper;
  $("nums").checked = !!e.options?.nums;
  $("symbols").checked = !!e.options?.symbols;
  $("useYubiKey").checked = !!e.yubiKeyRequired;
  if ($("yubiKeyMode")) $("yubiKeyMode").value = e.yubiKeyMode === "gate" ? "gate" : "prf";
  setYubiKeyMode($("yubiKeyMode")?.value || "prf");
  updateYubiKeyUi();
  updatePasswordStyleUi();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

async function renderEntries() {
  const box = $("entries");
  if (!box || !vaultUnlocked) return;

  const filter = ($("filter").value || "").toLowerCase();
  const entries = await loadEntries();
  const shown = entries.filter(e => (
    getEntryTitle(e) + " " +
    getEntrySite(e) + " " +
    getEntryLoginForDisplay(e) + " " +
    getEntryFullLogin(e)
  ).toLowerCase().includes(filter));

  box.innerHTML = "";
  if (!shown.length) {
    box.innerHTML = '<p class="muted">No matching vault entries.</p>';
    return;
  }

  shown.forEach(e => {
    const site = getEntrySite(e);
    const div = document.createElement("div");
    div.className = "entry";
    div.innerHTML = `
      <div class="entry-title">${escapeHtml(getEntryTitle(e))}</div>
      <div class="entry-line">Website ID: ${getEntryId(e) ? escapeHtml(getEntryId(e)) : "not saved"}</div>
      ${site ? `<div class="entry-line">Site: ${escapeHtml(site)}</div>` : ""}
      <div class="entry-line">Login: <span data-login>${escapeHtml(getEntryLoginForDisplay(e) || "not saved")}</span>${e.fullLoginStored ? '<span class="sensitive-note">full stored</span>' : ""}</div>
      <div class="entry-line">Password hint: <span data-pwhint>${escapeHtml(maskPasswordHint(e.passwordHint))}</span></div>
      ${e.yubiKeyRequired ? `<div class="entry-line"><span class="high-security-badge">YubiKey PRF Required</span></div>` : ""}
      <div class="entry-line">Length: ${e.length} - Counter: ${e.counter}</div>
      <div class="entry-actions">
        <button data-use>Use</button>
        <button data-hint>Show hint</button>
        <button data-copy>Copy login</button>
        <button data-delete class="danger">Delete</button>
      </div>`;
    div.querySelector("[data-use]").onclick = () => applyEntry(e);
    div.querySelector("[data-hint]").onclick = async () => {
      if (await verifyPin()) {
        div.querySelector("[data-login]").textContent = canRevealFullLogin(e) ? getEntryFullLogin(e) : (getEntryLoginForDisplay(e) || "not saved");
        div.querySelector("[data-pwhint]").textContent = e.passwordHint || "not saved";
      } else alert("Wrong PIN.");
    };
    div.querySelector("[data-copy]").onclick = async () => {
      if (await verifyPin()) {
        const value = canRevealFullLogin(e) ? getEntryFullLogin(e) : getEntryLoginForDisplay(e);
        try { await navigator.clipboard.writeText(value || ""); } catch {}
        if (!canRevealFullLogin(e)) alert("Only the masked login was stored for this entry.");
      } else alert("Wrong PIN.");
    };
    div.querySelector("[data-delete]").onclick = async () => {
      if (!(await verifyPin())) return alert("Wrong PIN.");
      const all = await loadEntries();
      await saveEntries(all.filter(x => getEntryKey(x) !== getEntryKey(e)));
      renderEntries();
    };
    box.appendChild(div);
  });
}

function escapeHtml(s) {
  return String(s || "").replace(/[&<>"']/g, m => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" }[m]));
}

async function exportVault() {
  if (!(await ensureVaultUnlocked("Export requires your vault PIN."))) return;
  const entries = await loadEntries();
  const blob = new Blob([JSON.stringify({ version: "mobile-2", exported: new Date().toISOString(), entries }, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "goblinpass-mobile-export.json";
  a.click();
  URL.revokeObjectURL(url);
}

function downloadTextFile(filename, text, type = "text/html") {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function methodCellsForLogbook(entry) {
  const methods = [
    ["Yubikey", !!entry.yubiKeyRequired],
    ["Master Password", entry.useMasterPassword !== false],
    ["Google", !!entry.googleSecurityFactorRequired],
    ["Trusted Device", !!entry.trustedDeviceRequired]
  ];
  return methods.map(([label, checked]) => `<span class="method-box">${checked ? "[x]" : "[ ]"} ${escapeHtml(label)}</span>`).join("");
}

async function exportOfflineLogbook() {
  if (!(await ensureVaultUnlocked("Logbook export requires your vault PIN."))) return;
  const entries = await loadEntries();
  const rows = entries.map(entry => `
    <tr>
      <td>${escapeHtml(getEntryId(entry))}</td>
      <td>${escapeHtml(getEntrySite(entry))}</td>
      <td>${methodCellsForLogbook(entry)}</td>
      <td>${escapeHtml(entry.length || 16)}</td>
      <td>${escapeHtml(entry.counter || 1)}</td>
      <td>${escapeHtml(getEntryLoginForDisplay(entry) || "")}</td>
    </tr>`).join("");
  const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GoblinPass 1.0 Offline ID Logbook Export</title>
  <style>
    @page{size:A4;margin:10mm}
    *{box-sizing:border-box}
    body{margin:0;background:#fff;color:#111;font-family:Arial,sans-serif;font-size:11px}
    header{border:1px solid #222;border-radius:10px;padding:12px;margin-bottom:8px}
    h1{margin:0 0 4px;font-size:22px}
    p{margin:0;color:#333}
    .notice{border:1px solid #555;border-radius:8px;padding:8px;margin-bottom:8px;font-weight:700}
    table{width:100%;border-collapse:collapse;table-layout:fixed}
    th,td{border:1px solid #555;padding:5px;vertical-align:top;word-break:break-word}
    th{background:#eee;text-align:left;text-transform:uppercase;font-size:10px}
    tr{break-inside:avoid;page-break-inside:avoid}
    .method-box{display:inline-block;margin:0 5px 3px 0;white-space:nowrap}
    footer{margin-top:8px;text-align:center;font-weight:700}
  </style>
</head>
<body>
  <header>
    <h1>GoblinPass 1.0 Offline ID Logbook</h1>
    <p>Website IDs and safe lookup details only. Never write down passwords.</p>
  </header>
  <div class="notice">This export does not include generated passwords, master passwords, YubiKey secrets, recovery phrases, or additional secret values.</div>
  <table>
    <thead><tr><th>ID</th><th>Website</th><th>Security Method</th><th>Length</th><th>Counter</th><th>Notes</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="6">No vault entries exported.</td></tr>'}</tbody>
  </table>
  <footer>GoblinPass 1.0 • Offline ID Logbook • Do not store passwords on this sheet</footer>
</body>
</html>`;
  downloadTextFile("GoblinPass_1_Offline_ID_Logbook_Export.html", html);
}

async function downloadOfflineSource() {
  try {
    const [html, css, js, manifest] = await Promise.all([
      fetch("index.html").then(response => response.text()),
      fetch("style.css").then(response => response.text()),
      fetch("app.js").then(response => response.text()),
      fetch("manifest.webmanifest").then(response => response.text()).catch(() => "{}")
    ]);
    const source = html
      .replace(/<link rel="manifest" href="manifest\.webmanifest">/, `<script type="application/json" id="offlineManifest">${escapeHtml(manifest)}</script>`)
      .replace(/<link rel="stylesheet" href="style\.css[^"]*">/, `<style>\n${css}\n</style>`)
      .replace(/<script src="app\.js[^"]*"><\/script>/, `<script>\n${js}\n<\/script>`);
    downloadTextFile("GoblinPass_1_Offline_Source.html", source);
  } catch (error) {
    alert("Could not build the offline download from local files. Open this page from the GoblinPass folder and try again.");
  }
}

async function importVault(file) {
  if (!(await ensureVaultUnlocked("Import requires your vault PIN."))) return;
  const text = await file.text();
  const data = JSON.parse(text);
  const incoming = Array.isArray(data) ? data : data.entries;
  if (!Array.isArray(incoming)) throw new Error("Invalid export file.");
  const current = await loadEntries();
  const merged = [...incoming, ...current];
  const dedup = [];
  const seen = new Set();
  for (const e of merged) {
    const key = getEntryId(e);
    if (key && !seen.has(key)) { seen.add(key); dedup.push(e); }
  }
  await saveEntries(dedup);
  renderEntries();
}

document.addEventListener("DOMContentLoaded", () => {
  applySecurityKeySetting();
  applyMasterPasswordSetting();
  updateTrustedDeviceStatus();
  updateGoogleStatus();
  $("defaultPasswordStyle").value = getDefaultPasswordStyle();
  $("passwordStyle").value = getDefaultPasswordStyle();
  $("saveWebsiteIds").checked = loadSettings().saveWebsiteIds !== false;
  if ($("useMasterPassword")) $("useMasterPassword").checked = isMasterPasswordEnabled();
  if ($("offlineDeviceMode")) $("offlineDeviceMode").checked = !!loadSettings().offlineDeviceMode;
  $("memorableStrength").value = "standard";
  updatePasswordStyleUi();
  $("generate").onclick = generate;
  $("save").onclick = saveCurrent;
  $("vaultBtn").onclick = showVault;
  $("setOrUnlockPin").onclick = setOrUnlockPin;
  $("filter").oninput = renderEntries;
  $("exportBtn").onclick = exportVault;
  if ($("exportLogbookBtn")) $("exportLogbookBtn").onclick = exportOfflineLogbook;
  if ($("downloadOfflineSource")) $("downloadOfflineSource").onclick = downloadOfflineSource;
  $("importFile").onchange = async ev => {
    try { if (ev.target.files[0]) await importVault(ev.target.files[0]); }
    catch (e) { alert(e.message); }
  };
  $("toggleGenerated").onclick = () => {
    if (loadSettings().copyPasswordOnly) return;
    generatedVisible = !generatedVisible;
    $("resultText").textContent = generatedVisible
      ? "Generated and copied: " + generatedPassword
      : "Generated and copied: " + previewPassword(generatedPassword);
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
  $("useYubiKey").onchange = () => {
    generatedPassword = "";
    updateYubiKeyUi();
    warnIfYubiKeyStorageLooksTemporary();
  };
  if ($("yubiKeyMode")) $("yubiKeyMode").onchange = () => {
    setYubiKeyMode($("yubiKeyMode").value);
    generatedPassword = "";
    lastGeneratedMeta = null;
    updateYubiKeyUi();
    warnIfYubiKeyStorageLooksTemporary();
  };
  if ($("registerYubiKey")) $("registerYubiKey").onclick = registerYubiKey;
  if ($("setupAndTestYubiKeyPrf")) $("setupAndTestYubiKeyPrf").onclick = setupAndTestYubiKeyPrf;
  if ($("forgetYubiKey")) $("forgetYubiKey").onclick = forgetYubiKey;
  if ($("testYubiKeyPrf")) $("testYubiKeyPrf").onclick = testYubiKeyPrf;
  updateYubiKeyUi();
  warnIfYubiKeyStorageLooksTemporary();
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
  if ($("useMasterPassword")) $("useMasterPassword").onchange = () => {
    const enabled = $("useMasterPassword").checked;
    if (!enabled) {
      const ok = confirm("Warning: turning off Master Password removes it from password generation. If you lose access to your remaining enabled factors, you may not be able to regenerate the same passwords. Continue?");
      if (!ok) {
        $("useMasterPassword").checked = true;
        return;
      }
    }
    saveSettings({ useMasterPassword: enabled });
    applyMasterPasswordSetting();
  };
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
  if ($("offlineDeviceMode")) $("offlineDeviceMode").onchange = () => {
    saveSettings({ offlineDeviceMode: $("offlineDeviceMode").checked });
    if (!$("offlineDeviceMode").checked) hidePasswordQr();
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
});
