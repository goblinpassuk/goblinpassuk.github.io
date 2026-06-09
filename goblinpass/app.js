const $ = (id) => document.getElementById(id);

let generatedPassword = "";
let generatedVisible = false;
let vaultUnlocked = false;
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
const SETTINGS_KEY = "goblinpass_mobile_settings_v1";
const TRUSTED_DEVICE_KEY = "goblinpass_trusted_device_key_v1";
const YUBIKEY_CREDENTIAL_KEY = "goblinpass_yubikey_credential_id_v1";
const YUBIKEY_MODE_KEY = "goblinpass_yubikey_mode_v1";
const GOOGLE_CLIENT_ID = "908605927082-sne248f74g829ek1kh1mh11gumjj411m.apps.googleusercontent.com";

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
  return JSON.parse(localStorage.getItem(PIN_KEY) || "null");
}

async function savePinRecord(record) {
  localStorage.setItem(PIN_KEY, JSON.stringify(record));
}

async function hashPin(pin, salt) {
  return await sha256Hex("GOBLINPASS-PIN-v1|" + pin + "|" + salt);
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
      googleSecurityFactorEnabled: false,
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
  const ok = confirm("Anyone with this recovery key, your master password, and your security key can recreate your passwords. Store it safely offline.");
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
  return localStorage.getItem(YUBIKEY_CREDENTIAL_KEY) || "";
}

function getYubiKeyMode() {
  const mode = $("yubiKeyMode")?.value || localStorage.getItem(YUBIKEY_MODE_KEY) || "prf";
  return mode === "gate" ? "gate" : "prf";
}

function setYubiKeyMode(mode) {
  localStorage.setItem(YUBIKEY_MODE_KEY, mode === "gate" ? "gate" : "prf");
}

function setYubiKeyMessage(message, type = "info") {
  const el = $("yubiKeyMessage");
  if (!el) return;
  el.textContent = message || "";
  el.dataset.messageType = type;
  el.classList.toggle("hidden", !message);
}

async function browserPrfCapabilityText() {
  if (!window.PublicKeyCredential) return "WebAuthn is not available in this browser.";
  if (typeof PublicKeyCredential.getClientCapabilities !== "function") {
    return "This browser does not expose a PRF capability check. GoblinPass will test PRF during generation.";
  }
  try {
    const caps = await PublicKeyCredential.getClientCapabilities("public-key");
    return caps.extensions?.includes("prf")
      ? "Browser reports WebAuthn PRF support."
      : "Browser does not report WebAuthn PRF support.";
  } catch {
    return "GoblinPass could not read the browser PRF capability. It will test PRF during generation.";
  }
}

function updateYubiKeyUi() {
  const enabled = !!$("useYubiKey")?.checked;
  const registered = !!getYubiKeyCredentialId();
  const mode = getYubiKeyMode();
  if ($("yubiKeyMode")) $("yubiKeyMode").value = mode;
  if ($("yubiKeyBox")) $("yubiKeyBox").classList.toggle("hidden", !enabled);
  if ($("yubiKeyStatus")) $("yubiKeyStatus").textContent = registered ? "Status: Registered" : "Status: Not registered";
  if (!enabled) setYubiKeyMessage("");
  else if (mode === "gate") setYubiKeyMessage("Titan-compatible mode verifies the registered security key before generation. It does not add a hidden PRF secret to the password formula.", "info");
  else if (!webAuthnPrfSupported()) setYubiKeyMessage("This browser does not expose WebAuthn PRF. Try a current Chromium-based browser over HTTPS with a YubiKey that supports hmac-secret.", "warning");
  else if (registered) setYubiKeyMessage("YubiKey is registered for this site origin. Keep using the same registered key to recreate YubiKey-protected passwords.", "success");
}

function webAuthnPrfSupported() {
  return !!(navigator.credentials?.create && navigator.credentials?.get && window.PublicKeyCredential);
}

async function yubiKeySalt() {
  const siteId = $("siteId").value.trim().toLowerCase();
  const login = $("login").value.trim().toLowerCase();
  const material = `GoblinPass-YubiKey-v1|${siteId}|${login}|${location.origin}`;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(material)));
}

function yubiKeyErrorMessage(error) {
  if (!webAuthnPrfSupported()) return "This browser does not support WebAuthn PRF.";
  if (error?.name === "NotAllowedError") return "YubiKey prompt was cancelled, timed out, the wrong YubiKey was used, or touch/PIN was not completed.";
  if (error?.name === "InvalidStateError") return "This YubiKey may already be registered for this app.";
  if (error?.name === "NotReadableError") return "YubiKey not detected or could not be read.";
  if (error?.name === "SecurityError") return "WebAuthn is not available for this origin. Use HTTPS or GitHub Pages.";
  if (String(error?.message || "").includes("PRF extension data")) return "This key registered successfully, but this browser/key combination did not return PRF data during generation. GoblinPass cannot use it as a password ingredient here.";
  return error?.message || "YubiKey failed. Check that the registered YubiKey is connected.";
}

async function registerYubiKey() {
  if (!webAuthnPrfSupported()) {
    setYubiKeyMessage("This browser does not expose WebAuthn PRF. Try a current Chromium-based browser over HTTPS with a YubiKey that supports hmac-secret.", "warning");
    return;
  }
  setYubiKeyMessage("Waiting for the browser and YubiKey. Complete any touch or PIN prompt.", "info");
  try {
    const credential = await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: "GoblinPass" },
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
          residentKey: "discouraged",
          userVerification: "preferred"
        },
        timeout: 60000,
        extensions: {
          prf: {}
        }
      }
    });
    const results = credential.getClientExtensionResults?.();
    localStorage.setItem(YUBIKEY_CREDENTIAL_KEY, bytesToBase64Url(new Uint8Array(credential.rawId)));
    updateYubiKeyUi();
    if (results?.prf?.enabled) {
      setYubiKeyMessage("YubiKey registered and PRF was confirmed during setup.", "success");
    } else {
      setYubiKeyMessage("YubiKey registered. Some browsers do not confirm PRF during setup, so GoblinPass will check PRF when you generate.", "info");
    }
  } catch (error) {
    setYubiKeyMessage(yubiKeyErrorMessage(error), "warning");
  }
}

async function forgetYubiKey() {
  localStorage.removeItem(YUBIKEY_CREDENTIAL_KEY);
  currentYubiKeyFactor = "";
  generatedPassword = "";
  lastGeneratedMeta = null;
  updateYubiKeyUi();
  const capability = await browserPrfCapabilityText();
  setYubiKeyMessage(`Local key registration forgotten. Register the YubiKey again with the latest PRF setup. ${capability}`, "info");
}

async function getYubiKeyFactor() {
  if (!$("useYubiKey")?.checked) return "";
  const id = getYubiKeyCredentialId();
  if (!id) throw new Error("Register a hardware security key before generating a hardware-key-protected password.");
  if (getYubiKeyMode() === "gate") {
    await verifyHardwareKeyGate(id);
    setYubiKeyMessage("Hardware key verified. Password generated using the normal GoblinPass formula.", "success");
    return "";
  }
  if (!webAuthnPrfSupported()) throw new Error("This browser does not support WebAuthn PRF.");
  const salt = await yubiKeySalt();
  try {
    const credential = await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: "public-key", id: base64UrlToBytes(id) }],
        userVerification: "preferred",
        timeout: 60000,
        extensions: {
          prf: { eval: { first: salt } }
        }
      }
    });
    const output = credential.getClientExtensionResults?.().prf?.results?.first;
    if (!output) throw new Error("This browser or YubiKey did not return PRF extension data.");
    const mixKey = await crypto.subtle.importKey(
      "raw",
      output,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const mixed = await crypto.subtle.sign("HMAC", mixKey, new TextEncoder().encode("GoblinPass-YubiKey-Mix-v1"));
    return bytesToBase64Url(new Uint8Array(mixed));
  } catch (error) {
    throw new Error(yubiKeyErrorMessage(error));
  }
}

async function verifyHardwareKeyGate(id = getYubiKeyCredentialId()) {
  try {
    await navigator.credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: "public-key", id: base64UrlToBytes(id) }],
        userVerification: "preferred",
        timeout: 60000
      }
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
    <p class="security-panel-title">Enter the full Security Key</p>
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
  const master = $("master").value;
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

async function generate() {
  if (!$("siteId").value.trim() || !$("master").value) return alert("Enter website ID and master password.");
  if (isSecurityKeyEnabled() && !getSecurityKeyInputValue()) return alert("Enter your Security Key, or turn it off in Settings.");
  if (isGoogleSecurityFactorEnabled() && !getGoogleSubjectForGeneration()) return alert("Sign in with Google before generating passwords, or turn off Google Security Factor in Settings.");
  const style = getQuickPasswordStyle();
  const strength = getMemorableStrength();
  try {
    currentYubiKeyFactor = await getYubiKeyFactor();
  } catch (error) {
    currentYubiKeyFactor = "";
    setYubiKeyMessage(error.message, "warning");
    return;
  }
  generatedPassword = await deterministicPassword(style, strength);
  lastGeneratedMeta = { style, strength, useYubiKey: !!$("useYubiKey")?.checked, yubiKeyMode: getYubiKeyMode() };
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
  return JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
}

async function saveEntries(entries) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(entries));
}

async function checkPin(pin) {
  const record = await getPinRecord();
  if (!record) return false;

  const now = Date.now();
  if (pinLockedUntil && now < pinLockedUntil) {
    alert("PIN locked. Try again soon.");
    return false;
  }

  const ok = (await hashPin(pin, record.salt)) === record.hash;
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

async function saveCurrent() {
  if (!(await ensureVaultUnlocked("Save requires your vault PIN."))) return;

  const savedStyle = getQuickPasswordStyle();
  const savedStrength = getMemorableStrength();
  let pwForHint = generatedPassword;
  const usingYubiKey = !!$("useYubiKey")?.checked;
  const yubiKeyMode = getYubiKeyMode();
  if (pwForHint && (!lastGeneratedMeta || lastGeneratedMeta.style !== savedStyle || lastGeneratedMeta.strength !== savedStrength || lastGeneratedMeta.useYubiKey !== usingYubiKey || lastGeneratedMeta.yubiKeyMode !== yubiKeyMode)) {
    pwForHint = "";
  }
  if (!pwForHint && isSecurityKeyEnabled() && !getSecurityKeyInputValue()) return alert("Enter your Security Key, or turn it off in Settings.");
  if (!pwForHint && isGoogleSecurityFactorEnabled() && !getGoogleSubjectForGeneration()) return alert("Sign in with Google before saving this entry, or turn off Google Security Factor in Settings.");
  if (!pwForHint && $("master").value && $("siteId").value.trim()) {
    try {
      currentYubiKeyFactor = await getYubiKeyFactor();
    } catch (error) {
      currentYubiKeyFactor = "";
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
  if (idx >= 0) {
    if (!entry.passwordHint && entries[idx].passwordHint) entry.passwordHint = entries[idx].passwordHint;
    entry.entryKey = entries[idx].entryKey || entry.entryKey;
    entries[idx] = entry;
  } else entries.unshift(entry);

  await saveEntries(entries);
  renderEntries();
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
    await savePinRecord({ salt, hash, created: new Date().toISOString() });
    vaultUnlocked = true;
    $("vaultPin").value = "";
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
      ${e.yubiKeyRequired ? `<div class="entry-line"><span class="high-security-badge">${e.yubiKeyMode === "gate" ? "Security Key Gate" : "YubiKey PRF Required"}</span></div>` : ""}
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
  updateTrustedDeviceStatus();
  updateGoogleStatus();
  $("defaultPasswordStyle").value = getDefaultPasswordStyle();
  $("passwordStyle").value = getDefaultPasswordStyle();
  $("saveWebsiteIds").checked = loadSettings().saveWebsiteIds !== false;
  $("memorableStrength").value = "standard";
  updatePasswordStyleUi();
  $("generate").onclick = generate;
  $("save").onclick = saveCurrent;
  $("vaultBtn").onclick = showVault;
  $("setOrUnlockPin").onclick = setOrUnlockPin;
  $("filter").oninput = renderEntries;
  $("exportBtn").onclick = exportVault;
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
  $("toggleMaster").onclick = () => {
    const visible = $("master").type === "password";
    $("master").type = visible ? "text" : "password";
    $("toggleMaster").textContent = visible ? "Hide" : "Show";
  };
  $("securityKey").onclick = openSecurityInputMethod;
  $("securityKey").oninput = () => {
    if (getSecurityInputMethod() === "normal") securityKeyMemory = "";
  };
  $("useYubiKey").onchange = () => { generatedPassword = ""; updateYubiKeyUi(); };
  if ($("yubiKeyMode")) $("yubiKeyMode").onchange = () => {
    setYubiKeyMode($("yubiKeyMode").value);
    generatedPassword = "";
    updateYubiKeyUi();
  };
  $("registerYubiKey").onclick = registerYubiKey;
  if ($("forgetYubiKey")) $("forgetYubiKey").onclick = forgetYubiKey;
  updateYubiKeyUi();
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
});
