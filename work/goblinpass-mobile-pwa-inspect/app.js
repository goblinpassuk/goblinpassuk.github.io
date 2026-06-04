const $ = (id) => document.getElementById(id);

let generatedPassword = "";
let generatedVisible = false;
let vaultUnlocked = false;
let pinFailCount = 0;
let pinLockedUntil = 0;

const STORAGE_KEY = "goblinpass_mobile_entries_v1";
const PIN_KEY = "goblinpass_mobile_pin_v1";

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
  if (s.length <= 4) return s[0] + "•••";
  if (s.includes("@")) {
    const [name, domain] = s.split("@");
    const left = name.length <= 4 ? name[0] + "•••" : name.slice(0,4) + "•••" + name.slice(-2);
    return left + "@" + domain;
  }
  return s.slice(0,4) + "•••" + s.slice(-2);
}

function storedLoginObject(login, storeFull) {
  return { maskedLogin: maskText(login), fullLogin: storeFull ? login : "", fullLoginStored: !!storeFull };
}
function getEntryLoginForDisplay(e) { return e.maskedLogin || maskText(e.login || ""); }
function getEntryFullLogin(e) { return e.fullLogin || e.login || ""; }
function canRevealFullLogin(e) { return !!(e.fullLogin || e.login); }

function charset() {
  let chars = "";
  if ($("lower").checked) chars += "abcdefghijklmnopqrstuvwxyz";
  if ($("upper").checked) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if ($("nums").checked) chars += "0123456789";
  if ($("symbols").checked) chars += "%!@#$_-";
  return chars || "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
}

async function deterministicPassword() {
  const site = $("site").value.trim().toLowerCase();
  const login = $("login").value.trim().toLowerCase();
  const master = $("master").value;
  const length = Math.max(8, Math.min(64, parseInt($("length").value || "16", 10)));
  const counter = parseInt($("counter").value || "1", 10);
  const chars = charset();

  const seed = `SPV1|${site}|${login}|${counter}|${master}|${chars}`;
  let out = "";
  let round = 0;
  while (out.length < length) {
    const hex = await sha256Hex(seed + "|" + round++);
    for (let i = 0; i < hex.length && out.length < length; i += 2) {
      const n = parseInt(hex.slice(i, i+2), 16);
      out += chars[n % chars.length];
    }
  }
  return out;
}

function previewPassword(pw) {
  if (!pw) return "";
  if (pw.length <= 8) return pw[0] + "••••" + pw.slice(-1);
  return pw.slice(0,4) + "••••••••" + pw.slice(-4);
}

function maskPasswordHint(hint) {
  return hint ? "•••••" : "not saved";
}

async function generate() {
  if (!$("site").value.trim() || !$("master").value) return alert("Enter site and master password.");
  generatedPassword = await deterministicPassword();
  generatedVisible = false;
  try { await navigator.clipboard.writeText(generatedPassword); } catch {}
  $("resultText").textContent = "Generated and copied: " + previewPassword(generatedPassword);
  $("result").classList.remove("hidden");
}

function getEntryPayload(passwordHint) {
  const login = $("login").value.trim();
  const loginStore = storedLoginObject(login, $("storeFullLogin").checked);
  return {
    site: $("site").value.trim().toLowerCase(),
    maskedLogin: loginStore.maskedLogin,
    fullLogin: loginStore.fullLogin,
    fullLoginStored: loginStore.fullLoginStored,
    passwordHint: passwordHint || "",
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

  let pwForHint = generatedPassword;
  if (!pwForHint && $("master").value && $("site").value.trim()) pwForHint = await deterministicPassword();

  const entry = getEntryPayload(pwForHint ? pwForHint.slice(0, 5) : "");
  if (!entry.site) return;

  const entries = await loadEntries();
  const idx = entries.findIndex(e => e.site === entry.site && getEntryLoginForDisplay(e) === entry.maskedLogin);
  if (idx >= 0) {
    if (!entry.passwordHint && entries[idx].passwordHint) entry.passwordHint = entries[idx].passwordHint;
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
    await savePinRecord({salt, hash, created:new Date().toISOString()});
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
    ? "Enter your vault PIN to unlock saved sites."
    : "Create a permanent 4 digit vault PIN. This PIN will be required to view saved sites.";
}

function applyEntry(e) {
  $("site").value = e.site || "";
  $("login").value = canRevealFullLogin(e) ? getEntryFullLogin(e) : getEntryLoginForDisplay(e);
  $("storeFullLogin").checked = !!e.fullLoginStored;
  $("length").value = e.length || 16;
  $("counter").value = e.counter || 1;
  $("lower").checked = !!e.options?.lower;
  $("upper").checked = !!e.options?.upper;
  $("nums").checked = !!e.options?.nums;
  $("symbols").checked = !!e.options?.symbols;
  window.scrollTo({top:0, behavior:"smooth"});
}

async function renderEntries() {
  const box = $("entries");
  if (!box || !vaultUnlocked) return;

  const filter = ($("filter").value || "").toLowerCase();
  const entries = await loadEntries();
  const shown = entries.filter(e => (e.site + " " + getEntryLoginForDisplay(e) + " " + getEntryFullLogin(e)).toLowerCase().includes(filter));

  box.innerHTML = "";
  if (!shown.length) {
    box.innerHTML = '<p class="muted">No matching vault entries.</p>';
    return;
  }

  shown.forEach(e => {
    const div = document.createElement("div");
    div.className = "entry";
    div.innerHTML = `
      <div class="entry-title">${escapeHtml(e.site)}</div>
      <div class="entry-line">Login: <span data-login>${escapeHtml(getEntryLoginForDisplay(e))}</span>${e.fullLoginStored ? '<span class="sensitive-note">full stored</span>' : ''}</div>
      <div class="entry-line">Password hint: <span data-pwhint>${escapeHtml(maskPasswordHint(e.passwordHint))}</span></div>
      <div class="entry-line">Length: ${e.length} · Counter: ${e.counter}</div>
      <div class="entry-actions">
        <button data-use>Use</button>
        <button data-hint>Show hint</button>
        <button data-copy>Copy login</button>
        <button data-delete class="danger">Delete</button>
      </div>`;
    div.querySelector("[data-use]").onclick = () => applyEntry(e);
    div.querySelector("[data-hint]").onclick = async () => {
      if (await verifyPin()) {
        div.querySelector("[data-login]").textContent = canRevealFullLogin(e) ? getEntryFullLogin(e) : getEntryLoginForDisplay(e);
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
      await saveEntries(all.filter(x => !(x.site === e.site && getEntryLoginForDisplay(x) === getEntryLoginForDisplay(e))));
      renderEntries();
    };
    box.appendChild(div);
  });
}

function escapeHtml(s) {
  return String(s || "").replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[m]));
}

async function exportVault() {
  if (!(await ensureVaultUnlocked("Export requires your vault PIN."))) return;
  const entries = await loadEntries();
  const blob = new Blob([JSON.stringify({version:"mobile-1", exported:new Date().toISOString(), entries}, null, 2)], {type:"application/json"});
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
    const key = `${e.site}|${getEntryLoginForDisplay(e)}`;
    if (!seen.has(key)) { seen.add(key); dedup.push(e); }
  }
  await saveEntries(dedup);
  renderEntries();
}

document.addEventListener("DOMContentLoaded", () => {
  $("generate").onclick = generate;
  $("save").onclick = saveCurrent;
  $("vaultBtn").onclick = showVault;
  $("setOrUnlockPin").onclick = setOrUnlockPin;
  $("filter").oninput = renderEntries;
  $("exportBtn").onclick = exportVault;
  $("importFile").onchange = async ev => {
    try { if (ev.target.files[0]) await importVault(ev.target.files[0]); }
    catch(e) { alert(e.message); }
  };
  $("toggleGenerated").onclick = () => {
    generatedVisible = !generatedVisible;
    $("resultText").textContent = generatedVisible
      ? "Generated and copied: " + generatedPassword
      : "Generated and copied: " + previewPassword(generatedPassword);
  };
  $("toggleMaster").onclick = () => {
    $("master").type = $("master").type === "password" ? "text" : "password";
  };
});
