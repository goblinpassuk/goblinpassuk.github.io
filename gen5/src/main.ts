import { backupQrParts, createBackup, downloadBackup, drawBackupQr, openBackup } from "./backup.js";
import { SecureClipboard } from "./clipboard.js";
import { base64url, fromBase64url, utf8, wipe } from "./crypto.js";
import { GENERATOR_VERSION, GeneratorSession } from "./generator.js";
import { SecurityLifecycle } from "./lifecycle.js";
import { VaultStorage } from "./storage.js";
import type { BackupPayload, GeneratorOptions, VaultRecordV2 } from "./types.js";
import { SecureVault, type UnlockedVault } from "./vault.js";
import { webAuthnSupport } from "./webauthn.js";

function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Required UI element is missing: ${id}`);
  return found as T;
}

const appShell = element<HTMLElement>("appShell");
const appGate = element<HTMLElement>("appGate");
const gateTitle = element<HTMLElement>("gateTitle");
const gateDescription = element<HTMLElement>("gateDescription");
const gateUnlock = element<HTMLButtonElement>("gateUnlock");
const gateStatus = element<HTMLElement>("gateStatus");
const form = element<HTMLFormElement>("generatorForm");
const generatePassword = element<HTMLButtonElement>("generatePassword");
const websiteId = element<HTMLInputElement>("websiteId");
const masterPassword = element<HTMLInputElement>("masterPassword");
const generatedPassword = element<HTMLInputElement>("generatedPassword");
const statusMessage = element<HTMLElement>("statusMessage");
const vaultStatus = element<HTMLElement>("vaultStatus");
const vaultBadge = element<HTMLElement>("vaultBadge");
const protectMaster = element<HTMLButtonElement>("protectMaster");
const unlockMaster = element<HTMLButtonElement>("unlockMaster");
const lockMaster = element<HTMLButtonElement>("lockMaster");
const forgetMaster = element<HTMLButtonElement>("forgetMaster");
const toggleMaster = element<HTMLButtonElement>("toggleMaster");
const togglePassword = element<HTMLButtonElement>("togglePassword");
const copyPassword = element<HTMLButtonElement>("copyPassword");
const toggleQr = element<HTMLButtonElement>("toggleQr");
const qrPanel = element<HTMLElement>("qrPanel");
const qrPlaceholder = element<HTMLElement>("qrPlaceholder");
const qrCanvas = element<HTMLCanvasElement>("passwordQr");
const addPasskey = element<HTMLButtonElement>("addPasskey");
const exportBackup = element<HTMLButtonElement>("exportBackup");
const importBackup = element<HTMLButtonElement>("importBackup");
const backupFile = element<HTMLInputElement>("backupFile");
const backupDialog = element<HTMLDialogElement>("backupDialog");
const backupDialogTitle = element<HTMLElement>("backupDialogTitle");
const backupPassphrase = element<HTMLInputElement>("backupPassphrase");
const backupConfirm = element<HTMLButtonElement>("backupConfirm");
const backupCancel = element<HTMLButtonElement>("backupCancel");
const backupQrCanvas = element<HTMLCanvasElement>("backupQrCanvas");
const backupQrControls = element<HTMLElement>("backupQrControls");
const backupQrLabel = element<HTMLElement>("backupQrLabel");
const backupQrPrevious = element<HTMLButtonElement>("backupQrPrevious");
const backupQrNext = element<HTMLButtonElement>("backupQrNext");
const offlineStatus = element<HTMLElement>("offlineStatus");
const passkeyList = element<HTMLElement>("passkeyList");
const clipboardTimeout = element<HTMLSelectElement>("clipboardTimeout");

const storage = new VaultStorage();
const secureVault = new SecureVault(storage);
let vaultRecord: VaultRecordV2 | undefined;
let legacyAvailable = false;
let unlockedVault: UnlockedVault | null = null;
let generator: GeneratorSession | null = null;
let available = false;
let busy = false;
let backupMode: "export" | "import" | null = null;
let pendingBackupText = "";
let deferredLockReason = "";
let qrParts: string[] = [];
let qrPartIndex = 0;
const clipboard = new SecureClipboard(30_000, 1_500);
const vaultChannel = typeof BroadcastChannel === "function"
  ? new BroadcastChannel("goblinpass-gen5-vault-events")
  : null;
const lifecycle = new SecurityLifecycle(reason => {
  if (busy) {
    if (!deferredLockReason || deferredLockReason === "window lost focus") deferredLockReason = reason;
  }
  else lock(`Locked: ${reason}.`);
}, 5 * 60_000);

function finishDeferredLock(authenticatorCeremony = false): void {
  if (!deferredLockReason) return;
  const reason = deferredLockReason;
  deferredLockReason = "";
  if (authenticatorCeremony && reason === "window lost focus" && document.hasFocus()) {
    lifecycle.arm();
    return;
  }
  lock(`Locked: ${reason}.`);
}

function renderPasskeys(): void {
  passkeyList.replaceChildren();
  if (!unlockedVault) return;
  for (const passkey of unlockedVault.record.credentials) {
    const row = document.createElement("div");
    row.className = "passkey-item";
    const label = document.createElement("span");
    label.textContent = `${passkey.label} · added ${new Date(passkey.createdAt).toLocaleDateString()}`;
    const remove = document.createElement("button");
    remove.className = "danger-button";
    remove.type = "button";
    remove.textContent = "Remove";
    remove.disabled = unlockedVault.record.credentials.length <= 1;
    remove.addEventListener("click", () => void removeRegisteredPasskey(passkey.id));
    row.append(label, remove);
    passkeyList.append(row);
  }
}

function message(target: HTMLElement, value: string, kind?: "success" | "warning" | "error"): void {
  target.textContent = value;
  if (kind) target.dataset.kind = kind;
  else delete target.dataset.kind;
}

function updateUi(): void {
  const unlocked = Boolean(generator && unlockedVault);
  generatePassword.disabled = !unlocked || busy;
  protectMaster.hidden = Boolean(vaultRecord);
  protectMaster.disabled = busy || !available;
  unlockMaster.hidden = !vaultRecord || unlocked;
  lockMaster.hidden = !unlocked;
  forgetMaster.hidden = !vaultRecord;
  addPasskey.hidden = !unlocked;
  exportBackup.hidden = !unlocked;
  importBackup.hidden = Boolean(vaultRecord);
  masterPassword.readOnly = Boolean(vaultRecord);
  masterPassword.placeholder = vaultRecord ? "Protected — never placed in this field" : "Enter once for protected setup";
  vaultBadge.textContent = unlocked ? "Vault unlocked" : vaultRecord ? "Vault locked" : "Secure setup required";
  renderPasskeys();
}

function showGate(text = ""): void {
  appShell.hidden = true;
  appShell.inert = true;
  appGate.hidden = false;
  gateUnlock.disabled = busy || !available;
  if (!available) {
    gateTitle.textContent = "Secure access unavailable";
    gateDescription.textContent = "WebAuthn PRF and a user-verifying platform passkey are required.";
    gateUnlock.textContent = "Secure browser required";
  } else if (vaultRecord) {
    gateTitle.textContent = "Unlock GoblinPass 5.0";
    gateDescription.textContent = "Verify with Windows Hello or your platform authenticator before the app opens.";
    gateUnlock.textContent = busy ? "Waiting for verification…" : "Unlock securely";
  } else if (legacyAvailable) {
    gateTitle.textContent = "Upgrade protected vault";
    gateDescription.textContent = "Your earlier Gen 5 vault needs a one-time authenticated migration to the multi-passkey format.";
    gateUnlock.textContent = busy ? "Migrating securely…" : "Migrate with Windows Hello";
  } else {
    gateTitle.textContent = "Create protected access";
    gateDescription.textContent = "Complete one-time setup before password generation is enabled.";
    gateUnlock.textContent = "Continue to secure setup";
  }
  message(gateStatus, text);
}

function openApp(): void { appGate.hidden = true; appShell.hidden = false; appShell.inert = false; }

function clearGenerated(): void {
  generatedPassword.value = "";
  generatedPassword.type = "password";
  togglePassword.disabled = true;
  copyPassword.disabled = true;
  toggleQr.disabled = true;
  qrPanel.hidden = true;
  qrPlaceholder.hidden = false;
  qrCanvas.getContext("2d")?.clearRect(0, 0, qrCanvas.width, qrCanvas.height);
}

function clearBackupUi(): void {
  backupPassphrase.value = "";
  pendingBackupText = "";
  qrParts = [];
  qrPartIndex = 0;
  backupQrControls.hidden = true;
  backupQrCanvas.hidden = true;
  backupQrCanvas.getContext("2d")?.clearRect(0, 0, backupQrCanvas.width, backupQrCanvas.height);
  if (backupDialog.open) backupDialog.close();
  backupMode = null;
}

function lock(reason = "Vault locked."): void {
  generator?.destroy();
  generator = null;
  unlockedVault?.destroy();
  unlockedVault = null;
  masterPassword.value = "";
  clipboard.cancel();
  clearGenerated();
  clearBackupUi();
  updateUi();
  showGate(reason);
}

async function startGenerator(vault: UnlockedVault): Promise<void> {
  const masterBytes = vault.takeMasterPassword();
  try {
    generator = GeneratorSession.create(masterBytes);
  } finally {
    wipe(masterBytes);
  }
  unlockedVault = vault;
  lifecycle.arm();
  updateUi();
  openApp();
}

async function unlock(): Promise<boolean> {
  if (busy || !vaultRecord) return false;
  busy = true;
  showGate("Waiting for platform verification…");
  try {
    await startGenerator(await secureVault.unlock(vaultRecord));
    message(vaultStatus, "Unlocked. The Gen 4-compatible generator is available only in memory until the app locks.", "success");
    return true;
  } catch (error) {
    showGate(error instanceof Error ? error.message : "Unlock failed.");
    return false;
  } finally {
    busy = false;
    updateUi();
    finishDeferredLock(true);
  }
}

async function setup(): Promise<void> {
  if (busy || !available || vaultRecord) return;
  const masterBytes = utf8(masterPassword.value);
  masterPassword.value = "";
  if (masterBytes.length < 12) {
    wipe(masterBytes);
    message(vaultStatus, "Use a master password of at least 12 UTF-8 bytes.", "warning");
    return;
  }
  busy = true;
  updateUi();
  try {
    const created = await secureVault.setup(masterBytes);
    vaultRecord = created.record;
    vaultChannel?.postMessage({ type: "vault-updated", revision: vaultRecord.revision });
    await startGenerator(created);
    message(vaultStatus, "Protected vault created. Add a second passkey and encrypted backup for recovery.", "success");
  } catch (error) {
    message(vaultStatus, error instanceof Error ? error.message : "Secure setup failed.", "error");
  } finally {
    wipe(masterBytes);
    busy = false;
    updateUi();
    finishDeferredLock(true);
  }
}

async function migrateLegacy(): Promise<void> {
  if (busy || !legacyAvailable) return;
  busy = true;
  showGate("Authenticate the old vault, then register its replacement passkey.");
  try {
    const migrated = await secureVault.migrateLegacy();
    vaultRecord = migrated.record;
    legacyAvailable = false;
    vaultChannel?.postMessage({ type: "vault-updated", revision: vaultRecord.revision });
    await startGenerator(migrated);
    message(vaultStatus, "Legacy vault migrated atomically. Create and test an encrypted recovery backup.", "success");
  } catch (error) {
    showGate(error instanceof Error ? error.message : "Migration failed; the legacy record was preserved.");
  } finally {
    busy = false;
    updateUi();
    finishDeferredLock(true);
  }
}

async function removeRegisteredPasskey(passkeyId: string): Promise<void> {
  if (!unlockedVault || !confirm("Remove this passkey from the local vault? Remove it from Windows settings separately after testing another passkey.")) return;
  busy = true;
  try {
    await unlockedVault.removePasskey(storage, passkeyId);
    vaultRecord = unlockedVault.record;
    vaultChannel?.postMessage({ type: "vault-updated", revision: vaultRecord.revision });
    message(vaultStatus, "Passkey wrapper removed. The OS credential may still require removal in system settings.", "success");
  } catch (error) {
    message(vaultStatus, error instanceof Error ? error.message : "Passkey removal failed.", "error");
  } finally { busy = false; updateUi(); finishDeferredLock(); }
}

function generatorOptions(): GeneratorOptions {
  return {
    length: Number(element<HTMLInputElement>("passwordLength").value),
    counter: Number(element<HTMLInputElement>("passwordCounter").value),
    lower: element<HTMLInputElement>("useLower").checked,
    upper: element<HTMLInputElement>("useUpper").checked,
    numbers: element<HTMLInputElement>("useNumbers").checked,
    symbols: element<HTMLInputElement>("useSymbols").checked
  };
}

async function generate(event: SubmitEvent): Promise<void> {
  event.preventDefault();
  if (!generator || !vaultRecord) { lock("Secure unlock is required."); return; }
  if (!form.reportValidity()) return;
  try {
    const password = await generator.generate(websiteId.value, generatorOptions());
    generatedPassword.value = password;
    togglePassword.disabled = false;
    copyPassword.disabled = false;
    toggleQr.disabled = false;
    drawBackupQr(qrCanvas, password);
    qrPanel.hidden = true;
    qrPlaceholder.hidden = false;
    await clipboard.copy(password, (text, warning) => message(statusMessage, text, warning ? "warning" : "success"));
    message(statusMessage, `Generated and copied. Clipboard clearing is scheduled for ${clipboard.clearAfterMs / 1_000} seconds.`, "success");
  } catch (error) {
    message(statusMessage, error instanceof Error ? error.message : "Generation failed.", "error");
  }
}

async function addAnotherPasskey(): Promise<void> {
  if (!unlockedVault) return;
  busy = true;
  updateUi();
  try {
    await unlockedVault.addPasskey(storage, `Recovery passkey ${unlockedVault.record.credentials.length + 1}`);
    vaultRecord = unlockedVault.record;
    vaultChannel?.postMessage({ type: "vault-updated", revision: vaultRecord.revision });
    message(vaultStatus, "Additional passkey added. Either registered passkey can now unlock the vault.", "success");
  } catch (error) {
    message(vaultStatus, error instanceof Error ? error.message : "Passkey registration failed.", "error");
  } finally {
    busy = false;
    updateUi();
    finishDeferredLock(true);
  }
}

function openBackupDialog(mode: "export" | "import"): void {
  backupMode = mode;
  backupDialogTitle.textContent = mode === "export" ? "Encrypt recovery backup" : "Decrypt recovery backup";
  backupPassphrase.value = "";
  backupQrControls.hidden = true;
  backupQrCanvas.hidden = true;
  backupDialog.showModal();
  backupPassphrase.focus();
}

async function confirmBackup(): Promise<void> {
  if (!backupMode || busy) return;
  busy = true;
  backupConfirm.disabled = true;
  const passphrase = utf8(backupPassphrase.value.normalize("NFKC"));
  backupPassphrase.value = "";
  try {
    if (backupMode === "export") {
      if (!unlockedVault || !vaultRecord) throw new Error("Unlock the vault before export.");
      const master = await unlockedVault.readMasterPassword();
      try {
        const payload: BackupPayload = {
          format: "goblinpass-recovery-payload", schema: 1, masterPassword: base64url(master),
          profileSalt: vaultRecord.profileSalt, generatorVersion: GENERATOR_VERSION
        };
        const encoded = await createBackup(payload, passphrase);
        downloadBackup(encoded);
        qrParts = backupQrParts(encoded);
        qrPartIndex = 0;
        showQrPart();
        backupQrControls.hidden = qrParts.length <= 1;
        backupQrCanvas.hidden = false;
        message(vaultStatus, "Encrypted recovery file downloaded. QR pages are available in the open dialog.", "success");
      } finally { wipe(master); }
    } else {
      const payload = await openBackup(pendingBackupText.trim(), passphrase);
      if (vaultRecord) throw new Error("Remove the existing vault before importing a recovery backup.");
      const master = fromBase64url(payload.masterPassword);
      const profileSalt = fromBase64url(payload.profileSalt);
      try {
        const created = await secureVault.setup(master, "Restored platform passkey", profileSalt);
        vaultRecord = created.record;
        vaultChannel?.postMessage({ type: "vault-updated", revision: vaultRecord.revision });
        await startGenerator(created);
      } finally { wipe(master, profileSalt); }
      backupDialog.close();
      message(vaultStatus, "Backup restored into a new passkey-protected vault.", "success");
    }
  } catch (error) {
    message(vaultStatus, error instanceof Error ? error.message : "Backup operation failed.", "error");
  } finally {
    wipe(passphrase);
    pendingBackupText = "";
    busy = false;
    backupConfirm.disabled = false;
    updateUi();
    finishDeferredLock();
  }
}

function showQrPart(): void {
  const part = qrParts[qrPartIndex];
  if (!part) return;
  drawBackupQr(backupQrCanvas, part);
  backupQrLabel.textContent = `QR ${qrPartIndex + 1} of ${qrParts.length}`;
  backupQrPrevious.disabled = qrPartIndex === 0;
  backupQrNext.disabled = qrPartIndex >= qrParts.length - 1;
}

gateUnlock.addEventListener("click", () => { if (vaultRecord) void unlock(); else if (legacyAvailable) void migrateLegacy(); else openApp(); });
protectMaster.addEventListener("click", () => void setup());
unlockMaster.addEventListener("click", () => void unlock());
lockMaster.addEventListener("click", () => lock("Locked by user."));
forgetMaster.addEventListener("click", async () => {
  if (!confirm("Remove the encrypted vault from this browser? Keep a tested recovery backup first.")) return;
  lock();
  await storage.remove();
  vaultChannel?.postMessage({ type: "vault-removed" });
  vaultRecord = undefined;
  updateUi();
  showGate("Local encrypted vault removed. The OS passkey may still need removal in system settings.");
});
addPasskey.addEventListener("click", () => void addAnotherPasskey());
exportBackup.addEventListener("click", () => openBackupDialog("export"));
importBackup.addEventListener("click", () => backupFile.click());
backupFile.addEventListener("change", async () => {
  const file = backupFile.files?.[0];
  backupFile.value = "";
  if (!file || file.size > 1_000_000) return;
  pendingBackupText = await file.text();
  openBackupDialog("import");
});
backupConfirm.addEventListener("click", () => void confirmBackup());
backupCancel.addEventListener("click", () => { pendingBackupText = ""; backupDialog.close(); });
backupQrPrevious.addEventListener("click", () => { qrPartIndex -= 1; showQrPart(); });
backupQrNext.addEventListener("click", () => { qrPartIndex += 1; showQrPart(); });
clipboardTimeout.addEventListener("change", () => { clipboard.clearAfterMs = Number(clipboardTimeout.value) * 1_000; });
form.addEventListener("submit", event => void generate(event));
copyPassword.addEventListener("click", () => void clipboard.copy(generatedPassword.value, (text, warning) => message(statusMessage, text, warning ? "warning" : "success")));
toggleQr.addEventListener("click", () => { qrPanel.hidden = !qrPanel.hidden; qrPlaceholder.hidden = !qrPanel.hidden; });
toggleMaster.addEventListener("click", () => { masterPassword.type = masterPassword.type === "password" ? "text" : "password"; });
togglePassword.addEventListener("click", () => { generatedPassword.type = generatedPassword.type === "password" ? "text" : "password"; });
window.addEventListener("storage", () => lock("Storage changed in another context."));
vaultChannel?.addEventListener("message", () => {
  if (generator || unlockedVault) lock("Vault changed in another tab.");
  void storage.read().then(record => { vaultRecord = record; updateUi(); showGate("Vault state refreshed from another tab."); });
});
window.addEventListener("online", () => { offlineStatus.textContent = "Offline ready"; });
window.addEventListener("offline", () => { offlineStatus.textContent = "Working offline"; });

async function initialise(): Promise<void> {
  const support = await webAuthnSupport();
  available = support.available;
  vaultRecord = await storage.read();
  legacyAvailable = !vaultRecord && Boolean(await storage.readLegacy());
  updateUi();
  showGate(support.reason ?? "");
  if ("serviceWorker" in navigator) await navigator.serviceWorker.register("./service-worker.js").catch(() => undefined);
}

void initialise().catch(error => showGate(error instanceof Error ? error.message : "Secure initialisation failed."));
