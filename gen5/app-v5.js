(function () {
  "use strict";

  const $ = id => document.getElementById(id);
  const form = $("generatorForm");
  const websiteId = $("websiteId");
  const passwordLength = $("passwordLength");
  const passwordCounter = $("passwordCounter");
  const masterPassword = $("masterPassword");
  const useLower = $("useLower");
  const useUpper = $("useUpper");
  const useNumbers = $("useNumbers");
  const useSymbols = $("useSymbols");
  const toggleMaster = $("toggleMaster");
  const generatedPassword = $("generatedPassword");
  const togglePassword = $("togglePassword");
  const copyPassword = $("copyPassword");
  const toggleQr = $("toggleQr");
  const qrPanel = $("qrPanel");
  const qrPlaceholder = $("qrPlaceholder");
  const qrPlaceholderMessage = $("qrPlaceholderMessage");
  const resultPanel = $("resultPanel");
  const resultStatus = $("statusMessage");
  const protectMaster = $("protectMaster");
  const unlockMaster = $("unlockMaster");
  const lockMaster = $("lockMaster");
  const forgetMaster = $("forgetMaster");
  const vaultBadge = $("vaultBadge");
  const vaultStatus = $("vaultStatus");
  const vaultDescription = $("vaultDescription");
  const supportNotice = $("supportNotice");
  const installButton = $("installApp");
  const offlineStatus = $("offlineStatus");
  const vault = window.GoblinPassSecureVault;

  let savedRecord = null;
  let unlocked = false;
  let available = false;
  let busy = false;
  let installPrompt = null;
  let lockTimer = null;
  const AUTO_LOCK_MS = 5 * 60 * 1000;

  function setVaultMessage(message, kind) {
    vaultStatus.textContent = message;
    if (kind) vaultStatus.dataset.kind = kind;
    else delete vaultStatus.dataset.kind;
  }

  function describeCredentialError(error) {
    if (error?.name === "NotAllowedError") return "Windows Hello was cancelled or timed out. Nothing changed.";
    if (error?.name === "InvalidStateError") return "That passkey could not be created in its current state.";
    if (error?.name === "NotSupportedError") return "This browser or authenticator does not support the required passkey encryption feature.";
    return error?.message || "Secure unlock could not complete.";
  }

  function updateVaultUi() {
    const hasSavedPassword = Boolean(savedRecord);
    protectMaster.hidden = hasSavedPassword;
    protectMaster.disabled = !available || busy;
    unlockMaster.hidden = !hasSavedPassword || unlocked;
    unlockMaster.disabled = busy;
    lockMaster.hidden = !hasSavedPassword || !unlocked;
    lockMaster.disabled = busy;
    forgetMaster.hidden = !hasSavedPassword;
    forgetMaster.disabled = busy;
    masterPassword.readOnly = hasSavedPassword;
    masterPassword.dataset.vaultState = hasSavedPassword ? (unlocked ? "unlocked" : "locked") : "manual";
    toggleMaster.disabled = hasSavedPassword && !unlocked;

    if (!hasSavedPassword) {
      vaultBadge.textContent = available ? "Vault ready to set up" : "Manual entry only";
      vaultDescription.textContent = "Enter your master password, then protect it with Windows Hello or this device's biometric/passkey unlock.";
      masterPassword.placeholder = "Enter to use or protect";
    } else if (unlocked) {
      vaultBadge.textContent = "Vault unlocked";
      vaultDescription.textContent = "Your decrypted master password is available only for this session and will lock after five minutes.";
      masterPassword.placeholder = "Unlocked";
    } else {
      vaultBadge.textContent = "Vault locked";
      vaultDescription.textContent = "The encrypted master password is saved locally. Use Windows Hello to unlock it.";
      masterPassword.placeholder = "Locked — use Windows Hello";
    }
  }

  function clearResult(message) {
    generatedPassword.value = "";
    generatedPassword.type = "password";
    togglePassword.textContent = "Show";
    togglePassword.disabled = true;
    copyPassword.disabled = true;
    toggleQr.disabled = true;
    toggleQr.textContent = "Show QR code";
    toggleQr.setAttribute("aria-expanded", "false");
    qrPanel.hidden = true;
    qrPlaceholder.hidden = false;
    qrPlaceholderMessage.textContent = "Generate a password to enable its QR code.";
    resultPanel.classList.remove("has-result");
    resultStatus.textContent = message || "Generate the same password again with the same Website ID, Master Password, and options.";
  }

  function resetLockTimer() {
    clearTimeout(lockTimer);
    if (unlocked) lockTimer = setTimeout(() => lockVault("Master password locked automatically after five minutes."), AUTO_LOCK_MS);
  }

  function lockVault(message) {
    clearTimeout(lockTimer);
    lockTimer = null;
    unlocked = false;
    masterPassword.value = "";
    masterPassword.type = "password";
    toggleMaster.textContent = "Show";
    toggleMaster.setAttribute("aria-pressed", "false");
    clearResult("Vault locked. Unlock it before generating another password.");
    setVaultMessage(message || "Locked. Your master password remains encrypted in local storage.", "success");
    updateVaultUi();
  }

  async function protectEnteredMaster() {
    if (busy || !available) return;
    if (!masterPassword.value) {
      masterPassword.focus();
      setVaultMessage("Enter your master password first.", "warning");
      return;
    }
    busy = true;
    updateVaultUi();
    setVaultMessage("Follow the Windows Hello prompt to create secure unlock…");
    try {
      savedRecord = await vault.create(masterPassword.value);
      unlocked = true;
      resetLockTimer();
      setVaultMessage("Protected. Only the AES-GCM encrypted copy is stored; Windows Hello is required to decrypt it.", "success");
    } catch (error) {
      setVaultMessage(describeCredentialError(error), "error");
    } finally {
      busy = false;
      updateVaultUi();
    }
  }

  async function unlockVault() {
    if (busy || !savedRecord) return false;
    busy = true;
    updateVaultUi();
    setVaultMessage("Waiting for Windows Hello…");
    try {
      masterPassword.value = await vault.unlock(savedRecord);
      unlocked = true;
      resetLockTimer();
      setVaultMessage("Unlocked for five minutes. Lock now when you are finished.", "success");
      return true;
    } catch (error) {
      setVaultMessage(describeCredentialError(error), "error");
      return false;
    } finally {
      busy = false;
      updateVaultUi();
    }
  }

  async function forgetSavedMaster() {
    if (busy || !savedRecord) return;
    if (!window.confirm("Remove the encrypted master password from this browser? The Windows passkey may remain in Windows settings.")) return;
    busy = true;
    updateVaultUi();
    try {
      await vault.deleteRecord();
      savedRecord = null;
      unlocked = false;
      masterPassword.value = "";
      clearResult("Saved master password removed. You can continue with manual entry.");
      setVaultMessage("Encrypted master password removed from this browser. No plaintext copy was stored.", "success");
    } catch (error) {
      setVaultMessage(describeCredentialError(error), "error");
    } finally {
      busy = false;
      updateVaultUi();
    }
  }

  function toggleVisibility(input, button) {
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    button.textContent = show ? "Hide" : "Show";
    button.setAttribute("aria-pressed", String(show));
    if (input === masterPassword) resetLockTimer();
  }

  async function writeToClipboard() {
    if (!generatedPassword.value) return false;
    try {
      await navigator.clipboard.writeText(generatedPassword.value);
      return true;
    } catch {
      try {
        generatedPassword.type = "text";
        generatedPassword.select();
        return document.execCommand("copy");
      } catch {
        return false;
      } finally {
        generatedPassword.setSelectionRange(0, 0);
        generatedPassword.type = "password";
      }
    }
  }

  function beginGestureClipboardWrite(passwordPromise) {
    if (!navigator.clipboard?.write || typeof window.ClipboardItem !== "function") return null;
    try {
      const blob = passwordPromise.then(password => new Blob([password], { type: "text/plain" }));
      return navigator.clipboard.write([new ClipboardItem({ "text/plain": blob })]).then(() => true).catch(() => false);
    } catch {
      return null;
    }
  }

  function selectedCharacterKeys() {
    return [[useLower, "lower"], [useUpper, "upper"], [useNumbers, "nums"], [useSymbols, "symbols"]]
      .filter(([input]) => input.checked).map(([, key]) => key);
  }

  async function generatePassword(event) {
    event.preventDefault();
    if (savedRecord && !unlocked && !(await unlockVault())) return;
    if (!form.reportValidity()) return;
    const selectedKeys = selectedCharacterKeys();
    if (!selectedKeys.length) {
      resultStatus.textContent = "Select at least one password character group.";
      return;
    }
    try {
      resetLockTimer();
      const passwordPromise = window.goblinPassGenerate(websiteId.value, masterPassword.value, {
        length: passwordLength.value,
        counter: passwordCounter.value,
        selectedKeys
      });
      const gestureCopy = beginGestureClipboardWrite(passwordPromise);
      const password = await passwordPromise;
      generatedPassword.value = password;
      generatedPassword.type = "password";
      togglePassword.textContent = "Show";
      togglePassword.disabled = false;
      copyPassword.disabled = false;
      window.GoblinPassQrV4.draw($("passwordQr"), password);
      toggleQr.disabled = false;
      toggleQr.textContent = "Show QR code";
      toggleQr.setAttribute("aria-expanded", "false");
      qrPanel.hidden = true;
      qrPlaceholder.hidden = false;
      qrPlaceholderMessage.textContent = "QR code hidden for privacy. Select Show QR code to reveal it.";
      resultPanel.classList.add("has-result");
      let copied = gestureCopy ? await gestureCopy : false;
      if (!copied) copied = await writeToClipboard();
      resultStatus.textContent = copied
        ? "Generated locally and copied to the clipboard."
        : "Generated locally, but automatic copying was blocked. Use Copy to try again.";
    } catch (error) {
      resultStatus.textContent = error.message || "The password could not be generated.";
    }
  }

  function toggleQrCode() {
    if (!generatedPassword.value) return;
    const show = qrPanel.hidden;
    qrPanel.hidden = !show;
    qrPlaceholder.hidden = show;
    toggleQr.textContent = show ? "Hide QR code" : "Show QR code";
    toggleQr.setAttribute("aria-expanded", String(show));
    if (!show) qrPlaceholderMessage.textContent = "QR code hidden for privacy.";
  }

  function updateConnectionStatus() {
    offlineStatus.textContent = navigator.onLine ? "Offline ready" : "Working offline";
  }

  async function initialise() {
    const support = await vault.support();
    available = support.available;
    supportNotice.hidden = available;
    if (!available) {
      supportNotice.querySelector("span").textContent = `${support.reason} You can still generate with manual entry; GoblinPass will not save it.`;
      setVaultMessage(support.reason, "warning");
    }
    try {
      savedRecord = await vault.getRecord();
      if (savedRecord) setVaultMessage("Encrypted master password found. Unlock it with Windows Hello when needed.", "success");
      else if (available) setVaultMessage("Ready to create a device-protected vault.");
    } catch (error) {
      available = false;
      supportNotice.hidden = false;
      setVaultMessage(error.message, "error");
    }
    updateVaultUi();
  }

  form.addEventListener("submit", generatePassword);
  protectMaster.addEventListener("click", protectEnteredMaster);
  unlockMaster.addEventListener("click", unlockVault);
  lockMaster.addEventListener("click", () => lockVault());
  forgetMaster.addEventListener("click", forgetSavedMaster);
  toggleMaster.addEventListener("click", () => toggleVisibility(masterPassword, toggleMaster));
  togglePassword.addEventListener("click", () => toggleVisibility(generatedPassword, togglePassword));
  copyPassword.addEventListener("click", async () => {
    resultStatus.textContent = await writeToClipboard() ? "Password copied to the clipboard." : "Clipboard access was blocked.";
  });
  toggleQr.addEventListener("click", toggleQrCode);
  [websiteId, passwordLength, passwordCounter, useLower, useUpper, useNumbers, useSymbols].forEach(input => input.addEventListener("input", () => clearResult()));
  masterPassword.addEventListener("input", () => clearResult());
  document.addEventListener("pointerdown", () => { if (unlocked) resetLockTimer(); }, { passive: true });
  document.addEventListener("keydown", () => { if (unlocked) resetLockTimer(); });
  window.addEventListener("online", updateConnectionStatus);
  window.addEventListener("offline", updateConnectionStatus);
  window.addEventListener("beforeinstallprompt", event => {
    event.preventDefault();
    installPrompt = event;
    installButton.hidden = false;
  });
  window.addEventListener("appinstalled", () => {
    installPrompt = null;
    installButton.hidden = true;
    offlineStatus.textContent = "Installed";
  });
  installButton.addEventListener("click", async () => {
    if (!installPrompt) return;
    installPrompt.prompt();
    await installPrompt.userChoice;
    installPrompt = null;
    installButton.hidden = true;
  });

  if ("serviceWorker" in navigator) navigator.serviceWorker.register("./service-worker.js").catch(() => {
    offlineStatus.textContent = "Open once online to install";
  });
  clearResult();
  updateConnectionStatus();
  initialise();
}());
