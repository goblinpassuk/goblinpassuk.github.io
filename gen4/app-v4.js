(function () {
  "use strict";

  const form = document.getElementById("generatorForm");
  const websiteId = document.getElementById("websiteId");
  const passwordLength = document.getElementById("passwordLength");
  const passwordCounter = document.getElementById("passwordCounter");
  const masterPassword = document.getElementById("masterPassword");
  const toggleMaster = document.getElementById("toggleMaster");
  const resultPanel = document.getElementById("resultPanel");
  const generatedPassword = document.getElementById("generatedPassword");
  const togglePassword = document.getElementById("togglePassword");
  const copyPassword = document.getElementById("copyPassword");
  const toggleQr = document.getElementById("toggleQr");
  const qrCanvas = document.getElementById("passwordQr");
  const qrPanel = document.getElementById("qrPanel");
  const qrPlaceholder = document.getElementById("qrPlaceholder");
  const qrPlaceholderMessage = document.getElementById("qrPlaceholderMessage");
  const resultStatus = document.getElementById("statusMessage");
  const installButton = document.getElementById("installApp");
  const offlineStatus = document.getElementById("offlineStatus");
  let installPrompt = null;

  function clearResult() {
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
    resultStatus.textContent = "Nothing is saved. Generate the same password again with the same Website ID and Master Password.";
  }

  function toggleVisibility(input, button) {
    const shouldShow = input.type === "password";
    input.type = shouldShow ? "text" : "password";
    button.textContent = shouldShow ? "Hide" : "Show";
    button.setAttribute("aria-pressed", String(shouldShow));
  }

  async function copyGeneratedPassword() {
    if (!generatedPassword.value) return;
    try {
      await navigator.clipboard.writeText(generatedPassword.value);
    } catch (error) {
      generatedPassword.type = "text";
      generatedPassword.select();
      document.execCommand("copy");
      generatedPassword.setSelectionRange(0, 0);
      generatedPassword.type = "password";
    }
    resultStatus.textContent = "Password copied to the clipboard.";
  }

  function toggleQrCode() {
    if (!generatedPassword.value) return;
    const shouldShow = qrPanel.hidden;
    qrPanel.hidden = !shouldShow;
    qrPlaceholder.hidden = shouldShow;
    toggleQr.textContent = shouldShow ? "Hide QR code" : "Show QR code";
    toggleQr.setAttribute("aria-expanded", String(shouldShow));
    if (!shouldShow) qrPlaceholderMessage.textContent = "QR code hidden for privacy.";
  }

  async function generatePassword(event) {
    event.preventDefault();
    if (!form.reportValidity()) return;
    try {
      const password = await window.goblinPassGenerate(websiteId.value, masterPassword.value, {
        length: passwordLength.value,
        counter: passwordCounter.value,
        selectedKeys: ["lower", "upper", "nums", "symbols"]
      });
      generatedPassword.value = password;
      generatedPassword.type = "password";
      togglePassword.textContent = "Show";
      togglePassword.disabled = false;
      copyPassword.disabled = false;
      window.GoblinPassQrV4.draw(qrCanvas, password);
      toggleQr.disabled = false;
      toggleQr.textContent = "Show QR code";
      toggleQr.setAttribute("aria-expanded", "false");
      qrPanel.hidden = true;
      qrPlaceholder.hidden = false;
      qrPlaceholderMessage.textContent = "QR code hidden for privacy. Select Show QR code to reveal it.";
      resultPanel.classList.add("has-result");
      resultStatus.textContent = "Generated locally. The QR code is hidden until you choose to show it.";
    } catch (error) {
      resultStatus.textContent = error.message || "The password could not be generated.";
    }
  }

  function updateConnectionStatus() {
    offlineStatus.textContent = navigator.onLine ? "Offline ready" : "Working offline";
  }

  form.addEventListener("submit", generatePassword);
  toggleMaster.addEventListener("click", function () { toggleVisibility(masterPassword, toggleMaster); });
  togglePassword.addEventListener("click", function () { toggleVisibility(generatedPassword, togglePassword); });
  copyPassword.addEventListener("click", copyGeneratedPassword);
  toggleQr.addEventListener("click", toggleQrCode);
  [websiteId, passwordLength, passwordCounter, masterPassword].forEach(function (input) {
    input.addEventListener("input", clearResult);
  });
  window.addEventListener("online", updateConnectionStatus);
  window.addEventListener("offline", updateConnectionStatus);
  window.addEventListener("beforeinstallprompt", function (event) {
    event.preventDefault();
    installPrompt = event;
    installButton.hidden = false;
  });
  window.addEventListener("appinstalled", function () {
    installPrompt = null;
    installButton.hidden = true;
    offlineStatus.textContent = "Installed";
  });
  installButton.addEventListener("click", async function () {
    if (!installPrompt) return;
    installPrompt.prompt();
    await installPrompt.userChoice;
    installPrompt = null;
    installButton.hidden = true;
  });

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("./service-worker.js").catch(function () {
      offlineStatus.textContent = "Open once online to install";
    });
  }
  clearResult();
  updateConnectionStatus();
})();
