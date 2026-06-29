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
  const qrCanvas = document.getElementById("passwordQr");
  const qrPanel = document.getElementById("qrPanel");
  const qrPlaceholder = document.getElementById("qrPlaceholder");
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
    qrPanel.hidden = true;
    qrPlaceholder.hidden = false;
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
      qrPanel.hidden = false;
      qrPlaceholder.hidden = true;
      resultPanel.classList.add("has-result");
      resultStatus.textContent = "Generated locally. Scan the QR code or use Copy.";
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
