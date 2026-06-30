(function () {
  "use strict";

  const cameraPreview = document.getElementById("cameraPreview");
  const cameraPlaceholder = document.getElementById("cameraPlaceholder");
  const scanGuide = document.getElementById("scanGuide");
  const startCameraButton = document.getElementById("startCamera");
  const stopCameraButton = document.getElementById("stopCamera");
  const imageInput = document.getElementById("qrImage");
  const scannerStatus = document.getElementById("scannerStatus");
  const supportStatus = document.getElementById("supportStatus");
  const passwordInput = document.getElementById("scannedPassword");
  const passwordSummary = document.getElementById("passwordSummary");
  const togglePasswordButton = document.getElementById("togglePassword");
  const copyPasswordButton = document.getElementById("copyPassword");
  const clearPasswordButton = document.getElementById("clearPassword");
  const installScannerButton = document.getElementById("installScanner");

  let detector = null;
  let detectorChecked = false;
  let cameraStream = null;
  let scanFrame = 0;
  let detecting = false;
  let lastDetectionTime = 0;
  let installPrompt = null;

  function setStatus(message, kind = "info") {
    scannerStatus.textContent = message;
    scannerStatus.dataset.kind = kind;
  }

  function hasPassword() {
    return passwordInput.value.length > 0;
  }

  function updatePasswordControls() {
    const available = hasPassword();
    togglePasswordButton.disabled = !available;
    copyPasswordButton.disabled = !available;
    clearPasswordButton.disabled = !available;
    passwordSummary.textContent = available
      ? `Password captured and hidden (${passwordInput.value.length} characters).`
      : "No password scanned.";
  }

  function hidePassword() {
    passwordInput.type = "password";
    togglePasswordButton.textContent = "Show";
    togglePasswordButton.setAttribute("aria-pressed", "false");
  }

  function acceptPassword(value) {
    const password = String(value || "");
    if (password.length < 8 || password.length > 64 || !/^[A-Za-z0-9%!@#$_-]+$/.test(password)) {
      setStatus("That QR code does not contain a valid GoblinPass password.", "warning");
      return false;
    }
    passwordInput.value = password;
    hidePassword();
    updatePasswordControls();
    stopCamera();
    setStatus("QR code scanned. The password is hidden and ready to copy.", "success");
    return true;
  }

  async function createDetector() {
    if (detectorChecked) return detector;
    detectorChecked = true;
    if (typeof window.BarcodeDetector !== "function") return null;
    try {
      if (typeof window.BarcodeDetector.getSupportedFormats === "function") {
        const formats = await window.BarcodeDetector.getSupportedFormats();
        if (!formats.includes("qr_code")) return null;
      }
      detector = new window.BarcodeDetector({ formats: ["qr_code"] });
    } catch {
      detector = null;
    }
    return detector;
  }

  async function detectFrom(source) {
    const barcodeDetector = await createDetector();
    if (barcodeDetector) {
      try {
        const results = await barcodeDetector.detect(source);
        const qrCode = results.find(result => !result.format || result.format === "qr_code");
        if (qrCode?.rawValue) return qrCode.rawValue;
      } catch {}
    }
    try {
      return await window.GoblinPassQrReader.detect(source);
    } catch {
      return "";
    }
  }

  async function scanVideoFrame(time) {
    if (!cameraStream) return;
    scanFrame = requestAnimationFrame(scanVideoFrame);
    if (detecting || cameraPreview.readyState < HTMLMediaElement.HAVE_CURRENT_DATA || time - lastDetectionTime < 180) return;
    detecting = true;
    lastDetectionTime = time;
    try {
      const value = await detectFrom(cameraPreview);
      if (value) acceptPassword(value);
    } catch (error) {
      if (cameraStream) setStatus(error?.message || "The camera frame could not be scanned.", "warning");
    } finally {
      detecting = false;
    }
  }

  async function startCamera() {
    if (cameraStream) return;
    if (!window.isSecureContext) return setStatus("Camera scanning requires HTTPS.", "warning");
    if (!navigator.mediaDevices?.getUserMedia) return setStatus("Camera access is not supported by this browser.", "warning");
    startCameraButton.disabled = true;
    setStatus("Requesting rear-camera access…");
    try {
      await createDetector();
      cameraStream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: { facingMode: { ideal: "environment" }, width: { ideal: 1280 }, height: { ideal: 960 } }
      });
      cameraPreview.srcObject = cameraStream;
      await cameraPreview.play();
      cameraPreview.hidden = false;
      cameraPlaceholder.hidden = true;
      scanGuide.hidden = false;
      stopCameraButton.disabled = false;
      setStatus("Camera active. Hold the QR code inside the frame.");
      scanFrame = requestAnimationFrame(scanVideoFrame);
    } catch (error) {
      cameraStream = null;
      startCameraButton.disabled = false;
      stopCameraButton.disabled = true;
      const denied = error?.name === "NotAllowedError";
      setStatus(denied ? "Camera permission was not granted." : (error?.message || "The camera could not start."), "warning");
    }
  }

  function stopCamera() {
    if (scanFrame) cancelAnimationFrame(scanFrame);
    scanFrame = 0;
    cameraStream?.getTracks().forEach(track => track.stop());
    cameraStream = null;
    cameraPreview.pause();
    cameraPreview.srcObject = null;
    cameraPreview.hidden = true;
    cameraPlaceholder.hidden = false;
    scanGuide.hidden = true;
    startCameraButton.disabled = false;
    stopCameraButton.disabled = true;
  }

  async function scanImageFile() {
    const file = imageInput.files?.[0];
    imageInput.value = "";
    if (!file) return;
    setStatus("Scanning the selected image…");
    try {
      const image = typeof createImageBitmap === "function"
        ? await createImageBitmap(file)
        : await new Promise((resolve, reject) => {
          const element = new Image();
          const url = URL.createObjectURL(file);
          element.onload = () => { URL.revokeObjectURL(url); resolve(element); };
          element.onerror = () => { URL.revokeObjectURL(url); reject(new Error("The image could not be opened.")); };
          element.src = url;
        });
      try {
        const value = await detectFrom(image);
        if (!value) setStatus("No QR code was found in that image.", "warning");
        else acceptPassword(value);
      } finally {
        image.close?.();
      }
    } catch (error) {
      setStatus(error?.message || "The selected image could not be scanned.", "warning");
    }
  }

  async function copyPassword() {
    if (!hasPassword()) return;
    try {
      await navigator.clipboard.writeText(passwordInput.value);
      setStatus("Password copied to the clipboard.", "success");
    } catch {
      try {
        const previousType = passwordInput.type;
        passwordInput.type = "text";
        passwordInput.select();
        const copied = document.execCommand("copy");
        passwordInput.setSelectionRange(0, 0);
        passwordInput.type = previousType;
        setStatus(copied ? "Password copied to the clipboard." : "Copy was blocked by the browser.", copied ? "success" : "warning");
      } catch {
        hidePassword();
        setStatus("Copy was blocked. Use Show and copy the password manually.", "warning");
      }
    }
  }

  function togglePassword() {
    if (!hasPassword()) return;
    const show = passwordInput.type === "password";
    passwordInput.type = show ? "text" : "password";
    togglePasswordButton.textContent = show ? "Hide" : "Show";
    togglePasswordButton.setAttribute("aria-pressed", String(show));
  }

  function clearPassword() {
    passwordInput.value = "";
    hidePassword();
    updatePasswordControls();
    setStatus("Scanned password cleared from this page.");
  }

  startCameraButton.addEventListener("click", startCamera);
  stopCameraButton.addEventListener("click", () => {
    stopCamera();
    setStatus("Camera stopped.");
  });
  imageInput.addEventListener("change", scanImageFile);
  togglePasswordButton.addEventListener("click", togglePassword);
  copyPasswordButton.addEventListener("click", copyPassword);
  clearPasswordButton.addEventListener("click", clearPassword);
  installScannerButton.addEventListener("click", async () => {
    if (!installPrompt) return;
    installPrompt.prompt();
    await installPrompt.userChoice;
    installPrompt = null;
    installScannerButton.hidden = true;
  });
  window.addEventListener("pagehide", stopCamera);
  window.addEventListener("beforeinstallprompt", event => {
    event.preventDefault();
    installPrompt = event;
    installScannerButton.hidden = false;
  });
  window.addEventListener("appinstalled", () => {
    installPrompt = null;
    installScannerButton.hidden = true;
    supportStatus.textContent = "Scanner installed";
  });
  document.addEventListener("visibilitychange", () => { if (document.hidden) stopCamera(); });

  if (window.GoblinPassQrReader || typeof window.BarcodeDetector === "function") {
    supportStatus.textContent = "Local QR scanner ready";
  } else {
    supportStatus.textContent = "QR scanner unsupported in this browser";
    startCameraButton.disabled = true;
    imageInput.disabled = true;
    setStatus("QR detection could not be loaded in this browser.", "warning");
  }
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("./service-worker.js").catch(() => {});
  updatePasswordControls();
})();
