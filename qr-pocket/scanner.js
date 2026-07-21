const startButton = document.querySelector('#start-button');
const stopButton = document.querySelector('#stop-button');
const placeholder = document.querySelector('#camera-placeholder');
const cameraMessage = document.querySelector('#camera-message');
const fileInput = document.querySelector('#file-input');
const resultEmpty = document.querySelector('#result-empty');
const resultContent = document.querySelector('#result-content');
const resultText = document.querySelector('#result-text');
const copyResult = document.querySelector('#copy-result');
const openResult = document.querySelector('#open-result');
const resultDot = document.querySelector('.result-dot');
const toast = document.querySelector('#toast');
let scanner;
let scanning = false;
let lastResult = '';
let toastTimer;

function showToast(message) {
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 2200);
}

function isSafeUrl(value) {
  try {
    const url = new URL(value);
    return ['http:', 'https:', 'mailto:', 'tel:'].includes(url.protocol);
  } catch {
    return false;
  }
}

function showResult(decodedText) {
  if (!decodedText || decodedText === lastResult) return;
  lastResult = decodedText;
  resultText.textContent = decodedText;
  resultEmpty.classList.add('hidden');
  resultContent.classList.remove('hidden');
  resultDot.classList.add('active');
  if (isSafeUrl(decodedText)) {
    openResult.href = decodedText;
    openResult.classList.remove('hidden');
  } else {
    openResult.classList.add('hidden');
  }
  if (navigator.vibrate) navigator.vibrate(100);
  showToast('QR code found');
}

async function startCamera() {
  if (typeof Html5Qrcode === 'undefined') {
    showToast('Scanner library could not load. Check your connection.');
    return;
  }
  scanner ||= new Html5Qrcode('reader');
  startButton.disabled = true;
  cameraMessage.textContent = 'Requesting camera access…';
  try {
    await scanner.start(
      { facingMode: 'environment' },
      { fps: 10, qrbox: (w, h) => ({ width: Math.min(w, h) * 0.7, height: Math.min(w, h) * 0.7 }) },
      showResult,
      () => {}
    );
    scanning = true;
    placeholder.classList.add('hidden');
    stopButton.classList.remove('hidden');
  } catch (error) {
    startButton.disabled = false;
    cameraMessage.textContent = 'Camera access was unavailable';
    showToast('Allow camera access, then try again');
  }
}

async function stopCamera() {
  if (!scanner || !scanning) return;
  await scanner.stop();
  scanning = false;
  placeholder.classList.remove('hidden');
  stopButton.classList.add('hidden');
  startButton.disabled = false;
  cameraMessage.textContent = 'Camera is ready when you are';
}

async function scanFile(file) {
  if (!file) return;
  if (typeof Html5Qrcode === 'undefined') {
    showToast('Scanner library could not load. Check your connection.');
    return;
  }
  if (scanning) await stopCamera();
  scanner ||= new Html5Qrcode('reader');
  try {
    const decodedText = await scanner.scanFile(file, true);
    lastResult = '';
    showResult(decodedText);
  } catch {
    showToast('No QR code found in that image');
  } finally {
    fileInput.value = '';
  }
}

startButton.addEventListener('click', startCamera);
stopButton.addEventListener('click', stopCamera);
fileInput.addEventListener('change', event => scanFile(event.target.files[0]));
copyResult.addEventListener('click', async () => {
  if (!lastResult) return;
  try {
    await navigator.clipboard.writeText(lastResult);
    showToast('Result copied to clipboard');
  } catch {
    const fallback = document.createElement('textarea');
    fallback.value = lastResult;
    fallback.setAttribute('readonly', '');
    fallback.style.position = 'fixed';
    fallback.style.opacity = '0';
    document.body.appendChild(fallback);
    fallback.select();
    try {
      document.execCommand('copy');
      showToast('Result copied to clipboard');
    } catch {
      showToast('Could not copy result');
    } finally {
      fallback.remove();
    }
  }
});
window.addEventListener('pagehide', () => {
  if (scanner && scanning) scanner.stop().catch(() => {});
});
