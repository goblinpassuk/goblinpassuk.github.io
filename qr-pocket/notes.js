const input = document.querySelector('#note-input');
const count = document.querySelector('#char-count');
const generateButton = document.querySelector('#generate-button');
const clearButton = document.querySelector('#clear-button');
const copyButton = document.querySelector('#copy-button');
const downloadButton = document.querySelector('#download-button');
const qrContainer = document.querySelector('#qrcode');
const qrStage = document.querySelector('#qr-stage');
const emptyState = document.querySelector('#empty-state');
const status = document.querySelector('#qr-status');
const toast = document.querySelector('#toast');
let toastTimer;

function showToast(message) {
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 2200);
}

function updateCount() {
  count.textContent = `${input.value.length.toLocaleString()} / 1,500`;
}

function generateQr() {
  const text = input.value.trim();
  if (!text) {
    showToast('Write a note first');
    input.focus();
    return;
  }

  if (typeof QRCode === 'undefined') {
    showToast('QR library could not load. Check your connection.');
    return;
  }

  qrContainer.innerHTML = '';
  try {
    new QRCode(qrContainer, {
      text,
      width: 280,
      height: 280,
      colorDark: '#171a16',
      colorLight: '#ffffff',
      correctLevel: QRCode.CorrectLevel.M
    });
  } catch {
    showToast('That note is too large for one QR code');
    qrContainer.innerHTML = '';
    return;
  }
  qrStage.classList.remove('empty');
  emptyState.hidden = true;
  status.textContent = 'Ready to scan';
  copyButton.disabled = false;
  downloadButton.disabled = false;
}

async function copyNote() {
  try {
    await navigator.clipboard.writeText(input.value);
    showToast('Note copied to clipboard');
  } catch {
    input.select();
    document.execCommand('copy');
    showToast('Note copied to clipboard');
  }
}

function downloadQr() {
  const source = qrContainer.querySelector('canvas') || qrContainer.querySelector('img');
  if (!source) return;
  const link = document.createElement('a');
  link.download = 'qr-note.png';
  link.href = source.tagName === 'CANVAS' ? source.toDataURL('image/png') : source.src;
  link.click();
}

function clearAll() {
  input.value = '';
  updateCount();
  qrContainer.innerHTML = '';
  qrStage.classList.add('empty');
  emptyState.hidden = false;
  status.textContent = 'Waiting for a note';
  copyButton.disabled = true;
  downloadButton.disabled = true;
  input.focus();
}

input.addEventListener('input', updateCount);
input.addEventListener('keydown', event => {
  if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') generateQr();
});
generateButton.addEventListener('click', generateQr);
clearButton.addEventListener('click', clearAll);
copyButton.addEventListener('click', copyNote);
downloadButton.addEventListener('click', downloadQr);
updateCount();
