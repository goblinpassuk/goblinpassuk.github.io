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

  if (typeof qrcode === 'undefined') {
    showToast('QR library could not load. Check your connection.');
    return;
  }

  qrContainer.replaceChildren();
  try {
    const code = qrcode(0, 'M');
    code.addData(text, 'Byte');
    code.make();
    const modules = code.getModuleCount();
    const scale = Math.max(1, Math.floor(280 / modules));
    const canvas = document.createElement('canvas');
    canvas.width = modules * scale;
    canvas.height = modules * scale;
    const context = canvas.getContext('2d', { alpha: false });
    context.fillStyle = '#ffffff';
    context.fillRect(0, 0, canvas.width, canvas.height);
    context.fillStyle = '#171a16';
    for (let row = 0; row < modules; row += 1) {
      for (let column = 0; column < modules; column += 1) {
        if (code.isDark(row, column)) context.fillRect(column * scale, row * scale, scale, scale);
      }
    }
    qrContainer.append(canvas);
  } catch {
    showToast('That note is too large for one QR code');
    qrContainer.replaceChildren();
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
  qrContainer.replaceChildren();
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
