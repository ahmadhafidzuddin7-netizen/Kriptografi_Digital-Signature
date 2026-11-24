// =========================================================
// Utilitas Konversi Buffer, PEM, Base64, & Hex
// =========================================================
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const cleanB64 = base64.replace(/\s+/g, '');
  const binary = atob(cleanB64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function arrayBufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToArrayBuffer(hex) {
  const cleanHex = hex.replace(/\s+/g, '');
  if (cleanHex.length % 2 !== 0) throw new Error('Format Hex tidak valid.');
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
  }
  return bytes.buffer;
}

function formatAsPem(base64Str, label) {
  const lines = base64Str.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

function pemToArrayBuffer(pem) {
  const stripped = pem
    .replace(/-----BEGIN [A-Z0-9 ]+-----/g, '')
    .replace(/-----END [A-Z0-9 ]+-----/g, '')
    .replace(/\s+/g, '');
  return base64ToArrayBuffer(stripped);
}

function showToast(msg = 'Berhasil disalin!') {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2200);
}

function downloadFile(filename, content, mimeType = 'text/plain') {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// =========================================================
// Navigasi Tab
// =========================================================
document.querySelectorAll('.tab-btn').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(btn.dataset.tab).classList.add('active');
  });
});

// =========================================================
// Tombol Salin (Clipboard)
// =========================================================
document.querySelectorAll('[data-copy]').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const target = document.getElementById(btn.dataset.copy);
    if (!target || !target.value) return;
    await navigator.clipboard.writeText(target.value);
    showToast('Disalin ke clipboard!');
  });
});

// =========================================================
// 1. Pembangkit Pasangan Kunci (Key Generation)
// =========================================================
document.getElementById('btn-generate-keys').addEventListener('click', async () => {
  const algo = document.getElementById('keygen-algo').value;

  try {
    let keyParams;
    if (algo === 'ECDSA') {
      keyParams = { name: 'ECDSA', namedCurve: 'P-256' };
    } else {
      keyParams = {
        name: 'RSA-PSS',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      };
    }

    const keyPair = await window.crypto.subtle.generateKey(keyParams, true, ['sign', 'verify']);

    const spkiBuffer = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
    const pkcs8Buffer = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

    const publicPem = formatAsPem(arrayBufferToBase64(spkiBuffer), 'PUBLIC KEY');
    const privatePem = formatAsPem(arrayBufferToBase64(pkcs8Buffer), 'PRIVATE KEY');

    document.getElementById('gen-public-key').value = publicPem;
    document.getElementById('gen-private-key').value = privatePem;
    document.getElementById('keygen-output').classList.remove('hidden');
    showToast(`Pasangan kunci ${algo} berhasil dibuat!`);
  } catch (err) {
    alert('Gagal membuat kunci: ' + err.message);
  }
});

document.getElementById('dl-public-key').addEventListener('click', () => {
  const val = document.getElementById('gen-public-key').value;
  if (val) downloadFile('public_key.pem', val);
});

document.getElementById('dl-private-key').addEventListener('click', () => {
  const val = document.getElementById('gen-private-key').value;
  if (val) downloadFile('private_key.pem', val);
});

document.getElementById('btn-autofill-keys').addEventListener('click', () => {
  const algo = document.getElementById('keygen-algo').value;
  const pub = document.getElementById('gen-public-key').value;
  const priv = document.getElementById('gen-private-key').value;

  document.getElementById('sign-algo').value = algo;
  document.getElementById('verify-algo').value = algo;
  document.getElementById('sign-private-key').value = priv;
  document.getElementById('verify-public-key').value = pub;

  document.querySelector('[data-tab="tab-sign"]').click();
  showToast('Kunci diisi otomatis ke Tab Tanda Tangan & Verifikasi!');
});

// =========================================================
// 2. Penandatanganan Pesan / File (Signing)
// =========================================================
let signFileBuffer = null;

async function getSignDataBuffer() {
  const mode = document.querySelector('input[name="sign-input-type"]:checked').value;
  if (mode === 'text') {
    const text = document.getElementById('sign-message').value;
    return new TextEncoder().encode(text).buffer;
  } else {
    if (!signFileBuffer) throw new Error('Silakan pilih file terlebih dahulu.');
    return signFileBuffer;
  }
}

async function updateSignHashPreview() {
  try {
    const buffer = await getSignDataBuffer();
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
    document.getElementById('sign-sha256-preview').textContent = arrayBufferToHex(hashBuffer);
  } catch {
    document.getElementById('sign-sha256-preview').textContent = '-';
  }
}

document.querySelectorAll('input[name="sign-input-type"]').forEach((radio) => {
  radio.addEventListener('change', (e) => {
    const isText = e.target.value === 'text';
    document.getElementById('sign-text-box').classList.toggle('hidden', !isText);
    document.getElementById('sign-file-box').classList.toggle('hidden', isText);
    updateSignHashPreview();
  });
});

document.getElementById('sign-message').addEventListener('input', updateSignHashPreview);

document.getElementById('sign-file').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) {
    signFileBuffer = null;
    document.getElementById('sign-file-info').textContent = 'Belum ada file dipilih.';
    updateSignHashPreview();
    return;
  }
  signFileBuffer = await file.arrayBuffer();
  document.getElementById('sign-file-info').textContent = `${file.name} (${file.size.toLocaleString()} bytes)`;
  updateSignHashPreview();
});

// Hitung hash awal saat halaman dimuat
updateSignHashPreview();

document.getElementById('btn-sign').addEventListener('click', async () => {
  const algo = document.getElementById('sign-algo').value;
  const privatePem = document.getElementById('sign-private-key').value.trim();

  if (!privatePem) {
    alert('Masukkan Kunci Privat (PEM) terlebih dahulu.');
    return;
  }

  try {
    const dataBuffer = await getSignDataBuffer();
    const keyBuffer = pemToArrayBuffer(privatePem);

    const importParams =
      algo === 'ECDSA'
        ? { name: 'ECDSA', namedCurve: 'P-256' }
        : { name: 'RSA-PSS', hash: 'SHA-256' };

    const privateKey = await window.crypto.subtle.importKey(
      'pkcs8',
      keyBuffer,
      importParams,
      false,
      ['sign']
    );

    const signParams =
      algo === 'ECDSA'
        ? { name: 'ECDSA', hash: { name: 'SHA-256' } }
        : { name: 'RSA-PSS', saltLength: 32 };

    const signatureBuffer = await window.crypto.subtle.sign(signParams, privateKey, dataBuffer);

    document.getElementById('sign-output-b64').value = arrayBufferToBase64(signatureBuffer);
    document.getElementById('sign-output-hex').value = arrayBufferToHex(signatureBuffer);
    document.getElementById('sign-result').classList.remove('hidden');
    showToast('Tanda tangan digital berhasil dibuat!');
  } catch (err) {
    alert('Gagal menandatangani data. Pastikan algoritma dan format Kunci Privat sesuai.\nDetail: ' + err.message);
  }
});

document.getElementById('btn-send-to-verify').addEventListener('click', () => {
  const algo = document.getElementById('sign-algo').value;
  const sigB64 = document.getElementById('sign-output-b64').value;
  const mode = document.querySelector('input[name="sign-input-type"]:checked').value;

  document.getElementById('verify-algo').value = algo;
  document.getElementById('verify-signature').value = sigB64;

  if (mode === 'text') {
    document.querySelector('input[name="verify-input-type"][value="text"]').checked = true;
    document.getElementById('verify-text-box').classList.remove('hidden');
    document.getElementById('verify-file-box').classList.add('hidden');
    document.getElementById('verify-message').value = document.getElementById('sign-message').value;
  }

  document.querySelector('[data-tab="tab-verify"]').click();
  showToast('Data & tanda tangan dikirim ke Tab Verifikasi!');
});

document.getElementById('btn-download-bundle').addEventListener('click', () => {
  const mode = document.querySelector('input[name="sign-input-type"]:checked').value;
  const bundle = {
    algorithm: document.getElementById('sign-algo').value,
    hashAlgorithm: 'SHA-256',
    sha256Digest: document.getElementById('sign-sha256-preview').textContent,
    message: mode === 'text' ? document.getElementById('sign-message').value : '[BINARY_FILE]',
    signatureBase64: document.getElementById('sign-output-b64').value,
    signatureHex: document.getElementById('sign-output-hex').value,
    timestamp: new Date().toISOString(),
  };
  downloadFile('signature_proof.json', JSON.stringify(bundle, null, 2), 'application/json');
});

// =========================================================
// 3. Verifikasi Tanda Tangan (Verification)
// =========================================================
let verifyFileBuffer = null;

document.querySelectorAll('input[name="verify-input-type"]').forEach((radio) => {
  radio.addEventListener('change', (e) => {
    const isText = e.target.value === 'text';
    document.getElementById('verify-text-box').classList.toggle('hidden', !isText);
    document.getElementById('verify-file-box').classList.toggle('hidden', isText);
  });
});

document.getElementById('verify-file').addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file) {
    verifyFileBuffer = null;
    document.getElementById('verify-file-info').textContent = 'Belum ada file dipilih.';
    return;
  }
  verifyFileBuffer = await file.arrayBuffer();
  document.getElementById('verify-file-info').textContent = `${file.name} (${file.size.toLocaleString()} bytes)`;
});

// Simulasi modifikasi 1 karakter (Tamper Test)
document.getElementById('btn-tamper-test').addEventListener('click', () => {
  const box = document.getElementById('verify-message');
  if (!box.value) return;
  const lastChar = box.value.slice(-1);
  const alteredChar = lastChar === '.' ? '!' : '.';
  box.value = box.value.slice(0, -1) + alteredChar;
  showToast('Pesan dimodifikasi 1 karakter! Klik Verifikasi Keaslian.');
});

document.getElementById('btn-verify').addEventListener('click', async () => {
  const algo = document.getElementById('verify-algo').value;
  const publicPem = document.getElementById('verify-public-key').value.trim();
  const sigInput = document.getElementById('verify-signature').value.trim();
  const statusBox = document.getElementById('verify-status');

  if (!publicPem || !sigInput) {
    alert('Lengkapi Kunci Publik dan Tanda Tangan Digital terlebih dahulu.');
    return;
  }

  try {
    const mode = document.querySelector('input[name="verify-input-type"]:checked').value;
    let dataBuffer;
    if (mode === 'text') {
      dataBuffer = new TextEncoder().encode(document.getElementById('verify-message').value).buffer;
    } else {
      if (!verifyFileBuffer) throw new Error('Pilih file yang ingin diverifikasi terlebih dahulu.');
      dataBuffer = verifyFileBuffer;
    }

    // Deteksi otomatis format tanda tangan (Hex vs Base64)
    const isHex = /^[0-9a-fA-F\s]+$/.test(sigInput) && sigInput.replace(/\s+/g, '').length % 2 === 0;
    const sigBuffer = isHex ? hexToArrayBuffer(sigInput) : base64ToArrayBuffer(sigInput);

    const keyBuffer = pemToArrayBuffer(publicPem);
    const importParams =
      algo === 'ECDSA'
        ? { name: 'ECDSA', namedCurve: 'P-256' }
        : { name: 'RSA-PSS', hash: 'SHA-256' };

    const publicKey = await window.crypto.subtle.importKey(
      'spki',
      keyBuffer,
      importParams,
      false,
      ['verify']
    );

    const verifyParams =
      algo === 'ECDSA'
        ? { name: 'ECDSA', hash: { name: 'SHA-256' } }
        : { name: 'RSA-PSS', saltLength: 32 };

    const isValid = await window.crypto.subtle.verify(verifyParams, publicKey, sigBuffer, dataBuffer);

    statusBox.classList.remove('hidden', 'valid', 'invalid');
    if (isValid) {
      statusBox.classList.add('valid');
      statusBox.innerHTML =
        '✅ TANDA TANGAN VALID — Identitas penanda tangan terkonfirmasi dan integritas data utuh (tidak berubah).';
    } else {
      statusBox.classList.add('invalid');
      statusBox.innerHTML =
        '❌ TANDA TANGAN TIDAK VALID — Data telah dimodifikasi atau tidak cocok dengan Kunci Publik pengirim.';
    }
  } catch (err) {
    statusBox.classList.remove('hidden', 'valid');
    statusBox.classList.add('invalid');
    statusBox.textContent = '⚠️ Terjadi kesalahan verifikasi: ' + err.message;
  }
});