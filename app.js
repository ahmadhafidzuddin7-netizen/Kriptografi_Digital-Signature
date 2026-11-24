const $ = id => document.getElementById(id);
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = s => Uint8Array.from(atob(s.replace(/\s/g, '')), c => c.charCodeAt(0));
const toPem = (buf, label) => `-----BEGIN ${label}-----\n${b64(buf).match(/.{1,64}/g).join('\n')}\n-----END ${label}-----`;
const fromPem = pem => unb64(pem.replace(/-----[^-]+-----/g, ''));

// Parameter algoritma (ECDSA P-256 + SHA-256)
const KEY = { name: 'ECDSA', namedCurve: 'P-256' };
const SIG = { name: 'ECDSA', hash: 'SHA-256' };

// Ambil teks pesan sebagai bytes
const getData = p => new TextEncoder().encode($(p + '-msg').value);

function status(cls, msg) {
  const s = $('status');
  s.className = cls;
  s.textContent = msg;
}

$('gen').onclick = async () => {
  const k = await crypto.subtle.generateKey(KEY, true, ['sign', 'verify']);
  $('s-pub').value = toPem(await crypto.subtle.exportKey('spki', k.publicKey), 'PUBLIC KEY');
  $('s-priv').value = toPem(await crypto.subtle.exportKey('pkcs8', k.privateKey), 'PRIVATE KEY');
};

$('sign').onclick = async () => {
  try {
    const key = await crypto.subtle.importKey('pkcs8', fromPem($('s-priv').value), KEY, false, ['sign']);
    $('s-sig').value = b64(await crypto.subtle.sign(SIG, key, getData('s')));
  } catch (e) {
    alert('Gagal menandatangani. Buat kunci dulu / cek kunci privat.\n' + e.message);
  }
};

$('send').onclick = () => {
  if (!$('s-sig').value) return alert('Buat tanda tangan terlebih dahulu.');
  $('r-msg').value = $('s-msg').value;
  $('r-pub').value = $('s-pub').value;
  $('r-sig').value = $('s-sig').value;
  $('receiver').scrollIntoView({ behavior: 'smooth' });
  status('info', '📨 Data diterima dari Pengirim. Klik Verifikasi.');
};

$('tamper').onclick = () => {
  const m = $('r-msg').value;
  if (!m) return;
  $('r-msg').value = m.slice(0, -1) + (m.endsWith('.') ? '!' : '.');
  status('info', 'Pesan diubah 1 karakter. Klik Verifikasi untuk melihat hasilnya.');
};

$('verify').onclick = async () => {
  try {
    const key = await crypto.subtle.importKey('spki', fromPem($('r-pub').value), KEY, false, ['verify']);
    const ok = await crypto.subtle.verify(SIG, key, unb64($('r-sig').value), getData('r'));
    status(ok ? 'ok' : 'bad', ok
      ? '✅ VALID — pesan benar dari pemilik kunci dan tidak berubah.'
      : '❌ TIDAK VALID — pesan telah diubah atau tanda tangan tidak cocok dengan kunci publik.');
  } catch (e) {
    status('bad', '⚠️ Kesalahan: pastikan kunci & tanda tangan terisi dengan benar. (' + e.message + ')');
  }
};
