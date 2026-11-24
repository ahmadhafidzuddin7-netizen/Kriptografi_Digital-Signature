from flask import Flask, render_template, request
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

app = Flask(__name__)

PASSPHRASE = "passwordku"
PUB_FILE = "kunci_publik_Alice.pem"
PRIV_FILE = "kunci_privat_Alice.pem"


def pembangkitan_kunci_rsa() -> dict:
    key = RSA.generate(1024)
    kunci_publik = key.publickey()

    with open(PUB_FILE, "wb") as f_pub:
        f_pub.write(kunci_publik.export_key("PEM"))

    with open(PRIV_FILE, "wb") as f_priv:
        f_priv.write(key.export_key("PEM", passphrase=PASSPHRASE))

    return {
        "n": str(key.n),
        "e": str(key.e),
        "d": str(key.d),
        "pub_pem": kunci_publik.export_key("PEM").decode("utf-8"),
        "priv_pem": key.export_key("PEM", passphrase=PASSPHRASE).decode("utf-8"),
    }


def menandatangani(pesan: str) -> str:
    if not os.path.exists(PRIV_FILE):
        pembangkitan_kunci_rsa()

    nilai_hash = SHA256.new(pesan.encode("utf-8"))
    with open(PRIV_FILE, "rb") as f_priv:
        kunci_privat = RSA.import_key(f_priv.read(), passphrase=PASSPHRASE)

    tanda_tangan = pkcs1_15.new(kunci_privat).sign(nilai_hash)
    return tanda_tangan.hex()


def memverifikasi(tanda_tangan_hex: str, pesan: str) -> bool:
    if not os.path.exists(PUB_FILE):
        return False

    try:
        tanda_tangan = bytes.fromhex(tanda_tangan_hex.strip())
        nilai_hash = SHA256.new(pesan.encode("utf-8"))
        with open(PUB_FILE, "rb") as f_pub:
            kunci_publik = RSA.import_key(f_pub.read())

        pkcs1_15.new(kunci_publik).verify(nilai_hash, tanda_tangan)
        return True
    except (ValueError, TypeError):
        return False


@app.route("/", methods=["GET", "POST"])
def index():
    key_info = None
    pesan_sign = ""
    signature_hex = ""
    pesan_verify = ""
    signature_verify = ""
    verify_status = None
    status_kunci = os.path.exists(PUB_FILE) and os.path.exists(PRIV_FILE)

    if request.method == "POST":
        action = request.form.get("action")

        if action == "generate":
            key_info = pembangkitan_kunci_rsa()
            status_kunci = True

        elif action == "sign":
            pesan_sign = request.form.get("pesan_sign", "")
            signature_hex = menandatangani(pesan_sign)
            # Otomatis isi kolom verifikasi untuk memudahkan pengujian
            pesan_verify = pesan_sign
            signature_verify = signature_hex
            status_kunci = True

        elif action == "verify":
            pesan_verify = request.form.get("pesan_verify", "")
            signature_verify = request.form.get("signature_verify", "")
            verify_status = memverifikasi(signature_verify, pesan_verify)

    return render_template(
        "index.html",
        key_info=key_info,
        status_kunci=status_kunci,
        pesan_sign=pesan_sign,
        signature_hex=signature_hex,
        pesan_verify=pesan_verify,
        signature_verify=signature_verify,
        verify_status=verify_status,
    )


if __name__ == "__main__":
    app.run(debug=True)