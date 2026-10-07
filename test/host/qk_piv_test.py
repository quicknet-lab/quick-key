#!/usr/bin/env python3
"""tools/qk_piv.py against the software PIV card in fakecard.py: key generation, certificates
(self-signed and imported), signing requests, public keys, management key."""
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakecard  # noqa: E402
import qk  # noqa: E402
import qk_piv as piv  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization as ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # noqa: E402

PIN = fakecard.PIN
tmp = tempfile.mkdtemp()


def fails(fn, text):
    try:
        fn()
    except (qk.QkError, RuntimeError) as e:
        assert text in str(e), e
        return
    raise AssertionError(f"no error '{text}'")


def check_signature(cert):
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
    else:
        pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))


card = fakecard.install()

# ---- an empty card
d = piv.details()
assert d["serial"] and d["mgmt"] == {"algo": "3des", "default": True}
assert all(s["key"] is None and s["cert"] is None for s in d["slots"]) and len(d["slots"]) == 4
assert piv.slot_of("9a") == 0x9A and piv.slot_of("9E") == 0x9E
fails(lambda: piv.slot_of("9f"), "slot:")
print("details of an empty card")

# ---- keys
fails(lambda: piv.generate(0x9A, "nistp256", mgmt_key=bytes(24)), "wrong management key")
fails(lambda: piv.generate(0x9A, "rsa4096"), "algorithm")
fails(lambda: piv.generate(0x9A, "nistp256", touch="sometimes"), "touch")
fails(lambda: piv.generate(0x9A, "nistp256", mgmt_key=bytes(32)), "3DES")
pub = piv.generate(0x9A, "nistp256", touch="cached")
assert pub["algo"] == "nistp256" and len(pub["point"]) == 65
assert piv.generate(0x9D, "rsa2048")["algo"] == "rsa2048"
piv.generate(0x9C, "nistp256")
piv.generate(0x9E, "nistp256")
d = piv.details()
by = {s["slot"]: s for s in d["slots"]}
assert by[0x9A]["touch"] == "cached" and by[0x9A]["pin_policy"] == "once" and by[0x9C]["pin_policy"] == "always"
assert by[0x9E]["pin_policy"] == "never" and by[0x9D]["key"]["algo"] == "rsa2048"
print("keys generated: P-256 (touch cached), RSA-2048, policies read back")

# ---- public key export
pem_text = piv.public_pem(0x9A)
assert ser.load_pem_public_key(pem_text.encode()).public_numbers().x == \
    int.from_bytes(pub["point"][1:33], "big")
for slot in (0x9A, 0x9D):
    path = os.path.join(tmp, f"s{slot:x}.pub")
    open(path, "w").write(piv.ssh_line(slot, "piv") + "\n")
    out = subprocess.run(["ssh-keygen", "-l", "-f", path], capture_output=True, text=True, check=True).stdout
    assert ("ECDSA" if slot == 0x9A else "RSA") in out and "piv" in out, out
fails(lambda: piv.public_pem(0x99), "no key")
print("public keys: PEM and SSH lines")

# ---- self-signed certificates: P-256 and RSA, signed by the card
fails(lambda: piv.self_signed(0x9A, "000000", "CN=Jane"), "wrong PIN")
fails(lambda: piv.self_signed(0x9A, PIN, "not a subject"), "subject")
fails(lambda: piv.self_signed(0x9A, PIN, "CN=Jane", days=0), "days")
for slot in (0x9A, 0x9D, 0x9C, 0x9E):
    der = piv.self_signed(slot, PIN, "CN=Jane Doe,O=Example", days=30)
    cert = x509.load_der_x509_certificate(der)
    check_signature(cert)
    assert cert.subject == cert.issuer and cert.subject.rfc4514_string() == "CN=Jane Doe,O=Example"
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days in (30, 29)
    expect = piv.key_object(piv.public_key(card, slot)).public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
    assert cert.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo) == expect
    assert piv.read_cert(slot) == der
assert card.presses == ["piv9a"], card.presses            # the touch policy of 9A was honoured once
if shutil.which("openssl"):
    path = os.path.join(tmp, "c.pem")
    open(path, "w").write(piv.export_cert(0x9D))
    out = subprocess.run(["openssl", "verify", "-CAfile", path, path], capture_output=True, text=True)
    assert out.stdout.strip().endswith("OK"), out
    text = subprocess.run(["openssl", "x509", "-in", path, "-noout", "-text"], capture_output=True, text=True).stdout
    assert "sha256WithRSAEncryption" in text and "Jane Doe" in text
print("self-signed certificates: P-256 and RSA signatures made by the card verify (also with openssl)")

summary = piv.details()["slots"][0]["cert"]
assert summary["subject"] == "CN=Jane Doe,O=Example" and summary["self_signed"] and len(summary["fingerprint"]) == 64
assert "valid until" in piv.cert_text(piv.read_cert(0x9A))

# a wrong management key is found before the card signs: no PIN try spent, no press
tries, presses = card.tries["pin"], list(card.presses)
fails(lambda: piv.self_signed(0x9A, PIN, "CN=x", mgmt_key=bytes(24)), "wrong management key")
assert card.tries["pin"] == tries and card.presses == presses
# one unreadable certificate does not hide the other slots
card.objects[0x5FC10A] = bytes.fromhex("53 05 70 03 01 02 03".replace(" ", ""))
d = piv.details()
assert {s["slot"]: s["cert"]["subject"] for s in d["slots"] if s["cert"]}[0x9C] == "(unreadable certificate)"
assert [s for s in d["slots"] if s["slot"] == 0x9A][0]["cert"]["subject"].startswith("CN=Jane")
card.objects.pop(0x5FC10A)
print("management key checked before signing; an unreadable certificate does not break the status")

# ---- signing requests
for slot in (0x9C, 0x9D):
    text = piv.csr(slot, PIN, "CN=Jane Doe,O=Example")
    req = x509.load_pem_x509_csr(text.encode())
    assert req.is_signature_valid and req.subject.rfc4514_string() == "CN=Jane Doe,O=Example"
    assert req.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo) == \
        piv.key_object(piv.public_key(card, slot)).public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
if shutil.which("openssl"):
    path = os.path.join(tmp, "r.pem")
    open(path, "w").write(piv.csr(0x9A, PIN, "CN=Req"))
    out = subprocess.run(["openssl", "req", "-in", path, "-noout", "-verify"], capture_output=True, text=True)
    assert "verify OK" in out.stderr + out.stdout, out
fails(lambda: piv.csr(0x9A, "000000", "CN=x"), "wrong PIN")
print("signing requests signed on the card verify (also with openssl)")

# ---- import, export, delete
other = ec.generate_private_key(ec.SECP256R1())
name = x509.Name.from_rfc4514_string("CN=Elsewhere")
import datetime
now = datetime.datetime.now(datetime.timezone.utc)
foreign = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(other.public_key())
           .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)).sign(other, hashes.SHA256()))
fails(lambda: piv.import_cert(0x9A, foreign.public_bytes(ser.Encoding.PEM)), "another key")
fails(lambda: piv.import_cert(0x9A, b"junk"), "not a certificate")
mine = piv.read_cert(0x9A)
piv.delete_cert(0x9A)
assert piv.read_cert(0x9A) is None
fails(lambda: piv.export_cert(0x9A), "no certificate")
piv.import_cert(0x9A, x509.load_der_x509_certificate(mine).public_bytes(ser.Encoding.PEM))
assert piv.read_cert(0x9A) == mine
piv.delete_cert(0x9A)
piv.import_cert(0x9A, mine)                                        # DER too
assert piv.export_cert(0x9A).startswith("-----BEGIN CERTIFICATE-----")
fails(lambda: piv.delete_cert(0x9A, bytes(24)), "wrong management key")
print("certificates: foreign one refused, import PEM/DER, export, delete")

# ---- generating again drops the stale certificate
piv.generate(0x9A, "nistp256")
assert piv.read_cert(0x9A) is None
print("a new key removes the old certificate")

# ---- management key
key = piv.set_mgmt_key(None, None, "aes256")
assert len(key) == 32 and piv.details()["mgmt"] == {"algo": "aes256", "default": False}
fails(lambda: piv.generate(0x9A, "nistp256"), "AES-256")
piv.generate(0x9A, "nistp256", mgmt_key=key)
new3 = piv.set_mgmt_key(key, None, "3des")
assert len(new3) == 24
fails(lambda: piv.set_mgmt_key(new3, bytes(8) * 3, "3des"), "weak")
fails(lambda: piv.set_mgmt_key(new3, b"short", "3des"), "needs 24 bytes")
assert piv.parse_mgmt_key("") == piv.DEFAULT_MGMT and piv.parse_mgmt_key("00" * 16) == bytes(16)
fails(lambda: piv.parse_mgmt_key("zz"), "hex")
fails(lambda: piv.parse_mgmt_key("00" * 5), "16, 24 or 32")
print("management key: AES-256 and 3DES, weak and wrong keys refused")
print("QK PIV TEST DONE")
