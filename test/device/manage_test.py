# The management functions behind `qk pgp | piv | ssh | fido | otp` on the key: OpenPGP generation, import,
# fingerprints, public key export (gpg imports it), cardholder data; PIV keys, certificates, requests and the
# management key; SSH keys and passkey renaming over FIDO2, alwaysUv, large blobs; OTP reset.
# Needs PIN 314159, admin PIN 27182818 and the factory PIV management key (after `qk piv reset`).
# Run `gpgconf --kill scdaemon` first. ERASES the OpenPGP keys, PIV keys and all OTP accounts on the key,
# so it only runs with --erase-everything: use it on a test key, never on one that holds your keys.
#
# Button presses, in this order (the script prints PRESS BUTTON before each):
#   1  create a test passkey (rename test)
#   2  create the ed25519-sk key
#   3  create the ecdsa-sk key
#   4  reset PIV at the end
#   5  reset OTP at the end
import datetime
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import qk
import qk_fido as fido
import qk_pgp as pgp
import qk_piv as piv
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519

PIN, ADMIN = "314159", "27182818"
tmp = tempfile.mkdtemp()


def log(*a):
    print(*a, flush=True)


def fails(fn, text):
    try:
        fn()
    except (qk.QkError, RuntimeError) as e:
        assert text in str(e), e
        return
    raise AssertionError(f"no error '{text}'")


def sh(*cmd, env=None, input=None):
    return subprocess.run(cmd, capture_output=True, text=True, env=env, input=input)


if "--erase-everything" not in sys.argv:
    sys.exit("This test ERASES the OpenPGP keys, PIV keys and all OTP accounts on the key (and spends one wrong "
             "admin PIN try on purpose): run it with --erase-everything on a test key.")
log("Presses: 1 test passkey, 2-3 SSH keys, 4 PIV reset, 5 OTP reset")

# ---------------------------------------------------------------- OpenPGP
log("OpenPGP")
qk.pgp_reset(ADMIN)
d = pgp.details()
assert d["pin_tries"] == 8 and d["admin_tries"] == 3 and d["sex"] == "" and all(k["fingerprint"] is None for k in d["keys"])
fails(lambda: pgp.generate("00000000", 0, "ed25519"), "wrong admin PIN")
assert pgp.details()["admin_tries"] == 2
for k, algo in ((0, "ed25519"), (1, "cv25519"), (2, "ed25519")):
    assert pgp.generate(ADMIN, k, algo)["algo"] == algo
d = pgp.details()
assert [k["algo"] for k in d["keys"]] == ["ed25519", "cv25519", "ed25519"] and d["admin_tries"] == 3
for k in range(3):
    info = d["keys"][k]
    assert info["origin"] == "generated"
    assert pgp.fingerprint(pgp.key_body(k, pgp.read_public(k), info["created"])).hex().upper() == info["fingerprint"]
log("  Ed25519 / X25519 keys generated on the card, fingerprints registered")

# a signature of the card verifies with the public key it reports
c = pgp.card()
digest = hashlib.sha256(b"quick-key manage test").digest()
pgp.verify(c, 0x81, PIN)
sig, sw = c.send(0x00, 0x2A, 0x9E, 0x9A, digest, check=False)
assert sw == 0x9000
ed25519.Ed25519PublicKey.from_public_bytes(pgp.read_public(0)["point"]).verify(sig, digest)
assert pgp.details()["sig_count"] == d["sig_count"] + 1
log("  card signature verifies; the signature counter moved")

line = pgp.ssh_key(2, "qk-test")
open(os.path.join(tmp, "a.pub"), "w").write(line + "\n")
if shutil.which("ssh-keygen"):
    assert "ED25519" in sh("ssh-keygen", "-l", "-f", os.path.join(tmp, "a.pub")).stdout
fails(lambda: pgp.ssh_key(1), "cannot be used for SSH")

text = pgp.export_pgp("Quick-Key Test <test@example.org>", PIN)
assert text.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
if shutil.which("gpg"):
    home = tempfile.mkdtemp()
    os.chmod(home, 0o700)
    env = dict(os.environ, GNUPGHOME=home)
    res = sh("gpg", "--batch", "--no-tty", "--import", env=env, input=text)
    assert "imported" in res.stderr and "bad signature" not in res.stderr, res.stderr
    listing = sh("gpg", "--batch", "--no-tty", "--list-keys", "--with-colons", "--with-subkey-fingerprint", env=env).stdout
    fprs = [l.split(":")[9] for l in listing.splitlines() if l.startswith("fpr")]
    assert fprs == [k["fingerprint"] for k in pgp.details()["keys"]], (fprs, pgp.details()["keys"])
    log("  gpg imports the exported key; its fingerprints are the ones on the card")
else:
    log("  gpg not found: export not checked")

for algo in ("nistp256", "rsa2048"):
    pgp.generate(ADMIN, 0, algo)
    assert pgp.read_public(0)["algo"] == algo
log("  signature key regenerated as P-256 and RSA-2048")

# import
ed = ed25519.Ed25519PrivateKey.generate()
pub = pgp.import_key(ADMIN, 0, ed.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
assert pub["point"] == ed.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
pgp.verify(c, 0x81, PIN)
sig, sw = c.send(0x00, 0x2A, 0x9E, 0x9A, digest, check=False)
assert sw == 0x9000
ed.public_key().verify(sig, digest)
x = x25519.X25519PrivateKey.generate()
pub = pgp.import_key(ADMIN, 1, x.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
assert pub["point"] == x.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
p256 = ec.generate_private_key(ec.SECP256R1())
pub = pgp.import_key(ADMIN, 2, p256.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
assert pub["point"] == p256.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)
r = rsa.generate_private_key(65537, 2048)
pub = pgp.import_key(ADMIN, 0, r.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
assert int.from_bytes(pub["n"], "big") == r.public_key().public_numbers().n
assert [k["origin"] for k in pgp.details()["keys"]] == ["imported"] * 3
log("  import: Ed25519 (signs on the card), X25519, P-256, RSA-2048 give the public keys of the files")

pgp.set_cardholder(ADMIN, name="Test<<Quick", lang="en", sex="2", url="https://example.org/k.asc", login="qk")
d = pgp.details()
assert (d["name"], d["lang"], d["sex"], d["url"], d["login"]) == ("Test<<Quick", "en", "2", "https://example.org/k.asc", "qk")
log("  cardholder data written and read back")
qk.pgp_reset(ADMIN)
assert all(k["fingerprint"] is None for k in pgp.details()["keys"]) and pgp.details()["name"] == ""

# ---------------------------------------------------------------- PIV
log("PIV")
assert piv.details()["mgmt"]["default"], "the management key is not the factory one: run `qk piv reset` first"


def check_signature(cert):
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
    else:
        pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))


fails(lambda: piv.generate(0x9A, "nistp256", mgmt_key=bytes(24)), "wrong management key")
assert piv.generate(0x9A, "nistp256")["algo"] == "nistp256"
assert piv.generate(0x9D, "rsa2048")["algo"] == "rsa2048"
by = {s["slot"]: s for s in piv.details()["slots"]}
assert by[0x9A]["key"]["algo"] == "nistp256" and by[0x9A]["pin_policy"] == "once" and by[0x9A]["touch"] == "never"
assert by[0x9D]["key"]["algo"] == "rsa2048"
log("  keys generated: P-256 in 9A, RSA-2048 in 9D")

fails(lambda: piv.self_signed(0x9A, "000000", "CN=Quick-Key Test"), "wrong PIN")
for slot in (0x9A, 0x9D):
    der = piv.self_signed(slot, PIN, "CN=Quick-Key Test,O=Example", days=30)
    cert = x509.load_der_x509_certificate(der)
    check_signature(cert)
    assert piv.read_cert(slot) == der
    if shutil.which("openssl"):
        path = os.path.join(tmp, f"c{slot:x}.pem")
        open(path, "w").write(piv.export_cert(slot))
        assert sh("openssl", "verify", "-CAfile", path, path).stdout.strip().endswith("OK")
log("  self-signed certificates made with the card's keys verify (P-256 and RSA)")

for slot in (0x9A, 0x9D):
    req = x509.load_pem_x509_csr(piv.csr(slot, PIN, "CN=Quick-Key Request").encode())
    assert req.is_signature_valid
log("  signing requests made on the card verify")

mine = piv.read_cert(0x9A)
piv.delete_cert(0x9A)
assert piv.read_cert(0x9A) is None
piv.import_cert(0x9A, mine)
assert piv.read_cert(0x9A) == mine
other = ec.generate_private_key(ec.SECP256R1())
name = x509.Name.from_rfc4514_string("CN=Elsewhere")
now = datetime.datetime.now(datetime.timezone.utc)
foreign = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(other.public_key()).serial_number(1)
           .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1)).sign(other, hashes.SHA256()))
fails(lambda: piv.import_cert(0x9A, foreign.public_bytes(ser.Encoding.PEM)), "another key")
log("  certificate deleted, imported back; a certificate of another key refused")

piv.generate(0x9A, "nistp256")
assert piv.read_cert(0x9A) is None
key = piv.set_mgmt_key(None, None, "aes256")
assert piv.details()["mgmt"] == {"algo": "aes256", "default": False}
fails(lambda: piv.generate(0x9A, "nistp256"), "AES-256")
piv.generate(0x9A, "nistp256", mgmt_key=key)
log("  new key removes the old certificate; management key changed to AES-256 and used")
log("PRESS BUTTON: reset PIV")
qk.piv_reset()
assert piv.details()["mgmt"]["default"] and all(s["key"] is None for s in piv.details()["slots"])

# ---------------------------------------------------------------- FIDO2: passkey rename, SSH keys, alwaysUv, blobs
log("FIDO2")
from fido2.ctap2.pin import ClientPin

ctap = qk.fido_ctap()
cp = ClientPin(ctap)
cdh = os.urandom(32)
tok = cp.get_pin_token(PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, "rename.example")
log("PRESS BUTTON: create a test passkey")
att = ctap.make_credential(cdh, {"id": "rename.example", "name": "R"}, {"id": b"u1", "name": "bob", "displayName": "Bob"},
                           [{"type": "public-key", "alg": -7}], options={"rk": True},
                           pin_uv_param=cp.protocol.authenticate(tok, cdh), pin_uv_protocol=cp.protocol.VERSION)
cid = att.auth_data.credential_data.credential_id
cred = next(c for c in fido.passkeys(PIN)[2] if c["id"] == cid)
assert (cred["name"], cred["alg"], cred["rp"]) == ("bob", "ES256", "rename.example")
fido.rename(PIN, cid, cred["user_id"], "bob2", "Bob Two")
cred = next(c for c in fido.passkeys(PIN)[2] if c["id"] == cid)
assert (cred["name"], cred["display"]) == ("bob2", "Bob Two")
qk.fido_delete(PIN, cid)
assert cid not in [c["id"] for c in fido.passkeys(PIN)[2]]
log("  passkey renamed and deleted")

made = []
for algo, name in (("ed25519", "qk-test-a"), ("ecdsa", "qk-test-b")):
    log(f"PRESS BUTTON: create the {algo}-sk key")
    key = fido.ssh_create(PIN, algo, name)
    made.append((name, key))
keys = {k["name"]: k for k in fido.ssh_list(PIN)}
for name, key in made:
    assert keys[name]["key"]["line"] == key["line"] and keys[name]["fingerprint"].startswith("SHA256:")
    if shutil.which("ssh-keygen"):
        path = os.path.join(tmp, f"id_{name}")
        fido.save_ssh_key(keys[name]["key"], path, "qk")
        assert sh("ssh-keygen", "-y", "-f", path).stdout.split()[:2] == fido.public_line(key).split()[:2]
for name, _ in made:
    qk.fido_delete(PIN, keys[name]["id"])
assert not [k for k in fido.ssh_list(PIN) if k["name"].startswith("qk-test")]
log("  SSH keys created on the key, listed, exported (ssh-keygen reads the files), deleted")

try:
    assert fido.info()["always_uv"] is False
    assert fido.set_always_uv(PIN, True) is True and fido.info()["always_uv"] is True
finally:
    assert fido.set_always_uv(PIN, False) is False
log("  alwaysUv switched on and off")
n, size, cap = fido.large_blobs()
fido.clear_large_blobs(PIN)
assert fido.large_blobs()[:2] == (0, 0) and cap == 2048
log("  large blobs read and cleared")

# ---------------------------------------------------------------- OTP reset
log("OTP")
qk.Oath().add("qk-test", "JBSWY3DPEHPK3PXP")
assert [n for _, n in qk.Oath().list()] == ["qk-test"]
log("PRESS BUTTON: reset OTP")
qk.oath_reset()
assert qk.Oath().list() == []
log("  OTP reset erased the account")
log("MANAGE TEST DONE")
