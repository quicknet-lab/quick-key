#!/usr/bin/env python3
"""tools/qk_pgp.py against the software OpenPGP card in fakecard.py: algorithm
attributes, on-card generation, fingerprints, key import, cardholder data, SSH
export (checked by ssh-keygen) and the OpenPGP public key export (imported by gpg)."""
import os
import shutil
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakecard  # noqa: E402
import qk  # noqa: E402
import qk_pgp as pgp  # noqa: E402
from cryptography.hazmat.primitives import serialization as ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519  # noqa: E402

ADMIN, PIN = fakecard.ADMIN, fakecard.PIN


def fails(fn, text):
    try:
        fn()
    except (qk.QkError, RuntimeError) as e:
        assert text in str(e), e
        return
    raise AssertionError(f"no error '{text}'")


card = fakecard.install()

# ---- details of an empty card
d = pgp.details()
assert d["pin_tries"] == 8 and d["admin_tries"] == 3 and d["sig_count"] == 0 and d["sex"] == "" and d["name"] == ""
assert [k["algo"] for k in d["keys"]] == ["rsa2048"] * 3 and all(k["fingerprint"] is None for k in d["keys"])
print("details of an empty card")

# ---- attributes
assert pgp.algo_attr(0, "ed25519")[0] == 0x16 and pgp.algo_attr(1, "cv25519")[0] == 0x12
assert pgp.algo_attr(1, "nistp256")[0] == 0x12 and pgp.algo_attr(2, "nistp256")[0] == 0x13
fails(lambda: pgp.algo_attr(1, "ed25519"), "decryption key can be")
fails(lambda: pgp.algo_attr(0, "cv25519"), "signature key can be")
print("algorithm attributes per slot")

# ---- generation, fingerprints, SSH export
fails(lambda: pgp.generate("00000000", 0, "ed25519"), "wrong admin PIN")
assert card.tries["admin"] == 2
for k, algo in ((0, "ed25519"), (1, "cv25519"), (2, "ed25519")):
    pub = pgp.generate(ADMIN, k, algo)
    assert pub["algo"] == algo and len(pub["point"]) == 32
d = pgp.details()
assert [k["algo"] for k in d["keys"]] == ["ed25519", "cv25519", "ed25519"]
assert all(k["origin"] == "generated" and k["fingerprint"] and abs(k["created"] - time.time()) < 5 for k in d["keys"])
for k in range(3):
    pub, info = pgp.read_public(k), d["keys"][k]
    assert pgp.fingerprint(pgp.key_body(k, pub, info["created"])).hex().upper() == info["fingerprint"]
print("Ed25519 / X25519 generated; fingerprints match the public keys")

for algo in ("nistp256", "rsa2048"):
    pub = pgp.generate(ADMIN, 0, algo)
    assert pgp.read_public(0)["algo"] == algo
    line = pgp.ssh_key(0, "test@qk")
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "k.pub")
    open(path, "w").write(line + "\n")
    out = subprocess.run(["ssh-keygen", "-l", "-f", path], capture_output=True, text=True, check=True).stdout
    assert out.split()[2] == "test@qk" and ("ECDSA" in out if algo == "nistp256" else "RSA" in out), out
    # the fingerprint ssh-keygen shows is the SHA256 of the key blob: compare with the one we can compute
    import base64
    import hashlib
    blob = base64.b64decode(line.split()[1])
    assert out.split()[1] == "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    shutil.rmtree(tmp)
line = pgp.ssh_key(0)
pgp.generate(ADMIN, 0, "ed25519")
tmp = tempfile.mkdtemp()
open(os.path.join(tmp, "k.pub"), "w").write(pgp.ssh_key(0, "c") + "\n")
out = subprocess.run(["ssh-keygen", "-l", "-f", os.path.join(tmp, "k.pub")], capture_output=True, text=True).stdout
assert "ED25519" in out, out
fails(lambda: pgp.ssh_key(1), "cannot be used for SSH")
print("SSH public keys accepted by ssh-keygen (Ed25519, P-256, RSA-2048)")

# ---- cardholder data
fails(lambda: pgp.set_cardholder(ADMIN, name="Ünal"), "ASCII")
fails(lambda: pgp.set_cardholder(ADMIN, lang="e"), "language")
fails(lambda: pgp.set_cardholder(ADMIN, sex="x"), "sex")
pgp.set_cardholder(ADMIN, name="Doe<<Jane", lang="enru", sex="2", url="https://example.org/key.asc", login="jane")
d = pgp.details()
assert (d["name"], d["lang"], d["sex"], d["url"], d["login"]) == ("Doe<<Jane", "enru", "2", "https://example.org/key.asc", "jane")
pgp.set_cardholder(ADMIN, name="Doe<<John")
assert pgp.details()["name"] == "Doe<<John" and pgp.details()["lang"] == "enru"
print("cardholder name, language, sex, URL and login written; a field left as None is kept")

# ---- import
ed = ed25519.Ed25519PrivateKey.generate()
pem = ed.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
pub = pgp.import_key(ADMIN, 2, pem)
assert pub["point"] == ed.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
assert pgp.details()["keys"][2]["origin"] == "imported"
openssh = ed.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.OpenSSH, ser.NoEncryption())
assert pgp.import_key(ADMIN, 0, openssh)["point"] == pub["point"]
x = x25519.X25519PrivateKey.generate()
pub = pgp.import_key(ADMIN, 1, x.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
assert pub["algo"] == "cv25519" and pub["point"] == x.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
assert card.keys[1][0].private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption()) == \
    x.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())     # scalar order survives
p256 = ec.generate_private_key(ec.SECP256R1())
pub = pgp.import_key(ADMIN, 0, p256.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.TraditionalOpenSSL, ser.NoEncryption()))
assert pub["point"] == p256.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)
r = rsa.generate_private_key(65537, 2048)
pub = pgp.import_key(ADMIN, 2, r.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
assert int.from_bytes(pub["n"], "big") == r.public_key().public_numbers().n
enc = ed.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.BestAvailableEncryption(b"pw"))
fails(lambda: pgp.import_key(ADMIN, 2, enc), "password is needed")
fails(lambda: pgp.import_key(ADMIN, 2, enc, "bad"), "wrong key password")
assert pgp.import_key(ADMIN, 2, enc, "pw")["algo"] == "ed25519"
fails(lambda: pgp.import_key(ADMIN, 1, pem), "cannot be the decryption key")
fails(lambda: pgp.import_key(ADMIN, 0, b"garbage"), "not a private key")
fails(lambda: pgp.import_key(ADMIN, 0, ec.generate_private_key(ec.SECP384R1()).private_bytes(
    ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())), "only NIST P-256")
fails(lambda: pgp.import_key(ADMIN, 0, rsa.generate_private_key(65537, 3072).private_bytes(
    ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())), "only RSA-2048")
der = p256.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption())
assert pgp.import_key(ADMIN, 0, der)["algo"] == "nistp256"
der = r.private_bytes(ser.Encoding.DER, ser.PrivateFormat.TraditionalOpenSSL, ser.NoEncryption())
assert pgp.import_key(ADMIN, 0, der)["algo"] == "rsa2048"
assert pgp.import_key(ADMIN, 2, pem, "unneeded")["algo"] == "ed25519"       # a password for a key that has none
pgp.set_cardholder(ADMIN, lang="en")
pgp.set_cardholder(ADMIN, lang="")
assert pgp.details()["lang"] == ""
print("import: Ed25519 (PEM, OpenSSH), X25519 (scalar order), P-256, RSA-2048, encrypted keys, bad keys refused")

# ---- OpenPGP public key, checked by gpg
if shutil.which("gpg"):
    for sig_algo, dec_algo, aut_algo in (("ed25519", "cv25519", "ed25519"), ("nistp256", "nistp256", "nistp256"),
                                         ("rsa2048", "rsa2048", "ed25519")):
        pgp.generate(ADMIN, 0, sig_algo)
        pgp.generate(ADMIN, 1, dec_algo)
        pgp.generate(ADMIN, 2, aut_algo)
        signs = []
        text = pgp.export_pgp("Jane Doe <jane@example.org>", PIN, on_sign=signs.append)
        assert len(signs) == 3, signs
        home = tempfile.mkdtemp()
        os.chmod(home, 0o700)
        env = dict(os.environ, GNUPGHOME=home)
        run = lambda *a: subprocess.run(["gpg", "--batch", "--no-tty", *a], env=env, capture_output=True, text=True)  # noqa: E731
        res = subprocess.run(["gpg", "--batch", "--no-tty", "--import"], input=text, env=env, capture_output=True, text=True)
        assert "imported" in res.stderr and "bad signature" not in res.stderr and "invalid" not in res.stderr.lower() \
            and res.returncode == 0, res.stderr
        listing = run("--list-keys", "--with-colons", "--with-subkey-fingerprint").stdout
        fprs = [l.split(":")[9] for l in listing.splitlines() if l.startswith("fpr")]
        d = pgp.details()
        assert len(fprs) == 3, fprs                     # a subkey with a bad binding signature is dropped
        assert fprs[0] == d["keys"][0]["fingerprint"], (fprs, d["keys"][0])
        assert fprs[1] == d["keys"][1]["fingerprint"] and fprs[2] == d["keys"][2]["fingerprint"], fprs
        assert "Jane Doe <jane@example.org>" in listing
        checked = run("--check-sigs").stderr + run("--check-sigs").stdout
        assert "bad" not in checked.lower(), checked
        caps = [l.split(":")[11] for l in listing.splitlines() if l.startswith(("pub", "sub"))]
        assert caps[0].lower().startswith("sc") and "e" in caps[1].lower() and "a" in caps[2].lower(), caps
        shutil.rmtree(home)
    print("OpenPGP public key: gpg imports it for Ed25519 / P-256 / RSA, signatures valid, fingerprints match the card")
    fails(lambda: pgp.export_pgp("  ", PIN), "user ID")
    fails(lambda: pgp.export_pgp("A <a@b.c>", "000000"), "wrong PIN")
else:
    print("gpg not found: OpenPGP export not checked")
print("QK PGP TEST DONE")
