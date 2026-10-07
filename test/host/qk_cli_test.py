#!/usr/bin/env python3
"""The new `qk` commands (pgp, piv, ssh, fido, pwd audit, otp reset, updates) through qk.main() on the software
card and authenticator: arguments, output, errors."""
import contextlib
import io
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeapps  # noqa: E402
import fakecard  # noqa: E402
import fakefido  # noqa: E402
import qk  # noqa: E402

ADMIN, PIN = fakecard.ADMIN, fakecard.PIN
tmp = tempfile.mkdtemp()


def run(*argv, stdin=None):
    """(exit code, stdout, stderr) of `qk <argv>`."""
    out, err = io.StringIO(), io.StringIO()
    old = sys.argv, sys.stdin
    sys.argv = ["qk", *argv]
    if stdin is not None:
        sys.stdin = io.StringIO(stdin)
    code = 0
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            qk.main()
    except SystemExit as e:
        code = e.code or 0
    finally:
        sys.argv, sys.stdin = old
    return code, out.getvalue(), err.getvalue()


def ok(*argv, **kw):
    code, out, err = run(*argv, **kw)
    assert code == 0, (argv, code, err)
    return out


def bad(text, *argv, **kw):
    code, out, err = run(*argv, **kw)
    assert code != 0 and text in err, (argv, code, out, err)


# ---- OpenPGP
card = fakecard.install()
assert "[none]" in ok("pgp", "status")
out = ok("pgp", "generate", "authentication", "--admin-pin", ADMIN)
assert "ssh-ed25519 " in out and "authentication key ed25519" in out
bad("wrong admin PIN", "pgp", "generate", "signature", "--admin-pin", "00000000")
bad("can be", "pgp", "generate", "decryption", "--algo", "ed25519", "--admin-pin", ADMIN)
ok("pgp", "generate", "signature", "--algo", "nistp256", "--admin-pin", ADMIN)
bad("cancelled", "pgp", "generate", "signature", "--admin-pin", ADMIN, stdin="n\n")
assert "ecdsa-sha2-nistp256" in ok("pgp", "generate", "signature", "--admin-pin", ADMIN, "--yes", "--algo", "nistp256")
ok("pgp", "generate", "decryption", "--admin-pin", ADMIN)
line = ok("pgp", "ssh", "--comment", "me").strip()
assert line.startswith("ssh-ed25519 ") and line.endswith(" me") and line == line.splitlines()[0]
bad("cannot be used for SSH", "pgp", "ssh", "decryption")
ok("pgp", "cardholder", "--name", "Doe<<Jane", "--lang", "en", "--admin-pin", ADMIN)
assert "Doe<<Jane" in ok("pgp", "cardholder") and "Doe<<Jane" in ok("pgp", "status")
key = os.path.join(tmp, "k.pem")
from cryptography.hazmat.primitives import serialization as ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402
ed = ed25519.Ed25519PrivateKey.generate()
open(key, "wb").write(ed.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
assert "authentication key ed25519" in ok("pgp", "import", "authentication", key, "--admin-pin", ADMIN, "--yes")
assert "imported" in ok("pgp", "status")
bad("cannot read", "pgp", "import", "authentication", os.path.join(tmp, "missing"), "--admin-pin", ADMIN, "--yes")
asc = os.path.join(tmp, "pub.asc")
assert "written" in ok("pgp", "export", "Jane <j@x.org>", "-o", asc, "--pin", PIN)
assert open(asc).read().startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----")
bad("wrong PIN", "pgp", "export", "Jane <j@x.org>", "--pin", "000000")
print("pgp: status, generate (replace asks), ssh, cardholder, import, export")

# ---- PIV
assert "factory default" in ok("piv", "status")
bad("wrong management key", "piv", "generate", "9a", "--mgmt-key", "00" * 24)
out = ok("piv", "generate", "9a", "--mgmt-key", "", "--touch", "cached")
assert "-----BEGIN PUBLIC KEY-----" in out
assert "nistp256 touch cached" in ok("piv", "status")
out = ok("piv", "self-signed", "9a", "CN=Jane,O=Ex", "--pin", PIN, "--mgmt-key", "", "--days", "10")
assert "subject      CN=Jane,O=Ex" in out and "9a" not in out
crt = os.path.join(tmp, "c.pem")
assert "written" in ok("piv", "cert", "9a", "-o", crt)
assert "BEGIN CERTIFICATE" in ok("piv", "cert", "9a")
bad("no certificate", "piv", "cert", "9d")
req = os.path.join(tmp, "r.pem")
ok("piv", "csr", "9a", "CN=Req", "--pin", PIN, "-o", req)
assert open(req).read().startswith("-----BEGIN CERTIFICATE REQUEST-----")
assert ok("piv", "pubkey", "9a", "--ssh", "--comment", "piv").startswith("ecdsa-sha2-nistp256 ")
assert "BEGIN PUBLIC KEY" in ok("piv", "pubkey", "9a")
ok("piv", "delete-cert", "9a", "--mgmt-key", "")
ok("piv", "import-cert", "9a", crt, "--mgmt-key", "")
bad("not a certificate", "piv", "import-cert", "9a", key, "--mgmt-key", "")
from cryptography import x509  # noqa: E402
import datetime  # noqa: E402
now = datetime.datetime.now(datetime.timezone.utc)
name = x509.Name.from_rfc4514_string("CN=Elsewhere")
foreign = os.path.join(tmp, "foreign.pem")
open(foreign, "wb").write((x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ed.public_key())
                           .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                           .sign(ed, None)).public_bytes(ser.Encoding.PEM))
bad("another key", "piv", "import-cert", "9a", foreign, "--mgmt-key", "")
out = ok("piv", "mgmt-key", "--mgmt-key", "", "--algo", "aes128")
assert "new key:" in out
bad("AES-128", "piv", "generate", "9a", "--mgmt-key", "", "--yes")
print("piv: status, generate, self-signed, cert, csr, pubkey, import/delete, management key")

# ---- FIDO and SSH
dev = fakefido.install()
dev.add("github.com", "alice", -7, "Alice")
cid = dev.creds[0]["id"].hex()
assert "github.com" in ok("fido", "list", "--pin", fakefido.PIN) and "ES256" in ok("fido", "list", "--pin", fakefido.PIN)
assert "PIN tries" in ok("fido", "info")
ok("fido", "rename", cid[:8], "alice2", "--pin", fakefido.PIN)
assert "alice2" in ok("fido", "list", "--pin", fakefido.PIN)
bad("no passkey", "fido", "rename", "ffffffff", "x", "--pin", fakefido.PIN)
assert "alwaysUv: off" in ok("fido", "always-uv")
assert "alwaysUv: on" in ok("fido", "always-uv", "on", "--pin", fakefido.PIN)
ok("fido", "always-uv", "off", "--pin", fakefido.PIN)
assert "2 entries" in ok("fido", "blobs")
assert "0 entries" in ok("fido", "blobs", "--clear", "--pin", fakefido.PIN)
f = os.path.join(tmp, "id_sk")
out = ok("ssh", "create", "--name", "work", "--file", f, "--comment", "me", "--pin", fakefido.PIN)
assert "sk-ssh-ed25519@openssh.com " in out and os.path.exists(f) and os.path.exists(f + ".pub")
presses = dev.presses
bad("exists", "ssh", "create", "--file", f, "--pin", fakefido.PIN)
bad("lost without its file", "ssh", "create", "--no-resident", "--pin", fakefido.PIN)
assert dev.presses == presses, "nothing may be made on the key when the file is refused"
assert "SHA256:" in ok("ssh", "list", "--pin", fakefido.PIN)
g = os.path.join(tmp, "exported")
ok("ssh", "export", "work", g, "--pin", fakefido.PIN)
assert subprocess.run(["ssh-keygen", "-y", "-f", g], capture_output=True, text=True).returncode == 0
bad("no SSH key", "ssh", "export", "nope", g, "--pin", fakefido.PIN)
ok("ssh", "delete", "work", "--pin", fakefido.PIN)
assert "no SSH keys" in ok("ssh", "list", "--pin", fakefido.PIN)
print("fido / ssh: list, rename, alwaysUv, large blobs, create, export, delete")

# ---- OTP reset, password audit, updates
fakeapps.install()
fakeapps.FakeOath.accounts = {"a": {"hotp": False, "touch": False}}
assert "reset" in ok("otp", "reset") and fakeapps.FakeOath.accounts == {}
fakeapps.FakePwd.records = [{"id": 0, "name": "n", "flags": 0, "password": "password"},
                            {"id": 1, "name": "m", "flags": 0, "password": "Zx9$kLm2#pQw8vNr"}]
out = ok("pwd", "audit", "--pin", fakeapps.PIN)
assert "weak    n: a very common password" in out and "checked 2 passwords: 1 weak, 0 reused" in out, out
qk.update_status = lambda: {"latest": "1.1.0", "qk": "1.0.0", "qk_newer": True, "firmware": None, "firmware_newer": False}
out = ok("updates")
assert "latest release: 1.1.0" in out and "qk self-update" in out and "no key plugged in" in out
qk.self_update = lambda version=None, log=print: "1.1.0"
qk.qk_version = lambda: "1.0.0"
assert "1.0.0 -> 1.1.0" in ok("self-update")
print("otp reset, pwd audit, updates, self-update")
print("QK CLI TEST DONE")
