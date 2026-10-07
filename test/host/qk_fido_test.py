#!/usr/bin/env python3
"""tools/qk_fido.py without a key: passkey details and renaming, alwaysUv, large
blobs, SSH keys (public key lines and private key files checked by ssh-keygen)."""
import base64
import hashlib
import os
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakefido  # noqa: E402
import qk  # noqa: E402
import qk_fido as fido  # noqa: E402
from fido2.ctap import CtapError  # noqa: E402

PIN = fakefido.PIN


def fails(fn, text):
    try:
        fn()
    except qk.QkError as e:
        assert text in str(e), e
        return
    raise AssertionError(f"no error '{text}'")


def keygen(*args):
    r = subprocess.run(["ssh-keygen", *args], capture_output=True, text=True)
    assert r.returncode == 0, (args, r.stderr)
    return r.stdout.strip()


dev = fakefido.install()
tmp = tempfile.mkdtemp()

# ---- passkeys
gh = dev.add("github.com", "alice", -7, "Alice", "GitHub", 1)
dev.add("example.org", "bob", -8, "", "", 3)
used, free, creds = fido.passkeys(PIN)
assert (used, free) == (2, 48) and {c["rp"] for c in creds} == {"github.com", "example.org"}
c = next(c for c in creds if c["rp"] == "github.com")
assert (c["name"], c["display"], c["alg"], c["protect"], c["rp_name"]) == ("alice", "Alice", "ES256", "optional", "GitHub")
assert next(c for c in creds if c["rp"] == "example.org")["alg"] == "EdDSA"
assert next(c for c in creds if c["rp"] == "example.org")["protect"] == "required"
fails(lambda: fido.passkeys("000000"), "wrong PIN")
fido.rename(PIN, c["id"], c["user_id"], "alice2", "Alice Two")
c = next(c for c in fido.passkeys(PIN)[2] if c["rp"] == "github.com")
assert (c["name"], c["display"]) == ("alice2", "Alice Two")
fails(lambda: fido.rename(PIN, c["id"], c["user_id"], "", ""), "user name is needed")
print("passkeys: details, rename, wrong PIN")

# ---- authenticator info, alwaysUv, large blobs
i = fido.info()
assert i["pin_tries"] == dev.pin_tries and i["always_uv"] is False and i["max_blob"] == 2048
assert fido.set_always_uv(PIN, True) is True and fido.info()["always_uv"] is True
assert fido.set_always_uv(PIN, True) is True and fido.set_always_uv(PIN, False) is False
assert fido.large_blobs() == (2, 42, 2048)
fido.clear_large_blobs(PIN)
assert fido.large_blobs() == (0, 0, 2048)
print("alwaysUv on/off, large blobs counted and cleared")

# ---- CTAP errors become messages
for code, text in ((CtapError.ERR.PIN_INVALID, "wrong PIN"), (CtapError.ERR.KEY_STORE_FULL, "no room"),
                   (CtapError.ERR.ACTION_TIMEOUT, "not confirmed"), (CtapError.ERR.PIN_BLOCKED, "PIN blocked"),
                   (CtapError.ERR.OTHER, "key refused (OTHER)")):
    def boom(code=code):
        with fido.ctap_errors():
            raise CtapError(code)
    fails(boom, text)

# ---- SSH keys: each type, resident or not
for algo, kind in (("ed25519", "sk-ssh-ed25519@openssh.com"), ("ecdsa", "sk-ecdsa-sha2-nistp256@openssh.com")):
    for resident in (True, False):
        before = dev.presses
        path = os.path.join(tmp, f"id_{algo}_{resident}")
        key = fido.ssh_create(PIN, algo, "work", resident, verify_required=not resident,
                              path=None if resident else path, comment="me@host")
        assert dev.presses == before + 1 and key["type"] == kind and key["application"] == "ssh:work"
        assert key["flags"] == (0x21 if resident else 0x05), key["flags"]
        line = fido.public_line(key, "me@host")
        pub = os.path.join(tmp, f"{algo}{resident}.pub")
        open(pub, "w").write(line + "\n")
        out = keygen("-l", "-f", pub)
        assert out.split()[2] == "me@host" and ("ED25519-SK" in out or "ECDSA-SK" in out), out
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(key["blob"]).digest()).decode().rstrip("=")
        assert out.split()[1] == fp, (out, fp)
        if resident:
            fido.save_ssh_key(key, path, "me@host")
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
        assert keygen("-y", "-f", path) == line, "ssh-keygen derives the same public key from the file"
        assert open(path + ".pub").read().strip() == line
        fails(lambda: fido.save_ssh_key(key, path), "exists")
print("SSH keys: ed25519-sk / ecdsa-sk, resident or not; ssh-keygen reads the public lines and the private files")

# resident keys are listed and exported; the non-resident ones stay off the key
keys = fido.ssh_list(PIN)
assert sorted(k["name"] for k in keys) == ["work", "work"] and len(dev.creds) == 4     # two plain passkeys + two ssh keys
k = keys[0]
out = os.path.join(tmp, "exported")
fido.save_ssh_key(k["key"], out)
assert keygen("-y", "-f", out) == k["key"]["line"]
assert keygen("-l", "-f", out + ".pub").split()[1] == k["fingerprint"]
assert k["key"]["flags"] == 0x21
print("ssh_list: only ssh: credentials, exported files readable by ssh-keygen")

made = dev.presses
exists = os.path.join(tmp, "taken")
open(exists, "w").write("x")
fails(lambda: fido.ssh_create(PIN, path=exists), "exists")
fails(lambda: fido.ssh_create(PIN, resident=False), "lost without its file")
assert dev.presses == made, "refused before anything was made on the key"
via = os.path.join(tmp, "via_path")
k = fido.ssh_create(PIN, "ed25519", "p", True, False, via, "c@h")
assert open(via + ".pub").read().strip() == fido.public_line(k, "c@h") and dev.presses == made + 1
print("ssh_create: a refused file stops it before the key is made; with a path it writes the files")
lone = os.path.join(tmp, "lone")
open(lone + ".pub", "w").write("other key\n")
fails(lambda: fido.save_ssh_key(keys[0]["key"], lone), "exists")
assert open(lone + ".pub").read() == "other key\n" and not os.path.exists(lone), "nothing written, nothing overwritten"
fails(lambda: fido.ssh_create(PIN, "rsa"), "ed25519 or ecdsa")
fails(lambda: fido.ssh_create("000000", "ed25519"), "wrong PIN")
dev.add("x.example", "rsa-user", -257)
dev.creds[-1]["public_key"] = {1: 3, 3: -257, -1: b"n", -2: b"e"}
fido.ssh_list(PIN)          # an RSA passkey in the list is skipped, not an error
print("QK FIDO TEST DONE")
