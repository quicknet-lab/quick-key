#!/usr/bin/env python3
"""qk — management tool for the Quick-Key security key.

Install: see the README (install.sh). Requires fido2, pyscard, esptool, textual.

The functions below the CLI layer return data and raise QkError, so that
the TUI (qk_tui.py) can use them too; cmd_* functions print.
"""
import argparse
import base64
import csv
import getpass
import hashlib
import hmac
import io
import json
import os
import re
import struct
import subprocess
import sys
import time
from typing import NoReturn

VID, PID = 0x1209, 0x0001
READER_NAME = "Quick-Key"

GITHUB_REPO = "quicknet-lab/quick-key"
# SHA-256 of the Secure Boot V2 public key (RSA-3072) that release keys burn
# on their first start. `qk flash` and `qk update` accept only release images
# signed with this key; tools/make_release.sh refuses to package with another.
SECURE_BOOT_DIGEST = "38343f3959e47692027b47ab61d8eabd437cc04f448b4e82d91fe58f40b0cd8d"

(ADMIN_VERSION, ADMIN_UUID, ADMIN_REBOOT, ADMIN_RNG, ADMIN_FACTORY_RESET, ADMIN_BOOTLOADER,
 ADMIN_OTA_BEGIN, ADMIN_OTA_WRITE, ADMIN_OTA_END) = range(0x41, 0x4A)
OTA_ERRORS = {1: "not confirmed on the key", 2: "protocol error", 3: "flash error",
              4: "image rejected: invalid signature or corrupt image",
              5: "image is older than the running firmware: downgrades are refused"}
OTA_CHUNK = 4096

AID_OATH = bytes.fromhex("A0000005272101")
AID_PGP = bytes.fromhex("D27600012401")
AID_PIV = bytes.fromhex("A000000308")
AID_ADMIN = bytes.fromhex("F0514B41444D")
AID_PWD = bytes.fromhex("F0514B505744")


class QkError(Exception):
    pass


def die(msg) -> NoReturn:
    raise QkError(msg)


# ---------------------------------------------------------------- FIDO (HID)

def hid_device():
    from fido2.hid import CtapHidDevice
    for d in CtapHidDevice.list_devices():
        if d.descriptor.vid == VID and d.descriptor.pid == PID:
            return d
    die("Quick-Key not found (FIDO HID)")


def admin(cmd, data=b""):
    return hid_device().call(0x80 | cmd, data)


def fido_ctap():
    from fido2.ctap2 import Ctap2
    return Ctap2(hid_device())


def fido_cm(ctap, pin):
    from fido2.ctap2 import CredentialManagement
    from fido2.ctap2.pin import ClientPin
    cp = ClientPin(ctap)
    token = cp.get_pin_token(pin, ClientPin.PERMISSION.CREDENTIAL_MGMT)
    return CredentialManagement(ctap, cp.protocol, token)


def ask_pin(args, prompt="PIN: "):
    return args.pin or getpass.getpass(prompt)


def cmd_fido_info(args):
    import qk_fido
    qk_fido.cmd_fido_info(args)


def fido_creds(pin):
    """(used, free, [{"rp", "name", "display", "id"}]) of resident credentials."""
    cm = fido_cm(fido_ctap(), pin)
    meta = cm.get_metadata()
    creds = []
    if meta[1]:
        for rp in cm.enumerate_rps():
            for cred in cm.enumerate_creds(rp[4]):
                user = cred[6]
                creds.append({"rp": rp[3]["id"], "name": user.get("name", "-"),
                              "display": user.get("displayName", ""), "id": cred[7]["id"]})
    return meta[1], meta[2], creds


def fido_delete(pin, cred_id):
    fido_cm(fido_ctap(), pin).delete_cred({"id": cred_id, "type": "public-key"})


def cmd_fido_list(args):
    import qk_fido
    qk_fido.cmd_fido_list(args)


def cmd_fido_delete(args):
    fido_delete(ask_pin(args), bytes.fromhex(args.cred_id))
    print("deleted")


def cmd_fido_reset(args):
    print("Re-plug the key and run this within 10 seconds, then press the button.")
    fido_ctap().reset()
    print("FIDO reset done: all passkeys erased")


# ---------------------------------------------------------------- CCID

class Card:
    def __init__(self):
        from smartcard.System import readers
        rs = [r for r in readers() if READER_NAME in str(r)]
        if not rs:
            die("Quick-Key not found (smart card reader). Is gpg's scdaemon holding it? Try: gpgconf --kill scdaemon")
        self.conn = rs[0].createConnection()
        self.conn.connect()

    def send(self, cla, ins, p1, p2, data=b"", check=True):
        if len(data) > 255:
            apdu = [cla, ins, p1, p2, 0, len(data) >> 8, len(data) & 0xFF] + list(data) + [0, 0]
        else:
            apdu = [cla, ins, p1, p2] + ([len(data)] + list(data) if data else []) + [0]
        resp, sw1, sw2 = self.conn.transmit(apdu)
        while sw1 == 0x61:
            more, sw1, sw2 = self.conn.transmit([0x00, 0xC0, 0, 0, sw2])
            resp += more
        sw = (sw1 << 8) | sw2
        if check and sw != 0x9000:
            raise RuntimeError(f"card error {sw:04X} (INS {ins:02X})")
        return bytes(resp), sw

    def select(self, aid):
        return self.send(0x00, 0xA4, 0x04, 0x00, aid, check=False)


def tlv_parse(b):
    out, i = [], 0
    while i < len(b):
        t = b[i]
        i += 1
        if t & 0x1F == 0x1F:
            t = (t << 8) | b[i]
            i += 1
        ln = b[i]
        i += 1
        if ln == 0x81:
            ln = b[i]
            i += 1
        elif ln == 0x82:
            ln = (b[i] << 8) | b[i + 1]
            i += 2
        out.append((t, b[i:i + ln]))
        i += ln
    return out


def tlv_get(b, tag):
    for t, v in tlv_parse(b):
        if t == tag:
            return v
    return None


def tlv(tag, value):
    ln = len(value)
    t = tag.to_bytes(2, "big") if tag > 0xFF else bytes([tag])
    if ln < 0x80:
        head = t + bytes([ln])
    elif ln < 0x100:
        head = t + bytes([0x81, ln])
    else:
        head = t + bytes([0x82, ln >> 8, ln & 0xFF])
    return head + value


# ---------------------------------------------------------------- OTP (OATH)

class Oath:
    def __init__(self, password=None):
        self.card = Card()
        resp, sw = self.card.select(AID_OATH)
        if sw != 0x9000:
            die("OTP application not available")
        self.salt = tlv_get(resp, 0x71)
        challenge = tlv_get(resp, 0x74)
        if challenge is not None:
            if password is None:
                password = getpass.getpass("OTP password: ")
            key = self.derive(password)
            mine = os.urandom(8)
            data = tlv(0x75, hmac.new(key, challenge, hashlib.sha1).digest()) + tlv(0x74, mine)
            resp, sw = self.card.send(0x00, 0xA3, 0, 0, data, check=False)
            if sw != 0x9000 or tlv_get(resp, 0x75) != hmac.new(key, mine, hashlib.sha1).digest():
                die("wrong OTP password")

    def derive(self, password):
        return hashlib.pbkdf2_hmac("sha1", password.encode(), self.salt, 1000, 16)

    def list(self):
        resp, _ = self.card.send(0x00, 0xA1, 0, 0)
        return [(v[0], v[1:].decode()) for t, v in tlv_parse(resp) if t == 0x72]

    def codes(self, compute_pending=True):
        """[(name, code)]. HOTP and touch accounts are computed one by one
        (touch needs the button), or left as None without compute_pending."""
        chal = struct.pack(">Q", int(time.time()) // 30)
        resp, _ = self.card.send(0x00, 0xA4, 0, 1, tlv(0x74, chal))
        items, name = [], None
        for t, v in tlv_parse(resp):
            if t == 0x71:
                name = v.decode()
            elif t == 0x76:
                items.append((name, self.fmt(v)))
            elif t in (0x77, 0x7C):
                items.append((name, self.calculate(name) if compute_pending else None))
        return items

    def calculate(self, name):
        chal = struct.pack(">Q", int(time.time()) // 30)
        resp, _ = self.card.send(0x00, 0xA2, 0, 1, tlv(0x71, name.encode()) + tlv(0x74, chal))
        return self.fmt(tlv_get(resp, 0x76))

    @staticmethod
    def fmt(v):
        digits = v[0]
        return str(int.from_bytes(v[1:], "big") % 10 ** digits).zfill(digits)

    def add(self, name, secret_b32, hotp=False, digits=6, algorithm="SHA1", touch=False, counter=0):
        try:
            secret = base64.b32decode(secret_b32.upper().replace(" ", "") + "=" * (-len(secret_b32.replace(" ", "")) % 8))
        except ValueError:
            die("secret is not valid base32")
        alg = {"SHA1": 1, "SHA256": 2, "SHA512": 3}[algorithm]
        data = tlv(0x71, name.encode()) + tlv(0x73, bytes([(0x10 if hotp else 0x20) | alg, digits]) + secret.ljust(14, b"\0"))
        if touch:
            data += bytes([0x78, 0x02])
        if hotp:
            data += tlv(0x7A, struct.pack(">I", counter))
        _, sw = self.card.send(0x00, 0x01, 0, 0, data, check=False)
        if sw == 0x6A84:
            die("storage full (50 accounts)")
        if sw != 0x9000:
            raise RuntimeError(f"card error {sw:04X} (INS 01)")

    def delete(self, name):
        self.card.send(0x00, 0x02, 0, 0, tlv(0x71, name.encode()))

    def set_password(self, new):
        """Sets the access password, or clears it when new is empty."""
        if not new:
            self.card.send(0x00, 0x03, 0, 0, tlv(0x73, b""))
            return
        key = self.derive(new)
        chal = os.urandom(8)
        data = tlv(0x73, b"\x01" + key) + tlv(0x74, chal) + tlv(0x75, hmac.new(key, chal, hashlib.sha1).digest())
        self.card.send(0x00, 0x03, 0, 0, data)

    def hmac_slots(self):
        """Configured HMAC-SHA1 challenge-response slots, of (1, 2)."""
        out = []
        for slot, cmd in ((1, 0x30), (2, 0x38)):
            _, sw = self.card.send(0x00, 0x01, cmd, 0, bytes(64), check=False)
            if sw == 0x9000:
                out.append(slot)
        return out

    def hmac_set(self, slot, secret):
        """Writes a challenge-response secret, or deletes the slot when it is
        empty; needs the button."""
        _, sw = self.card.send(0x00, 0xB1, slot, 0, secret, check=False)
        if sw == 0x6982:
            die("not confirmed")
        if sw != 0x9000:
            raise RuntimeError(f"card error {sw:04X} (INS B1)")


def cmd_otp_list(args):
    for type_alg, name in Oath(args.password).list():
        kind = "HOTP" if type_alg & 0xF0 == 0x10 else "TOTP"
        print(f"{kind}  {name}")


def cmd_otp_code(args):
    oath = Oath(args.password)
    items = [(args.name, oath.calculate(args.name))] if args.name else oath.codes()
    for name, code in items:
        print(f"{name:40} {code}")


def cmd_otp_add(args):
    secret = args.secret or getpass.getpass("Secret (base32): ")
    Oath(args.password).add(args.name, secret, args.hotp, args.digits, args.algorithm, args.touch, args.counter)
    print(f"added {args.name}")


def cmd_otp_delete(args):
    Oath(args.password).delete(args.name)
    print(f"deleted {args.name}")


def cmd_hmac_status(args):
    slots = Oath(args.password).hmac_slots()
    for slot in (1, 2):
        print(f"slot {slot}: {'set' if slot in slots else 'empty'}")


def cmd_hmac_set(args):
    if args.secret:
        try:
            secret = bytes.fromhex(args.secret)
        except ValueError:
            die("secret is not valid hex")
        if not 1 <= len(secret) <= 64:
            die("secret must be 1-64 bytes")
    else:
        secret = os.urandom(20)
    oath = Oath(args.password)
    print(f"Press the button on the key to confirm: slot {args.slot} will be overwritten...")
    oath.hmac_set(args.slot, secret)
    print(f"slot {args.slot} set")
    if not args.secret:
        print(f"secret: {secret.hex()}  (keep it to program a backup key)")


def cmd_hmac_delete(args):
    oath = Oath(args.password)
    print(f"Press the button on the key to confirm: slot {args.slot} will be deleted...")
    oath.hmac_set(args.slot, b"")
    print(f"slot {args.slot} deleted")


def cmd_otp_set_password(args):
    oath = Oath(args.password)
    new = args.new_password if args.new_password is not None else getpass.getpass("New OTP password (empty to clear): ")
    oath.set_password(new)
    print("password set" if new else "password cleared")


def oath_reset():
    """Erases all OTP accounts, HMAC slots and the access password; needs the button.
    Works without the access password, so it helps when that is forgotten."""
    card = Card()
    if card.select(AID_OATH)[1] != 0x9000:
        die("OTP application not available")
    _, sw = card.send(0x00, 0x04, 0xDE, 0xAD, check=False)
    if sw != 0x9000:
        die("not confirmed on the key")


def cmd_otp_reset(args):
    print("Press the button on the key to confirm: ALL OTP accounts and HMAC secrets will be erased...")
    oath_reset()
    print("OTP reset: no accounts, no access password")


# ---------------------------------------------------------------- passwords

PWD_FIELDS = ("name", "url", "login", "password", "note", "otp")   # TLV tags 0x01..0x06
PWD_FLAGS, PWD_ID, PWD_STATUS, PWD_ENTRY = 0x07, 0x08, 0x09, 0x20
PWD_TOUCH = 0x01


class Pwd:
    def __init__(self):
        self.card = Card()
        resp, sw = self.card.select(AID_PWD)
        if sw != 0x9000:
            die("password manager not available (firmware too old?)")
        st = tlv_get(resp, PWD_STATUS)
        self.tries, self.count, self.max = st[2], st[3], st[4]

    def unlock(self, pin=None):
        if self.tries == 0:
            die(PIN_BLOCKED)
        pin = pin or getpass.getpass("PIN: ")
        _, sw = self.card.send(0x00, 0x20, 0, 0, pin.encode(), check=False)
        pin_error(sw)
        return self

    @staticmethod
    def parse(data):
        rec = {"flags": 0}
        for t, v in tlv_parse(data):
            if 1 <= t <= len(PWD_FIELDS):
                rec[PWD_FIELDS[t - 1]] = v.decode(errors="replace")
            elif t == PWD_FLAGS:
                rec["flags"] = v[0]
            elif t == PWD_ID:
                rec["id"] = v[0]
        return rec

    @staticmethod
    def encode(fields):
        data = b""
        for i, name in enumerate(PWD_FIELDS):
            if fields.get(name) is not None:
                data += tlv(i + 1, fields[name].encode())
        if fields.get("flags") is not None:
            data += tlv(PWD_FLAGS, bytes([fields["flags"]]))
        return data

    def list(self):
        out, start = [], 0
        while start < self.max:
            resp, _ = self.card.send(0x00, 0xA1, start, 0)
            page = [self.parse(v) for t, v in tlv_parse(resp) if t == PWD_ENTRY]
            if not page:
                break
            out += page
            start = page[-1]["id"] + 1
        return out

    def find(self, ref):
        """Record id from an id or a name (exact, then case-insensitive)."""
        if ref.isdigit():
            return int(ref)
        recs = self.list()
        for match in (lambda r: r["name"] == ref, lambda r: r["name"].lower() == ref.lower()):
            hits = [r for r in recs if match(r)]
            if len(hits) == 1:
                return hits[0]["id"]
            if hits:
                die(f"several records named '{ref}', use the id: {', '.join(str(r['id']) for r in hits)}")
        die(f"no record '{ref}'")

    def get(self, rid, with_password=False):
        resp, sw = self.card.send(0x00, 0xA2, 1 if with_password else 0, 0, tlv(PWD_ID, bytes([rid])), check=False)
        if sw == 0x6A88:
            die(f"no record {rid}")
        if sw == 0x6982:
            die("not confirmed on the key")
        if sw != 0x9000:
            die(f"card error {sw:04X}")
        return self.parse(resp)

    def put(self, fields, rid=None):
        data = (tlv(PWD_ID, bytes([rid])) if rid is not None else b"") + self.encode(fields)
        resp, sw = self.card.send(0x00, 0xA3, 0, 0, data, check=False)
        if sw == 0x6A84:
            die(f"storage full ({self.max} records)")
        if sw == 0x6985:
            die(DEFAULT_PINS)
        if sw == 0x6A80:
            die("invalid record: name is required; limits name 64, url 128, login 64, password 128, "
                "note 256, otp 64 bytes")
        if sw != 0x9000:
            die(f"card error {sw:04X}")
        return tlv_get(resp, PWD_ID)[0]

    def delete(self, rid):
        _, sw = self.card.send(0x00, 0xA4, 0, 0, tlv(PWD_ID, bytes([rid])), check=False)
        if sw != 0x9000:
            die(f"no record {rid}")

    def reset(self):
        """Erases all records; needs the button."""
        _, sw = self.card.send(0x00, 0x04, 0xDE, 0xAD, check=False)
        if sw != 0x9000:
            die("not confirmed")

    def generate(self, length, chars):
        sets = sum(1 << i for i, c in enumerate("luds") if c in chars)
        resp, sw = self.card.send(0x00, 0xA5, length, sets, check=False)
        if sw != 0x9000:
            die("bad generator options: length 4-128, --chars from 'luds'")
        return resp.decode()

    def export_records(self, on_touch=None):
        """All records with passwords; on_touch(name) before each one that needs the button."""
        out = []
        for r in self.list():
            if r["flags"] & PWD_TOUCH and on_touch:
                on_touch(r["name"])
            rec = self.get(r["id"], with_password=True)
            del rec["id"]
            out.append(rec)
        return out

    def import_records(self, records):
        """Adds records, skipping those already on the key (same name, login and URL).
        Returns (added, duplicates, [(name, note)]). Checks free space before writing."""
        on_key = self.list()
        seen = {(r["name"], r.get("login", ""), r.get("url", "")) for r in on_key}
        new, dupes, notes = [], 0, []
        for orig in records:
            rec, note = pwd_fit(orig)
            if note:
                notes.append((orig.get("name") or "(no name)", note))
            if not rec:
                continue
            key = (rec["name"], rec.get("login", ""), rec.get("url", ""))
            if key in seen:
                dupes += 1
                continue
            seen.add(key)
            new.append(rec)
        free = self.max - len(on_key)
        if len(new) > free:
            die(f"not enough space: {len(new)} new records, {free} of {self.max} free")
        for rec in new:
            self.put(rec)
        return len(new), dupes, notes


# Field limits on the key, in UTF-8 bytes.
PWD_LIMITS = {"name": 64, "url": 128, "login": 64, "password": 128, "note": 256, "otp": 64}


def pwd_fit(rec):
    """(record, note): name, URL and note are cut to the key's limits; the record is
    None (skipped) when it has no name or its login, password or OTP link does not fit."""
    out, cut = {"flags": rec.get("flags", 0)}, []
    for f in PWD_FIELDS:
        v = rec.get(f) or ""
        b = v.encode()
        if len(b) > PWD_LIMITS[f]:
            if f in ("login", "password", "otp"):
                return None, f"skipped: {f} longer than {PWD_LIMITS[f]} bytes"
            v = b[:PWD_LIMITS[f]].decode(errors="ignore")
            cut.append(f)
        if v:
            out[f] = v
    if not out.get("name"):
        return None, "skipped: no name"
    return out, f"{', '.join(cut)} shortened" if cut else None


COMMON_PASSWORDS = {"password", "123456", "12345678", "123456789", "qwerty", "qwerty123", "letmein", "admin",
                    "welcome", "iloveyou", "monkey", "dragon", "111111", "abc123", "password1", "changeme"}


def pwd_audit(records):
    """Weak and reused passwords among records that carry passwords:
    {"weak": [(name, why)], "reused": [[names sharing one password]], "empty": [names]}."""
    weak, empty, seen = [], [], {}
    for r in records:
        pw, name = r.get("password") or "", r.get("name") or "(no name)"
        if not pw:
            empty.append(name)
            continue
        seen.setdefault(pw, []).append(name)
        classes = sum(any(f(c) for c in pw) for f in (str.islower, str.isupper, str.isdigit,
                                                      lambda c: not c.isalnum()))
        if pw.lower() in COMMON_PASSWORDS:
            weak.append((name, "a very common password"))
        elif len(set(pw)) == 1:
            weak.append((name, "one character repeated"))
        elif len(pw) < 8:
            weak.append((name, "shorter than 8 characters"))
        elif len(pw) < 12 and classes < 3:
            weak.append((name, "short and of few character types"))
        elif len(pw) < 16 and classes < 2:
            weak.append((name, "one character type only"))
    return {"weak": weak, "reused": [names for names in seen.values() if len(names) > 1], "empty": empty}


def pwd_audit_records(p, on_skip=None):
    """(records with passwords, number skipped): passwords that need the button are not read."""
    out, skipped = [], 0
    for r in p.list():
        if r["flags"] & PWD_TOUCH:
            skipped += 1
            if on_skip:
                on_skip(r["name"])
            continue
        out.append(p.get(r["id"], with_password=True))
    return out, skipped


def cmd_pwd_audit(args):
    recs, skipped = pwd_audit_records(Pwd().unlock(args.pin))
    res = pwd_audit(recs)
    for name, why in res["weak"]:
        print(f"weak    {name}: {why}")
    for names in res["reused"]:
        print(f"reused  {', '.join(names)}")
    for name in res["empty"]:
        print(f"empty   {name}")
    print(f"checked {len(recs)} passwords: {len(res['weak'])} weak, {len(res['reused'])} reused" +
          (f"; {skipped} protected by the button were not read" if skipped else ""))


# Backup file: JSON whose records are encrypted with AES-256-GCM under a key
# derived from the backup password by scrypt.
PWD_BACKUP = "quick-key-passwords"
SCRYPT = {"n": 2 ** 17, "r": 8, "p": 1}


def backup_key(password, salt, n, r, p):
    return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, maxmem=256 * 1024 * 1024, dklen=32)


def pwd_backup_encrypt(records, password):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = os.urandom(16), os.urandom(12)
    plain = json.dumps([{k: v for k, v in r.items() if k in PWD_FIELDS or k == "flags"} for r in records])
    data = AESGCM(backup_key(password, salt, **SCRYPT)).encrypt(nonce, plain.encode(), PWD_BACKUP.encode())
    b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731
    return json.dumps({"format": PWD_BACKUP, "version": 1, "kdf": {"name": "scrypt", **SCRYPT, "salt": b64(salt)},
                       "nonce": b64(nonce), "data": b64(data)}, indent=1)


def pwd_backup_decrypt(text, password):
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        f = json.loads(text)
        if f.get("format") != PWD_BACKUP or f.get("version") != 1:
            die("not a Quick-Key password backup")
        kdf = f["kdf"]
        # Bounded: the file is not trusted, and a huge p or n would hang here
        # for hours inside a C call (Ctrl-C doesn't work).
        if not (isinstance(kdf["n"], int) and 2 <= kdf["n"] <= 1 << 20 and kdf["r"] == 8
                and isinstance(kdf["p"], int) and 1 <= kdf["p"] <= 4):
            die("unsupported backup parameters")
        key = backup_key(password, base64.b64decode(kdf["salt"]), kdf["n"], kdf["r"], kdf["p"])
        plain = AESGCM(key).decrypt(base64.b64decode(f["nonce"]), base64.b64decode(f["data"]), PWD_BACKUP.encode())
    except InvalidTag:
        die("wrong backup password or damaged file")
    except (ValueError, KeyError, TypeError, AttributeError):
        die("damaged backup file")
    records = json.loads(plain)
    if not isinstance(records, list) or not all(
            isinstance(r, dict) and all(isinstance(v, str) for k, v in r.items() if k != "flags") for r in records):
        die("damaged backup file")
    return records


# CSV exports of other password managers (Bitwarden, KeePassXC, Chrome,
# Firefox, Safari, 1Password): our field <- accepted column names.
CSV_COLUMNS = {"name": ("name", "title"), "url": ("url", "login_uri", "uri", "website"),
               "login": ("username", "login_username", "login"), "password": ("password", "login_password"),
               "note": ("notes", "note")}
CSV_TOTP = ("totp", "login_totp", "otpauth")


def pwd_csv_records(text):
    """(records, notes) from a CSV export. A record without a name is named after
    the URL's host. TOTP secrets are not imported (they belong in `qk otp`)."""
    from urllib.parse import urlparse
    rows = csv.DictReader(io.StringIO(text))
    cols = {c.strip().lower(): c for c in rows.fieldnames or []}
    pick = {f: next((cols[n] for n in names if n in cols), None) for f, names in CSV_COLUMNS.items()}
    totp = next((cols[n] for n in CSV_TOTP if n in cols), None)
    if not pick["password"]:
        die("not a password CSV: no password column")
    recs, notes = [], []
    for row in rows:
        rec = {f: (row.get(c) or "") if f == "password" else (row.get(c) or "").strip()
               for f, c in pick.items() if c}
        if not rec.get("name"):
            rec["name"] = urlparse(rec.get("url", "")).hostname or rec.get("login", "")
        if not any(rec.values()):
            continue
        if totp and row.get(totp):
            notes.append((rec["name"] or "(no name)", "TOTP secret not imported, add it with `qk otp add`"))
        recs.append(rec)
    return recs, notes


def pwd_load(path, password):
    """(records, notes) from a Quick-Key backup or a CSV export. password is the
    backup password or a function returning it; asked only for a backup."""
    try:
        with open(os.path.expanduser(path), encoding="utf-8-sig") as f:
            text = f.read()
    except OSError as e:
        die(f"cannot read {path}: {e.strerror}")
    except UnicodeDecodeError:
        die(f"{path} is not a text file")
    if text.lstrip().startswith("{"):
        password = password() if callable(password) else password
        if not password:
            die("backup password needed")
        return pwd_backup_decrypt(text, password), []
    try:
        return pwd_csv_records(text)
    except csv.Error as e:
        die(f"cannot read {path} as CSV: {e}")


def pwd_save_backup(path, records, password):
    """Writes the encrypted backup, readable only by the owner. Written to a
    new file that replaces the target at the end: a failed write keeps the old
    backup, and a symlink at the path is replaced instead of followed."""
    import tempfile
    data = pwd_backup_encrypt(records, password)
    path = os.path.expanduser(path)
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(path)), prefix=".qk-backup-")
        with os.fdopen(fd, "w") as f:     # mkstemp creates it with mode 0600
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except OSError as e:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)
        die(f"cannot write {path}: {e.strerror}")


def pwd_new_password(args):
    if args.generate:
        return Pwd().generate(args.generate, args.chars)
    if args.password is not None:
        return args.password
    pw = getpass.getpass("Password to store: ")
    if pw != getpass.getpass("Repeat: "):
        die("passwords do not match")
    return pw


def cmd_pwd_status(args):
    p = Pwd()
    print(f"PIN tries: {p.tries}")
    print(f"records:   {p.count} of {p.max}")


def cmd_pwd_list(args):
    recs = Pwd().unlock(args.pin).list()
    if not recs:
        print("no passwords")
    for r in recs:
        touch = " [touch]" if r["flags"] & PWD_TOUCH else ""
        print(f"{r['id']:3}  {r['name']:24} {r.get('login', ''):24} {r.get('url', '')}{touch}")


def cmd_pwd_get(args):
    p = Pwd().unlock(args.pin)
    rid = p.find(args.ref)
    rec = p.get(rid)
    if args.show and rec["flags"] & PWD_TOUCH:
        print("Press the button on the key to show the password...", file=sys.stderr)
    if args.show:
        rec = p.get(rid, with_password=True)
    for name in PWD_FIELDS:
        if name == "password":
            print(f"{name:9} {rec.get(name, '') if args.show else '******  (--show to reveal)'}")
        elif name in rec:
            print(f"{name:9} {rec[name]}")
    print(f"{'touch':9} {'yes' if rec['flags'] & PWD_TOUCH else 'no'}")


def cmd_pwd_add(args):
    password = pwd_new_password(args)
    p = Pwd().unlock(args.pin)
    fields = {"name": args.name, "url": args.url, "login": args.login, "password": password,
              "note": args.note, "otp": args.otp, "flags": PWD_TOUCH if args.touch else 0}
    rid = p.put(fields)
    print(f"added {args.name} (id {rid})" + (f", password: {password}" if args.generate else ""))


def cmd_pwd_edit(args):
    password = pwd_new_password(args) if (args.change_password or args.generate or args.password is not None) else None
    p = Pwd().unlock(args.pin)
    rid = p.find(args.ref)
    fields = {"name": args.name, "url": args.url, "login": args.login, "password": password,
              "note": args.note, "otp": args.otp}
    if args.touch is not None:
        fields["flags"] = PWD_TOUCH if args.touch else 0
    if all(v is None for v in fields.values()):
        die("nothing to change")
    p.put(fields, rid)
    print(f"updated id {rid}" + (f", password: {password}" if args.generate else ""))


def cmd_pwd_delete(args):
    p = Pwd().unlock(args.pin)
    rid = p.find(args.ref)
    p.delete(rid)
    print(f"deleted id {rid}")


def cmd_pwd_gen(args):
    print(Pwd().generate(args.length, args.chars))


def cmd_pwd_export(args):
    password = args.backup_password
    if password is None:
        password = getpass.getpass("Backup password: ")
        if password != getpass.getpass("Repeat: "):
            die("passwords do not match")
    if not password:
        die("backup password must not be empty")
    p = Pwd().unlock(args.pin)
    recs = p.export_records(lambda name: print(f"Press the button on the key for '{name}'...", file=sys.stderr))
    pwd_save_backup(args.file, recs, password)
    print(f"exported {len(recs)} records to {args.file}")


def cmd_pwd_import(args):
    recs, notes = pwd_load(args.file, args.backup_password or (lambda: getpass.getpass("Backup password: ")))
    added, dupes, more = Pwd().unlock(args.pin).import_records(recs)
    for name, note in notes + more:
        print(f"  {name}: {note}")
    print(f"imported {added} records" + (f", {dupes} already on the key" if dupes else ""))


def cmd_pwd_reset(args):
    p = Pwd()
    print("Press the button on the key to confirm: ALL passwords will be erased...")
    p.reset()
    print("password manager reset: no records")


# ---------------------------------------------------------------- device PIN
# One PIN (6-8 characters) for FIDO, OpenPGP PW1, PIV PIN and the password
# manager; the admin PIN (8 characters, OpenPGP PW3, PIV PUK) unblocks it.
# Managed through PIV commands, which take both padded to 8 bytes.

PIN_BLOCKED = "PIN blocked: unblock it with `qk pin unblock` (admin PIN)"


SECRET_ARG = "prompted if omitted; a value given here stays in the shell history and shows in the process list"
DEFAULT_PINS = ("the key still has a factory PIN: change both first "
                "(`qk pin change`, `qk pin change-admin`)")


def pin_error(sw, admin=False):
    if sw == 0x9000:
        return
    name = "admin PIN" if admin else "PIN"
    if sw & 0xFFF0 == 0x63C0:
        die(f"wrong {name}, {sw & 0x0F} tries left")
    if sw == 0x6983:
        die("admin PIN blocked: only `qk factory-reset` helps" if admin else PIN_BLOCKED)
    die(f"{name} rejected ({sw:04X})")


def pin_bytes(pin, admin=False):
    b = pin.encode()
    lo = 8 if admin else 6
    if not lo <= len(b) <= 8:
        die("admin PIN must be 8 characters" if admin else "PIN must be 6-8 characters")
    return b + b"\xFF" * (8 - len(b))


def piv_card():
    card = Card()
    if card.select(AID_PIV)[1] != 0x9000:
        die("PIV application not available")
    return card


def pin_tries():
    """(PIN tries, admin PIN tries), read from the OpenPGP PW status."""
    card = Card()
    card.select(AID_PGP)
    app, _ = card.send(0x00, 0xCA, 0x00, 0x6E)
    pw = tlv_get(tlv_get(app, 0x73), 0xC4)
    return pw[4], pw[6]


def pin_change(old, new):
    _, sw = piv_card().send(0x00, 0x24, 0x00, 0x80, pin_bytes(old) + pin_bytes(new), check=False)
    pin_error(sw)


def pin_change_admin(old, new):
    _, sw = piv_card().send(0x00, 0x24, 0x00, 0x81, pin_bytes(old, True) + pin_bytes(new, True), check=False)
    pin_error(sw, True)


def pin_unblock(admin_pin, new):
    _, sw = piv_card().send(0x00, 0x2C, 0x00, 0x80, pin_bytes(admin_pin, True) + pin_bytes(new), check=False)
    pin_error(sw, True)


def ask_new_pin(args, admin=False):
    new = args.new_pin
    if new is None:
        new = getpass.getpass("New admin PIN (8 characters): " if admin else "New PIN (6-8 characters): ")
        if new != getpass.getpass("Repeat: "):
            die("PINs do not match")
    pin_bytes(new, admin)           # check the length before asking anything else
    return new


def cmd_pin_status(args):
    user, adm = pin_tries()
    print(f"PIN tries:       {user}")
    print(f"admin PIN tries: {adm}")


def cmd_pin_change(args):
    old = args.pin or getpass.getpass("Current PIN: ")
    pin_bytes(old)
    pin_change(old, ask_new_pin(args))
    print("PIN changed")


def cmd_pin_change_admin(args):
    old = args.admin_pin or getpass.getpass("Current admin PIN: ")
    pin_bytes(old, True)
    pin_change_admin(old, ask_new_pin(args, True))
    print("admin PIN changed")


def cmd_pin_unblock(args):
    adm = args.admin_pin or getpass.getpass("Admin PIN: ")
    pin_bytes(adm, True)
    pin_unblock(adm, ask_new_pin(args))
    print("PIN set, tries restored")


# ---------------------------------------------------------------- OpenPGP / PIV


PGP_KEYS = ("signature", "decryption", "authentication")
PIV_SLOTS = ((0x9A, "authentication", 0x5FC105), (0x9C, "signature", 0x5FC10A),
             (0x9D, "key management", 0x5FC10B), (0x9E, "card authentication", 0x5FC101))


def pgp_algo(attr):
    if attr[0] == 0x01:
        return "rsa2048"
    if attr[0] == 0x16:
        return "ed25519"
    if attr[0] == 0x12 and attr[1:3] == b"\x2B\x06":
        return "cv25519"
    return "nistp256"


PGP_TOUCH = {0: "off", 1: "on", 2: "fixed"}


def pgp_status():
    """{"serial", "pin_tries", "admin_tries", "keys": [(name, algorithm, fingerprint hex or None)],
    "touch": [off/on/fixed per key]}"""
    card = Card()
    if card.select(AID_PGP)[1] not in (0x9000, 0x6285):
        die("OpenPGP application not available")
    app, _ = card.send(0x00, 0xCA, 0x00, 0x6E)
    disc = tlv_get(app, 0x73)
    pw = tlv_get(disc, 0xC4)
    fps = tlv_get(disc, 0xC5)
    keys = []
    for i, name in enumerate(PGP_KEYS):
        fp = fps[20 * i:20 * i + 20]
        keys.append((name, pgp_algo(tlv_get(disc, 0xC1 + i)), fp.hex().upper() if any(fp) else None))
    touch = [PGP_TOUCH.get((tlv_get(disc, 0xD6 + i) or b"\0")[0], "?") for i in range(3)]
    return {"serial": tlv_get(app, 0x4F)[10:14].hex().upper(), "pin_tries": pw[4], "admin_tries": pw[6],
            "keys": keys, "touch": touch}


def pgp_reset(admin_pin):
    card = Card()
    card.select(AID_PGP)
    _, sw = card.send(0x00, 0x20, 0x00, 0x83, admin_pin.encode(), check=False)
    pin_error(sw, True)
    card.send(0x00, 0xE6, 0x00, 0x00)
    card.send(0x00, 0x44, 0x00, 0x00)


def pgp_set_touch(admin_pin, key, mode):
    """Sets the user interaction flag of a key (index into PGP_KEYS) to
    "off", "on" or "fixed"."""
    card = Card()
    card.select(AID_PGP)
    _, sw = card.send(0x00, 0x20, 0x00, 0x83, admin_pin.encode(), check=False)
    pin_error(sw, True)
    value = {v: k for k, v in PGP_TOUCH.items()}[mode]
    _, sw = card.send(0x00, 0xDA, 0x00, 0xD6 + key, bytes([value, 0x20]), check=False)
    if sw == 0x6982:
        die("touch is fixed for this key: only `qk pgp reset` clears it")
    if sw != 0x9000:
        raise RuntimeError(f"card error {sw:04X} (PUT DATA)")


def piv_status():
    """[(slot, name, has certificate)]"""
    card = piv_card()
    out = []
    for slot, name, tag in PIV_SLOTS:
        _, sw = card.send(0x00, 0xCB, 0x3F, 0xFF, bytes([0x5C, 3]) + tag.to_bytes(3, "big"), check=False)
        out.append((slot, name, sw == 0x9000))
    return out


def piv_reset():
    """Erases PIV keys and certificates; needs the button."""
    _, sw = piv_card().send(0x00, 0xFB, 0x00, 0x00, check=False)
    if sw != 0x9000:
        die("not confirmed")


def cmd_pgp_status(args):
    import qk_pgp
    qk_pgp.cmd_status(args)


def cmd_pgp_reset(args):
    pgp_reset(args.admin_pin or getpass.getpass("Admin PIN: "))
    print("OpenPGP reset: keys and card data erased, PINs unchanged")


def cmd_pgp_touch(args):
    pgp_set_touch(args.admin_pin or getpass.getpass("Admin PIN: "), PGP_KEYS.index(args.key), args.mode)
    print(f"{args.key} key: touch {args.mode}")


def cmd_piv_status(args):
    import qk_piv
    qk_piv.cmd_status(args)


def cmd_piv_reset(args):
    print("Press the button on the key to confirm: PIV keys and certificates will be erased...")
    piv_reset()
    print("PIV reset: keys and certificates erased, default management key, PINs unchanged")


# ---------------------------------------------------------------- admin

def device_info():
    """(firmware version "x.y.z", UUID hex)"""
    v = admin(ADMIN_VERSION)
    return f"{v[0]}.{v[1]}.{v[2]}", admin(ADMIN_UUID).hex().upper()


def factory_reset():
    """Erases everything and reboots; needs the button."""
    if admin(ADMIN_FACTORY_RESET) != b"\x00":
        die("not confirmed")


def cmd_info(args):
    version, uuid = device_info()
    print(f"firmware: {version}")
    print(f"uuid:     {uuid}")


def cmd_reboot(args):
    admin(ADMIN_REBOOT)
    print("rebooting")


def cmd_factory_reset(args):
    print("Press the button on the key to confirm FACTORY RESET...")
    factory_reset()
    print("all data erased, rebooting")


def wait_for(predicate, timeout=15):
    t = time.time()
    while time.time() - t < timeout:
        r = predicate()
        if r:
            return r
        time.sleep(0.5)
    return None


ROM_APP_OFFSET, ROM_APP_MAX = 0x20000, 0x300000    # ota_0 in partitions.csv
ROM_OTADATA = ("0x19000", "0x2000")


def espressif_ports():
    from serial.tools import list_ports
    return {p.device for p in list_ports.comports() if p.vid == 0x303A}


def rom_port(port=None, ask_running=True):
    """Serial port of the key in the ROM download mode."""
    if port:
        return port
    before = espressif_ports()
    try:
        hid_device()
        running = ask_running
    except QkError:
        running = False
    if running:
        # Take the port that appears for this key, not another ESP32 board.
        print("Press the button on the key to confirm firmware update mode...")
        if admin(ADMIN_BOOTLOADER) != b"\x00":
            die("not confirmed")
        port = wait_for(lambda: next(iter(espressif_ports() - before), None))
        if not port:
            die("key did not enter update mode")
        return port
    if len(before) == 1:
        return before.pop()
    if not before:
        die("key not found: hold BOOT while plugging it in")
    die(f"several Espressif devices ({', '.join(sorted(before))}): choose one with --port")


def esptool_cmd(port, *args, after="no_reset", capture=False):
    """Runs esptool; its progress goes to the terminal unless captured."""
    return subprocess.run([sys.executable, "-m", "esptool", "--chip", "esp32s3", "-p", port, "-b", "460800",
                           "--after", after, *args], check=True, capture_output=capture, text=True).stdout


def chip_security(port):
    """(secure boot on, flash encryption on) of a chip in the ROM download mode."""
    try:
        out = esptool_cmd(port, "get_security_info", capture=True)
    except subprocess.CalledProcessError as e:
        # Secure Download mode answers only a few commands; that alone means
        # the chip is locked down.
        if "secure download mode" in (e.stdout + e.stderr).lower():
            return True, True
        die(f"cannot read the chip's security state:\n{e.stdout}{e.stderr}")
    low = out.lower()
    if "secure boot: enabled" not in low and "secure boot: disabled" not in low:
        die(f"unexpected esptool output (esptool 4.7 or newer needed):\n{out}")
    return "secure boot: enabled" in low, "flash encryption: enabled" in low


def update_rom(path, port=None):
    """Recovery path through the ROM download mode (no signature check), for
    development keys without Secure Boot."""
    with open(path, "rb") as f:
        image = f.read()
    # An app image starts with the ESP image magic; anything bigger than the
    # app slot would overwrite ota_1 and the key's data partitions.
    if image[:1] != b"\xE9" or len(image) > ROM_APP_MAX:
        die(f"{path} is not a Quick-Key app image (expected build/quick-key.bin, at most {ROM_APP_MAX} bytes)")
    port = rom_port(port)
    if any(chip_security(port)):
        die("this key has Secure Boot / flash encryption: it updates only with `qk update`")
    # Erase otadata so that the bootloader starts ota_0 even if ota_1 was active.
    esptool_cmd(port, "erase_region", *ROM_OTADATA)
    esptool_cmd(port, "write_flash", hex(ROM_APP_OFFSET), path, after="watchdog_reset")


# ---------------------------------------------------------------- releases

def say(msg):
    """print() that shows up before the output of a following subprocess."""
    print(msg, flush=True)


def sbv2_check(image, name):
    """Checks a Secure Boot V2 (RSA-3072) signature block made with the
    release key, as the chip does: image digest, key digest, RSA-PSS."""
    import zlib
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
    if len(image) < 4096 or len(image) % 4096:
        die(f"{name}: not a signed image")
    blk = image[-4096:-4096 + 1216]
    if blk[0] != 0xE7 or blk[1] != 0x02 or struct.unpack("<I", blk[1196:1200])[0] != zlib.crc32(blk[:1196]):
        die(f"{name}: no valid signature block")
    digest = hashlib.sha256(image[:-4096]).digest()
    if blk[4:36] != digest:
        die(f"{name}: image does not match its signature block")
    if hashlib.sha256(blk[36:812]).hexdigest() != SECURE_BOOT_DIGEST:
        die(f"{name}: signed with another key, not the Quick-Key release key")
    n = int.from_bytes(blk[36:420], "little")
    e = struct.unpack("<I", blk[420:424])[0]
    try:
        rsa.RSAPublicNumbers(e, n).public_key().verify(
            blk[812:1196][::-1], digest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
            utils.Prehashed(hashes.SHA256()))
    except InvalidSignature:
        die(f"{name}: invalid signature")


def _http_get(url, accept=None):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "qk", **({"Accept": accept} if accept else {})})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.read()
    except OSError as e:
        die(f"download failed: {url}: {e}")


def fetch_release(source=None, log=say):
    """Directory with a verified release: `source` is a local release
    directory, or None for the latest GitHub Release. Every file is checked
    against SHA256SUMS, the manifest's key against SECURE_BOOT_DIGEST, and
    the bootloader and the app against the release key."""
    if source and os.path.isdir(source):
        path = source
    else:
        info = json.loads(_http_get(f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest",
                                    "application/vnd.github+json"))
        tag = info["tag_name"]
        assets = {a["name"]: a["browser_download_url"] for a in info.get("assets", [])}
        if "manifest.json" not in assets or "SHA256SUMS" not in assets:
            die(f"release {tag} has no manifest.json / SHA256SUMS")
        path = os.path.join(os.path.expanduser("~/.cache/quick-key"), tag)
        os.makedirs(path, exist_ok=True)
        log(f"downloading release {tag}...")
        for name in ("SHA256SUMS", "manifest.json"):
            with open(os.path.join(path, name), "wb") as f:
                f.write(_http_get(assets[name]))
        manifest = json.load(open(os.path.join(path, "manifest.json")))
        for part in manifest["flash"]:
            name = os.path.basename(part["file"])
            if name not in assets:
                die(f"release {tag} has no {name}")
            with open(os.path.join(path, name), "wb") as f:
                f.write(_http_get(assets[name]))
    sums = {}
    for line in open(os.path.join(path, "SHA256SUMS")):
        digest, name = line.split()
        sums[name.lstrip("*")] = digest
    manifest = json.load(open(os.path.join(path, "manifest.json")))
    files = ["manifest.json"] + [p["file"] for p in manifest["flash"]]
    for name in files:
        data = open(os.path.join(path, name), "rb").read()
        if name not in sums or hashlib.sha256(data).hexdigest() != sums[name]:
            die(f"{name}: checksum does not match SHA256SUMS")
    for part in manifest["flash"]:
        if hashlib.sha256(open(os.path.join(path, part["file"]), "rb").read()).hexdigest() != part["sha256"]:
            die(f"{part['file']}: checksum does not match manifest.json")
    if manifest.get("secure_boot_digest") != SECURE_BOOT_DIGEST:
        die("the release is for another Secure Boot key")
    for name in ("bootloader.bin", manifest["app"]):
        sbv2_check(open(os.path.join(path, name), "rb").read(), name)
    return path, manifest


def flash_release(source=None, port=None, log=say):
    """First flash of a blank chip through the ROM download mode: erases the
    whole flash and writes a verified release. The first start then burns
    Secure Boot and flash encryption."""
    path, manifest = fetch_release(source, log)
    port = rom_port(port, ask_running=False)
    secure_boot, encryption = chip_security(port)
    if secure_boot or encryption:
        die("this key already has Secure Boot / flash encryption: update it with `qk update`")
    log(f"erasing the key on {port}...")
    esptool_cmd(port, "erase_flash")
    log(f"writing Quick-Key {manifest['version']}...")
    args = ["write_flash", "--flash_mode", "keep", "--flash_freq", "keep", "--flash_size", "keep"]
    for part in manifest["flash"]:
        args += [part["offset"], os.path.join(path, part["file"])]
    esptool_cmd(port, *args, after="watchdog_reset")
    return manifest["version"]


def cmd_flash(args):
    say("FIRST FLASH: the whole key is erased, and its first start burns Secure Boot and flash\n"
        "encryption into the chip for good. After that it accepts only signed Quick-Key releases.")
    version = flash_release(args.release, args.port)
    print(f"Quick-Key {version} written. Re-plug the key WITHOUT BOOT and leave it plugged in:")
    print("the first start takes about a minute. Then `qk info`.")


def ota_call(cmd, data=b""):
    status = admin(cmd, data)[0]
    if status:
        die(OTA_ERRORS.get(status, f"OTA error {status}"))


def _print_progress(done, total):
    print(f"\r{100 * done // total:3d}%", end="", flush=True)


def update_ota(path, log=print, progress=_print_progress):
    """Signed OTA update. log(message) reports steps, progress(sent, total) the transfer."""
    image = open(path, "rb").read()
    log("Press the button on the key to confirm the update...")
    ota_call(ADMIN_OTA_BEGIN, struct.pack(">I", len(image)))
    t = time.time()
    dev = hid_device()
    for off in range(0, len(image), OTA_CHUNK):
        status = dev.call(0x80 | ADMIN_OTA_WRITE, struct.pack(">I", off) + image[off:off + OTA_CHUNK])[0]
        if status:
            die(OTA_ERRORS.get(status, f"OTA error {status}"))
        progress(min(off + OTA_CHUNK, len(image)), len(image))
    log(f"\rsent {len(image)} bytes in {time.time() - t:.1f}s, verifying signature...")
    ota_call(ADMIN_OTA_END)
    log("accepted, rebooting")
    if wait_for(lambda: _try_version(), timeout=20):
        log(f"running firmware {'.'.join(map(str, _try_version()))}")


def _try_version():
    try:
        return tuple(admin(ADMIN_VERSION))
    except Exception:  # device is rebooting / not found yet
        return None


def latest_image(log=say):
    """(path, version) of the app of the latest verified GitHub Release."""
    path, manifest = fetch_release(log=log)
    return os.path.join(path, manifest["app"]), manifest["version"]


def cmd_update(args):
    if args.rom:
        if not args.firmware:
            die("--rom needs a firmware file")
        update_rom(args.firmware, args.port)
    elif args.firmware:
        if not os.path.isfile(args.firmware):
            die(f"no such file: {args.firmware}")
        update_ota(args.firmware)
    else:
        image, version = latest_image()
        running = device_info()[0]
        if running == version:
            print(f"already running the latest release {version}")
            return
        update_ota(image)
    print("update done")


def qk_version():
    try:
        from importlib.metadata import version
        return version("quick-key")
    except Exception:  # noqa: BLE001 - run from a source checkout
        return "source checkout"


def version_tuple(v):
    try:
        return tuple(int(x) for x in v.lstrip("v").split("."))
    except ValueError:
        die(f"cannot read the version '{v}'")


def latest_release():
    """Version (x.y.z) of the latest GitHub Release."""
    info = json.loads(_http_get(f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest",
                                "application/vnd.github+json"))
    return info["tag_name"].lstrip("v")


def update_status():
    """{"latest", "qk", "qk_newer", "firmware", "firmware_newer"}: this tool and the key's firmware
    against the latest release (they share a version). firmware is None without a key."""
    latest = latest_release()
    installed = qk_version()
    try:
        fw = device_info()[0]
    except Exception:  # noqa: BLE001 - no key plugged in
        fw = None
    newer = lambda v: v is not None and version_tuple(v) < version_tuple(latest)  # noqa: E731
    return {"latest": latest, "qk": installed, "qk_newer": installed != "source checkout" and newer(installed),
            "firmware": fw, "firmware_newer": newer(fw)}


def self_update(version=None, log=say):
    """Installs a release of qk (the latest unless `version`) into the environment it runs from;
    returns the version. The new code runs after qk is started again."""
    if qk_version() == "source checkout":
        die("qk runs from a source checkout: update it with git pull")
    target = (version or latest_release()).lstrip("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", target):
        die(f"not a release version: {target}")
    if target == qk_version():
        return target
    if not version and version_tuple(target) < version_tuple(qk_version()):
        die(f"the latest release {target} is older than the installed qk {qk_version()}")
    log(f"installing qk {target}...")
    r = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--upgrade",
                        f"https://github.com/{GITHUB_REPO}/archive/refs/tags/v{target}.tar.gz"],
                       capture_output=True, text=True, check=False)
    if r.returncode:
        die("pip could not install it: " + (r.stderr.strip().splitlines() or ["unknown error"])[-1])
    return target


def device_present():
    """True if a Quick-Key is plugged in (FIDO interface); talks to nothing."""
    try:
        from fido2.hid import CtapHidDevice
        return any(d.descriptor.vid == VID and d.descriptor.pid == PID for d in CtapHidDevice.list_devices())
    except Exception:  # noqa: BLE001
        return False


def cmd_updates(args):
    st = update_status()
    print(f"latest release: {st['latest']}")
    print(f"qk:             {st['qk']}" + ("  -> `qk self-update`" if st["qk_newer"] else ""))
    print(f"firmware:       {st['firmware'] or 'no key plugged in'}" + ("  -> `qk update`" if st["firmware_newer"] else ""))


def cmd_self_update(args):
    before = qk_version()
    after = self_update(args.version)
    print(f"qk is already {after}" if after == before else f"qk {before} -> {after}: run qk again to use it")


# ---------------------------------------------------------------- CLI

def cmd_tui(args):
    try:
        import qk_tui
    except ImportError as e:
        die(f"{e}: pip install textual")
    qk_tui.main()


def main():
    p = argparse.ArgumentParser(prog="qk", description="Quick-Key management tool")
    p.add_argument("--version", action="version", version=f"qk {qk_version()}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("info", help="firmware version and UUID").set_defaults(func=cmd_info)
    sub.add_parser("reboot", help="reboot the key").set_defaults(func=cmd_reboot)
    sub.add_parser("factory-reset", help="erase ALL data (button confirmation)").set_defaults(func=cmd_factory_reset)
    u = sub.add_parser("update", help="update the firmware over USB (button confirmation)")
    u.add_argument("firmware", nargs="?", help="signed quick-key.bin; the latest release if omitted")
    u.add_argument("--rom", action="store_true",
                   help="development keys without Secure Boot: flash through the ROM bootloader")
    u.add_argument("--port", help="with --rom: serial port of the key in download mode")
    u.set_defaults(func=cmd_update)
    fl = sub.add_parser("flash", help="first flash of a new key (erases it; Secure Boot is burned on its first start)")
    fl.add_argument("--release", help="local release directory instead of the latest GitHub Release")
    fl.add_argument("--port", help="serial port of the key in download mode")
    fl.set_defaults(func=cmd_flash)

    f = sub.add_parser("fido", help="passkeys (FIDO2)").add_subparsers(dest="sub", required=True)
    for name, func, help_ in (("info", cmd_fido_info, "authenticator info"),
                              ("list", cmd_fido_list, "list passkeys"),
                              ("reset", cmd_fido_reset, "erase all passkeys")):
        sp = f.add_parser(name, help=help_)
        sp.add_argument("--pin", help=SECRET_ARG)
        sp.set_defaults(func=func)
    sp = f.add_parser("delete", help="delete a passkey")
    sp.add_argument("cred_id", help="credential id (hex, from `qk fido list`)")
    sp.add_argument("--pin", help=SECRET_ARG)
    sp.set_defaults(func=cmd_fido_delete)
    import qk_fido
    qk_fido.add_fido_commands(f)
    qk_fido.add_ssh_commands(sub)

    o = sub.add_parser("otp", help="TOTP/HOTP codes").add_subparsers(dest="sub", required=True)
    for name, func, help_ in (("list", cmd_otp_list, "list accounts"),
                              ("code", cmd_otp_code, "show codes")):
        sp = o.add_parser(name, help=help_)
        sp.add_argument("--password", help=SECRET_ARG)
        if name == "code":
            sp.add_argument("name", nargs="?")
        sp.set_defaults(func=func)
    sp = o.add_parser("add", help="add an account")
    sp.add_argument("name")
    sp.add_argument("secret", nargs="?", help="base32 secret; prompted if omitted (an argument stays in shell history)")
    sp.add_argument("--hotp", action="store_true")
    sp.add_argument("--counter", type=int, default=0)
    sp.add_argument("--digits", type=int, default=6, choices=(6, 7, 8))
    sp.add_argument("--algorithm", default="SHA1", choices=("SHA1", "SHA256", "SHA512"))
    sp.add_argument("--touch", action="store_true", help="require button press")
    sp.add_argument("--password", help=SECRET_ARG)
    sp.set_defaults(func=cmd_otp_add)
    sp = o.add_parser("delete", help="delete an account")
    sp.add_argument("name")
    sp.add_argument("--password", help=SECRET_ARG)
    sp.set_defaults(func=cmd_otp_delete)
    h = o.add_parser("hmac", help="HMAC-SHA1 challenge-response slots (KeePassXC)").add_subparsers(
        dest="hsub", required=True)
    sp = h.add_parser("status", help="show which slots are set")
    sp.add_argument("--password", help=SECRET_ARG)
    sp.set_defaults(func=cmd_hmac_status)
    sp = h.add_parser("set", help="write a secret (button confirmation)")
    sp.add_argument("slot", type=int, choices=(1, 2))
    sp.add_argument("--secret", help="hex, 1-64 bytes (YubiKey uses 20); random 20 bytes if omitted")
    sp.add_argument("--password", help=SECRET_ARG)
    sp.set_defaults(func=cmd_hmac_set)
    sp = h.add_parser("delete", help="delete a slot (button confirmation)")
    sp.add_argument("slot", type=int, choices=(1, 2))
    sp.add_argument("--password", help=SECRET_ARG)
    sp.set_defaults(func=cmd_hmac_delete)
    o.add_parser("reset", help="erase all OTP accounts and HMAC secrets (button confirmation)").set_defaults(
        func=cmd_otp_reset)
    sp = o.add_parser("set-password", help="set or clear the access password")
    sp.add_argument("--password", help="current password; " + SECRET_ARG)
    sp.add_argument("--new-password", help=SECRET_ARG)
    sp.set_defaults(func=cmd_otp_set_password)

    w = sub.add_parser("pwd", help="password manager").add_subparsers(dest="sub", required=True)
    w.add_parser("status", help="PIN state and number of records").set_defaults(func=cmd_pwd_status)
    sp = w.add_parser("list", help="list records (without passwords)")
    sp.add_argument("--pin", help=SECRET_ARG)
    sp.set_defaults(func=cmd_pwd_list)
    sp = w.add_parser("get", help="show a record")
    sp.add_argument("ref", help="record id or name")
    sp.add_argument("--show", action="store_true", help="reveal the password")
    sp.add_argument("--pin", help=SECRET_ARG)
    sp.set_defaults(func=cmd_pwd_get)
    for name, func, help_ in (("add", cmd_pwd_add, "add a record"), ("edit", cmd_pwd_edit, "change a record")):
        sp = w.add_parser(name, help=help_)
        if name == "add":
            sp.add_argument("name")
        else:
            sp.add_argument("ref", help="record id or name")
            sp.add_argument("--name")
            sp.add_argument("--change-password", action="store_true", help="prompt for a new password")
        sp.add_argument("--url")
        sp.add_argument("--login")
        sp.add_argument("--note")
        sp.add_argument("--otp", help="name of a linked OTP account")
        sp.add_argument("--password", help="password value, prompted if omitted when adding; "
                        "a value given here stays in the shell history and shows in the process list")
        sp.add_argument("--generate", type=int, metavar="LEN", help="generate a password on the key")
        sp.add_argument("--chars", default="luds", help="generator sets: l=lower u=upper d=digits s=symbols")
        if name == "add":
            sp.add_argument("--touch", action="store_true", help="require button press to read the password")
        else:
            sp.add_argument("--touch", action=argparse.BooleanOptionalAction, help="require button press")
        sp.add_argument("--pin", help=SECRET_ARG)
        sp.set_defaults(func=func)
    sp = w.add_parser("delete", help="delete a record")
    sp.add_argument("ref", help="record id or name")
    sp.add_argument("--pin", help=SECRET_ARG)
    sp.set_defaults(func=cmd_pwd_delete)
    sp = w.add_parser("gen", help="generate a password on the key (not stored)")
    sp.add_argument("--length", type=int, default=20)
    sp.add_argument("--chars", default="luds", help="l=lower u=upper d=digits s=symbols")
    sp.set_defaults(func=cmd_pwd_gen)
    sp = w.add_parser("export", help="save all records to an encrypted backup file")
    sp.add_argument("file")
    sp.add_argument("--backup-password", help="password of the backup file; " + SECRET_ARG)
    sp.add_argument("--pin", help=SECRET_ARG)
    sp.set_defaults(func=cmd_pwd_export)
    sp = w.add_parser("audit", help="find weak and reused passwords (those protected by the button are skipped)")
    sp.add_argument("--pin", help=SECRET_ARG)
    sp.set_defaults(func=cmd_pwd_audit)
    sp = w.add_parser("import", help="add records from a backup or a CSV export of another password manager")
    sp.add_argument("file")
    sp.add_argument("--backup-password", help="password of a Quick-Key backup; " + SECRET_ARG)
    sp.add_argument("--pin", help=SECRET_ARG)
    sp.set_defaults(func=cmd_pwd_import)
    w.add_parser("reset", help="erase all passwords (button confirmation)").set_defaults(func=cmd_pwd_reset)

    g = sub.add_parser("pgp", help="OpenPGP card").add_subparsers(dest="sub", required=True)
    g.add_parser("status").set_defaults(func=cmd_pgp_status)
    sp = g.add_parser("reset", help="erase OpenPGP keys and card data (needs the admin PIN)")
    sp.add_argument("--admin-pin", help=SECRET_ARG)
    sp.set_defaults(func=cmd_pgp_reset)
    sp = g.add_parser("touch", help="require a button press for each use of a key (needs the admin PIN)")
    sp.add_argument("key", choices=PGP_KEYS)
    sp.add_argument("mode", choices=tuple(PGP_TOUCH.values()), help="fixed: only an OpenPGP reset clears it")
    sp.add_argument("--admin-pin", help=SECRET_ARG)
    sp.set_defaults(func=cmd_pgp_touch)
    import qk_pgp
    qk_pgp.add_commands(g)

    v = sub.add_parser("piv", help="PIV smart card").add_subparsers(dest="sub", required=True)
    v.add_parser("status").set_defaults(func=cmd_piv_status)
    v.add_parser("reset", help="erase PIV keys and certificates (button confirmation)").set_defaults(func=cmd_piv_reset)
    import qk_piv
    qk_piv.add_commands(v)

    n = sub.add_parser("pin", help="device PIN (all applications) and admin PIN").add_subparsers(dest="sub", required=True)
    n.add_parser("status", help="tries left").set_defaults(func=cmd_pin_status)
    sp = n.add_parser("change", help="change the PIN (6-8 characters)")
    sp.add_argument("--pin", help="current PIN; " + SECRET_ARG)
    sp.add_argument("--new-pin", help=SECRET_ARG)
    sp.set_defaults(func=cmd_pin_change)
    sp = n.add_parser("change-admin", help="change the admin PIN (8 characters)")
    sp.add_argument("--admin-pin", help="current admin PIN; " + SECRET_ARG)
    sp.add_argument("--new-pin", help=SECRET_ARG)
    sp.set_defaults(func=cmd_pin_change_admin)
    sp = n.add_parser("unblock", help="set a new PIN with the admin PIN")
    sp.add_argument("--admin-pin", help=SECRET_ARG)
    sp.add_argument("--new-pin", help=SECRET_ARG)
    sp.set_defaults(func=cmd_pin_unblock)

    sub.add_parser("updates", help="compare qk and the key's firmware with the latest release").set_defaults(
        func=cmd_updates)
    su = sub.add_parser("self-update", help="update qk itself to the latest release (or --version)")
    su.add_argument("--version", help="install this release instead of the latest")
    su.set_defaults(func=cmd_self_update)
    sub.add_parser("tui", help="interactive terminal UI (needs: pip install textual)").set_defaults(func=cmd_tui)

    args = p.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:  # noqa: BLE001 - user-facing CLI
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
