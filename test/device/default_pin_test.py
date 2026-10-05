# Factory PINs guard nothing. While either is still the default the key
# refuses to store keys and passwords, FIDO asks the platform to change the
# PIN first (forcePINChange), and every PIN change replaces the vault key;
# the factory value can't be chosen again. Starts with a FACTORY RESET
# (ERASES EVERYTHING, 1 button press) and ends with PIN 314159 / admin
# 27182818. Run `gpgconf --kill scdaemon` first.
import os, subprocess, sys, time
from fido2.hid import CtapHidDevice
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from smartcard.System import readers

PIV = [0xA0, 0x00, 0x00, 0x03, 0x08]
PGP = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
PWD = [0xF0, 0x51, 0x4B, 0x50, 0x57, 0x44]
MGM = "010203040506070801020304050607080102030405060708"
QK = [sys.executable, os.path.join(os.path.dirname(__file__), "..", "..", "tools", "qk.py")]

print("PRESS BUTTON (FACTORY RESET)")
subprocess.run(QK + ["factory-reset"], check=True)
devs, rs = [], []
for _ in range(40):
    time.sleep(0.5)
    try:                        # the key is rebooting: it may not answer yet
        devs = [d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x1209]
        rs = [x for x in readers() if "Quick-Key" in str(x)]
    except Exception:
        continue
    if devs and rs:
        break
ctap = Ctap2(devs[0])
cp = ClientPin(ctap)
c = rs[0].createConnection(); c.connect()

def tx(apdu, ok=0x9000):
    data, s1, s2 = c.transmit(list(apdu))
    while s1 == 0x61:
        more, s1, s2 = c.transmit([0x00, 0xC0, 0x00, 0x00, s2])
        data += more
    sw = (s1 << 8) | s2
    assert sw == ok, f"{bytes(apdu[:4]).hex()} -> {sw:04x}, expected {ok:04x}"
    return bytes(data)

def cmd(ins, p1, p2, data=b"", ok=0x9000):
    return tx([0x00, ins, p1, p2] + ([len(data)] + list(data) if data else []) + [0], ok)

def select(aid):
    tx([0x00, 0xA4, 0x04, 0x00, len(aid)] + aid)

def pad(pin):
    return pin.encode().ljust(8, b"\xff")

def tlv_find(d, tag):
    i = 0
    while i < len(d):
        t, n = d[i], d[i + 1]
        if t == tag:
            return d[i + 2:i + 2 + n]
        i += 2 + n

def set_pin(old, new, ok=0x9000):
    select(PIV)
    cmd(0x24, 0x00, 0x80, pad(old) + pad(new), ok)

def set_admin(old, new, ok=0x9000):
    select(PGP)
    cmd(0x24, 0x00, 0x83, old.encode() + new.encode(), ok)

def refused(user_pin, admin_pin):
    """Key generation and import in OpenPGP, a password record: all 6985."""
    select(PGP)
    cmd(0x20, 0x00, 0x83, admin_pin.encode())
    cmd(0x47, 0x80, 0x00, bytes([0xB6, 0x00]), ok=0x6985)
    cmd(0xDB, 0x3F, 0xFF, bytes([0x4D, 0x02, 0xB6, 0x00]), ok=0x6985)
    select(PWD)
    cmd(0x20, 0x00, 0x00, user_pin.encode())
    cmd(0xA3, 0x00, 0x00, bytes([0x01, 0x04]) + b"test", ok=0x6985)

def piv_generate(ok):
    c.disconnect()
    p = subprocess.run(["ykman", "--reader", "Quick-Key", "piv", "keys", "generate", "-m", MGM,
                        "-a", "ECCP256", "9a", "-"], capture_output=True, text=True)
    assert (p.returncode == 0) == ok, p.stdout + p.stderr
    c.connect()

# Factory state: PIV metadata and ykman report the default PIN.
select(PIV)
assert tlv_find(cmd(0xF7, 0x00, 0x80), 0x05) == b"\x01"
c.disconnect()
info = subprocess.run(["ykman", "--reader", "Quick-Key", "piv", "info"], capture_output=True, text=True).stdout
assert "default PIN" in info, info
c.connect()

assert ctap.get_info().force_pin_change
try:
    cp.get_pin_token("123456")
    raise AssertionError("token with the factory PIN")
except CtapError as e:
    assert e.code == CtapError.ERR.PIN_POLICY_VIOLATION, e
refused("123456", "12345678")
piv_generate(False)
print("factory PINs: forcePINChange, no token; OpenPGP, PIV and passwords refuse to store")

set_pin("123456", "123456", ok=0x6A80)          # the factory value can't be set
set_pin("123456", "314159")
select(PIV)
assert tlv_find(cmd(0xF7, 0x00, 0x80), 0x05) == b"\x00"
assert not ctap.get_info().force_pin_change
cp.get_pin_token("314159")
refused("314159", "12345678")
piv_generate(False)
print("factory admin PIN: FIDO works; OpenPGP, PIV and passwords still refuse to store")

set_admin("12345678", "12345678", ok=0x6A80)    # the factory value can't be set
set_admin("12345678", "27182818")
piv_generate(True)
# The vault key was replaced twice; the password manager made a new data key.
select(PWD)
cmd(0x20, 0x00, 0x00, b"314159")
rid = tlv_find(cmd(0xA3, 0x00, 0x00, bytes([0x01, 0x04]) + b"test"), 0x08)
cmd(0xA4, 0x00, 0x00, bytes([0x08, 0x01]) + rid)
print("both PINs changed: PIV generates a key, passwords are stored; PINs 314159 / 27182818")
