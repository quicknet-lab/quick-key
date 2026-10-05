# Fixes from the code review: INS A5 reaches OpenPGP (SELECT DATA) while a
# response is pending; a CCID message of the maximum length (4106 bytes) is
# received whole; PIV 9C (PIN "always") does not log out 9A (PIN "once");
# the FIDO firmware version comes from PROJECT_VER. Resets PIV at the end
# (1 button press). Run `gpgconf --kill scdaemon` first.
import hashlib, re, subprocess
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2
from smartcard.System import readers

MGM = "010203040506070801020304050607080102030405060708"

# ---- firmware version ----
ver = re.search(r'PROJECT_VER "(\d+)\.(\d+)\.(\d+)"', open("CMakeLists.txt").read()).groups()
ver = tuple(int(x) for x in ver)
dev = [d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x1209][0]
assert dev.device_version == ver, dev.device_version
assert Ctap2(dev).info.firmware_version == (ver[0] << 16) | (ver[1] << 8) | ver[2]
dev.close()
print(f"FIDO: CTAPHID INIT and getInfo report {'.'.join(map(str, ver))}")

r = [x for x in readers() if "Quick-Key" in str(x)][0]
c = r.createConnection(); c.connect()

def tx(apdu, ok=0x9000):
    data, s1, s2 = c.transmit(list(apdu))
    sw = (s1 << 8) | s2
    if ok is not None:
        assert sw == ok, f"{bytes(apdu[:4]).hex()} -> {sw:04x}, expected {ok:04x}"
    return bytes(data), sw

# ---- A5 while a response is pending ----
tx([0x00, 0xA4, 0x04, 0x00, 6] + list(bytes.fromhex("D27600012401")))
_, sw = tx([0x00, 0xCA, 0x00, 0x6E, 0x10], ok=None)          # short Le: the rest stays pending
assert sw >> 8 == 0x61, hex(sw)
data, _ = tx([0x00, 0xA5, 0x02, 0x04, 0x06, 0x60, 0x04, 0x5C, 0x02, 0x7F, 0x21])
assert data == b""                                         # SELECT DATA, not the leftover 6E bytes
print("OpenPGP: SELECT DATA (A5) works with a response pending")

# ---- CCID message of the maximum length ----
# Extended case 3: 4 + 3 + 4089 = 4096 bytes of APDU, 4106 with the CCID header.
# PUT DATA without the admin PIN: the answer must be 6982, not a hang.
apdu = [0x00, 0xDA, 0x7F, 0x21, 0x00, 4089 >> 8, 4089 & 0xFF] + [0x30] * 4089
tx(apdu, ok=0x6982)
tx([0x00, 0xCA, 0x00, 0xC4, 0x00])                         # the reader still works
print("CCID: 4106-byte message received whole")
c.disconnect()

# ---- PIV: 9C PIN "always" next to 9A PIN "once" ----
def yk(*args):
    p = subprocess.run(["ykman", "--reader", "Quick-Key", "piv", *args], capture_output=True, text=True)
    assert p.returncode == 0, f"ykman piv {' '.join(args)}: {p.stdout}{p.stderr}"

yk("keys", "generate", "-m", MGM, "-a", "ECCP256", "9a", "-")
yk("keys", "generate", "-m", MGM, "-a", "ECCP256", "9c", "-")
c.connect()
tx([0x00, 0xA4, 0x04, 0x00, 5, 0xA0, 0x00, 0x00, 0x03, 0x08])

def sign(slot, ok=0x9000):
    h = hashlib.sha256(bytes([slot])).digest()
    body = bytes([0x7C, 36, 0x82, 0x00, 0x81, 32]) + h
    return tx([0x00, 0x87, 0x11, slot, len(body)] + list(body) + [0], ok=ok)

tx([0x00, 0x20, 0x00, 0x80, 8] + list(b"314159\xff\xff"))
sign(0x9C)
sign(0x9C, ok=0x6982)                                      # "always": needs the PIN again
sign(0x9A)                                                 # "once": still unlocked
tx([0x00, 0x20, 0x00, 0x80, 8] + list(b"314159\xff\xff"))
sign(0x9C)
print("PIV: 9C asks for the PIN every time, 9A stays unlocked")

print("PRESS BUTTON (Reset PIV?)")
tx([0x00, 0xFB, 0x00, 0x00])
c.disconnect()
print("review fixes tests passed")
