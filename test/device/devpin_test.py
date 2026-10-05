# Device PIN shared by all applications: change it in one application, use it
# in the others; one try counter; unblock with the admin PIN; keys and
# passwords survive PIN changes; length limits. Leaves PIN 314159 / admin
# 27182818. Needs an empty password manager. Resets PIV at the end
# (1 button press).
import hashlib, subprocess
from fido2.hid import CtapHidDevice
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from smartcard.System import readers

PIV = [0xA0, 0x00, 0x00, 0x03, 0x08]
PGP = [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]
PWD = [0xF0, 0x51, 0x4B, 0x50, 0x57, 0x44]
MGM = "010203040506070801020304050607080102030405060708"

def yk(*args, ok=True):
    p = subprocess.run(["ykman", "--reader", "Quick-Key", "piv", *args], capture_output=True, text=True)
    assert (p.returncode == 0) == ok, f"ykman piv {' '.join(args)}: {p.stdout}{p.stderr}"

# PIV key made before the PIN changes (ykman runs before we hold the reader).
yk("keys", "generate", "-m", MGM, "-a", "ECCP256", "9a", "/tmp/qk_9a.pem")

r = [x for x in readers() if "Quick-Key" in str(x)][0]
c = r.createConnection(); c.connect()

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
    b = pin.encode()
    return b + b"\xff" * (8 - len(b))

def piv_verify(pin, ok=0x9000):
    select(PIV)
    tx([0x00, 0x20, 0x00, 0x80, 8] + list(pad(pin)), ok)

def pgp_verify(pin, ref=0x81, ok=0x9000):
    select(PGP)
    b = pin.encode()
    tx([0x00, 0x20, 0x00, ref, len(b)] + list(b), ok)

def pwd_verify(pin, ok=0x9000):
    select(PWD)
    b = pin.encode()
    tx([0x00, 0x20, 0x00, 0x00, len(b)] + list(b), ok)

ctap = Ctap2([d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x1209][0])

def fido_verify(pin, err=None):
    try:
        ClientPin(ctap).get_pin_token(pin)
        assert err is None, f"FIDO accepted {pin!r}"
    except CtapError as e:
        assert e.code == err, f"FIDO {pin!r}: {e.code!r}, expected {err!r}"

def tries():
    return ClientPin(ctap).get_pin_retries()[0]

def everywhere(pin):
    fido_verify(pin)
    piv_verify(pin)
    pgp_verify(pin)
    pgp_verify(pin, 0x82)
    pwd_verify(pin)

def nowhere(pin):
    # Each wrong try costs one from the shared counter; a right PIN restores it.
    fido_verify(pin, CtapError.ERR.PIN_INVALID)
    piv_verify(pin, 0x63C6)
    pgp_verify(pin, ok=0x63C5)
    pwd_verify(pin, 0x63C4)
    assert tries() == 4

info = ctap.get_info()
assert info.options["clientPin"] and info.min_pin_length == 6
assert tries() == 8
everywhere("314159")
print("PIN 314159 works in FIDO, PIV, OpenPGP (81/82), passwords")

DIGEST = hashlib.sha256(b"devpin").digest()

def piv_sign(pin):
    piv_verify(pin)
    resp = cmd(0x87, 0x11, 0x9A, bytes([0x7C, 0x24, 0x82, 0x00, 0x81, 0x20]) + DIGEST)
    assert resp[0] == 0x7C

def pwd_check(pin):
    pwd_verify(pin)
    resp = cmd(0xA2, 0x01, 0x00, bytes([0x08, 1, 0]))
    assert b"s3cr3t" in resp

piv_sign("314159")
pwd_verify("314159")
cmd(0xA3, 0x00, 0x00, bytes([0x01, 4]) + b"site" + bytes([0x04, 6]) + b"s3cr3t")
pwd_check("314159")

# FIDO: too long / too short is a policy violation, the PIN stays.
for bad in ("üüüü1", "12345"):                  # 9 bytes UTF-8, 5 bytes
    try:
        ClientPin(ctap).change_pin("314159", bad)
        assert False, f"FIDO accepted new PIN {bad!r}"
    except (CtapError, ValueError) as e:
        assert isinstance(e, ValueError) or e.code == CtapError.ERR.PIN_POLICY_VIOLATION, e
fido_verify("314159")

# Change in FIDO -> works everywhere, the old one nowhere; keys still open.
NEW1 = "üö1234"                                  # 8 bytes UTF-8
ClientPin(ctap).change_pin("314159", NEW1)
nowhere("314159")
everywhere(NEW1)
piv_sign(NEW1)
pwd_check(NEW1)
print("changed in FIDO: works everywhere, keys and passwords still open")

# Change in OpenPGP (old || new), then in PIV (padded to 8 bytes each).
select(PGP)
cmd(0x24, 0x00, 0x81, NEW1.encode() + b"Qk-pin7")
everywhere("Qk-pin7")
select(PIV)
cmd(0x24, 0x00, 0x80, pad("Qk-pin7") + pad("12345"), ok=0x6A80)     # too short
cmd(0x24, 0x00, 0x80, pad("Qk-pin7") + pad("314159"))
everywhere("314159")
print("changed in OpenPGP and PIV")

# One counter: blocked in PIV = blocked in FIDO and passwords.
for left in range(7, 0, -1):
    piv_verify("000000", 0x63C0 | left)
piv_verify("000000", 0x6983)
fido_verify("314159", CtapError.ERR.PIN_BLOCKED)
pwd_verify("314159", 0x6983)
pgp_verify("314159", ok=0x6983)
# Unblock in OpenPGP with PW3 (no Reset Code).
select(PGP)
cmd(0x2C, 0x00, 0x81, b"resetcode" + b"654321", ok=0x6982)
cmd(0x20, 0x00, 0x83, b"27182818")
cmd(0xDA, 0x00, 0xD3, b"resetcode1", ok=0x6A81)
cmd(0x2C, 0x02, 0x81, b"654321")
everywhere("654321")
piv_sign("654321")
print("blocked everywhere at once, unblocked with the admin PIN in OpenPGP")

# Block again, unblock in PIV with the PUK.
for left in range(7, 0, -1):
    pgp_verify("000000", ok=0x63C0 | left)
pgp_verify("000000", ok=0x6983)
assert tries() == 0
select(PIV)
cmd(0x2C, 0x00, 0x80, pad("00000000") + pad("314159"), ok=0x63C2)
cmd(0x2C, 0x00, 0x80, pad("27182818") + pad("314159"))
everywhere("314159")
print("unblocked with the PUK in PIV")

# Admin PIN: one for OpenPGP PW3 and PIV PUK, exactly 8 characters.
select(PGP)
cmd(0x24, 0x00, 0x83, b"27182818" + b"3141597", ok=0x6700)
cmd(0x24, 0x00, 0x83, b"27182818" + b"87654321")
pgp_verify("27182818", 0x83, ok=0x63C2)
select(PIV)
cmd(0x24, 0x00, 0x81, pad("87654321") + pad("27182818"))
pgp_verify("27182818", 0x83)
select(PGP)
st = tx([0x00, 0xCA, 0x00, 0xC4, 0x00])
assert st[4] == 8 and st[6] == 3, st.hex()
print("admin PIN shared by OpenPGP PW3 and PIV PUK")

# Clean up: delete the password, reset PIV (PINs stay).
pwd_verify("314159")
cmd(0xA4, 0x00, 0x00, bytes([0x08, 1, 0]))
select(PIV)
print("PRESS BUTTON (Reset PIV?)")
cmd(0xFB, 0x00, 0x00)
piv_verify("314159")
assert tries() == 8
c.disconnect()
print("devpin tests passed")
