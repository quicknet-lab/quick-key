# PIV objects that need the PIN (SP 800-73-4): a management key stored by
# ykman with --protect (printed information, 5FC109) is not readable without
# the PIN, readable with it, and ykman still works with it; PUT DATA accepts
# only standard object IDs. Resets PIV at the
# end (1 button press).
import subprocess
from smartcard.System import readers

MGM = "010203040506070801020304050607080102030405060708"

def yk(*args, ok=True):
    p = subprocess.run(["ykman", "--reader", "Quick-Key", "piv", *args], capture_output=True, text=True)
    assert (p.returncode == 0) == ok, f"ykman piv {' '.join(args)}: {p.stdout}{p.stderr}"
    return p.stdout

yk("access", "change-management-key", "-m", MGM, "-P", "314159", "--generate", "--protect", "-f")
assert "protected by PIN" in yk("info")

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

def get(tag, ok=0x9000):
    return tx([0x00, 0xCB, 0x3F, 0xFF, 5, 0x5C, 3] + list(tag.to_bytes(3, "big")) + [0], ok)

tx([0x00, 0xA4, 0x04, 0x00, 5, 0xA0, 0x00, 0x00, 0x03, 0x08])
get(0x5FC109, ok=0x6982)
get(0x5FC102)                                               # CHUID stays public
tx([0x00, 0x20, 0x00, 0x80, 8] + list(b"314159\xff\xff"))
assert get(0x5FC109)[0] == 0x53
c.disconnect()
print("PIV: protected management key needs the PIN, CHUID does not")

# ykman reads the stored key itself after the PIN: no -m needed.
yk("keys", "generate", "-P", "314159", "-a", "ECCP256", "9a", "-")
yk("keys", "generate", "-P", "000000", "-a", "ECCP256", "9a", "-", ok=False)
print("PIV: ykman uses the protected key with the PIN only")

# Only standard object IDs are writable (keeps PUT DATA from filling the flash).
open("/tmp/qk_obj.bin", "wb").write(b"\x01\x02\x03")
yk("objects", "import", "-P", "314159", "0x5FC10D", "/tmp/qk_obj.bin")
yk("objects", "import", "-P", "314159", "0x5FC1FF", "/tmp/qk_obj.bin", ok=False)
yk("objects", "import", "-P", "314159", "0x123456", "/tmp/qk_obj.bin", ok=False)
print("PIV: PUT DATA limited to standard object IDs")

c.connect()
tx([0x00, 0xA4, 0x04, 0x00, 5, 0xA0, 0x00, 0x00, 0x03, 0x08])
tx([0x00, 0x20, 0x00, 0x80, 8] + list(b"314159\xff\xff"))   # restore the try spent above
print("PRESS BUTTON (Reset PIV?)")
tx([0x00, 0xFB, 0x00, 0x00])
c.disconnect()
print("PIV protect tests passed")
