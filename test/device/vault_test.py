# PIN changes and recovery with keys sealed to the vault: OpenPGP (APDU) and PIV (ykman).
# Run after pgp_test.py (needs the OpenPGP signature key). Resets PIV at the end.
import hashlib, subprocess, time
from smartcard.System import readers

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
    return tx([0x00, ins, p1, p2, len(data)] + list(data) + ([0] if ins in (0x2A, 0x47) else []), ok)

def select():
    tx([0x00, 0xA4, 0x04, 0x00, 6, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])

DIGEST = hashlib.sha256(b"vault").digest()

def sign(ok=0x9000):
    return cmd(0x2A, 0x9E, 0x9A, DIGEST, ok)

# ---- OpenPGP ----
select()
pub = cmd(0x47, 0x81, 0x00, bytes([0xB6, 0x00]))      # public key without a PIN
assert len(pub) > 64
t = time.time()
cmd(0x20, 0x00, 0x81, b"314159")
print(f"PW1 verify {time.time() - t:.2f}s")
t = time.time()
assert len(sign()) == 64
print(f"sign {time.time() - t:.2f}s")

cmd(0x24, 0x00, 0x81, b"314159" + b"654321")           # change PW1 (the device PIN)
select()
cmd(0x20, 0x00, 0x81, b"314159", ok=0x63C7)
cmd(0x20, 0x00, 0x81, b"654321")
sign()
print("PW1 changed, signature key works")

select()
for left in range(7, 0, -1):
    cmd(0x20, 0x00, 0x81, b"000000", ok=0x63C0 | left)
cmd(0x20, 0x00, 0x81, b"000000", ok=0x6983)
cmd(0x20, 0x00, 0x81, b"654321", ok=0x6983)
cmd(0xDA, 0x00, 0xD3, b"resetcode1", ok=0x6982)        # no Reset Code (and PW3 not verified)
cmd(0x2C, 0x00, 0x81, b"resetcode1" + b"314159", ok=0x6982)
cmd(0x20, 0x00, 0x83, b"27182818")
cmd(0x2C, 0x02, 0x81, b"314159")                       # reset PW1 by PW3
select()
cmd(0x20, 0x00, 0x81, b"314159")
sign()
cmd(0x24, 0x00, 0x83, b"27182818" + b"87654321")        # change PW3
select()
cmd(0x20, 0x00, 0x83, b"27182818", ok=0x63C2)
cmd(0x20, 0x00, 0x83, b"87654321")
cmd(0x24, 0x00, 0x83, b"87654321" + b"27182818")
print("PW1 blocked and reset by PW3, PW3 changed; PINs restored")
c.disconnect()

# ---- PIV (ykman) ----
MGM = "010203040506070801020304050607080102030405060708"

def yk(*args, ok=True):
    p = subprocess.run(["ykman", "--reader", "Quick-Key", "piv", *args], capture_output=True, text=True)
    assert (p.returncode == 0) == ok, f"ykman piv {' '.join(args)}: {p.stdout}{p.stderr}"
    return p.stdout

def cert(slot, pin, ok=True):
    yk("certificates", "generate", "-m", MGM, "-P", pin, "-s", f"CN=vault {slot}", slot, f"/tmp/qk_{slot}.pem", ok=ok)

for slot in ("9a", "9c", "9d", "9e"):
    yk("keys", "generate", "-m", MGM, "-a", "ECCP256", slot, f"/tmp/qk_{slot}.pem")
    t = time.time()
    cert(slot, "314159")
    print(f"PIV {slot}: key generated, certificate signed by it ({time.time() - t:.1f}s)")

yk("access", "change-pin", "-P", "314159", "-n", "654321")
cert("9a", "314159", ok=False)
cert("9a", "654321")
yk("access", "change-puk", "-p", "27182818", "-n", "87654321")
for _ in range(8):
    yk("access", "change-pin", "-P", "000000", "-n", "111111", ok=False)
yk("access", "unblock-pin", "-p", "87654321", "-n", "314159")
cert("9c", "314159")
yk("access", "change-puk", "-p", "87654321", "-n", "27182818")
print("PIV: PIN changed, blocked, unblocked with the new PUK; keys still work")

# 9E (card authentication) signs without a PIN; 9A refuses
c.connect()
tx([0x00, 0xA4, 0x04, 0x00, 5, 0xA0, 0x00, 0x00, 0x03, 0x08])
auth = bytes([0x7C, 0x24, 0x82, 0x00, 0x81, 0x20]) + DIGEST
resp = tx([0x00, 0x87, 0x11, 0x9E, len(auth)] + list(auth) + [0])
assert resp[0] == 0x7C and resp[2] == 0x82                 # 7C { 82 <DER signature> }
tx([0x00, 0x87, 0x11, 0x9A, len(auth)] + list(auth) + [0], ok=0x6982)
c.disconnect()
print("PIV: 9E signs without a PIN, 9A needs it")

# `ykman piv reset` would block PIN and PUK first, i.e. the device PINs, and
# end in a factory reset; reset PIV directly instead.
c.connect()
tx([0x00, 0xA4, 0x04, 0x00, 5, 0xA0, 0x00, 0x00, 0x03, 0x08])
print("PRESS BUTTON (Reset PIV?)")
tx([0x00, 0xFB, 0x00, 0x00])
c.disconnect()
print(yk("info"))
print("vault tests passed")
