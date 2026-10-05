# Touch confirmation and challenge-response: HMAC-SHA1 slots in the OATH
# application (KeePassXC protocol), OpenPGP user interaction flag, PIV touch
# policy and GET METADATA. 6 presses. With --timeout, one more request at the
# very end ("Sign?") must NOT be pressed: the signature is refused after 30 s. Ends with an OpenPGP card reset and a PIV reset.
# Run `gpgconf --kill scdaemon` first.
import hashlib, hmac, os, subprocess, sys, time
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from smartcard.System import readers

QK = [sys.executable, os.path.join(os.path.dirname(__file__), "..", "..", "tools", "qk.py")]
MGM = "010203040506070801020304050607080102030405060708"
AID_OATH = bytes.fromhex("A0000005272101")
AID_PGP = bytes.fromhex("D27600012401")
AID_PIV = bytes.fromhex("A000000308")

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

def cmd(ins, p1, p2, data=b"", le=True, ok=0x9000):
    return tx([0x00, ins, p1, p2] + ([len(data)] + list(data) if data else []) + ([0] if le else []), ok)

def select(aid):
    return cmd(0xA4, 0x04, 0x00, aid)

def tlv(tag, v):
    t = tag.to_bytes(2, "big") if tag > 0xFF else bytes([tag])
    return t + (bytes([len(v)]) if len(v) < 0x80 else bytes([0x81, len(v)])) + v

def tlv_find(b, tag):
    i = 0
    while i < len(b):
        t = b[i]; i += 1
        if t & 0x1F == 0x1F: t = (t << 8) | b[i]; i += 1
        l = b[i]; i += 1
        if l == 0x81: l = b[i]; i += 1
        elif l == 0x82: l = (b[i] << 8) | b[i + 1]; i += 2
        if t == tag: return b[i:i + l]
        i += l

def qk(*args):
    c.disconnect()
    p = subprocess.run(QK + list(args), capture_output=True, text=True)
    c.connect()
    assert p.returncode == 0, f"qk {' '.join(args)}: {p.stdout}{p.stderr}"

# ---- OpenPGP user interaction flag ----
OID_P256 = bytes.fromhex("2A8648CE3D030107")
select(AID_PGP)
cmd(0x20, 0x00, 0x83, b"27182818", le=False)               # start from a clean card
cmd(0xE6, 0x00, 0x00, le=False)
cmd(0x44, 0x00, 0x00, le=False)
select(AID_PGP)
assert cmd(0xCA, 0x7F, 0x74) == bytes.fromhex("810120")
assert cmd(0xCA, 0x00, 0xD6) == bytes.fromhex("0020")
cmd(0x20, 0x00, 0x83, b"27182818", le=False)
cmd(0xDA, 0x00, 0xC1, b"\x13" + OID_P256, le=False)
cmd(0x47, 0x80, 0x00, b"\xB6\x00")
cmd(0xDA, 0x00, 0xD6, b"\x01\x20", le=False)
cmd(0xDA, 0x00, 0xD6, b"\x03\x20", le=False, ok=0x6A80)
app = cmd(0xCA, 0x00, 0x6E)
assert tlv_find(tlv_find(app, 0x73), 0xD6) == b"\x01\x20" and tlv_find(app, 0x7F74) == bytes.fromhex("810120")
digest = hashlib.sha256(b"uif").digest()
cmd(0x20, 0x00, 0x81, b"314159", le=False)
print("PRESS BUTTON (Sign? OpenPGP key)")
assert len(cmd(0x2A, 0x9E, 0x9A, digest)) == 64
print("OpenPGP: UIF on, the press confirms a signature")


# ---- HMAC-SHA1 challenge-response ----
def chalresp(slot, challenge, ok=0x9000):
    # KeePassXC pads to 64 bytes PKCS#7-style; the key strips the padding.
    pad = 64 - len(challenge)
    return cmd(0x01, 0x30 if slot == 1 else 0x38, 0x00, challenge + bytes([pad]) * pad, ok=ok)

select(AID_OATH)
assert len(cmd(0x01, 0x10, 0x00)) == 4                  # serial, as KeePassXC reads it
print("PRESS BUTTON (Set HMAC? Slot 1)")
cmd(0xB1, 1, 0, b"\x0b" * 20, le=False)
# RFC 2202 test case 1.
assert chalresp(1, b"Hi There").hex() == "b617318655057264e28bc0b6fb378c8ef146be00"
chal = os.urandom(32)
assert chalresp(1, chal) == hmac.new(b"\x0b" * 20, chal, hashlib.sha1).digest()
chalresp(2, chal, ok=0x6A82)                            # empty slot: KeePassXC skips it
cmd(0xB1, 1, 0, b"\x01" * 65, le=False, ok=0x6700)
print("HMAC: RFC 2202 vector, KeePassXC padding, empty slot")

# Works without the OATH access code; writing a slot needs it.
qk("otp", "set-password", "--new-password", "pw")
select(AID_OATH)
assert chalresp(1, chal) == hmac.new(b"\x0b" * 20, chal, hashlib.sha1).digest()
cmd(0xB1, 1, 0, b"\x01" * 20, le=False, ok=0x6982)
qk("otp", "set-password", "--password", "pw", "--new-password", "")
select(AID_OATH)
print("HMAC: answers behind the OATH password, writing needs it")

print("PRESS BUTTON (Delete HMAC? Slot 1)")
cmd(0xB1, 1, 0, le=False)
chalresp(1, chal, ok=0x6A82)
print("HMAC: slot deleted")

# ---- PIV ----
select(AID_PIV)
assert cmd(0xFD, 0x00, 0x00) == bytes([5, 4, 3])

def meta(p2):
    return cmd(0xF7, 0x00, p2)

def pin8(p):
    return p.encode().ljust(8, b"\xff")

# The test PINs are not the factory ones (default_pin_test.py checks the flag set).
m = meta(0x80)
assert tlv_find(m, 0x05) == b"\x00" and tlv_find(m, 0x06) == bytes([8, 8])
m = meta(0x81)
assert tlv_find(m, 0x06) == bytes([3, 3])
m = meta(0x9B)
assert tlv_find(m, 0x01) == b"\x03" and tlv_find(m, 0x05) == b"\x01"
c.disconnect()
info = subprocess.run(["ykman", "--reader", "Quick-Key", "piv", "info"], capture_output=True, text=True).stdout
assert "5.4.3" in info and "default PIN" not in info and "default Management key" in info, info
print("PIV: version 5.4.3, PIN/PUK/management key metadata, ykman piv info warnings")

def yk(*args, ok=True):
    p = subprocess.run(["ykman", "--reader", "Quick-Key", "piv", *args], capture_output=True, text=True)
    assert (p.returncode == 0) == ok, f"ykman piv {' '.join(args)}: {p.stdout}{p.stderr}"
    return p.stdout

yk("keys", "generate", "-m", MGM, "-a", "ECCP256", "--touch-policy", "ALWAYS", "9a", "/tmp/qk_9a.pem")
yk("keys", "generate", "-m", MGM, "-a", "ECCP256", "--touch-policy", "CACHED", "9d", "/tmp/qk_9d.pem")
yk("keys", "generate", "-m", MGM, "-a", "ECCP256", "--pin-policy", "NEVER", "9c", "-", ok=False)
yk("keys", "generate", "-m", MGM, "-a", "ECCP256", "--pin-policy", "ALWAYS", "9c", "-")
out = yk("keys", "info", "9a")
assert "ALWAYS" in out, out
c.connect()
select(AID_PIV)
m = meta(0x9A)
pub = serialization.load_pem_public_key(open("/tmp/qk_9a.pem", "rb").read())
assert tlv_find(m, 0x01) == b"\x11" and tlv_find(m, 0x02) == b"\x02\x02" and tlv_find(m, 0x03) == b"\x01"
assert tlv_find(tlv_find(m, 0x04), 0x86) == pub.public_bytes(serialization.Encoding.X962,
                                                              serialization.PublicFormat.UncompressedPoint)
assert tlv_find(meta(0x9D), 0x02) == b"\x02\x03" and tlv_find(meta(0x9C), 0x02) == b"\x03\x01"
print("PIV: generation with touch policies, PIN policy fixed per slot, slot metadata")

def sign(slot):
    h = hashlib.sha256(slot.to_bytes(1, "big")).digest()
    resp = cmd(0x87, 0x11, slot, tlv(0x7C, b"\x82\x00" + tlv(0x81, h)))
    return h, tlv_find(tlv_find(resp, 0x7C), 0x82)

cmd(0x20, 0x00, 0x80, pin8("314159"), le=False)
print("PRESS BUTTON (Use PIV key? Slot 9A)")
h, sig = sign(0x9A)
pub.verify(sig, h, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
print("PRESS BUTTON (Use PIV key? Slot 9D)")
sign(0x9D)
t = time.time()
sign(0x9D)                                                  # cached: no press
assert time.time() - t < 3
print("PIV: touch ALWAYS asks, CACHED asks once")

print("PRESS BUTTON (Reset PIV?)")
cmd(0xFB, 0x00, 0x00, le=False)
c.disconnect()

# ---- OpenPGP: the last request is left unpressed ----
c.connect()
select(AID_PGP)
cmd(0x20, 0x00, 0x83, b"27182818", le=False)
cmd(0x20, 0x00, 0x81, b"314159", le=False)
if "--timeout" in sys.argv:
    print("\n" + "!" * 64 + "\n!!  DO NOT PRESS the button now, even though the screen asks:   !!\n"
          "!!  waiting 30 s for the timeout (the signature must be refused) !!\n" + "!" * 64)
    t = time.time()
    cmd(0x2A, 0x9E, 0x9A, digest, ok=0x6982)
    assert time.time() - t > 25
cmd(0xDA, 0x00, 0xD6, b"\x02\x20", le=False)               # fixed
cmd(0xDA, 0x00, 0xD6, b"\x00\x20", le=False, ok=0x6982)
assert cmd(0xCA, 0x00, 0xD6) == b"\x02\x20"
cmd(0xE6, 0x00, 0x00, le=False)                             # card reset clears it
cmd(0x44, 0x00, 0x00, le=False)
select(AID_PGP)
assert cmd(0xCA, 0x00, 0xD6) == b"\x00\x20"
print("OpenPGP: UIF fixed can only be cleared by a card reset" + (", timeout refused" if "--timeout" in sys.argv else ""))
print("touch tests passed")
