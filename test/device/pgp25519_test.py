# OpenPGP Ed25519 / X25519: on-card generation, signing, ECDH, import. No button presses.
# Ends with a card reset (terminate + activate): RSA attributes, PINs unchanged.
import hashlib
from smartcard.System import readers
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

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

def cmd(ins, p1, p2, data=b"", le=False, ok=0x9000):
    return tx([0x00, ins, p1, p2, len(data)] + list(data) + ([0] if le else []), ok)

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
        if t == tag: return b[i:i + l]
        i += l

raw = lambda k: k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
OID_ED = bytes.fromhex("2B06010401DA470F01")
OID_CV = bytes.fromhex("2B060104019755010501")
CRT = {"sig": 0xB6, "dec": 0xB8, "aut": 0xA4}

def select():
    tx([0x00, 0xA4, 0x04, 0x00, 6, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])

def pubkey(slot, generate=False):
    resp = cmd(0x47, 0x80 if generate else 0x81, 0x00, bytes([CRT[slot], 0x00]), le=True)
    return tlv_find(tlv_find(resp, 0x7F49), 0x86)

def import_key(slot, priv):
    body = bytes([CRT[slot], 0x00]) + tlv(0x7F48, bytes([0x92, len(priv)])) + tlv(0x5F48, priv)
    cmd(0xDB, 0x3F, 0xFF, tlv(0x4D, body))

select()
cmd(0x20, 0x00, 0x83, b"27182818")
cmd(0xDA, 0x00, 0xC1, bytes([0x16]) + OID_ED)
cmd(0xDA, 0x00, 0xC2, bytes([0x12]) + OID_CV)
cmd(0xDA, 0x00, 0xC3, bytes([0x16]) + OID_ED)
cmd(0xDA, 0x00, 0xC2, bytes([0x16]) + OID_ED, ok=0x6A80)        # EdDSA not allowed for decryption

sig_pub = pubkey("sig", generate=True)
dec_pub = pubkey("dec", generate=True)
aut_pub = pubkey("aut", generate=True)
assert len(sig_pub) == len(dec_pub) == len(aut_pub) == 32
select()
assert pubkey("sig") == sig_pub                                  # readable without a PIN

cmd(0x20, 0x00, 0x81, b"314159")
digest = hashlib.sha256(b"hello ed25519").digest()
sig = cmd(0x2A, 0x9E, 0x9A, digest, le=True)
Ed25519PublicKey.from_public_bytes(sig_pub).verify(sig, digest)
print("Ed25519 signature key: generated on card, signature verified")

cmd(0x20, 0x00, 0x82, b"314159")
for prefix in (b"", b"\x40"):
    eph = X25519PrivateKey.generate()
    expect = eph.exchange(X25519PublicKey.from_public_bytes(dec_pub))
    point = prefix + raw(eph.public_key())
    z = cmd(0x2A, 0x80, 0x86, tlv(0xA6, tlv(0x7F49, tlv(0x86, point))), le=True)
    assert z == expect, (z.hex(), expect.hex())
print("X25519 decryption key: ECDH matches the host (with and without 0x40 prefix)")

challenge = b"ssh challenge"
Ed25519PublicKey.from_public_bytes(aut_pub).verify(cmd(0x88, 0x00, 0x00, challenge, le=True), challenge)
print("Ed25519 authentication key: internal authenticate verified")

# Import: RFC 8032 seed and the RFC 7748 scalar sent big-endian (as GnuPG does)
cmd(0x20, 0x00, 0x83, b"27182818")
import_key("sig", bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
assert pubkey("sig").hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
alice = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
import_key("dec", alice[::-1])
assert pubkey("dec").hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
print("import: Ed25519 seed and big-endian X25519 scalar give the RFC public keys")

# Reset the card with PW3: terminate, activate. (Blocking PW3 would block the
# device admin PIN and turn activate into a factory reset.)
select()
cmd(0x20, 0x00, 0x83, b"27182818")
cmd(0xE6, 0x00, 0x00)
cmd(0x44, 0x00, 0x00)
select()
print("card reset; OpenPGP 25519 tests passed")
