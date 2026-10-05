# OpenPGP: a malformed key import is rejected and leaves the existing key
# working (same public key, still signs, key status unchanged). No button
# presses. Ends with a card reset (terminate + activate); PINs unchanged.
# Run `gpgconf --kill scdaemon` first.
import hashlib
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

def cmd(ins, p1, p2, data=b"", le=True, ok=0x9000):
    return tx([0x00, ins, p1, p2] + ([len(data)] + list(data) if data else []) + ([0] if le else []), ok)

def tlv(tag, v):
    t = tag.to_bytes(2, "big") if tag > 0xFF else bytes([tag])
    return t + (bytes([len(v)]) if len(v) < 0x80 else bytes([0x81, len(v)])) + v

OID_P256 = bytes.fromhex("2A8648CE3D030107")
cmd(0xA4, 0x04, 0x00, bytes.fromhex("D27600012401"))
cmd(0x20, 0x00, 0x83, b"27182818", le=False)
cmd(0xDA, 0x00, 0xC1, b"\x13" + OID_P256, le=False)
pub = cmd(0x47, 0x80, 0x00, b"\xB6\x00")
status = cmd(0xCA, 0x00, 0xDE)

# Private key of 33 bytes (P-256 takes at most 32): rejected.
bad = tlv(0x4D, b"\xB6\x00" + tlv(0x7F48, b"\x92\x21") + tlv(0x5F48, b"\x01" * 33))
cmd(0xDB, 0x3F, 0xFF, bad, le=False, ok=0x6A80)
# No private key at all: rejected.
bad = tlv(0x4D, b"\xB6\x00" + tlv(0x7F48, b"") + tlv(0x5F48, b""))
cmd(0xDB, 0x3F, 0xFF, bad, le=False, ok=0x6A80)

assert cmd(0x47, 0x81, 0x00, b"\xB6\x00") == pub
assert cmd(0xCA, 0x00, 0xDE) == status
cmd(0x20, 0x00, 0x81, b"314159", le=False)
assert len(cmd(0x2A, 0x9E, 0x9A, hashlib.sha256(b"keep").digest())) == 64
print("OpenPGP: malformed imports rejected, the existing key still signs")

cmd(0xE6, 0x00, 0x00, le=False)
cmd(0x44, 0x00, 0x00, le=False)
c.disconnect()
print("OpenPGP keep tests passed")
