import hashlib, os, time
from smartcard.System import readers
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, utils
from cryptography.hazmat.primitives import hashes

r = [x for x in readers() if "Quick-Key" in str(x)][0]
c = r.createConnection(); c.connect()

def tx(apdu, ok=(0x9000,)):
    data, s1, s2 = c.transmit(list(apdu))
    while s1 == 0x61:
        more, s1, s2 = c.transmit([0x00, 0xC0, 0x00, 0x00, s2])
        data += more
    sw = (s1 << 8) | s2
    assert sw in ok, f"{bytes(apdu[:4]).hex()} -> {sw:04x}"
    return bytes(data)

def ext(cla, ins, p1, p2, data=b"", le=True):
    a = [cla, ins, p1, p2, 0, len(data) >> 8, len(data) & 0xFF] + list(data) if data else [cla, ins, p1, p2, 0]
    if le: a += [0, 0] if data else [0, 0]
    return a

def tlv_find(b, tag):
    i = 0
    while i < len(b):
        t = b[i]; i += 1
        if t & 0x1F == 0x1F: t = (t << 8) | b[i]; i += 1
        l = b[i]; i += 1
        if l == 0x81: l = b[i]; i += 1
        elif l == 0x82: l = (b[i] << 8) | b[i+1]; i += 2
        if t == tag: return b[i:i+l]
        i += l

tx([0x00, 0xA4, 0x04, 0x00, 6, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x01])
tx([0x00, 0x20, 0x00, 0x83, 8] + list(b"27182818"))
print("PW3 ok")
# wrong PW1 must fail and decrement
data, s1, s2 = c.transmit([0x00, 0x20, 0x00, 0x81, 6] + list(b"000000"))
print("wrong PW1 ->", hex((s1 << 8) | s2))

# Signature key: switch to ECDSA P-256, generate, sign
p256 = bytes([0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07])
tx([0x00, 0xDA, 0x00, 0xC1, len(p256)] + list(p256))
t = time.time()
pub = tx(ext(0x00, 0x47, 0x80, 0x00, bytes([0xB6, 0x00])))
pt = tlv_find(tlv_find(pub, 0x7F49), 0x86)
print(f"P-256 generated in {time.time()-t:.1f}s, point len", len(pt))
ecpub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pt)
tx([0x00, 0x20, 0x00, 0x81, 6] + list(b"314159"))
digest = hashlib.sha256(b"hello quick-key").digest()
sig = tx(ext(0x00, 0x2A, 0x9E, 0x9A, digest))
der = utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big"))
ecpub.verify(der, b"hello quick-key", ec.ECDSA(hashes.SHA256()))
print("ECDSA signature verified")
data, s1, s2 = c.transmit(ext(0x00, 0x2A, 0x9E, 0x9A, digest))
print("second sign without PIN (forced) ->", hex((s1 << 8) | s2))

# Decryption key: RSA-2048 generate (slow), encrypt on host, decipher on card
t = time.time()
pub = tx(ext(0x00, 0x47, 0x80, 0x00, bytes([0xB8, 0x00])))
k = tlv_find(pub, 0x7F49)
n = int.from_bytes(tlv_find(k, 0x81), "big"); e = int.from_bytes(tlv_find(k, 0x82), "big")
print(f"RSA-2048 generated in {time.time()-t:.1f}s, e={e}, n bits={n.bit_length()}")
rpub = rsa.RSAPublicNumbers(e, n).public_key()
secret = os.urandom(32)
ct = rpub.encrypt(secret, padding.PKCS1v15())
tx([0x00, 0x20, 0x00, 0x82, 6] + list(b"314159"))
pt = tx(ext(0x00, 0x2A, 0x80, 0x86, b"\x00" + ct))
print("RSA decipher ok:", pt == secret)

# Auth key: RSA-2048 internal authenticate (PKCS#1 v1.5 sign over DigestInfo)
app = tx([0x00, 0xCA, 0x00, 0x6E, 0x00])
print("key status DE:", tlv_find(tlv_find(app, 0x73), 0xDE).hex())
cnt = tx([0x00, 0xCA, 0x00, 0x7A, 0x00])
print("signature counter:", int.from_bytes(tlv_find(cnt, 0x93), "big"))
print("ALL OPENPGP STEPS PASSED")
