# PIV RSA-2048: generation (ykman), self-signed certificates, raw signature and
# decryption over GENERAL AUTHENTICATE with command chaining, 9E without a PIN,
# RSA and P-256 keys side by side. Resets PIV at the end (1 button press).
import subprocess, time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from smartcard.System import readers

MGM = "010203040506070801020304050607080102030405060708"
RSA, ECC = 0x07, 0x11

def yk(*args, ok=True):
    p = subprocess.run(["ykman", "--reader", "Quick-Key", "piv", *args], capture_output=True, text=True)
    assert (p.returncode == 0) == ok, f"ykman piv {' '.join(args)}: {p.stdout}{p.stderr}"
    return p.stdout

def pubkey(slot):
    return serialization.load_pem_public_key(open(f"/tmp/qk_{slot}.pem", "rb").read())

for slot, alg in (("9a", "RSA2048"), ("9c", "ECCP256"), ("9d", "RSA2048"), ("9e", "RSA2048")):
    t = time.time()
    yk("keys", "generate", "-m", MGM, "-a", alg, slot, f"/tmp/qk_{slot}.pem")
    gen = time.time() - t
    t = time.time()
    yk("certificates", "generate", "-m", MGM, "-P", "314159", "-s", f"CN=rsa {slot}", slot, f"/tmp/qk_{slot}.pem")
    print(f"PIV {slot} {alg}: generated {gen:.1f}s, certificate {time.time() - t:.1f}s")
    pub = pubkey(slot)
    if alg == "RSA2048":
        assert isinstance(pub, rsa.RSAPublicKey) and pub.key_size == 2048 and pub.public_numbers().e == 65537
    else:
        assert isinstance(pub, ec.EllipticCurvePublicKey)

# Certificates are self-signed by the card key: check the signature.
for slot in ("9a", "9c", "9d", "9e"):
    pem = yk("certificates", "export", slot, "-")
    crt = x509.load_pem_x509_certificate(pem.encode())
    pub = crt.public_key()
    if slot == "9c":
        pub.verify(crt.signature, crt.tbs_certificate_bytes, ec.ECDSA(crt.signature_hash_algorithm))
    else:
        pub.verify(crt.signature, crt.tbs_certificate_bytes, padding.PKCS1v15(), crt.signature_hash_algorithm)
print("PIV: certificate signatures verify")

# ---- raw APDUs ----
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

def send(ins, p1, p2, data, ok=0x9000):
    # Command chaining in 255-byte pieces.
    while len(data) > 255:
        tx([0x10, ins, p1, p2, 255] + list(data[:255]), ok=0x9000)
        data = data[255:]
    return tx([0x00, ins, p1, p2, len(data)] + list(data) + [0], ok)

def rsa_op(slot, block, ok=0x9000, alg=RSA):
    body = bytes([0x82, 0x00, 0x81, 0x82, 0x01, 0x00]) + block
    resp = send(0x87, alg, slot, bytes([0x7C, 0x82, 0x01, 0x06]) + body, ok)
    if ok != 0x9000:
        return None
    assert resp[:8] == bytes([0x7C, 0x82, 0x01, 0x04, 0x82, 0x82, 0x01, 0x00]), resp[:8].hex()
    return resp[8:]

def verify_pin():
    tx([0x00, 0x20, 0x00, 0x80, 8] + list(b"314159\xff\xff"))

tx([0x00, 0xA4, 0x04, 0x00, 5, 0xA0, 0x00, 0x00, 0x03, 0x08])

# Decryption in 9D: the card returns the padded block, the host strips it.
pub9d = pubkey("9d")
secret = b"quick-key rsa decrypt"
ct = pub9d.encrypt(secret, padding.PKCS1v15())
rsa_op(0x9D, ct, ok=0x6982)                                 # no PIN
verify_pin()
t = time.time()
em = rsa_op(0x9D, ct)
print(f"PIV 9D: decrypt {time.time() - t:.2f}s")
assert em[:2] == b"\x00\x02" and em.endswith(b"\x00" + secret)
rsa_op(0x9D, ct, ok=0x6A86, alg=ECC)                        # wrong algorithm for the slot

# 9E: RSA signature without a PIN, checked with the public key.
c.disconnect(); c.connect()
tx([0x00, 0xA4, 0x04, 0x00, 5, 0xA0, 0x00, 0x00, 0x03, 0x08])
pub9e = pubkey("9e")
msg = b"card authentication"
h = hashes.Hash(hashes.SHA256()); h.update(msg)
di = bytes.fromhex("3031300d060960864801650304020105000420") + h.finalize()
block = b"\x00\x01" + b"\xff" * (256 - 3 - len(di)) + b"\x00" + di
sig = rsa_op(0x9E, block)
pub9e.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
rsa_op(0x9A, block, ok=0x6982)                              # 9A needs the PIN
print("PIV: 9E RSA signs without a PIN, 9A needs it")

# Input as large as the modulus is rejected.
verify_pin()
rsa_op(0x9A, b"\xff" * 256, ok=0x6A80)

# Not `ykman piv reset`: it blocks PIN and PUK (the device PINs) first.
tx([0x00, 0xA4, 0x04, 0x00, 5, 0xA0, 0x00, 0x00, 0x03, 0x08])
print("PRESS BUTTON (Reset PIV?)")
tx([0x00, 0xFB, 0x00, 0x00])
c.disconnect()
print("PIV RSA tests passed")
