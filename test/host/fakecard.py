"""Software models of the key's smart card applications for tests without a key.

FakeCard has the interface of qk.Card (select, send) and behaves like the
firmware's OpenPGP application (main/apps/openpgp.c): PIN checks, algorithm
attributes, key generation and import with real keys, signing, cardholder data.
Install it with `fakecard.install()`: qk.Card then returns the shared instance.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../tools"))
import qk  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization as ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils, x25519  # noqa: E402

PIN, ADMIN = "314159", "27182818"
OID = {"nistp256": bytes.fromhex("2A8648CE3D030107"), "ed25519": bytes.fromhex("2B06010401DA470F01"),
       "cv25519": bytes.fromhex("2B060104019755010501")}


class FakeCard:
    def __init__(self):
        self.app = None
        self.pin, self.admin = PIN, ADMIN
        self.tries = {"pin": 8, "admin": 3}
        self.reset_pgp()
        self.reset_piv()
        self.ok = set()
        self.presses = []              # what asked for the button

    def reset_piv(self):
        self.mgmt_alg, self.mgmt_key = 3, bytes.fromhex("0102030405060708" * 3)
        self.piv_keys = {}              # slot -> (private key, alg id, touch)
        self.objects = {}
        self.challenge = None

    def reset_pgp(self):
        rsa_attr = bytes.fromhex("010800002000")
        self.attr = [rsa_attr] * 3
        self.keys = [None] * 3          # (private object, status)
        self.fp = [bytes(20)] * 3
        self.date = [bytes(4)] * 3
        self.uif = [0, 0, 0]
        self.holder = {0x5B: b"", 0x5F2D: b"", 0x5F35: b"\x00"}
        self.url, self.login = b"", b""
        self.sig_count = 0

    # ---- Card interface
    def select(self, aid):
        if aid == qk.AID_PGP:
            self.app, self.ok = "pgp", set()
            return b"", 0x9000
        if aid == qk.AID_PIV:
            self.app, self.ok = "piv", set()
            return b"", 0x9000
        return b"", 0x6A82

    def send(self, cla, ins, p1, p2, data=b"", check=True):
        data = bytes(data)
        resp, sw = (self.process_piv if self.app == "piv" else self.process)(ins, p1, p2, data)
        if check and sw != 0x9000:
            raise RuntimeError(f"card error {sw:04X} (INS {ins:02X})")
        return resp, sw

    # ---- helpers
    def algo(self, k):
        a = self.attr[k]
        if a[0] == 1:
            return "rsa2048"
        if a[0] == 0x16:
            return "ed25519"
        if a[0] == 0x12 and a[1:] == OID["cv25519"]:
            return "cv25519"
        return "nistp256"

    def pub_tlv(self, k):
        priv, _ = self.keys[k]
        algo = self.algo(k)
        if algo == "rsa2048":
            n = priv.public_key().public_numbers()
            e = n.e.to_bytes(4, "big").lstrip(b"\0")
            return qk.tlv(0x7F49, qk.tlv(0x81, n.n.to_bytes(256, "big")) + qk.tlv(0x82, e))
        if algo in ("ed25519", "cv25519"):
            raw = priv.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
            return qk.tlv(0x7F49, qk.tlv(0x86, raw))
        pt = priv.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)
        return qk.tlv(0x7F49, qk.tlv(0x86, pt))

    def check_pin(self, which, pin):
        if self.tries[which] == 0:
            return 0x6983
        if pin != (self.pin if which == "pin" else self.admin):
            self.tries[which] -= 1
            return 0x63C0 | self.tries[which]
        self.tries[which] = 8 if which == "pin" else 3
        return 0x9000

    def app_data(self):
        info = b"".join(bytes([i + 1, 0 if not self.keys[i] else self.keys[i][1]]) for i in range(3))
        pw = bytes([0, 8, 8, 8, self.tries["pin"], 0, self.tries["admin"]])
        disc = (b"".join(qk.tlv(0xC1 + i, self.attr[i]) for i in range(3)) + qk.tlv(0xC4, pw) +
                qk.tlv(0xC5, b"".join(self.fp)) + qk.tlv(0xCD, b"".join(self.date)) + qk.tlv(0xDE, info) +
                b"".join(qk.tlv(0xD6 + i, bytes([self.uif[i], 0x20])) for i in range(3)))
        aid = bytes.fromhex("D2760001240103 04FFFE".replace(" ", "")) + bytes.fromhex("0000AB12") + b"\0\0"
        return qk.tlv(0x4F, aid) + qk.tlv(0x73, disc)

    # ---- the application
    def process(self, ins, p1, p2, data):
        if ins == 0x20:                                         # VERIFY
            ref = p2
            if ref == 0x83:
                sw = self.check_pin("admin", data.decode())
                (self.ok.add if sw == 0x9000 else self.ok.discard)("pw3")
                return b"", sw
            sw = self.check_pin("pin", data.decode())
            if sw == 0x9000:
                self.ok.add("pw1_%02x" % ref)
            return b"", sw
        if ins == 0xCA:                                         # GET DATA
            tag = (p1 << 8) | p2
            if tag == 0x6E:
                return self.app_data(), 0x9000
            if tag == 0x0065:
                return b"".join(qk.tlv(t, v) for t, v in self.holder.items()), 0x9000
            if tag == 0x5F50:
                return self.url, 0x9000
            if tag == 0x005E:
                return self.login, 0x9000
            if tag == 0x0093:
                return self.sig_count.to_bytes(3, "big"), 0x9000
            if 0xC1 <= tag <= 0xC3:
                return self.attr[tag - 0xC1], 0x9000
            return b"", 0x6A88
        if ins == 0xDA:                                         # PUT DATA
            if "pw3" not in self.ok:
                return b"", 0x6982
            tag = (p1 << 8) | p2
            if 0xC1 <= tag <= 0xC3:
                k = tag - 0xC1
                if data != self.attr[k]:
                    self.keys[k], self.fp[k], self.date[k] = None, bytes(20), bytes(4)
                    self.attr[k] = data
            elif 0xC7 <= tag <= 0xC9:
                self.fp[tag - 0xC7] = data
            elif 0xCE <= tag <= 0xD0:
                self.date[tag - 0xCE] = data
            elif tag in self.holder:
                self.holder[tag] = data
            elif tag == 0x5F50:
                self.url = data
            elif tag == 0x005E:
                self.login = data
            elif 0xD6 <= tag <= 0xD8:
                self.uif[tag - 0xD6] = data[0]
            else:
                return b"", 0x6A88
            return b"", 0x9000
        if ins == 0x47:                                         # GENERATE
            k = {0xB6: 0, 0xB8: 1, 0xA4: 2}[data[0]]
            if p1 == 0x81:
                return (self.pub_tlv(k), 0x9000) if self.keys[k] else (b"", 0x6A88)
            if "pw3" not in self.ok:
                return b"", 0x6982
            algo = self.algo(k)
            priv = {"rsa2048": lambda: rsa.generate_private_key(65537, 2048),
                    "ed25519": ed25519.Ed25519PrivateKey.generate, "cv25519": x25519.X25519PrivateKey.generate,
                    "nistp256": lambda: ec.generate_private_key(ec.SECP256R1())}[algo]()
            self.keys[k] = (priv, 1)
            return self.pub_tlv(k), 0x9000
        if ins == 0xDB:                                         # PUT DATA (odd): key import
            if "pw3" not in self.ok:
                return b"", 0x6982
            d = dict(qk.tlv_parse(data))[0x4D]
            k = {0xB6: 0, 0xB8: 1, 0xA4: 2}[d[0]]
            rest = dict(qk.tlv_parse(d[2:]))
            tl, body = rest[0x7F48], rest[0x5F48]
            algo = self.algo(k)
            if algo == "rsa2048":
                items = {}
                lens = list(tl)
                pos = 0
                while pos < len(lens):
                    tag, ln = lens[pos], lens[pos + 1]
                    pos += 2
                    if ln == 0x81:
                        ln = lens[pos]
                        pos += 1
                    items[tag] = ln
                e = body[:items[0x91]]
                p = int.from_bytes(body[items[0x91]:items[0x91] + 128], "big")
                q = int.from_bytes(body[items[0x91] + 128:items[0x91] + 256], "big")
                ei = int.from_bytes(e, "big")
                self.keys[k] = (rsa.RSAPrivateNumbers(
                    p, q, pow(ei, -1, (p - 1) * (q - 1)), pow(ei, -1, p - 1), pow(ei, -1, q - 1), pow(q, -1, p),
                    rsa.RSAPublicNumbers(ei, p * q)).private_key(), 2)
            elif algo == "ed25519":
                self.keys[k] = (ed25519.Ed25519PrivateKey.from_private_bytes(body), 2)
            elif algo == "cv25519":
                self.keys[k] = (x25519.X25519PrivateKey.from_private_bytes(body[::-1]), 2)
            else:
                self.keys[k] = (ec.derive_private_key(int.from_bytes(body, "big"), ec.SECP256R1()), 2)
            return b"", 0x9000
        if ins == 0x2A and (p1, p2) == (0x9E, 0x9A):            # PSO: COMPUTE DIGITAL SIGNATURE
            if "pw1_81" not in self.ok:
                return b"", 0x6982
            self.ok.discard("pw1_81")
            if self.uif[0]:
                self.presses.append("sign")
            priv = self.keys[0][0]
            self.sig_count += 1
            algo = self.algo(0)
            if algo == "ed25519":
                return priv.sign(data), 0x9000
            if algo == "nistp256":
                der = priv.sign(data, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                r, s = utils.decode_dss_signature(der)
                return r.to_bytes(32, "big") + s.to_bytes(32, "big"), 0x9000
            assert data.startswith(bytes.fromhex("3031300d060960864801650304020105000420"))
            return priv.sign(data[19:], padding.PKCS1v15(), utils.Prehashed(hashes.SHA256())), 0x9000
        if ins == 0xE6:                                         # TERMINATE DF
            if "pw3" not in self.ok:
                return b"", 0x6982
            self.reset_pgp()
            return b"", 0x9000
        if ins == 0x44:                                         # ACTIVATE FILE
            return b"", 0x9000
        return b"", 0x6D00

    # ---- PIV
    def process_piv(self, ins, p1, p2, data):
        if ins == 0xFD:
            return bytes([5, 4, 3]), 0x9000
        if ins == 0xF8:
            return bytes.fromhex("0000AB12"), 0x9000
        if ins == 0x20:                                         # VERIFY PIN
            if len(data) != 8:
                return b"", 0x6700
            pin = data.rstrip(b"\xff").decode()
            sw = self.check_pin("pin", pin)
            if sw == 0x9000:
                self.ok.add("piv_pin")
            return b"", sw
        if ins == 0xF7:                                         # GET METADATA
            return self.piv_metadata(p2)
        if ins == 0xCB:                                         # GET DATA
            tag = int.from_bytes(data[2:2 + data[1]], "big")
            obj = self.objects.get(tag)
            return (obj, 0x9000) if obj is not None else (b"", 0x6A82)
        if ins == 0xDB:                                         # PUT DATA
            if "piv_mgmt" not in self.ok:
                return b"", 0x6982
            tag = int.from_bytes(data[2:2 + data[1]], "big")
            rest = data[2 + data[1]:]
            if rest == b"\x53\x00":
                self.objects.pop(tag, None)
            else:
                self.objects[tag] = rest
            return b"", 0x9000
        if ins == 0x87:                                         # GENERAL AUTHENTICATE
            return self.piv_auth(p1, p2, data)
        if ins == 0x47:                                         # GENERATE
            if "piv_mgmt" not in self.ok:
                return b"", 0x6982
            ac = dict(qk.tlv_parse(data))[0xAC]
            fields = dict(qk.tlv_parse(ac))
            alg = fields[0x80][0]
            touch = fields.get(0xAB, b"\x01")[0]
            priv = rsa.generate_private_key(65537, 2048) if alg == 0x07 else ec.generate_private_key(ec.SECP256R1())
            self.piv_keys[p2] = (priv, alg, touch)
            return qk.tlv(0x7F49, self.piv_pub(p2)), 0x9000
        if ins == 0xFB:                                         # RESET (the button is pressed)
            self.presses.append("piv reset")
            self.reset_piv()
            return b"", 0x9000
        if ins == 0xFF:                                         # SET MANAGEMENT KEY
            if "piv_mgmt" not in self.ok:
                return b"", 0x6982
            self.mgmt_alg, self.mgmt_key = data[0], data[3:]
            return b"", 0x9000
        return b"", 0x6D00

    def piv_pub(self, slot):
        priv, alg, _ = self.piv_keys[slot]
        if alg == 0x07:
            n = priv.public_key().public_numbers()
            return qk.tlv(0x81, n.n.to_bytes(256, "big")) + qk.tlv(0x82, n.e.to_bytes(3, "big"))
        return qk.tlv(0x86, priv.public_key().public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint))

    def piv_metadata(self, ref):
        if ref == 0x9B:
            default = int(self.mgmt_alg == 3 and self.mgmt_key == bytes.fromhex("0102030405060708" * 3))
            return qk.tlv(0x01, bytes([self.mgmt_alg])) + qk.tlv(0x02, b"\x00\x01") + qk.tlv(0x05, bytes([default])), 0x9000
        if ref == 0x80:
            return qk.tlv(0x01, b"\xff") + qk.tlv(0x05, b"\x00") + qk.tlv(0x06, bytes([8, self.tries["pin"]])), 0x9000
        if ref not in self.piv_keys:
            return b"", 0x6A88
        _, alg, touch = self.piv_keys[ref]
        policy = bytes([3 if ref == 0x9C else 1 if ref == 0x9E else 2, touch])
        return (qk.tlv(0x01, bytes([alg])) + qk.tlv(0x02, policy) + qk.tlv(0x03, b"\x01") +
                qk.tlv(0x04, self.piv_pub(ref))), 0x9000

    def piv_auth(self, p1, p2, data):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        tpl = dict(qk.tlv_parse(qk.tlv_get(data, 0x7C)))
        if p2 == 0x9B:
            if p1 != self.mgmt_alg:
                return b"", 0x6A86
            bs = 8 if self.mgmt_alg == 3 else 16
            if 0x81 in tpl and tpl[0x81] == b"":
                self.challenge = os.urandom(bs)
                return qk.tlv(0x7C, qk.tlv(0x81, self.challenge)), 0x9000
            if 0x82 in tpl and self.challenge:
                try:
                    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
                except ImportError:
                    TripleDES = algorithms.TripleDES
                alg = TripleDES(self.mgmt_key) if self.mgmt_alg == 3 else algorithms.AES(self.mgmt_key)
                enc = Cipher(alg, modes.ECB()).encryptor()
                ok = enc.update(self.challenge) + enc.finalize() == tpl[0x82]
                self.challenge = None
                if ok:
                    self.ok.add("piv_mgmt")
                return b"", 0x9000 if ok else 0x6982
            return b"", 0x6A80
        if p2 not in self.piv_keys:
            return b"", 0x6A88
        if p2 != 0x9E and "piv_pin" not in self.ok:
            return b"", 0x6982
        if p2 == 0x9C:
            self.ok.discard("piv_pin")
        priv, alg, touch = self.piv_keys[p2]
        if touch in (2, 3):
            self.presses.append(f"piv{p2:02x}")
        data = tpl[0x81]
        if alg == 0x07:
            nums = priv.private_numbers()
            sig = pow(int.from_bytes(data, "big"), nums.d, nums.public_numbers.n).to_bytes(256, "big")
        else:
            sig = priv.sign(data, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return qk.tlv(0x7C, qk.tlv(0x82, sig)), 0x9000


_card = None


def install():
    """Makes qk.Card() return one shared FakeCard (a fresh one each call of install)."""
    global _card
    _card = FakeCard()
    qk.Card = lambda: _card
    return _card
