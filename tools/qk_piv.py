"""PIV smart card management for qk: key generation, certificates (view,
import, export, delete), self-signed certificates and signing requests made
with the key on the card, public key export and the management key.

Like the functions in qk.py, these return data and raise qk.QkError, so that
the TUI can use them too. The card has no key import and no key deletion:
a key is replaced by generating a new one, or erased with `qk piv reset`.
"""
import datetime
import hashlib
import os
import sys

import qk
import qk_pgp
from qk import die, tlv, tlv_get

ALGS = {0x07: "rsa2048", 0x11: "nistp256"}
ALG_IDS = {v: k for k, v in ALGS.items()}
TOUCH = {1: "never", 2: "always", 3: "cached"}
TOUCH_IDS = {v: k for k, v in TOUCH.items()}
PIN_POLICY = {1: "never", 2: "once", 3: "always"}
MGMT_ALGS = {"3des": (0x03, 24), "aes128": (0x08, 16), "aes192": (0x0A, 24), "aes256": (0x0C, 32)}
DEFAULT_MGMT = bytes.fromhex("0102030405060708" * 3)
SLOT_NAMES = {f"{slot:02x}": slot for slot, _, _ in qk.PIV_SLOTS}
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def card():
    return qk.piv_card()


def slot_of(name):
    """0x9A.. from "9a" / "9A" / 154."""
    if isinstance(name, int):
        return name
    slot = SLOT_NAMES.get(str(name).lower().removeprefix("0x"))
    if slot is None:
        die(f"slot: one of {', '.join(sorted(SLOT_NAMES))}")
    return slot


def cert_tag(slot):
    return next(tag for s, _, tag in qk.PIV_SLOTS if s == slot)


def get_object(c, tag):
    resp, sw = c.send(0x00, 0xCB, 0x3F, 0xFF, bytes([0x5C, 3]) + tag.to_bytes(3, "big"), check=False)
    return resp if sw == 0x9000 else None


def metadata(c, ref):
    resp, sw = c.send(0x00, 0xF7, 0x00, ref, check=False)
    return resp if sw == 0x9000 else None


# ---------------------------------------------------------------- certificates

def load_cert(der):
    from cryptography import x509
    try:
        return x509.load_der_x509_certificate(der)
    except ValueError:
        die("not a certificate")


def read_cert(slot, c=None):
    """DER of the certificate in a slot, or None."""
    obj = get_object(c or card(), cert_tag(slot))
    return tlv_get(tlv_get(obj, 0x53) or b"", 0x70) if obj else None


def cert_summary(der):
    from cryptography.hazmat.primitives import hashes
    cert = load_cert(der)
    utc = lambda name: getattr(cert, name + "_utc", None) or getattr(cert, name)  # noqa: E731
    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "not_before": utc("not_valid_before"), "not_after": utc("not_valid_after"),
            "serial": f"{cert.serial_number:X}", "fingerprint": cert.fingerprint(hashes.SHA256()).hex().upper(),
            "self_signed": cert.subject == cert.issuer}


def safe_summary(der):
    """cert_summary, or a stand-in when the object in the slot is not a certificate we can read."""
    if not der:
        return None
    try:
        return cert_summary(der)
    except qk.QkError:
        return {"subject": "(unreadable certificate)", "issuer": "", "not_before": datetime.datetime.min,
                "not_after": datetime.datetime.min, "serial": "", "fingerprint": "0" * 64, "self_signed": False}


def cert_text(der):
    """Human-readable lines of a certificate."""
    s = cert_summary(der)
    fp = s["fingerprint"]
    return "\n".join([f"subject      {s['subject']}", f"issuer       {s['issuer']}",
                      f"valid from   {s['not_before']:%Y-%m-%d}", f"valid until  {s['not_after']:%Y-%m-%d}",
                      f"serial       {s['serial']}", f"SHA-256      {' '.join(fp[i:i + 4] for i in range(0, 64, 4))}"])


# ---------------------------------------------------------------- status

def public_key(c, slot):
    """{"algo", "point"} or {"algo", "n", "e"} of the key in a slot (readable without a PIN), or None."""
    meta = metadata(c, slot)
    if not meta:
        return None
    algo = ALGS.get((tlv_get(meta, 0x01) or b"\0")[0])
    body = tlv_get(meta, 0x04)
    if not body or not algo:
        return None
    if algo == "rsa2048":
        return {"algo": algo, "n": tlv_get(body, 0x81), "e": tlv_get(body, 0x82)}
    return {"algo": algo, "point": tlv_get(body, 0x86)}


def details():
    """{"serial", "mgmt": {"algo", "default"}, "pin_default", "slots": [{"slot", "name", "key", "touch",
    "pin_policy", "cert"}]}: the key and certificate of every slot (without a PIN)."""
    c = card()
    serial, _ = c.send(0x00, 0xF8, 0x00, 0x00, check=False)
    mm = metadata(c, 0x9B) or b""
    pm = metadata(c, 0x80) or b""
    mgmt_alg = next((n for n, (i, _) in MGMT_ALGS.items() if i == (tlv_get(mm, 0x01) or b"\0")[0]), "3des")
    slots = []
    for slot, name, _ in qk.PIV_SLOTS:
        pub, meta = public_key(c, slot), metadata(c, slot)
        pol = tlv_get(meta, 0x02) if meta else None
        der = read_cert(slot, c)
        slots.append({"slot": slot, "name": name, "key": pub,
                      "touch": TOUCH.get(pol[1], "?") if pol else None,
                      "pin_policy": PIN_POLICY.get(pol[0], "?") if pol else None,
                      "cert": safe_summary(der), "cert_der": der})
    return {"serial": serial.hex().upper() if serial else "", "mgmt": {"algo": mgmt_alg,
            "default": bool((tlv_get(mm, 0x05) or b"\0")[0])}, "pin_default": bool((tlv_get(pm, 0x05) or b"\0")[0]),
            "slots": slots}


# ---------------------------------------------------------------- authentication

def block_cipher(alg_id, key):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if alg_id == 0x03:
        try:
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
        except ImportError:                                  # cryptography < 43
            TripleDES = algorithms.TripleDES
        return Cipher(TripleDES(key), modes.ECB())
    return Cipher(algorithms.AES(key), modes.ECB())


def parse_mgmt_key(text):
    """Bytes of a management key written in hex; empty means the factory key."""
    text = (text or "").replace(" ", "")
    if not text:
        return DEFAULT_MGMT
    try:
        key = bytes.fromhex(text)
    except ValueError:
        die("management key: hex digits only")
    if len(key) not in (16, 24, 32):
        die("management key: 16, 24 or 32 bytes (32, 48 or 64 hex digits)")
    return key


def authenticate(c, key=None):
    """Proves knowledge of the management key to the card (external authentication)."""
    key = key or DEFAULT_MGMT
    mm = metadata(c, 0x9B)
    alg = (tlv_get(mm, 0x01) or b"\x03")[0] if mm else 0x03
    resp, sw = c.send(0x00, 0x87, alg, 0x9B, bytes([0x7C, 0x02, 0x81, 0x00]), check=False)
    if sw != 0x9000:
        raise RuntimeError(f"card error {sw:04X} (management key)")
    challenge = tlv_get(tlv_get(resp, 0x7C), 0x81)
    expected = {0x03: 24, 0x08: 16, 0x0A: 24, 0x0C: 32}.get(alg)
    if len(key) != expected:
        die(f"the card's management key is {'3DES (48 hex digits)' if alg == 3 else f'AES-{expected * 8} ({expected * 2} hex digits)'}")
    enc = block_cipher(alg, key).encryptor()
    answer = enc.update(challenge) + enc.finalize()
    _, sw = c.send(0x00, 0x87, alg, 0x9B, tlv(0x7C, tlv(0x82, answer)), check=False)
    if sw != 0x9000:
        die("wrong management key")


def verify_pin(c, pin):
    _, sw = c.send(0x00, 0x20, 0x00, 0x80, qk.pin_bytes(pin), check=False)
    qk.pin_error(sw)


# ---------------------------------------------------------------- keys

def generate(slot, algo, touch="never", mgmt_key=None, drop_cert=True):
    """Makes a key in a slot (replacing the old one, and by default its now stale certificate);
    returns its public part."""
    if algo not in ALG_IDS:
        die("algorithm: nistp256 or rsa2048")
    if touch not in TOUCH_IDS:
        die("touch: never, always or cached")
    c = card()
    authenticate(c, mgmt_key)
    policy = tlv(0xAB, bytes([TOUCH_IDS[touch]])) if touch != "never" else b""
    resp, sw = c.send(0x00, 0x47, 0x00, slot, tlv(0xAC, tlv(0x80, bytes([ALG_IDS[algo]])) + policy), check=False)
    if sw == 0x6985:
        die(qk.DEFAULT_PINS)
    if sw != 0x9000:
        raise RuntimeError(f"card error {sw:04X} (GENERATE)")
    if drop_cert and read_cert(slot, c):
        put_object(c, cert_tag(slot), b"\x53\x00")
    return public_key(c, slot)


def pub_pem(pub):
    """A public key (as public_key() returns it) as PEM (SubjectPublicKeyInfo)."""
    from cryptography.hazmat.primitives import serialization as ser
    return key_object(pub).public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo).decode()


def public_pem(slot):
    """The public key of a slot as PEM."""
    pub = public_key(card(), slot)
    if not pub:
        die(f"slot {slot:02X} has no key")
    return pub_pem(pub)


def ssh_line(slot, comment=""):
    pub = public_key(card(), slot)
    if not pub:
        die(f"slot {slot:02X} has no key")
    return qk_pgp.ssh_public_key(pub, comment)


def key_object(pub):
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    if pub["algo"] == "rsa2048":
        return rsa.RSAPublicNumbers(int.from_bytes(pub["e"], "big"), int.from_bytes(pub["n"], "big")).public_key()
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pub["point"])


# ---------------------------------------------------------------- certificates on the card

def put_object(c, tag, value):
    _, sw = c.send(0x00, 0xDB, 0x3F, 0xFF, bytes([0x5C, 3]) + tag.to_bytes(3, "big") + value, check=False)
    if sw == 0x6982:
        die("management key not accepted")
    if sw == 0x6A84:
        die("not enough room on the key for this certificate")
    if sw != 0x9000:
        raise RuntimeError(f"card error {sw:04X} (PUT DATA)")


def import_cert(slot, data, mgmt_key=None):
    """Stores a certificate (PEM or DER) in a slot; it must belong to the key in that slot."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization as ser
    try:
        cert = x509.load_pem_x509_certificate(data) if b"-----BEGIN" in data else x509.load_der_x509_certificate(data)
    except ValueError:
        die("not a certificate (PEM or DER)")
    c = card()
    pub = public_key(c, slot)
    if pub:
        spki = ser.PublicFormat.SubjectPublicKeyInfo
        if key_object(pub).public_bytes(ser.Encoding.DER, spki) != cert.public_key().public_bytes(ser.Encoding.DER, spki):
            die(f"this certificate is for another key than the one in slot {slot:02X}")
    der = cert.public_bytes(ser.Encoding.DER)
    authenticate(c, mgmt_key)
    put_object(c, cert_tag(slot), tlv(0x53, tlv(0x70, der) + b"\x71\x01\x00\xFE\x00"))


def delete_cert(slot, mgmt_key=None):
    c = card()
    authenticate(c, mgmt_key)
    put_object(c, cert_tag(slot), b"\x53\x00")


def cert_pem(der):
    from cryptography.hazmat.primitives import serialization as ser
    return load_cert(der).public_bytes(ser.Encoding.PEM).decode()


def export_cert(slot):
    """PEM of the certificate in a slot."""
    der = read_cert(slot)
    if not der:
        die(f"slot {slot:02X} has no certificate")
    return cert_pem(der)


# ---------------------------------------------------------------- signing on the card

def card_sign(c, slot, pub, message):
    """Signature of `message` (SHA-256) by the key in a slot: DER for ECDSA, raw for RSA."""
    digest = hashlib.sha256(message).digest()
    if pub["algo"] == "rsa2048":
        data = b"\x00\x01" + b"\xFF" * (256 - 3 - 19 - 32) + b"\x00" + SHA256_DIGEST_INFO + digest
    else:
        data = digest
    resp, sw = c.send(0x00, 0x87, ALG_IDS[pub["algo"]], slot, tlv(0x7C, tlv(0x82, b"") + tlv(0x81, data)), check=False)
    if sw == 0x6982:
        die("the PIN was refused or the button was not pressed in time")
    if sw != 0x9000:
        raise RuntimeError(f"card error {sw:04X} (signature)")
    return tlv_get(tlv_get(resp, 0x7C), 0x82)


def der_items(b):
    """The complete TLVs inside a DER structure's content."""
    out, i = [], 0
    while i < len(b):
        j = i + 1
        n = b[j]
        j += 1
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(b[j:j + k], "big")
            j += k
        out.append(b[i:j + n])
        i = j + n
    return out


def der_content(b):
    """The content of the outer TLV."""
    n = b[1]
    return b[2:] if n < 0x80 else b[2 + (n & 0x7F):]


def dummy_key(algo):
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    return rsa.generate_private_key(65537, 1024) if algo == "rsa2048" else ec.generate_private_key(ec.SECP256R1())


def sign_structure(slot, pin, build, c=None):
    """Makes a certificate or a request whose signature comes from the card: `build(key)` signs the
    structure with a stand-in key of the same type; its signed part is signed again by the card
    and joined with the algorithm identifier and the card's signature."""
    from cryptography.hazmat.primitives import hashes
    c = c or card()
    pub = public_key(c, slot)
    if not pub:
        die(f"slot {slot:02X} has no key: generate one first")
    stand_in = build(dummy_key(pub["algo"]), key_object(pub), hashes.SHA256())
    tbs, algorithm, _ = der_items(der_content(stand_in))
    if slot != 0x9E:
        verify_pin(c, pin)
    sig = card_sign(c, slot, pub, tbs)
    return tlv(0x30, tbs + algorithm + tlv(0x03, b"\x00" + sig))


def parse_subject(text):
    from cryptography import x509
    try:
        return x509.Name.from_rfc4514_string(text)
    except ValueError:
        die("subject: write it like CN=Jane Doe,O=Example")


def self_signed(slot, pin, subject, days=365, mgmt_key=None):
    """Creates a self-signed certificate for the key in a slot (signed on the card, which needs
    the PIN and, with a touch policy, the button) and stores it there; returns the DER."""
    from cryptography import x509
    name = parse_subject(subject)
    if not 1 <= days <= 36500:
        die("days: 1 to 36500")
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)

    def build(stand_in, pub, hash_):
        return (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(pub)
                .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
                .not_valid_after(now + datetime.timedelta(days=days))
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
                .sign(stand_in, hash_)).public_bytes(_der())
    c = card()
    authenticate(c, mgmt_key)                       # first: a wrong key must not cost a PIN try and a press
    der = sign_structure(slot, pin, build, c)
    put_object(c, cert_tag(slot), tlv(0x53, tlv(0x70, der) + b"\x71\x01\x00\xFE\x00"))
    return der


def csr(slot, pin, subject):
    """A PEM certificate signing request for the key in a slot, signed on the card."""
    return pem("CERTIFICATE REQUEST", sign_request(slot, pin, parse_subject(subject)))


def _der():
    from cryptography.hazmat.primitives import serialization as ser
    return ser.Encoding.DER


def pem(label, der):
    import base64
    b64 = base64.b64encode(der).decode()
    return "\n".join([f"-----BEGIN {label}-----"] + [b64[i:i + 64] for i in range(0, len(b64), 64)] +
                     [f"-----END {label}-----", ""])


def sign_request(slot, pin, name):
    """DER of a request for the card key in `slot`: a request made with a stand-in key has the card's
    public key put in place of the stand-in's, and the card signs the result."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization as ser
    c = card()
    pub = public_key(c, slot)
    if not pub:
        die(f"slot {slot:02X} has no key: generate one first")
    spki = key_object(pub).public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
    stand_in = x509.CertificateSigningRequestBuilder().subject_name(name).sign(dummy_key(pub["algo"]), hashes.SHA256())
    info, algorithm, _ = der_items(der_content(stand_in.public_bytes(ser.Encoding.DER)))
    version, subject, _, *attributes = der_items(der_content(info))
    info = tlv(0x30, version + subject + spki + b"".join(attributes))
    if slot != 0x9E:
        verify_pin(c, pin)
    sig = card_sign(c, slot, pub, info)
    return tlv(0x30, info + algorithm + tlv(0x03, b"\x00" + sig))


# ---------------------------------------------------------------- management key

def set_mgmt_key(old_key, new_key, algo="3des"):
    """Changes the management key; returns it (bytes). new_key None makes a random one."""
    if algo not in MGMT_ALGS:
        die(f"algorithm: {', '.join(MGMT_ALGS)}")
    alg_id, length = MGMT_ALGS[algo]
    new_key = new_key or os.urandom(length)
    if len(new_key) != length:
        die(f"{algo} needs {length} bytes ({length * 2} hex digits)")
    if algo == "3des" and (new_key[:8] == new_key[8:16] or new_key[8:16] == new_key[16:]):
        die("a 3DES key whose parts repeat is weak: use another key")
    c = card()
    authenticate(c, old_key)
    _, sw = c.send(0x00, 0xFF, 0xFF, 0xFF, bytes([alg_id, 0x9B, length]) + new_key, check=False)
    if sw != 0x9000:
        raise RuntimeError(f"card error {sw:04X} (set management key)")
    return new_key


# ---------------------------------------------------------------- CLI

def slot_arg(sp):
    sp.add_argument("slot", choices=sorted(SLOT_NAMES), help="9a authentication, 9c signature, "
                    "9d key management, 9e card authentication")


def ask_mgmt(args):
    if args.mgmt_key is not None:
        return parse_mgmt_key(args.mgmt_key)
    import getpass
    return parse_mgmt_key(getpass.getpass("Management key (hex; empty: factory key): "))


def ask_pin(args):
    import getpass
    return args.pin or getpass.getpass("PIN: ")


def cmd_status(args):
    d = details()
    print(f"serial:          {d['serial']}")
    print(f"management key:  {d['mgmt']['algo']}{' (factory default: change it!)' if d['mgmt']['default'] else ''}")
    for s in d["slots"]:
        key = f"{s['key']['algo']} touch {s['touch']}, PIN {s['pin_policy']}" if s["key"] else "no key"
        print(f"slot {s['slot']:02X} {s['name']:20} {key}")
        if s["cert"]:
            print(f"        certificate {s['cert']['subject']}, until {s['cert']['not_after']:%Y-%m-%d}")


def cmd_generate(args):
    slot = slot_of(args.slot)
    c = card()
    if public_key(c, slot) and not args.yes:
        if input(f"Slot {slot:02X} already has a key; it will be destroyed. Continue? [y/N] ").lower() != "y":
            die("cancelled")
    print("Generating on the card" + (" (RSA takes up to 10 seconds)..." if args.algo == "rsa2048" else "..."))
    pub = generate(slot, args.algo, args.touch, ask_mgmt(args))
    print(f"slot {slot:02X}: {pub['algo']} key made")
    print(public_pem(slot), end="")


def cmd_cert(args):
    slot = slot_of(args.slot)
    pem_text = export_cert(slot)
    if args.output:
        with open(args.output, "w") as f:
            f.write(pem_text)
        print(f"certificate written to {args.output}")
    else:
        print(cert_text(read_cert(slot)))
        print(pem_text, end="")


def cmd_import_cert(args):
    try:
        data = open(args.file, "rb").read()
    except OSError as e:
        die(f"cannot read {args.file}: {e.strerror}")
    import_cert(slot_of(args.slot), data, ask_mgmt(args))
    print("certificate stored")


def cmd_delete_cert(args):
    delete_cert(slot_of(args.slot), ask_mgmt(args))
    print("certificate deleted")


def cmd_self_signed(args):
    slot = slot_of(args.slot)
    pin, mgmt = ask_pin(args), ask_mgmt(args)
    print("Signing on the card (press the button if the key needs it)...", file=sys.stderr)
    print(cert_text(self_signed(slot, pin, args.subject, args.days, mgmt)))


def cmd_csr(args):
    text = csr(slot_of(args.slot), ask_pin(args), args.subject)
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
        print(f"request written to {args.output}")
    else:
        print(text, end="")


def cmd_pubkey(args):
    slot = slot_of(args.slot)
    print(ssh_line(slot, args.comment or "") if args.ssh else public_pem(slot), end="\n" if args.ssh else "")


def cmd_mgmt_key(args):
    old = ask_mgmt(args)
    new = None
    if args.new_key:
        try:
            new = bytes.fromhex(args.new_key.replace(" ", ""))
        except ValueError:
            die("new key: hex digits only")
    key = set_mgmt_key(old, new, args.algo)
    print("management key changed")
    if not args.new_key:
        print(f"new key: {key.hex()}  (write it down: without it keys and certificates cannot be changed)")


def add_commands(v):
    """Adds the commands of this module to the `qk piv` subparsers."""
    pin = "prompted if omitted; a value given here stays in the shell history and shows in the process list"
    mgmt = "hex; prompted if omitted (empty: factory key); " + "a value given here stays in the shell history"
    sp = v.add_parser("generate", help="make a key in a slot (replaces its key and certificate)")
    slot_arg(sp)
    sp.add_argument("--algo", choices=tuple(ALG_IDS), default="nistp256")
    sp.add_argument("--touch", choices=tuple(TOUCH_IDS), default="never", help="button policy of the key")
    sp.add_argument("--mgmt-key", help=mgmt)
    sp.add_argument("--yes", action="store_true", help="do not ask before replacing a key")
    sp.set_defaults(func=cmd_generate)
    sp = v.add_parser("cert", help="show or export the certificate of a slot")
    slot_arg(sp)
    sp.add_argument("-o", "--output", help="write the PEM to a file")
    sp.set_defaults(func=cmd_cert)
    sp = v.add_parser("import-cert", help="store a certificate (PEM or DER) in a slot")
    slot_arg(sp)
    sp.add_argument("file")
    sp.add_argument("--mgmt-key", help=mgmt)
    sp.set_defaults(func=cmd_import_cert)
    sp = v.add_parser("delete-cert", help="delete the certificate of a slot")
    slot_arg(sp)
    sp.add_argument("--mgmt-key", help=mgmt)
    sp.set_defaults(func=cmd_delete_cert)
    sp = v.add_parser("self-signed", help="make a self-signed certificate for the key in a slot (signed on the card)")
    slot_arg(sp)
    sp.add_argument("subject", help='for example "CN=Jane Doe,O=Example"')
    sp.add_argument("--days", type=int, default=365)
    sp.add_argument("--pin", help=pin)
    sp.add_argument("--mgmt-key", help=mgmt)
    sp.set_defaults(func=cmd_self_signed)
    sp = v.add_parser("csr", help="make a certificate signing request for the key in a slot (signed on the card)")
    slot_arg(sp)
    sp.add_argument("subject", help='for example "CN=Jane Doe,O=Example"')
    sp.add_argument("-o", "--output")
    sp.add_argument("--pin", help=pin)
    sp.set_defaults(func=cmd_csr)
    sp = v.add_parser("pubkey", help="print the public key of a slot (PEM, or --ssh)")
    slot_arg(sp)
    sp.add_argument("--ssh", action="store_true", help="as an SSH public key line")
    sp.add_argument("--comment")
    sp.set_defaults(func=cmd_pubkey)
    sp = v.add_parser("mgmt-key", help="change the management key")
    sp.add_argument("--mgmt-key", help="current key: " + mgmt)
    sp.add_argument("--new-key", help="hex; a random key is made if omitted")
    sp.add_argument("--algo", choices=tuple(MGMT_ALGS), default="3des")
    sp.set_defaults(func=cmd_mgmt_key)
