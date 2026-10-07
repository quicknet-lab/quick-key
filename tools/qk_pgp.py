"""OpenPGP card management for qk: on-card key generation, key import,
fingerprints, cardholder data, SSH and OpenPGP public key export.

Like the functions in qk.py, these return data and raise qk.QkError, so that
the TUI can use them too.
"""
import base64
import hashlib
import struct
import sys
import time

import qk
from qk import AID_PGP, PGP_KEYS, die, pin_error, tlv, tlv_get

CRT = (0xB6, 0xB8, 0xA4)                 # control reference templates of the signature, decryption, authentication key
OID_P256 = bytes.fromhex("2A8648CE3D030107")
OID_ED25519 = bytes.fromhex("2B06010401DA470F01")
OID_CV25519 = bytes.fromhex("2B060104019755010501")
RSA_ATTR = bytes.fromhex("010800002000")

# Algorithms a key slot accepts; the first one is the default.
SLOT_ALGOS = (("ed25519", "nistp256", "rsa2048"),      # signature
              ("cv25519", "nistp256", "rsa2048"),      # decryption
              ("ed25519", "nistp256", "rsa2048"))      # authentication

KEY_STATUS = {0: "none", 1: "generated", 2: "imported"}
SEX = {"0": "unknown", "1": "male", "2": "female", "9": "not applicable"}


def algo_attr(key, algo):
    """Algorithm attributes (DO C1-C3) for a key slot (index into PGP_KEYS)."""
    if algo not in SLOT_ALGOS[key]:
        die(f"the {PGP_KEYS[key]} key can be {', '.join(SLOT_ALGOS[key])}, not {algo}")
    if algo == "rsa2048":
        return RSA_ATTR
    if algo == "ed25519":
        return b"\x16" + OID_ED25519
    if algo == "cv25519":
        return b"\x12" + OID_CV25519
    return (b"\x12" if key == 1 else b"\x13") + OID_P256


def card():
    c = qk.Card()
    if c.select(AID_PGP)[1] not in (0x9000, 0x6285):
        die("OpenPGP application not available")
    return c


def verify(c, ref, pin):
    """VERIFY of PW1 (0x81 signature, 0x82 other) or PW3 (0x83)."""
    _, sw = c.send(0x00, 0x20, 0x00, ref, pin.encode(), check=False)
    pin_error(sw, ref == 0x83)


def put(c, tag, value):
    _, sw = c.send(0x00, 0xDA, tag >> 8, tag & 0xFF, value, check=False)
    if sw == 0x6982:
        die("the admin PIN has not been verified")
    if sw != 0x9000:
        raise RuntimeError(f"card error {sw:04X} (PUT DATA {tag:02X})")


def get(c, tag):
    resp, sw = c.send(0x00, 0xCA, tag >> 8, tag & 0xFF, check=False)
    return resp if sw == 0x9000 else b""


# ---------------------------------------------------------------- status

def details():
    """Everything the card tells without a PIN:
    {"serial", "pin_tries", "admin_tries", "pw1_multi", "sig_count", "name", "lang", "sex", "url", "login",
     "keys": [{"name", "algo", "fingerprint", "created", "origin", "touch"}]}"""
    c = card()
    app, _ = c.send(0x00, 0xCA, 0x00, 0x6E)
    disc = tlv_get(app, 0x73)
    pw, fps, dates = tlv_get(disc, 0xC4), tlv_get(disc, 0xC5), tlv_get(disc, 0xCD)
    info = tlv_get(disc, 0xDE) or bytes(6)
    keys = []
    for i, name in enumerate(PGP_KEYS):
        fp = fps[20 * i:20 * i + 20]
        ts = struct.unpack(">I", dates[4 * i:4 * i + 4])[0]
        keys.append({"name": name, "algo": qk.pgp_algo(tlv_get(disc, 0xC1 + i)),
                     "fingerprint": fp.hex().upper() if any(fp) else None,
                     "created": ts or None, "origin": KEY_STATUS.get(info[2 * i + 1], "?"),
                     "touch": qk.PGP_TOUCH.get((tlv_get(disc, 0xD6 + i) or b"\0")[0], "?")})
    holder = get(c, 0x65)
    sx = tlv_get(holder, 0x5F35) or b""
    sex = chr(sx[0]) if sx and chr(sx[0]) in SEX else ""       # an empty card holds 0x00
    counter = get(c, 0x93)
    return {"serial": tlv_get(app, 0x4F)[10:14].hex().upper(), "pin_tries": pw[4], "admin_tries": pw[6],
            "pw1_multi": bool(pw[0]), "sig_count": int.from_bytes(counter, "big"),
            "name": (tlv_get(holder, 0x5B) or b"").decode(errors="replace"),
            "lang": (tlv_get(holder, 0x5F2D) or b"").decode(errors="replace"),
            "sex": sex,
            "url": get(c, 0x5F50).decode(errors="replace"), "login": get(c, 0x5E).decode(errors="replace"),
            "keys": keys}


# ---------------------------------------------------------------- public keys

def read_public(key, c=None):
    """{"algo", "n", "e"} for RSA or {"algo", "point"} for the other keys: the
    public part of a key, readable without a PIN. None if the key is absent."""
    c = c or card()
    resp, sw = c.send(0x00, 0x47, 0x81, 0x00, bytes([CRT[key], 0x00]), check=False)
    if sw != 0x9000:
        return None
    return parse_public(tlv_get(resp, 0x7F49), qk.pgp_algo(get(c, 0xC1 + key)))


def parse_public(body, algo):
    if algo == "rsa2048":
        return {"algo": algo, "n": tlv_get(body, 0x81), "e": tlv_get(body, 0x82)}
    point = tlv_get(body, 0x86)
    return {"algo": algo, "point": point}


def mpi(value):
    """OpenPGP multiprecision integer of big-endian bytes."""
    value = value.lstrip(b"\0")
    if not value:
        return b"\0\0"
    bits = (len(value) - 1) * 8 + value[0].bit_length()
    return struct.pack(">H", bits) + value


def key_body(key, pub, created):
    """Body of an OpenPGP v4 public key packet (RFC 4880, RFC 6637, draft-ietf-openpgp-rfc4880bis)."""
    head = b"\x04" + struct.pack(">I", created)
    algo = pub["algo"]
    if algo == "rsa2048":
        return head + b"\x01" + mpi(pub["n"]) + mpi(pub["e"])
    kdf = b"\x03\x01\x08\x07"                       # SHA-256, AES-128
    if algo == "ed25519":
        return head + b"\x16" + bytes([len(OID_ED25519)]) + OID_ED25519 + mpi(b"\x40" + pub["point"])
    if algo == "cv25519":
        return head + b"\x12" + bytes([len(OID_CV25519)]) + OID_CV25519 + mpi(b"\x40" + pub["point"]) + kdf
    if key == 1:
        return head + b"\x12" + bytes([len(OID_P256)]) + OID_P256 + mpi(pub["point"]) + kdf
    return head + b"\x13" + bytes([len(OID_P256)]) + OID_P256 + mpi(pub["point"])


def fingerprint(body):
    return hashlib.sha1(b"\x99" + struct.pack(">H", len(body)) + body).digest()


def ssh_public_key(pub, comment=""):
    """The authorized_keys line of a card key, or an error for a key that SSH cannot use."""
    def s(b):
        return struct.pack(">I", len(b)) + b

    def mp(b):
        b = b.lstrip(b"\0")
        return s((b"\0" if b and b[0] & 0x80 else b"") + b)
    algo = pub["algo"]
    if algo == "ed25519":
        name, blob = "ssh-ed25519", s(b"ssh-ed25519") + s(pub["point"])
    elif algo == "nistp256" and len(pub["point"]) == 65:
        name = "ecdsa-sha2-nistp256"
        blob = s(name.encode()) + s(b"nistp256") + s(pub["point"])
    elif algo == "rsa2048":
        name, blob = "ssh-rsa", s(b"ssh-rsa") + mp(pub["e"]) + mp(pub["n"])
    else:
        die("this key cannot be used for SSH (X25519 is for decryption only)")
    return f"{name} {base64.b64encode(blob).decode()}" + (f" {comment}" if comment else "")


def ssh_key(key, comment="", c=None):
    pub = read_public(key, c)
    if not pub:
        die(f"the {PGP_KEYS[key]} key is empty")
    return ssh_public_key(pub, comment)


# ---------------------------------------------------------------- keys on the card

def register(c, key, pub, created):
    """Stores the creation date and the fingerprint that GnuPG expects for a
    key made at `created` (needs the admin PIN verified) and adds both to `pub`."""
    fp = fingerprint(key_body(key, pub, created))
    put(c, 0xCE + key, struct.pack(">I", created))
    put(c, 0xC7 + key, fp)
    pub["created"], pub["fingerprint"] = created, fp.hex().upper()


def generate(admin_pin, key, algo, c=None):
    """Makes a new key in a slot on the card (replacing the old one); returns its public part."""
    c = c or card()
    attr = algo_attr(key, algo)
    verify(c, 0x83, admin_pin)
    if get(c, 0xC1 + key) != attr:
        put(c, 0xC1 + key, attr)                    # a changed algorithm erases the key
    resp, sw = c.send(0x00, 0x47, 0x80, 0x00, bytes([CRT[key], 0x00]), check=False)
    if sw == 0x6985:
        die(qk.DEFAULT_PINS)
    if sw != 0x9000:
        raise RuntimeError(f"card error {sw:04X} (GENERATE)")
    pub = parse_public(tlv_get(resp, 0x7F49), algo)
    register(c, key, pub, int(time.time()))
    return pub


def load_private(data, password=None):
    """(algo, secret, public) of a PEM / DER / OpenSSH private key: secret is what the card
    imports, public is a dict like read_public()."""
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, x25519
    pw = password.encode() if password else None
    if data.lstrip().startswith(b"-----BEGIN OPENSSH"):
        load = ser.load_ssh_private_key
    elif b"-----BEGIN" in data:
        load = ser.load_pem_private_key
    else:
        load = ser.load_der_private_key
    try:
        try:
            k = load(data, pw)
        except TypeError as e:
            if pw is None or "not encrypted" not in str(e):
                raise
            k = load(data, None)                   # a password was given for a key that has none
    except TypeError:
        die("the key file is encrypted: a password is needed")
    except ValueError as e:
        die(f"not a private key we can read ({e})" if "decrypt" not in str(e).lower() else "wrong key password")
    raw = ser.Encoding.Raw
    if isinstance(k, ed25519.Ed25519PrivateKey):
        return ("ed25519", k.private_bytes(raw, ser.PrivateFormat.Raw, ser.NoEncryption()),
                {"algo": "ed25519", "point": k.public_key().public_bytes(raw, ser.PublicFormat.Raw)})
    if isinstance(k, x25519.X25519PrivateKey):
        # The card takes the X25519 scalar big-endian (as GnuPG sends it).
        return ("cv25519", k.private_bytes(raw, ser.PrivateFormat.Raw, ser.NoEncryption())[::-1],
                {"algo": "cv25519", "point": k.public_key().public_bytes(raw, ser.PublicFormat.Raw)})
    if isinstance(k, ec.EllipticCurvePrivateKey):
        if k.curve.name != "secp256r1":
            die(f"only NIST P-256 is supported, the key is {k.curve.name}")
        return ("nistp256", k.private_numbers().private_value.to_bytes(32, "big"),
                {"algo": "nistp256", "point": k.public_key().public_bytes(ser.Encoding.X962,
                                                                          ser.PublicFormat.UncompressedPoint)})
    if isinstance(k, rsa.RSAPrivateKey):
        n = k.private_numbers()
        if k.key_size != 2048 or n.public_numbers.e >= 1 << 32:
            die("only RSA-2048 keys with a 32-bit exponent are supported")
        e = n.public_numbers.e.to_bytes(4, "big").lstrip(b"\0")
        return ("rsa2048", (e, n.p.to_bytes(128, "big"), n.q.to_bytes(128, "big")),
                {"algo": "rsa2048", "n": n.public_numbers.n.to_bytes(256, "big"), "e": e})
    die("unsupported key type: use Ed25519, X25519, NIST P-256 or RSA-2048")


def import_key(admin_pin, key, data, password=None, c=None):
    """Writes a private key (see load_private) into a slot; returns its public part."""
    algo, secret, pub = load_private(data, password)
    if algo not in SLOT_ALGOS[key]:
        die(f"a {algo} key cannot be the {PGP_KEYS[key]} key ({', '.join(SLOT_ALGOS[key])} can)")
    c = c or card()
    attr = algo_attr(key, algo)
    verify(c, 0x83, admin_pin)
    if get(c, 0xC1 + key) != attr:
        put(c, 0xC1 + key, attr)
    if algo == "rsa2048":
        e, p, q = secret
        payload = e + p + q
        template = tlv(0x7F48, bytes([0x91, len(e), 0x92, 0x81, 128, 0x93, 0x81, 128]))
    else:
        payload = secret
        template = tlv(0x7F48, bytes([0x92, len(secret)]))
    body = bytes([CRT[key], 0x00]) + template + tlv(0x5F48, payload)
    _, sw = c.send(0x00, 0xDB, 0x3F, 0xFF, tlv(0x4D, body), check=False)
    if sw == 0x6985:
        die(qk.DEFAULT_PINS)
    if sw != 0x9000:
        die(f"the card refused the key (error {sw:04X})")
    register(c, key, pub, int(time.time()))
    return pub


# ---------------------------------------------------------------- cardholder data

def set_cardholder(admin_pin, name=None, lang=None, sex=None, url=None, login=None, c=None):
    """Writes the cardholder name ("Surname<<Given"), language (2-letter codes),
    sex ("0", "1", "2", "9"), URL of the public key and login data; None leaves a field."""
    c = c or card()
    if name is not None and (len(name.encode()) > 39 or not name.isascii()):
        die("name: at most 39 ASCII characters, written as Surname<<Given")
    if lang and (len(lang) % 2 or len(lang) > 8 or not lang.isalpha()):
        die("language: 1-4 two-letter codes such as 'en' or 'enru'")
    if sex is not None and sex not in SEX:
        die("sex: 0 unknown, 1 male, 2 female, 9 not applicable")
    verify(c, 0x83, admin_pin)
    for tag, value in ((0x5B, name), (0x5F2D, lang), (0x5F35, sex), (0x5F50, url), (0x5E, login)):
        if value is not None:
            put(c, tag, value.encode())


# ---------------------------------------------------------------- OpenPGP public key

CRC24_INIT, CRC24_POLY = 0xB704CE, 0x1864CFB


def crc24(data):
    crc = CRC24_INIT
    for b in data:
        crc ^= b << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= CRC24_POLY
    return crc & 0xFFFFFF


def armor(data):
    b64 = base64.b64encode(data).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "\n".join(["-----BEGIN PGP PUBLIC KEY BLOCK-----", ""] + lines +
                     ["=" + base64.b64encode(crc24(data).to_bytes(3, "big")).decode(),
                      "-----END PGP PUBLIC KEY BLOCK-----", ""])


def packet(tag, body):
    n = len(body)
    head = bytes([0xC0 | tag]) + (bytes([n]) if n < 192 else bytes([0xFF]) + struct.pack(">I", n))
    return head + body


def subpacket(kind, body):
    return bytes([len(body) + 1, kind]) + body


def pubkey_algo(key, pub):
    return {"rsa2048": 1, "ed25519": 22, "cv25519": 18}.get(pub["algo"]) or (18 if key == 1 else 19)


def signature(signer, key_index, pub, kind, material, hashed_extra, created, issuer_fp):
    """A v4 signature packet of `kind` over `material` (the data the signature covers, without
    the trailer). signer(digest_info_or_digest, algo) -> bytes returns the card's raw result."""
    pk_algo = pubkey_algo(key_index, pub)
    hashed = subpacket(2, struct.pack(">I", created)) + hashed_extra + subpacket(33, b"\x04" + issuer_fp)
    head = bytes([4, kind, pk_algo, 8]) + struct.pack(">H", len(hashed)) + hashed
    trailer = b"\x04\xFF" + struct.pack(">I", len(head))
    digest = hashlib.sha256(material + head + trailer).digest()
    raw = signer(digest, pub["algo"])
    if pub["algo"] == "rsa2048":
        mpis = mpi(raw)
    else:
        mpis = mpi(raw[:32]) + mpi(raw[32:])
    unhashed = subpacket(16, issuer_fp[-8:])
    return packet(2, head + struct.pack(">H", len(unhashed)) + unhashed + digest[:2] + mpis)


SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def export_pgp(user_id, pin, c=None, on_sign=None):
    """OpenPGP public key (armored text) of the card keys: the signature key is the primary key
    certified with `user_id`, the decryption and authentication keys are its subkeys. The
    signatures are made on the card, which needs the PIN (and the button, if the key asks for it).
    on_sign(what) is called before each signature."""
    c = c or card()
    if not user_id.strip():
        die("a user ID is needed, for example: Name <name@example.com>")
    pubs, dates, fps = [], [], []
    for k in range(3):
        pubs.append(read_public(k, c))
    d = details()
    if not pubs[0]:
        die("the signature key is empty: the OpenPGP key needs it as its primary key")
    for k in range(3):
        dates.append(d["keys"][k]["created"] or int(time.time()))
    bodies = [key_body(k, pubs[k], dates[k]) if pubs[k] else None for k in range(3)]
    fps = [fingerprint(b) if b else None for b in bodies]

    def signer_for(what):
        def sign(digest, algo):
            verify(c, 0x81, pin)                    # one signature per verification
            if on_sign:
                on_sign(what)
            data = SHA256_DIGEST_INFO + digest if algo == "rsa2048" else digest
            resp, sw = c.send(0x00, 0x2A, 0x9E, 0x9A, data, check=False)
            if sw == 0x6982:
                die("the key needs the button for a signature and it was not pressed in time")
            if sw != 0x9000:
                raise RuntimeError(f"card error {sw:04X} (signature)")
            return resp
        return sign
    sign = signer_for("the certificate")
    primary = b"\x99" + struct.pack(">H", len(bodies[0])) + bodies[0]
    out = packet(6, bodies[0])
    uid = user_id.encode()
    out += packet(13, uid)
    flags = subpacket(27, b"\x03")                  # certify, sign
    out += signature(sign, 0, pubs[0], 0x13, primary + b"\xB4" + struct.pack(">I", len(uid)) + uid,
                     flags + subpacket(30, b"\x01"), dates[0], fps[0])
    for k, usage, what in ((1, b"\x0C", "the encryption subkey"), (2, b"\x20", "the authentication subkey")):
        if not pubs[k]:
            continue
        sub = b"\x99" + struct.pack(">H", len(bodies[k])) + bodies[k]
        out += packet(14, bodies[k])
        out += signature(signer_for(what), 0, pubs[0], 0x18, primary + sub, subpacket(27, usage), dates[k], fps[0])
    return armor(out)


def fingerprint_text(fp):
    return " ".join(fp[i:i + 4] for i in range(0, 40, 4))


def long_id(fp):
    return fp[-16:]



# ---------------------------------------------------------------- CLI

def ask_admin(args):
    import getpass
    return args.admin_pin or getpass.getpass("Admin PIN: ")


def key_index(name):
    return PGP_KEYS.index(name)


def cmd_status(args):
    d = details()
    print(f"serial:       {d['serial']}")
    print(f"PIN tries:    PIN {d['pin_tries']}, admin PIN {d['admin_tries']}")
    print(f"signatures:   {d['sig_count']}")
    if d["name"] or d["url"] or d["login"] or d["lang"]:
        print(f"cardholder:   {d['name'] or '-'}  lang {d['lang'] or '-'}  sex {SEX.get(d['sex'], '-')}")
        print(f"URL / login:  {d['url'] or '-'}  /  {d['login'] or '-'}")
    for k in d["keys"]:
        created = time.strftime("%Y-%m-%d", time.gmtime(k["created"])) if k["created"] else "-"
        print(f"{k['name']:14} {k['algo']:9} touch {k['touch']:5} {k['origin']:9} {created}  "
              f"{k['fingerprint'] or '[none]'}")


def confirm_replace(args, key):
    """Asks before an occupied slot is overwritten, unless --yes."""
    if args.yes or not details()["keys"][key]["fingerprint"]:
        return
    if input(f"The {PGP_KEYS[key]} key already exists and will be destroyed. Continue? [y/N] ").lower() != "y":
        die("cancelled")


def print_new_key(key, pub):
    print(f"{PGP_KEYS[key]} key {pub['algo']}: {fingerprint_text(pub['fingerprint'])}")
    if pub["algo"] != "cv25519":
        print(ssh_public_key(pub, f"quick-key-{PGP_KEYS[key]}"))


def cmd_generate(args):
    key = key_index(args.key)
    algo = args.algo or SLOT_ALGOS[key][0]
    algo_attr(key, algo)
    confirm_replace(args, key)
    admin = ask_admin(args)
    print("Generating on the card" + (" (RSA takes up to 10 seconds)..." if algo == "rsa2048" else "..."))
    print_new_key(key, generate(admin, key, algo))


def cmd_import(args):
    key = key_index(args.key)
    try:
        data = open(args.file, "rb").read()
    except OSError as e:
        die(f"cannot read {args.file}: {e.strerror}")
    confirm_replace(args, key)
    admin = ask_admin(args)
    try:
        pub = import_key(admin, key, data, args.key_password)
    except qk.QkError as e:
        if "password is needed" not in str(e):
            raise
        import getpass
        pub = import_key(admin, key, data, getpass.getpass("Password of the key file: "))
    print_new_key(key, pub)


def cmd_ssh(args):
    print(ssh_key(key_index(args.key), args.comment or ""))


def cmd_export(args):
    import getpass
    pin = args.pin or getpass.getpass("PIN: ")
    text = export_pgp(args.user_id, pin, on_sign=lambda what: print(f"Signing {what}...", file=sys.stderr))
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
        print(f"public key written to {args.output}")
    else:
        print(text, end="")


def cmd_cardholder(args):
    fields = {"name": args.name, "lang": args.lang, "sex": args.sex, "url": args.url, "login": args.login}
    if all(v is None for v in fields.values()):
        d = details()
        for label, key in (("name", "name"), ("language", "lang"), ("sex", "sex"), ("URL", "url"), ("login", "login")):
            print(f"{label:9} {d[key] or '-'}")
        return
    set_cardholder(ask_admin(args), **fields)
    print("cardholder data written")


def add_commands(g):
    """Adds the commands of this module to the `qk pgp` subparsers."""
    pin = "prompted if omitted; a value given here stays in the shell history and shows in the process list"
    sp = g.add_parser("generate", help="make a key on the card (replaces the key in that slot)")
    sp.add_argument("key", choices=PGP_KEYS)
    sp.add_argument("--algo", choices=("ed25519", "cv25519", "nistp256", "rsa2048"),
                    help="default: ed25519 for signature/authentication, cv25519 for decryption")
    sp.add_argument("--admin-pin", help=pin)
    sp.add_argument("--yes", action="store_true", help="do not ask before replacing a key")
    sp.set_defaults(func=cmd_generate)
    sp = g.add_parser("import", help="write a private key file (PEM, DER or OpenSSH) to the card")
    sp.add_argument("key", choices=PGP_KEYS)
    sp.add_argument("file")
    sp.add_argument("--key-password", help="password of an encrypted key file; " + pin)
    sp.add_argument("--admin-pin", help=pin)
    sp.add_argument("--yes", action="store_true", help="do not ask before replacing a key")
    sp.set_defaults(func=cmd_import)
    sp = g.add_parser("ssh", help="print a card key as an SSH public key (authorized_keys line)")
    sp.add_argument("key", choices=PGP_KEYS, nargs="?", default="authentication")
    sp.add_argument("--comment")
    sp.set_defaults(func=cmd_ssh)
    sp = g.add_parser("export", help="make the OpenPGP public key of the card (signed on the card)")
    sp.add_argument("user_id", help='for example "Name <name@example.com>"')
    sp.add_argument("-o", "--output", help="write to a file instead of the terminal")
    sp.add_argument("--pin", help=pin)
    sp.set_defaults(func=cmd_export)
    sp = g.add_parser("cardholder", help="show or set the cardholder data (name, language, sex, URL, login)")
    sp.add_argument("--name", help="Surname<<Given")
    sp.add_argument("--lang", help="two-letter codes, for example en or enru")
    sp.add_argument("--sex", choices=tuple(SEX))
    sp.add_argument("--url", help="where the public key can be fetched")
    sp.add_argument("--login")
    sp.add_argument("--admin-pin", help=pin)
    sp.set_defaults(func=cmd_cardholder)
