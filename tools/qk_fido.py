"""FIDO2 management for qk: passkey details and renaming, alwaysUv, large blobs,
and SSH keys on the key (ed25519-sk and ecdsa-sk, resident or not).

Like the functions in qk.py, these return data and raise qk.QkError, so that
the TUI can use them too.
"""
import base64
import contextlib
import hashlib
import os
import struct

import qk
from qk import die

SSH_PREFIX = "ssh:"
SSH_UP, SSH_UV, SSH_RESIDENT = 0x01, 0x04, 0x20     # flags of an OpenSSH security key
ALGS = {-7: "ES256", -8: "EdDSA", -257: "RS256"}
PROTECT = {1: "optional", 2: "optional with ID list", 3: "required"}
SSH_TYPES = {"ed25519": ("sk-ssh-ed25519@openssh.com", -8), "ecdsa": ("sk-ecdsa-sha2-nistp256@openssh.com", -7)}


@contextlib.contextmanager
def ctap_errors():
    """Turns CTAP error codes into messages a person can act on."""
    from fido2.ctap import CtapError
    try:
        yield
    except CtapError as e:
        name = getattr(e.code, "name", str(e.code))
        text = {"PIN_INVALID": "wrong PIN", "PIN_BLOCKED": qk.PIN_BLOCKED, "PIN_AUTH_BLOCKED":
                "too many wrong PINs: re-plug the key and try again", "ACTION_TIMEOUT":
                "not confirmed on the key", "USER_ACTION_TIMEOUT": "not confirmed on the key",
                "KEEPALIVE_CANCEL": "cancelled", "KEY_STORE_FULL": "the key has no room for another passkey",
                "NO_CREDENTIALS": "no such passkey", "UNSUPPORTED_ALGORITHM": "the key does not support this algorithm",
                "PUAT_REQUIRED": "PIN required", "NOT_ALLOWED": "not allowed now (for FIDO reset: re-plug the key first)",
                "OPERATION_DENIED": "not confirmed on the key"}.get(name)
        die(text or f"key refused ({name})")


def token(ctap, pin, permission, rp_id=None):
    from fido2.ctap2.pin import ClientPin
    cp = ClientPin(ctap)
    return cp, cp.get_pin_token(pin, permission, rp_id)


# ---------------------------------------------------------------- passkeys

def passkeys(pin):
    """(used, free, [{"rp", "rp_name", "name", "display", "user_id", "id", "alg", "protect", "public_key"}])"""
    with ctap_errors():
        cm = qk.fido_cm(qk.fido_ctap(), pin)
        meta = cm.get_metadata()
        creds = []
        if meta[1]:
            for rp in cm.enumerate_rps():
                for cred in cm.enumerate_creds(rp[4]):
                    user, pk = cred[6], cred[8]
                    creds.append({"rp": rp[3]["id"], "rp_name": rp[3].get("name", ""), "name": user.get("name", "-"),
                                  "display": user.get("displayName", ""), "user_id": user["id"],
                                  "id": cred[7]["id"], "alg": ALGS.get(pk.get(3), str(pk.get(3))),
                                  "protect": PROTECT.get(cred.get(10), ""), "public_key": pk})
        return meta[1], meta[2], creds


def rename(pin, cred_id, user_id, name, display):
    """Changes the user name and display name stored with a passkey."""
    if not name:
        die("a user name is needed")
    with ctap_errors():
        qk.fido_cm(qk.fido_ctap(), pin).update_user_info(
            {"id": cred_id, "type": "public-key"}, {"id": user_id, "name": name, "displayName": display})


def info():
    """{"versions", "aaguid", "extensions", "options", "pin_tries", "always_uv", "max_blob"}"""
    from fido2.ctap2.pin import ClientPin
    ctap = qk.fido_ctap()
    i = ctap.info
    with ctap_errors():
        tries = ClientPin(ctap).get_pin_retries()[0]
    return {"versions": list(i.versions), "aaguid": str(i.aaguid), "extensions": list(i.extensions),
            "options": dict(i.options), "pin_tries": tries, "always_uv": bool(i.options.get("alwaysUv")),
            "max_blob": i.max_large_blob or 0}


def set_always_uv(pin, want):
    """Switches alwaysUv (a PIN for every registration and sign-in, U2F off) on or off; returns the new state."""
    from fido2.ctap2.config import Config
    from fido2.ctap2.pin import ClientPin
    ctap = qk.fido_ctap()
    if bool(ctap.info.options.get("alwaysUv")) == want:
        return want
    with ctap_errors():
        cp, tok = token(ctap, pin, ClientPin.PERMISSION.AUTHENTICATOR_CFG)
        Config(ctap, cp.protocol, tok).toggle_always_uv()
    return bool(qk.fido_ctap().info.options.get("alwaysUv"))


def large_blobs():
    """(entries, bytes of data, capacity): the large blob array readable without a PIN."""
    from fido2.ctap2.blob import LargeBlobs
    ctap = qk.fido_ctap()
    with ctap_errors():
        entries = LargeBlobs(ctap).read_blob_array()
    return len(entries), sum(e.get(3, 0) for e in entries), ctap.info.max_large_blob or 0


def clear_large_blobs(pin):
    from fido2.ctap2.blob import LargeBlobs
    from fido2.ctap2.pin import ClientPin
    ctap = qk.fido_ctap()
    with ctap_errors():
        cp, tok = token(ctap, pin, ClientPin.PERMISSION.LARGE_BLOB_WRITE)
        LargeBlobs(ctap, cp.protocol, tok).write_blob_array([])


# ---------------------------------------------------------------- SSH keys

def s(b):
    return struct.pack(">I", len(b)) + b


def ssh_key(public_key, application, key_handle, flags):
    """{"type", "blob", "line" (without comment), "application", "key_handle", "flags", "fields"} of a
    security key made on the card from its COSE public key."""
    if public_key.get(3) == -8:
        name, fields = SSH_TYPES["ed25519"][0], [s(public_key[-2])]
    elif public_key.get(3) == -7:
        name = SSH_TYPES["ecdsa"][0]
        fields = [s(b"nistp256"), s(b"\x04" + public_key[-2] + public_key[-3])]
    else:
        die("this passkey is not an Ed25519 or P-256 key: OpenSSH cannot use it")
    app = application.encode()
    blob = s(name.encode()) + b"".join(fields) + s(app)
    return {"type": name, "blob": blob, "line": f"{name} {base64.b64encode(blob).decode()}", "application": application,
            "key_handle": key_handle, "flags": flags, "fields": fields}


def public_line(key, comment=""):
    return key["line"] + (f" {comment}" if comment else "")


def private_file(key, comment=""):
    """The OpenSSH private key file (what `ssh-keygen -K` writes) of a security key: it holds the
    key handle, not a secret, and ssh needs the key to be plugged in to use it."""
    check = os.urandom(4)
    body = (check + check + s(key["type"].encode()) + b"".join(key["fields"]) + s(key["application"].encode()) +
            bytes([key["flags"]]) + s(key["key_handle"]) + s(b"") + s(comment.encode()))
    body += bytes(range(1, 8 - len(body) % 8 + 1)) if len(body) % 8 else b""
    data = b"openssh-key-v1\0" + s(b"none") + s(b"none") + s(b"") + struct.pack(">I", 1) + s(key["blob"]) + s(body)
    b64 = base64.b64encode(data).decode()
    return "\n".join(["-----BEGIN OPENSSH PRIVATE KEY-----"] + [b64[i:i + 70] for i in range(0, len(b64), 70)] +
                     ["-----END OPENSSH PRIVATE KEY-----", ""])


def ssh_create(pin, algo="ed25519", name="", resident=True, verify_required=False, path=None, comment=""):
    """Makes an SSH key on the key (button needed); returns the key dict of ssh_key(). A resident key
    stays on the key; one that is not resident is only usable with the files, so `path` is then
    required. With `path` the key files are written there (checked before anything is made)."""
    if algo not in SSH_TYPES:
        die("algorithm: ed25519 or ecdsa")
    if not resident and not path:
        die("a key that is not resident is lost without its file: give a file to save it to")
    if path:
        check_new_file(path)
    application = SSH_PREFIX + name
    ctap = qk.fido_ctap()
    with ctap_errors():
        from fido2.ctap2.pin import ClientPin
        cp, tok = token(ctap, pin, ClientPin.PERMISSION.MAKE_CREDENTIAL, application)
        cdh = os.urandom(32)
        att = ctap.make_credential(
            cdh, {"id": application, "name": application},
            {"id": os.urandom(32), "name": "openssh", "displayName": "openssh"},
            [{"type": "public-key", "alg": SSH_TYPES[algo][1]}], options={"rk": bool(resident)},
            pin_uv_param=cp.protocol.authenticate(tok, cdh), pin_uv_protocol=cp.protocol.VERSION)
    cd = att.auth_data.credential_data
    flags = SSH_UP | (SSH_UV if verify_required else 0) | (SSH_RESIDENT if resident else 0)
    key = ssh_key(cd.public_key, application, cd.credential_id, flags)
    if path:
        save_ssh_key(key, path, comment)
    return key


def ssh_list(pin):
    """Resident SSH keys on the key: [{"id", "name" (the part after ssh:), "key", "fingerprint"}]."""
    out = []
    for c in passkeys(pin)[2]:
        if c["rp"].startswith(SSH_PREFIX) and c["alg"] in ("EdDSA", "ES256"):
            key = ssh_key(c["public_key"], c["rp"], c["id"], SSH_UP | SSH_RESIDENT)
            digest = base64.b64encode(hashlib.sha256(key["blob"]).digest()).decode().rstrip("=")
            out.append({"id": c["id"], "name": c["rp"][len(SSH_PREFIX):], "key": key, "fingerprint": "SHA256:" + digest})
    return out


def check_new_file(path):
    path = os.path.expanduser(path)
    if os.path.exists(path) or os.path.exists(path + ".pub"):
        die(f"{path} exists: choose another file name")


def save_ssh_key(key, path, comment=""):
    """Writes the private key file (mode 600) and <path>.pub; refuses to overwrite."""
    path = os.path.expanduser(path)
    check_new_file(path)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        die(f"{path} exists: choose another file name")
    except OSError as e:
        die(f"cannot write {path}: {e.strerror}")
    with os.fdopen(fd, "w") as f:
        f.write(private_file(key, comment))
    try:
        with open(path + ".pub", "w") as f:
            f.write(public_line(key, comment) + "\n")
    except OSError as e:
        die(f"{path} written, but not {path}.pub: {e.strerror}")


# ---------------------------------------------------------------- CLI

def cmd_fido_info(args):
    i = info()
    print(f"versions:    {', '.join(i['versions'])}")
    print(f"aaguid:      {i['aaguid']}")
    print(f"extensions:  {', '.join(i['extensions']) or '-'}")
    print(f"PIN tries:   {i['pin_tries']}")
    print(f"alwaysUv:    {'on' if i['always_uv'] else 'off'}")
    print(f"options:     {', '.join(k for k, v in sorted(i['options'].items()) if v)}")


def cmd_fido_list(args):
    used, free, creds = passkeys(qk.ask_pin(args))
    print(f"passkeys: {used} used, {free} free")
    rp = None
    for c in creds:
        if c["rp"] != rp:
            rp = c["rp"]
            print(rp)
        print(f"  {c['name']:30} {c['display']:20} {c['alg']:6} id={c['id'].hex()}")


def cmd_fido_rename(args):
    pin = qk.ask_pin(args)
    cred = next((c for c in passkeys(pin)[2] if c["id"].hex().startswith(args.cred_id.lower())), None)
    if not cred:
        die("no passkey with this id: see `qk fido list`")
    rename(pin, cred["id"], cred["user_id"], args.name, cred["display"] if args.display is None else args.display)
    print("renamed")


def cmd_fido_always_uv(args):
    if args.state is None:
        print("alwaysUv: " + ("on" if info()["always_uv"] else "off"))
        return
    now = set_always_uv(qk.ask_pin(args), args.state == "on")
    print("alwaysUv: " + ("on" if now else "off"))


def cmd_fido_blobs(args):
    if args.clear:
        clear_large_blobs(qk.ask_pin(args))
        print("large blobs erased")
    n, size, cap = large_blobs()
    print(f"large blob array: {n} entries, {size} bytes of data, capacity {cap} bytes")


def ask_comment(args):
    return args.comment if args.comment is not None else "quick-key"


def cmd_ssh_create(args):
    pin = qk.ask_pin(args)
    print("Press the button on the key...")
    comment = ask_comment(args)
    key = ssh_create(pin, args.algo, args.name, not args.no_resident, args.verify_required, args.file, comment)
    if args.file:
        print(f"written {args.file} and {args.file}.pub")
    print(public_line(key, comment))


def cmd_ssh_list(args):
    keys = ssh_list(qk.ask_pin(args))
    if not keys:
        print("no SSH keys on the key")
    for k in keys:
        print(f"{k['name'] or '(default)':16} {k['fingerprint']}  {public_line(k['key'], ask_comment(args))}")


def cmd_ssh_export(args):
    keys = ssh_list(qk.ask_pin(args))
    for k in keys:
        if args.name in (k["name"], k["id"].hex()):
            save_ssh_key(k["key"], args.file, ask_comment(args))
            print(f"written {args.file} and {args.file}.pub")
            return
    die(f"no SSH key '{args.name}' on the key: see `qk ssh list`")


def cmd_ssh_delete(args):
    pin = qk.ask_pin(args)
    for k in ssh_list(pin):
        if args.name in (k["name"], k["id"].hex()):
            with ctap_errors():
                qk.fido_delete(pin, k["id"])
            print("deleted")
            return
    die(f"no SSH key '{args.name}' on the key: see `qk ssh list`")


def add_fido_commands(f):
    """Extra `qk fido` commands (and a richer info and list)."""
    pin = "prompted if omitted; a value given here stays in the shell history and shows in the process list"
    sp = f.add_parser("rename", help="change the user name of a passkey")
    sp.add_argument("cred_id", help="credential id or its first digits (hex, from `qk fido list`)")
    sp.add_argument("name")
    sp.add_argument("--display", help="display name")
    sp.add_argument("--pin", help=pin)
    sp.set_defaults(func=cmd_fido_rename)
    sp = f.add_parser("always-uv", help="show or switch 'a PIN for every sign-in' (turns U2F off)")
    sp.add_argument("state", nargs="?", choices=("on", "off"))
    sp.add_argument("--pin", help=pin)
    sp.set_defaults(func=cmd_fido_always_uv)
    sp = f.add_parser("blobs", help="large blob array of the key")
    sp.add_argument("--clear", action="store_true", help="erase it (PIN)")
    sp.add_argument("--pin", help=pin)
    sp.set_defaults(func=cmd_fido_blobs)


def add_ssh_commands(sub):
    pin = "prompted if omitted; a value given here stays in the shell history and shows in the process list"
    w = sub.add_parser("ssh", help="SSH keys on the key (FIDO2, ed25519-sk)").add_subparsers(dest="sub", required=True)
    sp = w.add_parser("create", help="make an SSH key on the key (button)")
    sp.add_argument("--name", default="", help="tells keys apart: the application is ssh:<name>")
    sp.add_argument("--algo", choices=tuple(SSH_TYPES), default="ed25519")
    sp.add_argument("--no-resident", action="store_true", help="keep only a key handle in the file, not on the key")
    sp.add_argument("--verify-required", action="store_true", help="every signature needs the PIN")
    sp.add_argument("--file", help="also write the private key file and .pub there (e.g. ~/.ssh/id_ed25519_sk)")
    sp.add_argument("--comment")
    sp.add_argument("--pin", help=pin)
    sp.set_defaults(func=cmd_ssh_create)
    sp = w.add_parser("list", help="resident SSH keys on the key, as authorized_keys lines")
    sp.add_argument("--comment")
    sp.add_argument("--pin", help=pin)
    sp.set_defaults(func=cmd_ssh_list)
    sp = w.add_parser("export", help="write the key files of a resident key (like `ssh-keygen -K`)")
    sp.add_argument("name", help="the name given at creation, or the credential id")
    sp.add_argument("file")
    sp.add_argument("--comment")
    sp.add_argument("--pin", help=pin)
    sp.set_defaults(func=cmd_ssh_export)
    sp = w.add_parser("delete", help="delete a resident SSH key from the key")
    sp.add_argument("name", help="the name given at creation, or the credential id")
    sp.add_argument("--pin", help=pin)
    sp.set_defaults(func=cmd_ssh_delete)
