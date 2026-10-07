"""A software FIDO2 authenticator for tests without a key: just the parts of
python-fido2 that qk_fido.py and qk.py use (credential management, makeCredential,
PIN retries, authenticatorConfig, large blobs)."""
import os
import hashlib
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../tools"))
import qk  # noqa: E402
import fido2.ctap2.config  # noqa: E402
import fido2.ctap2.pin  # noqa: E402
import fido2.ctap2.blob  # noqa: E402
from cryptography.hazmat.primitives import serialization as ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402

PIN = "314159"


class Obj:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class FakeFido:
    def __init__(self):
        self.creds = []                         # dicts of rp, user, id, alg, public_key
        self.always_uv, self.pin_tries = False, 8
        self.blobs = [{1: b"x", 2: b"n", 3: 40}, {1: b"y", 2: b"m", 3: 2}]
        self.presses = 0
        self.info = Obj(versions=["FIDO_2_1", "U2F_V2"], aaguid="1234", extensions=["credProtect", "hmac-secret"],
                        options={"rk": True, "alwaysUv": False, "credMgmt": True, "authnrCfg": True},
                        max_large_blob=2048)

    def add(self, rp, name, alg=-7, display="", rp_name="", protect=1):
        if alg == -8:
            raw = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
            pk = {1: 1, 3: -8, -1: 6, -2: raw}
        else:
            nums = ec.generate_private_key(ec.SECP256R1()).public_key().public_numbers()
            pk = {1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
        cred = {"rp": rp, "rp_name": rp_name, "user": {"id": os.urandom(8), "name": name, "displayName": display},
                "id": os.urandom(32), "public_key": pk, "protect": protect}
        self.creds.append(cred)
        return cred

    # ---- Ctap2
    def make_credential(self, cdh, rp, user, params, options=None, **kw):
        self.presses += 1
        cred = self.add(rp["id"], user["name"], params[0]["alg"])
        cred["user"]["id"] = user["id"]
        if not (options or {}).get("rk"):
            self.creds.remove(cred)
        return Obj(auth_data=Obj(credential_data=Obj(public_key=cred["public_key"], credential_id=cred["id"])))


class FakeCM:
    def __init__(self, dev):
        self.dev = dev

    def get_metadata(self):
        return {1: len(self.dev.creds), 2: 50 - len(self.dev.creds)}

    def enumerate_rps(self):
        seen = {}
        for c in self.dev.creds:
            seen[c["rp"]] = {3: {"id": c["rp"], "name": c["rp_name"]}, 4: hashlib.sha256(c["rp"].encode()).digest()}
        return list(seen.values())

    def enumerate_creds(self, rp_hash):
        return [{6: c["user"], 7: {"id": c["id"], "type": "public-key"}, 8: c["public_key"], 10: c["protect"]}
                for c in self.dev.creds if hashlib.sha256(c["rp"].encode()).digest() == rp_hash]

    def update_user_info(self, cred_id, user):
        c = next(c for c in self.dev.creds if c["id"] == cred_id["id"])
        c["user"] = dict(user)

    def delete_cred(self, cred_id):
        self.dev.creds[:] = [c for c in self.dev.creds if c["id"] != cred_id["id"]]


class FakeClientPin:
    PERMISSION = fido2.ctap2.pin.ClientPin.PERMISSION

    def __init__(self, ctap, *a, **kw):
        self.dev = ctap
        self.protocol = Obj(VERSION=2, authenticate=lambda tok, msg: b"auth")

    def get_pin_retries(self):
        return self.dev.pin_tries, 0

    def get_pin_token(self, pin, permissions=None, rp_id=None):
        if pin != PIN:
            from fido2.ctap import CtapError
            self.dev.pin_tries -= 1
            raise CtapError(CtapError.ERR.PIN_INVALID)
        return b"token"


class FakeConfig:
    def __init__(self, ctap, protocol=None, token=None):
        self.dev = ctap

    def toggle_always_uv(self):
        self.dev.always_uv = not self.dev.always_uv
        self.dev.info.options["alwaysUv"] = self.dev.always_uv


class FakeLargeBlobs:
    def __init__(self, ctap, protocol=None, token=None):
        self.dev = ctap

    def read_blob_array(self):
        return list(self.dev.blobs)

    def write_blob_array(self, arr):
        self.dev.blobs[:] = arr


_dev = None


def install():
    """Routes qk and qk_fido to one fresh FakeFido and returns it."""
    global _dev
    _dev = FakeFido()
    qk.fido_ctap = lambda: _dev
    qk.fido_cm = lambda ctap, pin: _check(pin) or FakeCM(_dev)
    fido2.ctap2.pin.ClientPin = FakeClientPin
    fido2.ctap2.config.Config = FakeConfig
    fido2.ctap2.blob.LargeBlobs = FakeLargeBlobs
    return _dev


def _check(pin):
    FakeClientPin(_dev).get_pin_token(pin)
