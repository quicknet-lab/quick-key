# Ed25519 (COSE -8) credentials. Needs PIN 314159. Four button presses.
import os
from fido2.hid import CtapHidDevice
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2, CredentialManagement
from fido2.ctap2.pin import ClientPin
from fido2.cose import CoseKey, EdDSA, ES256
from fido2.attestation import PackedAttestation

PIN = "314159"
dev = [d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x1209][0]
ctap = Ctap2(dev)
rp, user = {"id": "ed.example", "name": "ed"}, {"id": b"ed-user", "name": "ed"}
ED, ES = {"type": "public-key", "alg": -8}, {"type": "public-key", "alg": -7}

algs = [a["alg"] for a in ctap.get_info().algorithms]
assert algs == [-7, -8], algs

def register(params, rk=False):
    cdh = os.urandom(32)
    kw = {}
    if rk:
        cp = ClientPin(ctap)
        tok = cp.get_pin_token(PIN, ClientPin.PERMISSION.MAKE_CREDENTIAL, rp["id"])
        kw = {"pin_uv_param": cp.protocol.authenticate(tok, cdh), "pin_uv_protocol": cp.protocol.VERSION,
              "options": {"rk": True}}
    print("PRESS BUTTON: register", [p["alg"] for p in params], "rk" if rk else "")
    att = ctap.make_credential(cdh, rp, user, params, **kw)
    cred = att.auth_data.credential_data
    PackedAttestation().verify(att.att_stmt, att.auth_data, cdh)   # P-256 attestation key
    return cred

cred = register([ED, ES])
assert isinstance(cred.public_key, EdDSA) and cred.public_key[-1] == 6, cred.public_key
cdh = os.urandom(32)
print("PRESS BUTTON: sign in with the Ed25519 credential")
a = ctap.get_assertion(rp["id"], cdh, [{"type": "public-key", "id": cred.credential_id}])
cred.public_key.verify(a.auth_data + cdh, a.signature)
assert len(a.signature) == 64
print("Ed25519 credential: registered, assertion verified")

rk = register([ED], rk=True)
cp = ClientPin(ctap)
cm = CredentialManagement(ctap, cp.protocol, cp.get_pin_token(PIN, ClientPin.PERMISSION.CREDENTIAL_MGMT))
rp_hash = [r[4] for r in cm.enumerate_rps() if r[3]["id"] == rp["id"]][0]
creds = cm.enumerate_creds(rp_hash)
mine = [c for c in creds if c[7]["id"] == rk.credential_id][0]
assert CoseKey.parse(mine[8]) == rk.public_key
cm.delete_cred({"id": rk.credential_id, "type": "public-key"})
print("Ed25519 resident credential listed with its key and deleted")

assert isinstance(register([ES, ED]).public_key, ES256)
try:
    ctap.make_credential(os.urandom(32), rp, user, [{"type": "public-key", "alg": -257}])
    raise AssertionError("RS256 accepted")
except CtapError as e:
    assert e.code == CtapError.ERR.UNSUPPORTED_ALGORITHM, e
print("RP preference order respected, unsupported alg rejected; Ed25519 tests passed")
