import hashlib, os
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, CredentialManagement
from fido2.ctap2.pin import ClientPin
from fido2.ctap import CtapError

def log(*a): print(*a, flush=True)
dev = [d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x1209][0]
ctap = Ctap2(dev)
log("extensions:", ctap.info.extensions)
cp = ClientPin(ctap)
RP = "hmac.example"
cdh = hashlib.sha256(b"c").digest()

def token(perm):
    return cp.get_pin_token("314159", perm, RP)

log("STEP 1: makeCredential rk, credProtect=3, hmac-secret -> PRESS BUTTON")
t = token(ClientPin.PERMISSION.MAKE_CREDENTIAL)
att = ctap.make_credential(cdh, {"id": RP, "name": "H"}, {"id": b"carol", "name": "carol"},
                           [{"type": "public-key", "alg": -7}],
                           extensions={"credProtect": 3, "hmac-secret": True}, options={"rk": True},
                           pin_uv_param=cp.protocol.authenticate(t, cdh), pin_uv_protocol=cp.protocol.VERSION)
cred = att.auth_data.credential_data
log("  authData extensions:", att.auth_data.extensions, "cred meta:", hex(cred.credential_id[0]))
allow = [{"id": cred.credential_id, "type": "public-key"}]

log("STEP 2: getAssertion without PIN (credProtect=3) -> expect NO_CREDENTIALS, no press")
try:
    ctap.get_assertion(RP, cdh, allow_list=allow)
    log("  FAIL: credential usable without UV")
except CtapError as e:
    log("  ->", e.code.name)

def assertion_hmac(salts):
    ka, shared = cp._get_shared_secret()
    salt_enc = cp.protocol.encrypt(shared, b"".join(salts))
    ext = {"hmac-secret": {1: ka, 2: salt_enc, 3: cp.protocol.authenticate(shared, salt_enc),
                           4: cp.protocol.VERSION}}
    t = token(ClientPin.PERMISSION.GET_ASSERTION)
    a = ctap.get_assertion(RP, cdh, allow_list=allow, extensions=ext,
                           pin_uv_param=cp.protocol.authenticate(t, cdh), pin_uv_protocol=cp.protocol.VERSION)
    a.verify(cdh, cred.public_key)
    out = cp.protocol.decrypt(shared, a.auth_data.extensions["hmac-secret"])
    return a, out

salt1, salt2 = os.urandom(32), os.urandom(32)
log("STEP 3: getAssertion with PIN + hmac-secret(salt1) -> PRESS BUTTON")
a, out1 = assertion_hmac([salt1])
log("  flags", hex(a.auth_data.flags), "output len", len(out1))
log("STEP 4: getAssertion with PIN + hmac-secret(salt1, salt2) -> PRESS BUTTON")
a, out2 = assertion_hmac([salt1, salt2])
log("  output len", len(out2), "salt1 output stable:", out2[:32] == out1, "salt2 differs:", out2[32:] != out1)

c = CredentialManagement(ctap, cp.protocol, cp.get_pin_token("314159", ClientPin.PERMISSION.CREDENTIAL_MGMT))
for x in c.enumerate_creds(hashlib.sha256(RP.encode()).digest()):
    log("credMgmt: user", x[6], "credProtect", x[0x0A])
    c.delete_cred(x[7])
log("EXT TEST DONE")
