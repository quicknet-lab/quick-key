import os, time, hashlib, sys
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin
from fido2.ctap1 import Ctap1, ApduError
from fido2.attestation import PackedAttestation
from fido2.webauthn import AttestationObject
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography import x509

def log(*a): print(*a, flush=True)
dev = [d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x1209][0]
ctap = Ctap2(dev)
rp = {"id": "example.com", "name": "Example"}
user = {"id": b"user-1", "name": "alice", "displayName": "Alice"}
params = [{"type": "public-key", "alg": -7}]
cdh = hashlib.sha256(b"client-data").digest()

# The device PIN (314159) is always set, so a passkey needs a PIN token.
cp = ClientPin(ctap)
log("STEP 1: makeCredential rk=True with PIN -> PRESS BUTTON")
token = cp.get_pin_token("314159", ClientPin.PERMISSION.MAKE_CREDENTIAL, "example.com")
att = ctap.make_credential(cdh, rp, user, params, options={"rk": True},
                           pin_uv_param=cp.protocol.authenticate(token, cdh), pin_uv_protocol=cp.protocol.VERSION)
ao = AttestationObject.create(att.fmt, att.auth_data, att.att_stmt)
res = PackedAttestation().verify(att.att_stmt, att.auth_data, cdh)
cert = x509.load_der_x509_certificate(att.att_stmt["x5c"][0])
cred = att.auth_data.credential_data
log("  ok: fmt", att.fmt, "flags", hex(att.auth_data.flags), "attestation", res.attestation_type.name)
log("  cert subject:", cert.subject.rfc4514_string())

log("STEP 2: getAssertion (discoverable) -> PRESS BUTTON")
a = ctap.get_assertion("example.com", cdh)
a.verify(cdh, cred.public_key)
log("  ok: user", a.user, "counter", a.auth_data.counter, "cred id match", a.credential["id"] == cred.credential_id)

log("STEP 3: U2F register -> PRESS BUTTON")
u2f = Ctap1(dev)
app = hashlib.sha256(b"https://u2f.example").digest()
chal = os.urandom(32)
def retry(fn):
    t = time.time()
    while time.time() - t < 30:
        try:
            return fn()
        except ApduError as e:
            if e.code != 0x6985: raise
            time.sleep(0.25)
    raise TimeoutError
reg = retry(lambda: u2f.register(chal, app))
reg.verify(app, chal)
log("  ok: key handle len", len(reg.key_handle))
time.sleep(1)
log("STEP 4: U2F authenticate -> PRESS BUTTON")
auth = retry(lambda: u2f.authenticate(chal, app, reg.key_handle))
auth.verify(app, chal, reg.public_key)
log("  ok: counter", auth.counter, "up", auth.user_presence)

log("STEP 5: get token with PIN 314159, getAssertion with UV -> PRESS BUTTON")
token = cp.get_pin_token("314159", ClientPin.PERMISSION.GET_ASSERTION, "example.com")
pin_auth = cp.protocol.authenticate(token, cdh)
a = ctap.get_assertion("example.com", cdh, pin_uv_param=pin_auth, pin_uv_protocol=cp.protocol.VERSION)
a.verify(cdh, cred.public_key)
log("  ok: flags", hex(a.auth_data.flags), "user", a.user, "retries", cp.get_pin_retries())
try:
    cp.get_pin_token("000000")
except Exception as e:
    log("  wrong PIN rejected:", e, "retries", cp.get_pin_retries())
log("ALL FIDO STEPS PASSED")
