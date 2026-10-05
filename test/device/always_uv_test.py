# alwaysUv via authenticatorConfig. Needs PIN 314159. One button press.
import os
from fido2.hid import CtapHidDevice
from fido2.ctap import CtapError
from fido2.ctap1 import Ctap1, ApduError
from fido2.ctap2 import Ctap2, Config
from fido2.ctap2.pin import ClientPin

PIN = "314159"
dev = [d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x1209][0]
ctap = Ctap2(dev)

def token(perm, rp=None):
    cp = ClientPin(ctap)
    return cp.protocol, cp.get_pin_token(PIN, perm, rp)

def toggle():
    proto, tok = token(ClientPin.PERMISSION.AUTHENTICATOR_CFG)
    Config(ctap, proto, tok).toggle_always_uv()

def status():
    info = ctap.get_info()
    return info.options.get("alwaysUv"), info.options.get("makeCredUvNotRqd"), "U2F_V2" in info.versions

assert ctap.get_info().options.get("authnrCfg") is True
if status()[0]:
    toggle()                                            # leftover from an earlier run
assert status() == (False, True, True)

try:
    Config(ctap).toggle_always_uv()                     # PIN set: token required
    raise AssertionError("toggle without a token accepted")
except CtapError as e:
    assert e.code == CtapError.ERR.PUAT_REQUIRED, e
try:
    proto, tok = token(ClientPin.PERMISSION.GET_ASSERTION, "x.example")
    Config(ctap, proto, tok).toggle_always_uv()         # token without acfg permission
    raise AssertionError("toggle with a wrong permission accepted")
except CtapError as e:
    assert e.code == CtapError.ERR.PIN_AUTH_INVALID, e

toggle()
assert status() == (True, False, False)
print("alwaysUv on: makeCredUvNotRqd false, U2F hidden")

rp, user = {"id": "uv.example", "name": "uv"}, {"id": b"u1", "name": "u"}
params = [{"type": "public-key", "alg": -7}]
cdh = os.urandom(32)
try:
    ctap.make_credential(cdh, rp, user, params)
    raise AssertionError("makeCredential without UV accepted")
except CtapError as e:
    assert e.code == CtapError.ERR.PUAT_REQUIRED, e
try:
    ctap.get_assertion("uv.example", cdh)
    raise AssertionError("getAssertion without UV accepted")
except CtapError as e:
    assert e.code == CtapError.ERR.PUAT_REQUIRED, e
try:
    Ctap1(dev).get_version()
    raise AssertionError("U2F still works")
except ApduError as e:
    assert e.code == 0x6D00, hex(e.code)

proto, tok = token(ClientPin.PERMISSION.MAKE_CREDENTIAL, "uv.example")
cp = ClientPin(ctap)
param = cp.protocol.authenticate(tok, cdh)
print("PRESS BUTTON: register with UV")
att = ctap.make_credential(cdh, rp, user, params, pin_uv_param=param, pin_uv_protocol=cp.protocol.VERSION)
assert att.auth_data.flags & 0x04, "UV flag not set"
print("makeCredential with UV ok")

toggle()
assert status() == (False, True, True)
assert Ctap1(dev).get_version() == "U2F_V2"
print("alwaysUv off, U2F back; alwaysUv tests passed")
