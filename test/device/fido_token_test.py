# FIDO pinUvAuthToken rules and related fixes: a token serves one
# getAssertion, must be used within 30 s, dies when the PIN is changed through
# PIV; getPinRetries reports powerCycleState after 3 wrong PINs (the key is
# rebooted with `qk reboot`); an unauthenticated largeBlobs write can't abort
# an upload in progress. No button presses; takes about a minute.
# Run `gpgconf --kill scdaemon` first.
import hashlib, os, struct, subprocess, sys, time
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, CredentialManagement
from fido2.ctap2.pin import ClientPin
from fido2.ctap import CtapError
from smartcard.System import readers

PIN = "314159"
P = ClientPin.PERMISSION
QK = [sys.executable, os.path.join(os.path.dirname(__file__), "..", "..", "tools", "qk.py")]
RP = "token.example"
cdh = hashlib.sha256(b"token").digest()

def connect():
    for _ in range(40):
        devs = [d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x1209]
        if devs:
            ctap = Ctap2(devs[0])
            return ctap, ClientPin(ctap)
        time.sleep(0.5)
    raise RuntimeError("key not found")

def expect(code, f, *a, **kw):
    try:
        f(*a, **kw)
    except CtapError as e:
        assert e.code == code, f"{e.code.name}, expected {code.name}"
        return
    raise AssertionError(f"no error, expected {code.name}")

ctap, cp = connect()

def ga(tok, code):
    # up=false and no credential for the RP: no button, the token check comes first.
    expect(code, ctap.get_assertion, RP, cdh, options={"up": False},
           pin_uv_param=cp.protocol.authenticate(tok, cdh), pin_uv_protocol=cp.protocol.VERSION)

# One getAssertion per token.
tok = cp.get_pin_token(PIN, P.GET_ASSERTION, RP)
ga(tok, CtapError.ERR.NO_CREDENTIALS)
ga(tok, CtapError.ERR.PIN_AUTH_INVALID)
print("token: one getAssertion per token")

# Unused for more than 30 s: expired.
tok = cp.get_pin_token(PIN, P.GET_ASSERTION, RP)
time.sleep(31)
ga(tok, CtapError.ERR.PIN_AUTH_INVALID)
print("token: unused for 30 s expires")

# A PIN change through PIV kills the FIDO token.
tok = cp.get_pin_token(PIN, P.CREDENTIAL_MGMT)
CredentialManagement(ctap, cp.protocol, tok).get_metadata()
r = [x for x in readers() if "Quick-Key" in str(x)][0]
c = r.createConnection(); c.connect()

def tx(apdu):
    _, s1, s2 = c.transmit(list(apdu))
    assert (s1, s2) == (0x90, 0x00), f"{bytes(apdu[:4]).hex()} -> {s1:02x}{s2:02x}"

pin8 = lambda p: list(p.encode().ljust(8, b"\xff"))
tx([0x00, 0xA4, 0x04, 0x00, 5, 0xA0, 0x00, 0x00, 0x03, 0x08])
tx([0x00, 0x24, 0x00, 0x80, 16] + pin8(PIN) + pin8("654321"))
tx([0x00, 0x24, 0x00, 0x80, 16] + pin8("654321") + pin8(PIN))
c.disconnect()
expect(CtapError.ERR.PIN_AUTH_INVALID, CredentialManagement(ctap, cp.protocol, tok).get_metadata)
print("token: dies when the PIN is changed through PIV")

# largeBlobs: a write without a token doesn't reset the upload in progress.
tok = cp.get_pin_token(PIN, P.LARGE_BLOB_WRITE)
def write(offset, chunk, length=None, auth=True):
    msg = b"\xff" * 32 + b"\x0c\x00" + struct.pack("<I", offset) + hashlib.sha256(chunk).digest()
    kw = {"pin_uv_param": cp.protocol.authenticate(tok, msg), "pin_uv_protocol": cp.protocol.VERSION} if auth else {}
    return ctap.large_blobs(offset, set=chunk, length=length, **kw)

array = b"\x80"                                         # CBOR []
array += hashlib.sha256(array).digest()[:16]
write(0, array[:10], length=len(array))
expect(CtapError.ERR.PUAT_REQUIRED, write, 0, b"x" * 17, 17, auth=False)
write(10, array[10:])
assert ctap.large_blobs(0, get=100)[1] == array
print("largeBlobs: an unauthenticated write doesn't abort an upload")

# powerCycleState after 3 wrong PINs; a reboot clears it.
tries = cp.get_pin_retries()[0]
for _ in range(2):
    expect(CtapError.ERR.PIN_INVALID, cp.get_pin_token, "000000")
expect(CtapError.ERR.PIN_AUTH_BLOCKED, cp.get_pin_token, "000000")
assert cp.get_pin_retries() == (tries - 3, True), cp.get_pin_retries()
ctap.device.close()
subprocess.run(QK + ["reboot"], check=True, capture_output=True)
time.sleep(3)
ctap, cp = connect()
assert cp.get_pin_retries()[1] is False
cp.get_pin_token(PIN)                                   # restores the tries
assert cp.get_pin_retries()[0] == tries
print("getPinRetries: powerCycleState after 3 wrong PINs, cleared by a reboot")
print("FIDO token tests passed")
