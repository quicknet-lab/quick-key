# Oversized encrypted fields in CTAP2 are rejected before decryption: pinHashEnc
# (getPinToken), newPinEnc (changePIN) and hmac-secret saltEnc (getAssertion),
# for both PIN protocols. No PIN tries are spent and the PIN stays the same.
# No button presses.
import hashlib, os
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2
from fido2.ctap import CtapError

dev = [d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x1209][0]
ctap = Ctap2(dev)
size = min(1024, ctap.info.max_msg_size - 256) // 16 * 16
cdh = hashlib.sha256(b"len").digest()

def expect(code, f):
    try:
        f()
    except CtapError as e:
        assert e.code == code, f"{e.code.name}, expected {code.name}"
        return
    raise AssertionError(f"no error, expected {code.name}")

for proto in (PinProtocolV1(), PinProtocolV2()):
    cp = ClientPin(ctap, proto)
    cp.get_pin_token("314159", ClientPin.PERMISSION.GET_ASSERTION, "len.example")     # full tries to start with
    tries = cp.get_pin_retries()[0]
    v = proto.VERSION

    # getPinToken: the PIN hash is 16 bytes; 48 bytes already overran a 32-byte buffer.
    for n in (48, size):
        ka, shared = cp._get_shared_secret()
        enc = proto.encrypt(shared, os.urandom(n))
        expect(CtapError.ERR.PIN_AUTH_INVALID, lambda: ctap.client_pin(
            v, ClientPin.CMD.GET_TOKEN_USING_PIN, key_agreement=ka, pin_hash_enc=enc,
            permissions=ClientPin.PERMISSION.GET_ASSERTION, permissions_rpid="len.example"))

    # changePIN with the right PIN hash but an 80-byte new PIN block (64 allowed).
    # Protocol 1 gets to the decryption; protocol 2 already exceeds the
    # 112-byte message limit there.
    ka, shared = cp._get_shared_secret()
    new_enc = proto.encrypt(shared, os.urandom(80))
    hash_enc = proto.encrypt(shared, hashlib.sha256(b"314159").digest()[:16])
    code = CtapError.ERR.PIN_AUTH_INVALID if v == 1 else CtapError.ERR.INVALID_LENGTH
    expect(code, lambda: ctap.client_pin(
        v, ClientPin.CMD.CHANGE_PIN, key_agreement=ka, new_pin_enc=new_enc, pin_hash_enc=hash_enc,
        pin_uv_param=proto.authenticate(shared, new_enc + hash_enc)))

    # hmac-secret: valid saltAuth over an oversized saltEnc, no PIN needed to get there.
    ka, shared = cp._get_shared_secret()
    salt_enc = proto.encrypt(shared, os.urandom(size))
    ext = {"hmac-secret": {1: ka, 2: salt_enc, 3: proto.authenticate(shared, salt_enc), 4: v}}
    expect(CtapError.ERR.INVALID_LENGTH, lambda: ctap.get_assertion("len.example", cdh, extensions=ext))

    assert cp.get_pin_retries()[0] == tries, "PIN tries spent"
    cp.get_pin_token("314159", ClientPin.PERMISSION.GET_ASSERTION, "len.example")     # PIN unchanged
    print(f"PIN protocol {v}: oversized pinHashEnc, newPinEnc, saltEnc rejected ({size} bytes)")

print("CTAP length tests passed")
