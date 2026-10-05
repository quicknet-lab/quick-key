# largeBlobs + largeBlobKey. Needs PIN 314159. Two button presses.
import hashlib, os, struct
from fido2.hid import CtapHidDevice
from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2, CredentialManagement
from fido2.ctap2.blob import LargeBlobs
from fido2.ctap2.pin import ClientPin

PIN = "314159"
dev = [d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x1209][0]
ctap = Ctap2(dev)
P = ClientPin.PERMISSION
rp, user = {"id": "blob.example", "name": "blob"}, {"id": b"blob-user", "name": "blob"}
params = [{"type": "public-key", "alg": -7}]

info = ctap.get_info()
assert info.options.get("largeBlobs") and "largeBlobKey" in info.extensions
assert info.max_large_blob == 2048, info.max_large_blob

def token(perm, rp_id=None):
    cp = ClientPin(ctap)
    return cp.protocol, cp.get_pin_token(PIN, perm, rp_id)

def expect(code, fn, *a, **kw):
    try:
        fn(*a, **kw)
    except CtapError as e:
        assert e.code == code, (e.code, code)
        return
    raise AssertionError(f"expected {code}")

expect(CtapError.ERR.INVALID_OPTION, ctap.make_credential, os.urandom(32), rp, user, params,
       extensions={"largeBlobKey": True})               # needs rk

cdh = os.urandom(32)
proto, tok = token(P.MAKE_CREDENTIAL, rp["id"])
print("PRESS BUTTON: register with largeBlobKey")
att = ctap.make_credential(cdh, rp, user, params, extensions={"largeBlobKey": True}, options={"rk": True},
                           pin_uv_param=proto.authenticate(tok, cdh), pin_uv_protocol=proto.VERSION)
key = att.large_blob_key
assert key and len(key) == 32
cred_id = att.auth_data.credential_data.credential_id

proto, tok = token(P.LARGE_BLOB_WRITE)
lb = LargeBlobs(ctap, proto, tok)
lb.write_blob_array([])                                 # start from an empty array
assert lb.read_blob_array() == []
data = b"quick-key large blob " * 40
lb.put_blob(key, data)
assert lb.get_blob(key) == data
print("blob written and read back with the credential's key")

cdh = os.urandom(32)
proto, tok = token(P.GET_ASSERTION, rp["id"])
print("PRESS BUTTON: sign in with largeBlobKey")
a = ctap.get_assertion(rp["id"], cdh, extensions={"largeBlobKey": True},
                       pin_uv_param=proto.authenticate(tok, cdh), pin_uv_protocol=proto.VERSION)
assert a.large_blob_key == key
print("getAssertion returns the same largeBlobKey")

# Manual writes: two fragments, bad checksum, too big, no token
proto, tok = token(P.LARGE_BLOB_WRITE)
def write(offset, chunk, length=None, auth=True):
    msg = b"\xff" * 32 + b"\x0c\x00" + struct.pack("<I", offset) + hashlib.sha256(chunk).digest()
    kw = {"pin_uv_param": proto.authenticate(tok, msg), "pin_uv_protocol": proto.VERSION} if auth else {}
    return ctap.large_blobs(offset, set=chunk, length=length, **kw)

array = b"\x81\x41\x00"                                 # CBOR [h'00']
array += hashlib.sha256(array).digest()[:16]
write(0, array[:10], length=len(array))
write(10, array[10:])
assert ctap.large_blobs(0, get=100)[1] == array
print("two-fragment write ok")
bad = array[:-1] + bytes([array[-1] ^ 1])
expect(CtapError.ERR.INTEGRITY_FAILURE, write, 0, bad, len(bad))
assert ctap.large_blobs(0, get=100)[1] == array        # unchanged
expect(CtapError.ERR.LARGE_BLOB_STORAGE_FULL, write, 0, b"x" * 20, 2049)
expect(CtapError.ERR.INVALID_SEQ, write, 5, b"x")
expect(CtapError.ERR.PUAT_REQUIRED, write, 0, array, len(array), auth=False)
print("integrity check, size limit, sequence and auth enforced")

LargeBlobs(ctap, *token(P.LARGE_BLOB_WRITE)).write_blob_array([])
cm = CredentialManagement(ctap, *token(P.CREDENTIAL_MGMT))
rp_hash = hashlib.sha256(rp["id"].encode()).digest()
for c in cm.enumerate_creds(rp_hash):                   # also leftovers of interrupted runs
    cm.delete_cred(c[7])
print("cleaned up; largeBlobs tests passed")
