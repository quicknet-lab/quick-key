import hashlib
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, CredentialManagement
from fido2.ctap2.pin import ClientPin
from fido2.ctap import CtapError

def log(*a): print(*a, flush=True)
dev = [d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x1209][0]
ctap = Ctap2(dev)
log("versions:", ctap.info.versions, "credMgmt:", ctap.info.options.get("credMgmt"))
cp = ClientPin(ctap)
def cm():
    token = cp.get_pin_token("314159", ClientPin.PERMISSION.CREDENTIAL_MGMT)
    return CredentialManagement(ctap, cp.protocol, token)

c = cm()
log("metadata:", c.get_metadata())
for rp in c.enumerate_rps():
    log("rp:", rp[3]["id"])
    for cred in c.enumerate_creds(rp[4]):
        log("   user:", cred[6], "cred id ver:", hex(cred[7]["id"][0]))

log("make rk for delete.example -> PRESS BUTTON")
cdh = hashlib.sha256(b"x").digest()
token = cp.get_pin_token("314159", ClientPin.PERMISSION.MAKE_CREDENTIAL, "delete.example")
att = ctap.make_credential(cdh, {"id": "delete.example", "name": "D"},
                           {"id": b"bob", "name": "bob", "displayName": "Bob"},
                           [{"type": "public-key", "alg": -7}], options={"rk": True},
                           pin_uv_param=cp.protocol.authenticate(token, cdh), pin_uv_protocol=cp.protocol.VERSION)
cid = att.auth_data.credential_data.credential_id
log("  cred id version:", hex(cid[0]))

c = cm()
rph = hashlib.sha256(b"delete.example").digest()
c.update_user_info({"id": cid, "type": "public-key"}, {"id": b"bob", "name": "bob2", "displayName": "Bob Two"})
log("after update:", [x[6] for x in c.enumerate_creds(rph)])
c.delete_cred({"id": cid, "type": "public-key"})
log("deleted; metadata:", c.get_metadata())
try:
    ctap.get_assertion("delete.example", cdh, allow_list=[{"id": cid, "type": "public-key"}])
    log("FAIL: deleted credential still works")
except CtapError as e:
    log("assertion with deleted id ->", e.code.name)
log("CREDMGMT TEST DONE")
