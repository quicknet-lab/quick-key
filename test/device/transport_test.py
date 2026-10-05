# Transport fixes: CTAPHID channel IDs are random and only channels handed
# out by INIT are accepted, LOCK is reported as unsupported; a CCID card reset
# (ICC power on) drops the PIV PIN state through the worker. No button
# presses. Run `gpgconf --kill scdaemon` first.
import os, struct
from fido2.hid import CtapHidDevice, CTAPHID
from fido2.ctap import CtapError
from smartcard.System import readers
from smartcard.scard import SCARD_RESET_CARD

# ---- CTAPHID ----
def open_dev():
    return [d for d in CtapHidDevice.list_devices() if d.descriptor.vid == 0x1209][0]

cids = set()
for _ in range(3):
    d = open_dev()          # every open sends INIT and gets a new channel
    cids.add(d._channel_id)
    d.close()
dev = open_dev()
cids.add(dev._channel_id)
assert len(cids) == 4 and all(c not in (0, 0xFFFFFFFF) for c in cids), cids
assert dev.call(CTAPHID.PING, b"ping") == b"ping"

def expect(code, f):
    try:
        f()
    except CtapError as e:
        assert e.code == code, f"{e.code.name}, expected {code.name}"
        return
    raise AssertionError(f"no error, expected {code.name}")

expect(CtapError.ERR.INVALID_COMMAND, lambda: dev.call(CTAPHID.LOCK, b"\x05"))
own = dev._channel_id
dev._channel_id = struct.unpack(">I", os.urandom(4))[0] | 1
expect(CtapError.ERR.INVALID_CHANNEL, lambda: dev.call(CTAPHID.PING, b"x"))
dev._channel_id = own
assert dev.call(CTAPHID.PING, b"again") == b"again"
dev.close()
print("CTAPHID: random channel IDs, unknown channel rejected, LOCK unsupported")

# ---- CCID card reset ----
r = [x for x in readers() if "Quick-Key" in str(x)][0]
c = r.createConnection(); c.connect()

def tx(apdu, ok=0x9000):
    _, s1, s2 = c.transmit(list(apdu))
    sw = (s1 << 8) | s2
    assert sw == ok, f"{bytes(apdu[:4]).hex()} -> {sw:04x}, expected {ok:04x}"

SEL = [0x00, 0xA4, 0x04, 0x00, 5, 0xA0, 0x00, 0x00, 0x03, 0x08]
tx(SEL)
tx([0x00, 0x20, 0x00, 0x80, 8] + list(b"314159\xff\xff"))
tx([0x00, 0x20, 0x00, 0x80])                                # verified
c.reconnect(disposition=SCARD_RESET_CARD)                   # ICC power on
tx(SEL)
_, s1, s2 = c.transmit([0x00, 0x20, 0x00, 0x80])
assert s1 == 0x63, f"{s1:02x}{s2:02x}"                      # PIN needed again
c.disconnect()
print("CCID: a card reset drops the PIV PIN state")
print("transport tests passed")
