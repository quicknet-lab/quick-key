# Fixes in the smart card applications: an OpenPGP key import whose 7F48
# list ends in a truncated length is rejected; a touch-protected password
# record changes only with a press (its flag can't be cleared silently).
# 2 presses, both "Change record?" (refusal without a press goes through the
# same up_wait that touch_test.py checks). Run `gpgconf --kill scdaemon` first.
import os, subprocess, sys
from smartcard.System import readers

QK = [sys.executable, os.path.join(os.path.dirname(__file__), "..", "..", "tools", "qk.py")]

def qk(*args):
    p = subprocess.run(QK + list(args), capture_output=True, text=True)
    assert p.returncode == 0, f"qk {' '.join(args)}: {p.stdout}{p.stderr}"
    return p.stdout

r = [x for x in readers() if "Quick-Key" in str(x)][0]
c = r.createConnection(); c.connect()

def tx(apdu, ok=0x9000):
    data, s1, s2 = c.transmit(list(apdu))
    while s1 == 0x61:
        more, s1, s2 = c.transmit([0x00, 0xC0, 0x00, 0x00, s2])
        data += more
    sw = (s1 << 8) | s2
    assert sw == ok, f"{bytes(apdu[:4]).hex()} -> {sw:04x}, expected {ok:04x}"
    return bytes(data)

def cmd(ins, p1, p2, data=b"", ok=0x9000):
    return tx([0x00, ins, p1, p2] + ([len(data)] + list(data) if data else []), ok)

def tlv(tag, v):
    t = tag.to_bytes(2, "big") if tag > 0xFF else bytes([tag])
    return t + bytes([len(v)]) + v

# ---- OpenPGP: truncated length at the end of 7F48 ----
cmd(0xA4, 0x04, 0x00, bytes.fromhex("D27600012401"))
cmd(0x20, 0x00, 0x83, b"27182818")
status = cmd(0xCA, 0x00, 0xDE)
for tail in (b"\x92\x82", b"\x92\x82\x01", b"\x92\x81"):
    bad = tlv(0x4D, b"\xB6\x00" + tlv(0x7F48, tail) + tlv(0x5F48, b""))
    cmd(0xDB, 0x3F, 0xFF, bad, ok=0x6A80)
assert cmd(0xCA, 0x00, 0xDE) == status
print("OpenPGP: import with a truncated 7F48 length rejected, keys unchanged")
c.disconnect()

# ---- password record with --touch ----
out = qk("pwd", "add", "touch-edit", "--password", "pw-1", "--touch", "--pin", "314159")
rid = int(out.split("id ")[1].rstrip(")\n"))
c.connect()
cmd(0xA4, 0x04, 0x00, bytes.fromhex("F0514B505744"))
cmd(0x20, 0x00, 0x00, b"314159")
print("PRESS BUTTON (Change record? touch-edit)")
cmd(0xA3, 0x00, 0x00, tlv(0x08, bytes([rid])) + tlv(0x03, b"new-login"))      # keeps the flag
c.disconnect()
assert "touch     yes" in qk("pwd", "get", "touch-edit", "--pin", "314159")
c.connect()
cmd(0xA4, 0x04, 0x00, bytes.fromhex("F0514B505744"))
cmd(0x20, 0x00, 0x00, b"314159")
print("PRESS BUTTON (Change record? touch-edit) - clearing the flag also asks")
cmd(0xA3, 0x00, 0x00, tlv(0x08, bytes([rid])) + tlv(0x07, b"\x00"))
c.disconnect()
assert "touch     no" in qk("pwd", "get", "touch-edit", "--pin", "314159")
qk("pwd", "delete", "touch-edit", "--pin", "314159")
print("passwords: changing a touch record, including its flag, asks for the button")
print("apps fixes tests passed")
