# Password manager with the device PIN (314159 at start and end). Three button presses.
import time
from smartcard.System import readers

r = [x for x in readers() if "Quick-Key" in str(x)][0]
c = r.createConnection(); c.connect()

AID = [0xF0, 0x51, 0x4B, 0x50, 0x57, 0x44]

def raw(apdu):
    data, s1, s2 = c.transmit(list(apdu))
    while s1 == 0x61:
        more, s1, s2 = c.transmit([0x00, 0xC0, 0x00, 0x00, s2])
        data += more
    return bytes(data), (s1 << 8) | s2

def tx(ins, p1=0, p2=0, data=b"", ok=0x9000):
    a = [0x00, ins, p1, p2]
    a += [0, len(data) >> 8, len(data) & 0xFF] + list(data) + [0, 0] if data else [0, 0, 0]
    resp, sw = raw(a)
    assert sw == ok, f"ins {ins:02x} -> {sw:04x}, expected {ok:04x}"
    return resp

def tlv(tag, v):
    v = v.encode() if isinstance(v, str) else bytes(v)
    if len(v) < 0x80: return bytes([tag, len(v)]) + v
    if len(v) < 0x100: return bytes([tag, 0x81, len(v)]) + v
    return bytes([tag, 0x82, len(v) >> 8, len(v) & 0xFF]) + v

def tlv_list(b):
    out, i = [], 0
    while i < len(b):
        t = b[i]; l = b[i + 1]; i += 2
        if l == 0x81: l = b[i]; i += 1
        elif l == 0x82: l = (b[i] << 8) | b[i + 1]; i += 2
        out.append((t, b[i:i + l])); i += l
    return out

NAME, URL, LOGIN, PASS, NOTE, OTP, FLAGS, ID = 1, 2, 3, 4, 5, 6, 7, 8

def select():
    st = dict(tlv_list(raw([0x00, 0xA4, 0x04, 0x00, len(AID)] + AID)[0]))[0x09]
    return {"pin_set": st[1], "tries": st[2], "count": st[3], "max": st[4]}

def piv(ins, p2, data, ok=0x9000):
    # The device PIN is changed and unblocked through PIV (8-byte padded fields).
    raw([0x00, 0xA4, 0x04, 0x00, 5, 0xA0, 0x00, 0x00, 0x03, 0x08])
    _, sw = raw([0x00, ins, 0x00, p2, len(data)] + list(data))
    assert sw == ok, f"PIV {ins:02x} -> {sw:04x}"
    select()

def pad(pin):
    return pin.encode() + b"\xff" * (8 - len(pin))

def list_all():
    entries, start = [], 0
    while True:
        page = [dict(tlv_list(v)) for t, v in tlv_list(tx(0xA1, start)) if t == 0x20]
        if not page: return entries
        entries += page
        start = page[-1][ID][0] + 1

def get(i, with_pass=False):
    return dict(tlv_list(tx(0xA2, 1 if with_pass else 0, 0, tlv(ID, [i]))))

print("PRESS BUTTON: reset password manager (screen: 'Reset PWD?')")
select()
tx(0x04, 0xDE, 0xAD)
assert select() == {"pin_set": 1, "tries": 8, "count": 0, "max": 250}   # the device PIN
tx(0xA1, ok=0x6982)                                 # locked
tx(0x20, ok=0x63C8)
tx(0x20, data=b"000000", ok=0x63C7)
t = time.time()
tx(0x20, data=b"314159")
print(f"unlock (PBKDF2) {time.time() - t:.2f}s")
assert select()["tries"] == 8
tx(0x20, data=b"314159")
tx(0x24, data=tlv(0x11, "314159"), ok=0x6D00)       # no own PIN any more

# add, read, update
rid = tx(0xA3, data=tlv(NAME, "mail") + tlv(URL, "https://mail.example") + tlv(LOGIN, "me")
         + tlv(PASS, "s3cret") + tlv(NOTE, "note"))
rid = dict(tlv_list(rid))[ID][0]
rec = get(rid)
assert rec[NAME] == b"mail" and PASS not in rec and rec[NOTE] == b"note"
assert get(rid, True)[PASS] == b"s3cret"
tx(0xA3, data=tlv(ID, [rid]) + tlv(LOGIN, "me2") + tlv(NOTE, ""))
rec = get(rid, True)
assert rec[LOGIN] == b"me2" and NOTE not in rec and rec[PASS] == b"s3cret"
tx(0xA3, data=tlv(ID, [rid]) + tlv(NAME, ""), ok=0x6A80)     # name required
tx(0xA3, data=tlv(NAME, "x" * 65), ok=0x6A80)
tx(0xA2, data=tlv(ID, [99]), ok=0x6A88)

# touch-protected password
tid = dict(tlv_list(tx(0xA3, data=tlv(NAME, "Bänk") + tlv(PASS, "pin1") + tlv(FLAGS, [1]))))[ID][0]
assert PASS not in get(tid)
print("PRESS BUTTON: read 'Bänk' password (screen: 'B?nk')")
assert get(tid, True)[PASS] == b"pin1"

# fill to 250 records with long fields: list needs several pages
t = time.time()
for i in range(248):
    tx(0xA3, data=tlv(NAME, f"site{i:03d}".ljust(64, "n")) + tlv(URL, "u" * 128) + tlv(LOGIN, "l" * 64)
       + tlv(PASS, "p" * 128) + tlv(NOTE, "z" * 256) + tlv(OTP, "o" * 64))
print(f"248 records written in {time.time() - t:.1f}s")
tx(0xA3, data=tlv(NAME, "overflow"), ok=0x6A84)
t = time.time()
entries = list_all()
print(f"listed {len(entries)} records in {time.time() - t:.1f}s")
assert len(entries) == 250 and all(PASS not in e and NOTE not in e for e in entries)
assert len({e[ID][0] for e in entries}) == 250
assert get(50, True)[NOTE] == b"z" * 256

tx(0xA4, data=tlv(ID, [50]))
tx(0xA4, data=tlv(ID, [50]), ok=0x6A88)
assert select()["count"] == 249

# change the device PIN; data stays readable
piv(0x24, 0x80, pad("314159") + pad("654321"))
tx(0x20, data=b"314159", ok=0x63C7)
tx(0x20, data=b"654321")
assert get(rid, True)[PASS] == b"s3cret"

# generator (no PIN needed)
pw = tx(0xA5, 20, 0x0F).decode()
assert len(pw) == 20 and any(ch.isdigit() for ch in pw) and any(ch.isupper() for ch in pw)
tx(0xA5, 3, 0x0F, ok=0x6A86)
tx(0xA5, 16, 0, ok=0x6A86)
print("generated:", pw)

# blocking
select()
for left in range(7, 0, -1):
    tx(0x20, data=b"000000", ok=0x63C0 | left)
tx(0x20, data=b"000000", ok=0x6983)
tx(0x20, data=b"654321", ok=0x6983)
# unblock with the admin PIN: records are still there
piv(0x2C, 0x80, pad("27182818") + pad("314159"))
tx(0x20, data=b"314159")
assert get(rid, True)[PASS] == b"s3cret"

print("PRESS BUTTON: reset password manager (screen: 'Reset PWD?')")
tx(0x04, 0xDE, 0xAD)
assert select() == {"pin_set": 1, "tries": 8, "count": 0, "max": 250}
print("password manager ok")
