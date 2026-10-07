#!/usr/bin/env python3
"""The helpers of tools/qk.py added for the TUI without a key: password audit, release checks,
qk self-update, key detection, OTP reset."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../tools"))
import qk  # noqa: E402


def fails(fn, text):
    try:
        fn()
    except qk.QkError as e:
        assert text in str(e), e
        return
    raise AssertionError(f"no error '{text}'")


# ---- password audit
res = qk.pwd_audit([
    {"name": "a", "password": "password"}, {"name": "b", "password": "aaaaaaaaaa"}, {"name": "c", "password": "abc1"},
    {"name": "d", "password": "abcdefg1"}, {"name": "e", "password": "abcdefghijklm"},
    {"name": "f", "password": "Tr0ub4dor&3xyz!"}, {"name": "g", "password": "Tr0ub4dor&3xyz!"},
    {"name": "h", "password": ""}, {"name": "i"}, {"name": "j", "password": "Zx9$kLm2#pQw8vNr"}])
assert dict(res["weak"]) == {"a": "a very common password", "b": "one character repeated", "c": "shorter than 8 characters",
                             "d": "short and of few character types", "e": "one character type only"}, res["weak"]
assert res["reused"] == [["f", "g"]] and res["empty"] == ["h", "i"]
assert qk.pwd_audit([]) == {"weak": [], "reused": [], "empty": []}
print("password audit: common, repeated, short, few types, one type, reused, empty")


class FakePwd(qk.Pwd):
    def __init__(self):
        self.recs = [{"id": 0, "name": "x", "flags": 0, "password": "pw0"}, {"id": 1, "name": "t", "flags": qk.PWD_TOUCH,
                                                                           "password": "pw1"}]

    def list(self):
        return [{k: v for k, v in r.items() if k != "password"} for r in self.recs]

    def get(self, rid, with_password=False):
        assert not (self.recs[rid]["flags"] & qk.PWD_TOUCH), "a button-protected password must not be read"
        return dict(self.recs[rid])


skipped = []
recs, n = qk.pwd_audit_records(FakePwd(), skipped.append)
assert [r["name"] for r in recs] == ["x"] and n == 1 and skipped == ["t"]
print("audit reads only passwords that do not need the button")

# ---- versions and release checks
assert qk.version_tuple("v1.2.10") > qk.version_tuple("1.2.9") and qk.version_tuple("1.0.0") == (1, 0, 0)
fails(lambda: qk.version_tuple("1.x"), "cannot read the version")

state = {"tag": "v1.1.0", "installed": "1.0.0", "fw": "1.0.0"}
qk._http_get = lambda url, accept=None: ('{"tag_name": "%s"}' % state["tag"]).encode()
qk.qk_version = lambda: state["installed"]
qk.device_info = lambda: (state["fw"], "00") if state["fw"] else (_ for _ in ()).throw(qk.QkError("no key"))
st = qk.update_status()
assert st == {"latest": "1.1.0", "qk": "1.0.0", "qk_newer": True, "firmware": "1.0.0", "firmware_newer": True}, st
state.update(installed="1.1.0", fw=None)
st = qk.update_status()
assert st["qk_newer"] is False and st["firmware"] is None and st["firmware_newer"] is False, st
state.update(installed="source checkout", fw="1.1.0")
st = qk.update_status()
assert st["qk_newer"] is False and st["firmware_newer"] is False
print("update status: newer, current, no key, source checkout")

# ---- self-update
calls = []
qk.subprocess.run = lambda cmd, **kw: calls.append(cmd) or subprocess.CompletedProcess(cmd, 0, "", "")
state["installed"] = "1.0.0"
log = []
assert qk.self_update(log=log.append) == "1.1.0"
assert calls[0][1:5] == ["-m", "pip", "install", "--quiet"] and calls[0][-1].endswith("/archive/refs/tags/v1.1.0.tar.gz"), calls
assert calls[0][0] == sys.executable and log == ["installing qk 1.1.0..."]
assert qk.self_update("1.0.5") == "1.0.5" and calls[1][-1].endswith("v1.0.5.tar.gz")        # an explicit version may be older
fails(lambda: qk.self_update("1.0.0/../../evil"), "not a release version")
fails(lambda: qk.self_update("1.0"), "not a release version")
state["installed"] = "1.1.0"
n = len(calls)
assert qk.self_update() == "1.1.0" and len(calls) == n, "already current: nothing installed"
state["installed"] = "2.0.0"
fails(lambda: qk.self_update(), "older than the installed")
state["installed"] = "source checkout"
fails(lambda: qk.self_update(), "git pull")
state["installed"] = "1.0.0"
qk.subprocess.run = lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, "", "ERROR: no network\n")
fails(lambda: qk.self_update(), "ERROR: no network")
print("self-update: pip command, current, older, source checkout, pip failure")

# ---- key detection never raises
import fido2.hid  # noqa: E402
fido2.hid.CtapHidDevice.list_devices = staticmethod(lambda: [])
assert qk.device_present() is False
fido2.hid.CtapHidDevice.list_devices = staticmethod(lambda: (_ for _ in ()).throw(OSError("no hid")))
assert qk.device_present() is False


class Desc:
    def __init__(self, vid, pid):
        self.descriptor = type("D", (), {"vid": vid, "pid": pid})


fido2.hid.CtapHidDevice.list_devices = staticmethod(lambda: [Desc(1, 2), Desc(qk.VID, qk.PID)])
assert qk.device_present() is True
print("device_present")

# ---- OTP reset: without the access password, button confirmation
class OathCard:
    def __init__(self, sw):
        self.sw, self.sent = sw, []

    def select(self, aid):
        assert aid == qk.AID_OATH
        return b"", 0x9000

    def send(self, cla, ins, p1, p2, data=b"", check=True):
        self.sent.append((ins, p1, p2))
        return b"", self.sw


c = OathCard(0x9000)
qk.Card = lambda: c
qk.oath_reset()
assert c.sent == [(0x04, 0xDE, 0xAD)]
qk.Card = lambda: OathCard(0x6982)
fails(qk.oath_reset, "not confirmed")
print("OTP reset: INS 04 DE AD, not confirmed reported")
print("QK TOOLS TEST DONE")
