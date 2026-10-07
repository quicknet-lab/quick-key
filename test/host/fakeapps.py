"""In-memory stand-ins for qk.Oath and qk.Pwd (the OTP and password applications) for tests without a key.
State lives on the classes, as it lives on the key: every call of qk.Oath() / qk.Pwd() sees it."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../tools"))
import qk  # noqa: E402

PIN = "314159"
presses = []                         # what asked for the button


class FakeOath:
    accounts = {}                    # name -> {"hotp", "touch"}
    password = None
    hmac = {}

    def __init__(self, password=None):
        if self.password and password != self.password:
            raise qk.QkError("wrong OTP password")

    def list(self):
        return [((0x10 if a["hotp"] else 0x20) | 1, name) for name, a in self.accounts.items()]

    def codes(self, compute_pending=True):
        return [(n, None if a["hotp"] or a["touch"] else "123456") for n, a in self.accounts.items()]

    def calculate(self, name):
        if self.accounts[name]["touch"]:
            presses.append(f"otp {name}")
        return "654321"

    def add(self, name, secret, hotp=False, digits=6, algorithm="SHA1", touch=False, counter=0):
        self.accounts[name] = {"hotp": hotp, "touch": touch}

    def delete(self, name):
        del self.accounts[name]

    def set_password(self, new):
        type(self).password = new or None

    def hmac_slots(self):
        return sorted(self.hmac)

    def hmac_set(self, slot, secret):
        presses.append(f"hmac {slot}")
        if secret:
            self.hmac[slot] = secret
        else:
            self.hmac.pop(slot, None)


class FakePwd(qk.Pwd):
    records = []
    max = 100

    def __init__(self):
        self.tries, self.count = 8, len(self.records)

    def unlock(self, pin=None):
        if pin != PIN:
            raise qk.QkError("wrong PIN, 7 tries left")
        return self

    def list(self):
        return [{k: v for k, v in r.items() if k not in ("password", "note", "otp")} for r in self.records]

    def get(self, rid, with_password=False):
        rec = next(r for r in self.records if r["id"] == rid)
        if with_password and rec["flags"] & qk.PWD_TOUCH:
            presses.append(f"pwd {rec['name']}")
        return dict(rec) if with_password else {k: v for k, v in rec.items() if k != "password"}

    def put(self, fields, rid=None):
        fields = {k: v for k, v in fields.items() if v is not None}
        if rid is None:
            rid = max([r["id"] for r in self.records], default=-1) + 1
            self.records.append({"flags": 0, "id": rid, **fields})
        else:
            next(r for r in self.records if r["id"] == rid).update(fields)
        return rid

    def delete(self, rid):
        self.records[:] = [r for r in self.records if r["id"] != rid]

    def generate(self, length, chars):
        return "G" * length

    def reset(self):
        presses.append("pwd reset")
        self.records.clear()


def install():
    FakeOath.accounts, FakeOath.password, FakeOath.hmac = {}, None, {}
    FakePwd.records = []
    presses.clear()
    qk.Oath, qk.Pwd = FakeOath, FakePwd
    qk.oath_reset = lambda: (presses.append("otp reset"), FakeOath.accounts.clear(), setattr(FakeOath, "password", None))
