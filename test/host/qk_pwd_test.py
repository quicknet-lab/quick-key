#!/usr/bin/env python3
"""Password export/import in tools/qk.py without a key: backup encryption,
CSV formats of other managers, field limits, duplicates, free space."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../tools"))
import qk  # noqa: E402


def fails(fn, text):
    try:
        fn()
    except qk.QkError as e:
        assert text in str(e), e
        return
    raise AssertionError(f"no error '{text}'")


class FakePwd(qk.Pwd):
    """Pwd on a list instead of a card."""
    def __init__(self, recs=(), cap=10):
        self.recs, self.max = [dict(r, id=i) for i, r in enumerate(recs)], cap

    def list(self):
        return [{k: v for k, v in r.items() if k not in ("password", "note")} for r in self.recs]

    def get(self, rid, with_password=False):
        return dict(self.recs[rid])

    def put(self, fields, rid=None):
        self.recs.append(dict({k: v for k, v in fields.items() if v is not None}, id=len(self.recs)))
        return len(self.recs) - 1


tmp = tempfile.mkdtemp()


def write(name, text):
    path = os.path.join(tmp, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


# backup: round trip, wrong password, owner-only file
recs = [{"name": "Pöst", "url": "https://mail.example", "login": "me", "password": "p@ss \"1\"", "note": "n",
         "flags": 1}, {"name": "x", "password": "y", "flags": 0}]
path = os.path.join(tmp, "b.json")
qk.pwd_save_backup(path, recs, "secret")
assert os.stat(path).st_mode & 0o777 == 0o600
assert qk.pwd_load(path, "secret") == (recs, [])
assert qk.pwd_load(path, lambda: "secret")[0] == recs
fails(lambda: qk.pwd_load(path, "wrong"), "wrong backup password")
fails(lambda: qk.pwd_load(path, ""), "backup password needed")
fails(lambda: qk.pwd_load(write("j.json", '{"format": "other"}'), "x"), "not a Quick-Key password backup")
fails(lambda: qk.pwd_load(os.path.join(tmp, "missing"), "x"), "cannot read")

# writing replaces the file: an existing 0644 file becomes 0600, a symlink is
# replaced instead of followed, no temporary files are left
os.chmod(path, 0o644)
qk.pwd_save_backup(path, recs, "secret")
assert os.stat(path).st_mode & 0o777 == 0o600
victim = write("victim.txt", "keep")
link = os.path.join(tmp, "link.json")
os.symlink(victim, link)
qk.pwd_save_backup(link, recs, "secret")
assert not os.path.islink(link) and open(victim).read() == "keep"
assert not [n for n in os.listdir(tmp) if n.startswith(".qk-backup-")]

# untrusted backup fields: KDF parameters are bounded, the payload must be records
import json  # noqa: E402
f = json.load(open(path))
f["kdf"]["p"] = 1000
fails(lambda: qk.pwd_load(write("p.json", json.dumps(f)), "secret"), "unsupported backup parameters")
fails(lambda: qk.pwd_load(write("arr.json", "[1, 2]"), "secret"), "no password column")       # not JSON-object: CSV
fails(lambda: qk.pwd_load(write("t.json", qk.pwd_backup_encrypt([{"name": 5}], "secret")), "secret"),
      "damaged backup file")
fails(lambda: qk.pwd_load(write("big.csv", "name,password\n\"" + "x" * 200000 + "\",y\n"), "x"), "as CSV")

# CSV exports of other managers
chrome = "name,url,username,password,note\nGitHub,https://github.com,me,pw1, a note \n"
assert qk.pwd_load(write("c.csv", chrome), None) == (
    [{"name": "GitHub", "url": "https://github.com", "login": "me", "password": "pw1", "note": "a note"}], [])
firefox = ('"url","username","password","httpRealm","formActionOrigin","guid"\n'
           '"https://www.example.org:8080/login","u","p w ","","",""\n')
r = qk.pwd_load(write("f.csv", firefox), None)[0][0]
assert r["name"] == "www.example.org" and r["password"] == "p w "
bitwarden = ("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n"
             ",,login,Bank,,,0,https://bank.example,bob,pw2,JBSWY3DPEHPK3PXP\n"
             ",,note,Wifi,code 1234,,0,,,,\n")
r, notes = qk.pwd_load(write("bw.csv", "﻿" + bitwarden), None)
assert [x["name"] for x in r] == ["Bank", "Wifi"] and r[0]["login"] == "bob" and r[1]["note"] == "code 1234"
assert notes == [("Bank", "TOTP secret not imported, add it with `qk otp add`")]
keepass = '"Group","Title","Username","Password","URL","Notes","TOTP"\n"Root","Mail","a@b","pw3","","",""\n'
assert qk.pwd_load(write("k.csv", keepass), None)[0] == [
    {"name": "Mail", "url": "", "login": "a@b", "password": "pw3", "note": ""}]
safari = "Title,URL,Username,Password,Notes,OTPAuth\nShop,https://shop.example,s,pw4,,\n"
assert qk.pwd_load(write("s.csv", safari), None)[0][0]["name"] == "Shop"
fails(lambda: qk.pwd_load(write("x.csv", "a,b\n1,2\n"), None), "no password column")

# field limits: name/url/note cut on a UTF-8 boundary, login/password skip the record
r, note = qk.pwd_fit({"name": "ü" * 40, "url": "u" * 200, "password": "p"})
assert len(r["name"].encode()) == 64 and r["name"] == "ü" * 32 and len(r["url"]) == 128
assert note == "name, url shortened"
assert qk.pwd_fit({"name": "a", "password": "p" * 129}) == (None, "skipped: password longer than 128 bytes")
assert qk.pwd_fit({"name": "", "password": "p"}) == (None, "skipped: no name")
assert qk.pwd_fit({"name": "a", "password": "p"}) == ({"flags": 0, "name": "a", "password": "p"}, None)

# import: duplicates on the key and in the file, notes, free space
p = FakePwd([{"name": "GitHub", "login": "me", "url": "https://github.com", "password": "old", "flags": 0}], cap=4)
added, dupes, notes = p.import_records([
    {"name": "GitHub", "login": "me", "url": "https://github.com", "password": "new"},
    {"name": "A", "password": "1"}, {"name": "A", "password": "1"},
    {"name": "B", "login": "l" * 65, "password": "2"}, {"name": "C", "password": "3", "flags": 1}])
assert (added, dupes) == (2, 2) and notes == [("B", "skipped: login longer than 64 bytes")]
assert [r["name"] for r in p.recs] == ["GitHub", "A", "C"] and p.recs[2]["flags"] == 1
fails(lambda: p.import_records([{"name": n, "password": "x"} for n in "DE"]), "not enough space: 2 new records, 1")
assert len(p.recs) == 3                             # nothing written

# export -> import into an empty key gives the same records
touched = []
out = FakePwd(recs).export_records(touched.append)
assert touched == ["Pöst"] and out == recs
q = FakePwd()
assert q.import_records(out)[:2] == (2, 0)
assert [{k: v for k, v in r.items() if k != "id"} for r in q.recs] == recs

print("qk pwd export/import ok")
