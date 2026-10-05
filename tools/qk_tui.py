#!/usr/bin/env python3
"""qk tui — terminal UI for the Quick-Key security key.

Requires: pip install textual (plus the qk requirements).
Arrows / Tab move, Enter acts, the footer shows the keys of the current tab;
the mouse works too. Device calls run in a worker thread, one at a time.
"""
import os
import shutil
import subprocess
import threading
import time

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (Button, Checkbox, DataTable, Footer, Header, Input, Label, ProgressBar, Select,
                             Static, TabbedContent, TabPane)

import qk

DEFAULT_IMAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "build", "quick-key.bin")


# ---------------------------------------------------------------- dialogs

class Form(ModalScreen):
    """Fields: (key, label, kind, default) with kind text / password / check / select:<a,b,c>.
    Dismisses with {key: value} or None."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, title, fields, ok="OK", note=""):
        super().__init__()
        self.title_text, self.fields, self.ok, self.note = title, fields, ok, note

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="dialog"):
            yield Label(self.title_text, classes="dialog-title")
            if self.note:
                yield Static(self.note, classes="note")
            for key, label, kind, default in self.fields:
                if kind == "check":
                    yield Checkbox(label, bool(default), id=f"f_{key}")
                    continue
                yield Label(label)
                if kind.startswith("select:"):
                    opts = kind[7:].split(",")
                    yield Select([(o, o) for o in opts], value=default or opts[0], allow_blank=False, compact=True,
                                 id=f"f_{key}")
                else:
                    yield Input(str(default or ""), password=kind == "password", compact=True, id=f"f_{key}")
            with Horizontal(classes="buttons"):
                yield Button(self.ok, variant="primary", id="ok")
                yield Button("Cancel", id="cancel")

    def on_mount(self):
        self.query("Input, Select, Checkbox").first().focus()

    @on(Input.Submitted)
    def submitted(self):
        self.action_ok()

    @on(Button.Pressed, "#ok")
    def action_ok(self):
        self.dismiss({key: self.query_one(f"#f_{key}").value for key, *_ in self.fields})

    @on(Button.Pressed, "#cancel")
    def action_cancel(self):
        self.dismiss(None)


class Confirm(ModalScreen):
    BINDINGS = [Binding("escape", "no", "Cancel")]

    def __init__(self, message, ok="Yes"):
        super().__init__()
        self.message, self.ok = message, ok

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Static(self.message)
            with Horizontal(classes="buttons"):
                yield Button(self.ok, variant="error", id="yes")
                yield Button("Cancel", id="no")

    def on_mount(self):
        self.query_one("#no").focus()

    @on(Button.Pressed, "#yes")
    def yes(self):
        self.dismiss(True)

    @on(Button.Pressed, "#no")
    def action_no(self):
        self.dismiss(False)


class RecordView(ModalScreen):
    """A password record; the password itself is read on request."""

    BINDINGS = [Binding("escape", "close", "Close"), Binding("s", "show", "Show password"),
                Binding("c", "copy", "Copy password")]

    def __init__(self, rec):
        super().__init__()
        self.rec = rec

    def compose(self) -> ComposeResult:
        with Vertical(classes="dialog"):
            yield Label(self.rec["name"], classes="dialog-title")
            for name in qk.PWD_FIELDS:
                if name == "password":
                    yield Static(f"[b]password[/b]  ******", id="pw")
                elif name != "name" and self.rec.get(name):
                    yield Static(f"[b]{name:8}[/b]  {self.rec[name]}")
            if self.rec["flags"] & qk.PWD_TOUCH:
                yield Static("reading the password needs the button", classes="note")
            with Horizontal(classes="buttons"):
                yield Button("Show (s)", id="show")
                yield Button("Copy (c)", variant="primary", id="copy")
                yield Button("Close", id="close")

    def read_password(self, then):
        app, rid = self.app, self.rec["id"]
        press = "to read the password" if self.rec["flags"] & qk.PWD_TOUCH else None
        app.with_pin(lambda pin: qk.Pwd().unlock(pin).get(rid, with_password=True).get("password", ""), then,
                     press=press)

    @on(Button.Pressed, "#show")
    def action_show(self):
        self.read_password(lambda pw: self.query_one("#pw", Static).update(f"[b]password[/b]  {pw}"))

    @on(Button.Pressed, "#copy")
    def action_copy(self):
        def done(pw):
            self.app.copy(pw)
            self.app.notify("password copied to the clipboard")
        self.read_password(done)

    @on(Button.Pressed, "#close")
    def action_close(self):
        self.dismiss(None)


# ---------------------------------------------------------------- tabs

class Panel(VerticalScroll):
    """A tab that loads its data from the key when first shown and on `r`."""

    loaded = False

    def load(self):
        pass

    def table(self) -> DataTable:
        return self.query_one(DataTable)

    def selected(self):
        t = self.table()
        if not t.row_count:
            return None
        return t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value


class DeviceTab(Panel):
    def compose(self) -> ComposeResult:
        yield Static("", id="dev_info")
        yield ProgressBar(total=100, show_eta=False, id="ota_progress")
        yield Static("", id="ota_log")
        with Horizontal(classes="buttons"):
            yield Button("Update firmware", id="update")
            yield Button("Reboot", id="reboot")
            yield Button("Factory reset", variant="error", id="factory")

    def on_mount(self):
        self.query_one("#ota_progress").display = False

    def load(self):
        self.app.device(qk.device_info, self.show)

    def show(self, info):
        version, uuid = info
        self.query_one("#dev_info", Static).update(f"[b]firmware[/b]  {version}\n[b]uuid[/b]      {uuid}")

    @on(Button.Pressed, "#reboot")
    def reboot(self):
        self.app.confirm("Reboot the key?", lambda: self.app.device(lambda: qk.admin(qk.ADMIN_REBOOT),
                                                                    lambda _: self.app.notify("rebooting")))

    @on(Button.Pressed, "#factory")
    def factory(self):
        self.app.confirm("FACTORY RESET: erase ALL keys, passkeys, OTP accounts and passwords, "
                         "PINs back to 123456 / 12345678?",
                         lambda: self.app.device(qk.factory_reset,
                                                 lambda _: self.app.notify("all data erased, rebooting"),
                                                 press="to confirm FACTORY RESET"), ok="Erase everything")

    @on(Button.Pressed, "#update")
    def update(self):
        default = os.path.normpath(DEFAULT_IMAGE) if os.path.isfile(DEFAULT_IMAGE) else ""

        def go(v):
            if v is None:
                return
            path = os.path.expanduser(v["path"].strip())
            if path and not os.path.isfile(path):
                self.app.notify(f"no such file: {path}", severity="error")
                return
            bar, log = self.query_one("#ota_progress", ProgressBar), self.query_one("#ota_log", Static)
            bar.display = True
            bar.update(progress=0)
            call = self.app.call_from_thread

            def run():
                say = lambda m: call(log.update, m.strip())
                image = path or qk.latest_image(log=say)[0]
                qk.update_ota(image, log=say, progress=lambda d, t: call(bar.update, progress=100 * d / t))
            self.app.device(run, lambda _: self.load(), press="to confirm the update")
        self.app.ask(Form("Update firmware (signed image)",
                          [("path", "Image (empty: latest release)", "text", default)], ok="Update"), go)


class PinTab(Panel):
    def compose(self) -> ComposeResult:
        yield Static("", id="pin_info")
        yield Static("One PIN (6-8 characters) for passkeys, OpenPGP, PIV and passwords. The admin PIN "
                     "(8 characters) is OpenPGP PW3 and PIV PUK; it unblocks the PIN.", classes="note")
        with Horizontal(classes="buttons"):
            yield Button("Change PIN", id="change")
            yield Button("Change admin PIN", id="change_admin")
            yield Button("Unblock PIN", id="unblock")

    def load(self):
        self.app.device(qk.pin_tries, self.show)

    def show(self, tries):
        user, adm = tries
        style = lambda n: f"[red]{n}[/red]" if n == 0 else str(n)
        self.query_one("#pin_info", Static).update(
            f"[b]PIN tries left[/b]        {style(user)} of 8\n[b]admin PIN tries left[/b]  {style(adm)} of 3")

    def run(self, title, old_label, admin_old, admin_new, fn, message):
        fields = [("old", old_label, "password", ""), ("new", "New", "password", ""),
                  ("again", "Repeat new", "password", "")]

        def go(v):
            if not v:
                return
            if v["new"] != v["again"]:
                self.app.notify("new PINs do not match", severity="error")
                return

            def done(_):
                if not admin_new:
                    self.app.pin = v["new"]
                self.app.notify(message)
                self.load()
            self.app.device(lambda: fn(v["old"], v["new"]), done, after_error=lambda _: self.load())
        self.app.ask(Form(title, fields), go)

    @on(Button.Pressed, "#change")
    def change(self):
        self.run("Change PIN", "Current PIN", False, False, qk.pin_change, "PIN changed")

    @on(Button.Pressed, "#change_admin")
    def change_admin(self):
        self.run("Change admin PIN", "Current admin PIN", True, True, qk.pin_change_admin, "admin PIN changed")

    @on(Button.Pressed, "#unblock")
    def unblock(self):
        self.run("Unblock PIN", "Admin PIN", True, False, qk.pin_unblock, "PIN set, tries restored")


class PasskeysTab(Panel):
    BINDINGS = [Binding("d", "delete", "Delete")]

    def compose(self) -> ComposeResult:
        yield Static("", id="fido_info")
        yield DataTable(cursor_type="row", zebra_stripes=True)
        with Horizontal(classes="buttons"):
            yield Button("Delete (d)", id="delete")
            yield Button("Reset FIDO", variant="error", id="reset")

    def on_mount(self):
        self.table().add_columns("Site", "User", "Display name", "ID")

    def load(self):
        self.app.with_pin(qk.fido_creds, self.show)

    def show(self, data):
        used, free, creds = data
        self.query_one("#fido_info", Static).update(f"{used} passkeys, {free} free")
        t = self.table()
        t.clear()
        for c in creds:
            t.add_row(c["rp"], c["name"], c["display"], c["id"].hex()[:16] + "…", key=c["id"].hex())

    @on(Button.Pressed, "#delete")
    def action_delete(self):
        cid = self.selected()
        if not cid:
            return
        t = self.table()
        site, user = t.get_row(cid)[:2]
        self.app.confirm(f"Delete the passkey of {user} on {site}?",
                         lambda: self.app.with_pin(lambda pin: qk.fido_delete(pin, bytes.fromhex(cid)),
                                                   lambda _: self.load()), ok="Delete")

    @on(Button.Pressed, "#reset")
    def reset(self):
        self.app.confirm("Erase ALL passkeys? The key accepts this only within 10 s after plugging it in: "
                         "re-plug it first. The PIN stays.",
                         lambda: self.app.device(lambda: qk.fido_ctap().reset(), lambda _: self.load(),
                                                 press="to erase all passkeys"), ok="Erase passkeys")


class OtpTab(Panel):
    BINDINGS = [Binding("a", "add", "Add"), Binding("d", "delete", "Delete")]

    def compose(self) -> ComposeResult:
        yield DataTable(cursor_type="row", zebra_stripes=True)
        yield ProgressBar(total=30, show_eta=False, show_percentage=False, id="otp_time")
        yield Static("Enter copies a code; on a HOTP or button-protected account it computes the code first.",
                     classes="note")
        with Horizontal(classes="buttons"):
            yield Button("Add (a)", id="add")
            yield Button("Delete (d)", id="delete")
            yield Button("Access password", id="password")

    def on_mount(self):
        self.table().add_columns("Account", "Type", "Code")
        self.period = None
        self.set_interval(1, self.tick)

    def tick(self):
        bar = self.query_one("#otp_time", ProgressBar)
        bar.update(progress=30 - time.time() % 30)
        period = int(time.time()) // 30
        if self.loaded and self.period is not None and period != self.period and self.app.active_tab() is self:
            self.load()

    def oath(self):
        return qk.Oath(self.app.oath_password)

    def load(self):
        def fetch():
            o = self.oath()
            kinds = {name: "HOTP" if t & 0xF0 == 0x10 else "TOTP" for t, name in o.list()}
            return [(name, kinds.get(name, "TOTP"), code) for name, code in o.codes(compute_pending=False)]
        self.period = int(time.time()) // 30
        self.app.device(fetch, self.show, after_error=self.ask_password)

    def ask_password(self, err):
        if "OTP password" not in str(err):
            return
        def go(v):
            if v is not None:
                self.app.oath_password = v["password"]
                self.load()
        self.app.ask(Form("OTP access password", [("password", "Password", "password", "")]), go)

    def show(self, rows):
        t = self.table()
        cur = self.selected()
        t.clear()
        for name, kind, code in rows:
            t.add_row(name, kind, code or "[dim]Enter[/dim]", key=name)
        if cur in [r[0] for r in rows]:
            t.move_cursor(row=t.get_row_index(cur))

    @on(DataTable.RowSelected)
    def compute(self, ev):
        name = ev.row_key.value
        t = self.table()
        code = str(t.get_row(name)[2])
        if not code.startswith("[dim]"):
            self.app.copy(code)
            self.app.notify(f"{name}: {code} copied")
            return
        self.app.device(lambda: self.oath().calculate(name),
                        lambda code: t.update_cell(name, t.ordered_columns[2].key, code),
                        press=f"if '{name}' needs it")

    @on(Button.Pressed, "#add")
    def action_add(self):
        fields = [("name", "Account name (issuer:user)", "text", ""),
                  ("secret", "Secret (base32) or otpauth:// URI", "text", ""),
                  ("type", "Type", "select:TOTP,HOTP", "TOTP"), ("digits", "Digits", "select:6,7,8", "6"),
                  ("algorithm", "Algorithm", "select:SHA1,SHA256,SHA512", "SHA1"),
                  ("touch", "Require the button for codes", "check", False)]

        def go(v):
            if not v:
                return
            name, secret, hotp, digits, alg = v["name"], v["secret"].strip(), v["type"] == "HOTP", int(v["digits"]), v["algorithm"]
            counter = 0
            if secret.startswith("otpauth://"):
                from urllib.parse import parse_qs, unquote, urlparse
                u = urlparse(secret)
                q = {k: vs[0] for k, vs in parse_qs(u.query).items()}
                hotp = u.netloc.lower() == "hotp"
                name = name or unquote(u.path.lstrip("/"))
                secret, alg = q.get("secret", ""), q.get("algorithm", "SHA1").upper()
                # A bad URI must not crash the app: its traceback would print
                # the secret to the terminal.
                try:
                    digits, counter = int(q.get("digits", 6)), int(q.get("counter", 0))
                except ValueError:
                    digits = counter = None
                if digits not in (6, 7, 8) or counter is None or counter < 0 or alg not in ("SHA1", "SHA256", "SHA512"):
                    self.app.notify("unsupported otpauth URI (digits, counter or algorithm)", severity="error")
                    return
            if not name or not secret:
                self.app.notify("name and secret are required", severity="error")
                return
            self.app.device(lambda: self.oath().add(name, secret, hotp, digits, alg, v["touch"], counter),
                            lambda _: self.load())
        self.app.ask(Form("Add OTP account", fields, ok="Add"), go)

    @on(Button.Pressed, "#delete")
    def action_delete(self):
        name = self.selected()
        if name:
            self.app.confirm(f"Delete the OTP account {name}?",
                             lambda: self.app.device(lambda: self.oath().delete(name), lambda _: self.load()),
                             ok="Delete")

    @on(Button.Pressed, "#password")
    def password(self):
        def go(v):
            if v is None:
                return

            def done(_):
                self.app.oath_password = v["new"]
                self.app.notify("OTP password set" if v["new"] else "OTP password cleared")
            self.app.device(lambda: self.oath().set_password(v["new"]), done)
        self.app.ask(Form("OTP access password", [("new", "New password (empty to clear)", "password", "")]),
                             go)


class PasswordsTab(Panel):
    BINDINGS = [Binding("a", "add", "Add"), Binding("e", "edit", "Edit"), Binding("d", "delete", "Delete")]

    def compose(self) -> ComposeResult:
        yield Static("", id="pwd_info")
        yield DataTable(cursor_type="row", zebra_stripes=True)
        with Horizontal(classes="buttons"):
            yield Button("Add (a)", id="add")
            yield Button("Edit (e)", id="edit")
            yield Button("Delete (d)", id="delete")
            yield Button("Generate", id="gen")
            yield Button("Export", id="export")
            yield Button("Import", id="import")
            yield Button("Erase all", variant="error", id="reset")

    def on_mount(self):
        self.table().add_columns("Name", "Login", "URL", "Button")
        self.records = {}

    def load(self):
        def fetch(pin):
            p = qk.Pwd().unlock(pin)
            return p.list(), p.max
        self.app.with_pin(fetch, self.show)

    def show(self, data):
        recs, cap = data
        self.records = {str(r["id"]): r for r in recs}
        self.query_one("#pwd_info", Static).update(f"{len(recs)} of {cap} records")
        t = self.table()
        t.clear()
        for r in recs:
            t.add_row(r["name"], r.get("login", ""), r.get("url", ""), "yes" if r["flags"] & qk.PWD_TOUCH else "",
                      key=str(r["id"]))

    @on(DataTable.RowSelected)
    def open(self, ev):
        rid = int(ev.row_key.value)
        self.app.with_pin(lambda pin: qk.Pwd().unlock(pin).get(rid), lambda rec: self.app.ask(RecordView(rec)))

    def form(self, title, rec, rid):
        fields = [("name", "Name", "text", rec.get("name")), ("url", "URL", "text", rec.get("url")),
                  ("login", "Login", "text", rec.get("login")),
                  ("password", "Password" + (" (empty: keep)" if rid is not None else ""), "password", ""),
                  ("generate", "Generate the password on the key (20 characters)", "check", False),
                  ("note", "Note", "text", rec.get("note")), ("otp", "Linked OTP account", "text", rec.get("otp")),
                  ("touch", "Reading the password needs the button", "check", rec.get("flags", 0) & qk.PWD_TOUCH)]

        def go(v):
            if not v:
                return

            def save(pin):
                p = qk.Pwd().unlock(pin)
                fields = {k: v[k] for k in ("name", "url", "login", "note", "otp")}
                fields["flags"] = qk.PWD_TOUCH if v["touch"] else 0
                pw = p.generate(20, "luds") if v["generate"] else v["password"]
                if pw or rid is None:
                    fields["password"] = pw
                p.put(fields, rid)
            self.app.with_pin(save, lambda _: self.load())
        self.app.ask(Form(title, fields, ok="Save"), go)

    @on(Button.Pressed, "#add")
    def action_add(self):
        self.form("Add password", {}, None)

    @on(Button.Pressed, "#edit")
    def action_edit(self):
        rid = self.selected()
        if rid:
            self.app.with_pin(lambda pin: qk.Pwd().unlock(pin).get(int(rid)),
                              lambda rec: self.form(f"Edit {rec['name']}", rec, int(rid)))

    @on(Button.Pressed, "#delete")
    def action_delete(self):
        rid = self.selected()
        if rid:
            self.app.confirm(f"Delete {self.records[rid]['name']}?",
                             lambda: self.app.with_pin(lambda pin: qk.Pwd().unlock(pin).delete(int(rid)),
                                                       lambda _: self.load()), ok="Delete")

    @on(Button.Pressed, "#gen")
    def gen(self):
        def done(pw):
            self.app.copy(pw)
            self.app.notify(f"{pw}\n(copied to the clipboard)", title="Generated password", timeout=15)
        self.app.device(lambda: qk.Pwd().generate(20, "luds"), done)

    @on(Button.Pressed, "#export")
    def export(self):
        def go(v):
            if not v:
                return
            if not v["password"] or v["password"] != v["again"]:
                self.app.notify("The backup passwords are empty or do not match.", severity="error")
                return

            def run(pin):
                recs = qk.Pwd().unlock(pin).export_records()
                qk.pwd_save_backup(v["file"], recs, v["password"])
                return len(recs)
            touch = any(r["flags"] & qk.PWD_TOUCH for r in self.records.values())

            def export():
                self.app.with_pin(run, lambda n: self.app.notify(f"{n} records saved to {v['file']}"),
                                  press="for each password protected by the button" if touch else None)
            if os.path.exists(os.path.expanduser(v["file"])):
                self.app.confirm(f"{v['file']} exists. Replace it?", export, ok="Replace")
            else:
                export()
        self.app.ask(Form("Export passwords", [("file", "File", "text", "~/quick-key-passwords.json"),
                                               ("password", "Backup password", "password", ""),
                                               ("again", "Repeat", "password", "")], ok="Export",
                          note="All records with passwords, encrypted with the backup password."), go)

    @on(Button.Pressed, "#import")
    def import_(self):
        def go(v):
            if not v:
                return

            def run(pin):
                recs, notes = qk.pwd_load(v["file"], v["password"])
                added, dupes, more = qk.Pwd().unlock(pin).import_records(recs)
                return added, dupes, notes + more

            def done(res):
                added, dupes, notes = res
                msg = f"{added} records imported" + (f", {dupes} already on the key" if dupes else "")
                for name, note in notes[:8]:
                    msg += f"\n{name}: {note}"
                if len(notes) > 8:
                    msg += f"\n... and {len(notes) - 8} more notes (see `qk pwd import`)"
                self.app.notify(msg, title="Import", timeout=20)
                self.load()
            self.app.with_pin(run, done)
        self.app.ask(Form("Import passwords", [("file", "File", "text", ""),
                                               ("password", "Backup password (Quick-Key backup only)", "password", "")],
                          ok="Import", note="A Quick-Key backup, or a CSV export of Bitwarden, KeePassXC, "
                                            "Chrome, Firefox, Safari or 1Password. Records already on the key "
                                            "are skipped."), go)

    @on(Button.Pressed, "#reset")
    def reset(self):
        self.app.confirm("Erase ALL passwords?",
                         lambda: self.app.device(lambda: qk.Pwd().reset(), lambda _: self.load(),
                                                 press="to erase all passwords"), ok="Erase")


class PgpTab(Panel):
    def compose(self) -> ComposeResult:
        yield Static("", id="pgp_info")
        yield DataTable(cursor_type="row")
        with Horizontal(classes="buttons"):
            yield Button("Reset OpenPGP", variant="error", id="reset")

    def on_mount(self):
        self.table().add_columns("Key", "Algorithm", "Fingerprint")

    def load(self):
        self.app.device(qk.pgp_status, self.show)

    def show(self, st):
        self.query_one("#pgp_info", Static).update(f"[b]serial[/b]  {st['serial']}")
        t = self.table()
        t.clear()
        for name, algo, fp in st["keys"]:
            t.add_row(name, algo, " ".join(fp[i:i + 4] for i in range(0, 40, 4)) if fp else "[dim]none[/dim]")

    @on(Button.Pressed, "#reset")
    def reset(self):
        def go(v):
            if v:
                self.app.device(lambda: qk.pgp_reset(v["admin"]), lambda _: self.load())
        self.app.ask(Form("Reset OpenPGP", [("admin", "Admin PIN", "password", "")], ok="Erase keys",
                                  note="Erases the OpenPGP keys and card data. The PINs stay."), go)


class PivTab(Panel):
    def compose(self) -> ComposeResult:
        yield DataTable(cursor_type="row")
        yield Static("Management key by default 010203040506070801020304050607080102030405060708 (3DES). "
                     "Keys and certificates are made with ykman or OpenSC.", classes="note")
        with Horizontal(classes="buttons"):
            yield Button("Reset PIV", variant="error", id="reset")

    def on_mount(self):
        self.table().add_columns("Slot", "Purpose", "Certificate")

    def load(self):
        self.app.device(qk.piv_status, self.show)

    def show(self, slots):
        t = self.table()
        t.clear()
        for slot, name, cert in slots:
            t.add_row(f"{slot:02X}", name, "yes" if cert else "[dim]empty[/dim]")

    @on(Button.Pressed, "#reset")
    def reset(self):
        self.app.confirm("Erase PIV keys and certificates? The PINs stay.",
                         lambda: self.app.device(qk.piv_reset, lambda _: self.load(), press="to reset PIV"),
                         ok="Erase PIV")


# ---------------------------------------------------------------- app

class QkApp(App):
    TITLE = "Quick-Key"
    CSS = """
    TabbedContent, ContentSwitcher, TabPane { height: 1fr; }
    Panel { height: 1fr; padding: 1 2; }
    .buttons { height: auto; margin-top: 1; }
    .buttons Button { margin-right: 2; }
    .note { color: $text-muted; margin: 1 0; }
    DataTable { height: auto; max-height: 20; margin-top: 1; }
    #otp_time { margin-top: 1; }
    Form, Confirm, RecordView { align: center middle; }
    .dialog { width: 72; height: auto; max-height: 90%; border: thick $primary; background: $surface; padding: 1 2; }
    .dialog-title { text-style: bold; margin-bottom: 1; }
    .dialog Input, .dialog Select, .dialog Checkbox { margin-bottom: 1; }
    .dialog Input, .dialog Select { background: $boost; }
    """
    BINDINGS = [Binding("q", "quit", "Quit"), Binding("r", "reload", "Refresh")]
    TABS = (("device", "Device", DeviceTab), ("pin", "PIN", PinTab), ("passkeys", "Passkeys", PasskeysTab),
            ("otp", "OTP", OtpTab), ("passwords", "Passwords", PasswordsTab), ("pgp", "OpenPGP", PgpTab),
            ("piv", "PIV", PivTab))

    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()
        self.pin = None                 # the device PIN, kept for this session only
        self.oath_password = ""

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            for tid, title, cls in self.TABS:
                with TabPane(title, id=tid):
                    yield cls(id=f"tab_{tid}")
        yield Footer()

    def active_tab(self) -> Panel:
        return self.query_one(f"#tab_{self.query_one(TabbedContent).active}", Panel)

    @on(TabbedContent.TabActivated)
    def activated(self):
        tab = self.active_tab()
        self.refocus()
        if not tab.loaded:
            tab.loaded = True
            # After the focus moved: a dialog opened now would hand the focus
            # back to the previous tab when it closes, and switch to that tab.
            self.call_after_refresh(tab.load)

    def refocus(self):
        # Focus inside the current tab, so that its keys work and show in the footer.
        self.active_tab().query("DataTable, Button").first().focus()

    def ask(self, screen, then=None):
        """Shows a dialog; afterwards focus goes back to the current tab
        (Textual would restore it to wherever it was, maybe a hidden tab)."""
        def done(value):
            self.call_after_refresh(self.refocus)
            if then:
                then(value)
        self.push_screen(screen, done)

    def action_reload(self):
        self.active_tab().load()

    # ---- device access

    def device(self, fn, done=None, press=None, after_error=None):
        """Runs fn() in a worker; done(result) or after_error(exception) back on the UI thread.
        press: why the button is needed (shown while waiting)."""
        self._run(fn, done, press, after_error)

    @work(thread=True)
    def _run(self, fn, done, press, after_error):
        if press:
            self.call_from_thread(self.notify, f"Press the button on the key {press}.", title="Button",
                                  severity="warning", timeout=30)
        with self.lock:
            try:
                result = fn()
            except BaseException as e:  # noqa: BLE001 - shown to the user
                self.call_from_thread(self.failed, e, after_error)
                return
            finally:
                if press:
                    self.call_from_thread(self.clear_notifications)
        if done:
            self.call_from_thread(done, result)

    def failed(self, err, after_error):
        msg = str(err) or type(err).__name__
        if "PIN" in msg and "admin" not in msg:
            self.pin = None             # wrong or blocked: ask again next time
        if "OTP password" not in msg:
            self.notify(msg, title="Error", severity="error", timeout=8)
        if after_error:
            after_error(err)

    def with_pin(self, fn, done=None, press=None):
        """Runs fn(pin) with the session PIN, asking for it first if needed."""
        if self.pin:
            self.device(lambda: fn(self.pin), done, press)
            return

        def go(v):
            if v and v["pin"]:
                self.pin = v["pin"]
                self.device(lambda: fn(self.pin), done, press)
        self.ask(Form("PIN", [("pin", "Device PIN", "password", "")], note="Kept in memory until you quit."), go)

    def confirm(self, message, then, ok="Yes"):
        self.ask(Confirm(message, ok), lambda yes: then() if yes else None)

    def copy(self, text):
        """Copies a secret; on macOS it is cleared after 30 s (and on exit) if
        the clipboard still holds it."""
        if shutil.which("pbcopy"):
            subprocess.run(["pbcopy"], input=text.encode(), check=False)
            self.copied = text
            self.set_timer(CLIPBOARD_CLEAR_S, lambda: clear_clipboard(text))
        else:
            self.copy_to_clipboard(text)


CLIPBOARD_CLEAR_S = 30


def clear_clipboard(text):
    """Empties the macOS clipboard if it still holds text."""
    if not text or not shutil.which("pbpaste"):
        return
    now = subprocess.run(["pbpaste"], capture_output=True, check=False).stdout
    if now == text.encode():
        subprocess.run(["pbcopy"], input=b"", check=False)


def main():
    app = QkApp()
    try:
        app.run()
    finally:
        clear_clipboard(getattr(app, "copied", None))


if __name__ == "__main__":
    main()
