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
from textual.command import Hit, Hits, Provider
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (Button, Checkbox, DataTable, Footer, Header, Input, Label, ProgressBar, Select,
                             Static, TabbedContent, TabPane)

import qk
import qk_fido
import qk_pgp
import qk_piv

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


class TextView(ModalScreen):
    """Shows a text (a public key, a certificate) that can be copied or saved to a file."""

    BINDINGS = [Binding("escape", "close", "Close"), Binding("c", "copy", "Copy")]

    def __init__(self, title, text, note=""):
        super().__init__()
        self.title_text, self.text, self.note = title, text, note

    def compose(self) -> ComposeResult:
        with VerticalScroll(classes="dialog wide"):
            yield Label(self.title_text, classes="dialog-title")
            if self.note:
                yield Static(self.note, classes="note")
            yield Static(self.text, markup=False, id="text_body")
            with Horizontal(classes="buttons"):
                yield Button("Copy (c)", variant="primary", id="copy")
                yield Button("Save to file", id="save")
                yield Button("Close", id="close")

    def on_mount(self):
        self.query_one("#copy").focus()

    @on(Button.Pressed, "#copy")
    def action_copy(self):
        self.app.copy(self.text)
        self.app.notify("copied to the clipboard")

    @on(Button.Pressed, "#save")
    def save(self):
        def go(v):
            if v and v["file"].strip():
                path = os.path.expanduser(v["file"].strip())
                try:
                    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                        f.write(self.text if self.text.endswith("\n") else self.text + "\n")
                except FileExistsError:
                    self.app.notify(f"{path} exists: choose another file name", severity="error")
                except OSError as e:
                    self.app.notify(f"cannot write {path}: {e.strerror}", severity="error")
                else:
                    self.app.notify(f"saved to {path}")
        self.app.push_screen(Form("Save to file", [("file", "File", "text", "")], ok="Save"), go)

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
        yield Static("", id="dev_updates", classes="note")
        yield ProgressBar(total=100, show_eta=False, id="ota_progress")
        yield Static("", id="ota_log")
        with Horizontal(classes="buttons"):
            yield Button("Check for updates", id="check")
            yield Button("Update firmware", id="update")
            yield Button("Update qk", id="update_qk")
        with Horizontal(classes="buttons"):
            yield Button("Reboot", id="reboot")
            yield Button("Factory reset", variant="error", id="factory")

    def on_mount(self):
        self.query_one("#ota_progress").display = False
        self.version = None

    def load(self):
        self.app.device(qk.device_info, self.show)

    def show(self, info):
        version, uuid = info
        self.version = version
        self.query_one("#dev_info", Static).update(
            f"[b]firmware[/b]  {version}\n[b]uuid[/b]      {uuid}\n[b]qk[/b]        {qk.qk_version()}")

    @on(Button.Pressed, "#check")
    def check(self):
        def show(st):
            lines = [f"Latest release: {st['latest']}"]
            lines.append("qk is up to date." if not st["qk_newer"] else
                         f"qk {st['qk']} is outdated: press Update qk.")
            if st["firmware"] is None:
                lines.append("No key plugged in: the firmware was not checked.")
            else:
                lines.append("The firmware is up to date." if not st["firmware_newer"] else
                             f"The firmware {st['firmware']} is outdated: press Update firmware.")
            self.query_one("#dev_updates", Static).update("\n".join(lines))
        self.app.device(qk.update_status, show, busy="Asking GitHub for the latest release...")

    @on(Button.Pressed, "#update_qk")
    def update_qk(self):
        log, before = self.query_one("#ota_log", Static), qk.qk_version()

        def run():
            return qk.self_update(log=lambda m: self.app.call_from_thread(log.update, m))

        def done(version):
            self.query_one("#ota_log", Static).update("")
            msg = (f"qk {version} is installed. Quit (q) and start qk again to use it." if version != before
                   else f"qk is already {version}.")
            self.query_one("#dev_updates", Static).update(msg)
            self.app.notify(msg, title="qk update", timeout=15)
        self.app.confirm("Download the latest qk release from GitHub and install it into the environment qk "
                         "runs from? Start qk again afterwards.", lambda: self.app.device(
                             run, done, busy="Installing qk..."), ok="Update qk")

    @on(Button.Pressed, "#reboot")
    def reboot(self):
        self.app.confirm("Reboot the key?", lambda: self.app.device(lambda: qk.admin(qk.ADMIN_REBOOT),
                                                                    lambda _: self.app.notify("rebooting")))

    @on(Button.Pressed, "#factory")
    def factory(self):
        self.app.confirm("FACTORY RESET: erase ALL keys, passkeys, OTP accounts and passwords, "
                         "PINs back to 123456 / 12345678?",
                         lambda: self.app.device(qk.factory_reset,
                                                 lambda _: (setattr(self.app, "mgmt_key", None),
                                                            self.app.notify("all data erased, rebooting")),
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
    BINDINGS = [Binding("d", "delete", "Delete"), Binding("e", "rename", "Rename"), Binding("/", "filter", "Filter"),
                Binding("u", "always_uv", "Always PIN"), Binding("b", "blobs", "Large blobs")]

    def compose(self) -> ComposeResult:
        yield Static("", id="fido_info")
        yield Input(placeholder="Filter by site or user (/)", compact=True, id="filter")
        yield DataTable(cursor_type="row", zebra_stripes=True)
        yield Static("Enter shows the details of a passkey.", classes="note")
        with Horizontal(classes="buttons"):
            yield Button("Rename (e)", id="rename")
            yield Button("Delete (d)", id="delete")
            yield Button("Always PIN (u)", id="always_uv")
            yield Button("Large blobs (b)", id="blobs")
            yield Button("Reset FIDO", variant="error", id="reset")

    def on_mount(self):
        self.table().add_columns("Site", "User", "Display name", "Algorithm", "Protection", "ID")
        self.creds, self.always_uv = {}, False

    def load(self):
        def fetch(pin):
            return qk_fido.passkeys(pin), qk_fido.info()["always_uv"]
        self.app.with_pin(fetch, self.show)

    def show(self, data):
        (used, free, creds), self.always_uv = data
        self.creds = {c["id"].hex(): c for c in creds}
        self.query_one("#fido_info", Static).update(
            f"{used} passkeys, {free} free   [b]always ask for the PIN[/b] {'on' if self.always_uv else 'off'}")
        self.render_rows()

    def render_rows(self):
        needle = self.query_one("#filter", Input).value.strip().lower()
        t = self.table()
        t.clear()
        for cid, c in self.creds.items():
            if needle and needle not in f"{c['rp']} {c['name']} {c['display']}".lower():
                continue
            t.add_row(c["rp"], c["name"], c["display"], c["alg"], c["protect"], cid[:16] + "…", key=cid)

    @on(Input.Changed, "#filter")
    def filtered(self):
        self.render_rows()

    @on(Input.Submitted, "#filter")
    def filter_done(self):
        self.table().focus()

    def action_filter(self):
        self.query_one("#filter", Input).focus()

    def current(self):
        cid = self.selected()
        return self.creds.get(cid) if cid else None

    @on(DataTable.RowSelected)
    def details(self):
        c = self.current()
        if not c:
            return
        lines = [("site", c["rp"]), ("site name", c["rp_name"]), ("user", c["name"]), ("display name", c["display"]),
                 ("user ID", c["user_id"].hex()), ("credential ID", c["id"].hex()), ("algorithm", c["alg"]),
                 ("credProtect", c["protect"] or "-")]
        self.app.ask(TextView(f"Passkey of {c['name']} on {c['rp']}",
                              "\n".join(f"{k:14}{v}" for k, v in lines if v)))

    @on(Button.Pressed, "#rename")
    def action_rename(self):
        c = self.current()
        if not c:
            return

        def go(v):
            if v:
                self.app.with_pin(lambda pin: qk_fido.rename(pin, c["id"], c["user_id"], v["name"].strip(), v["display"]),
                                  lambda _: self.load())
        self.app.ask(Form(f"Rename the passkey on {c['rp']}", [("name", "User name", "text", c["name"]),
                                                              ("display", "Display name", "text", c["display"])],
                          ok="Rename", note="Only the label stored on the key changes; the site is not told."), go)

    @on(Button.Pressed, "#delete")
    def action_delete(self):
        c = self.current()
        if not c:
            return
        self.app.confirm(f"Delete the passkey of {c['name']} on {c['rp']}?",
                         lambda: self.app.with_pin(lambda pin: qk.fido_delete(pin, c["id"]),
                                                   lambda _: self.load()), ok="Delete")

    @on(Button.Pressed, "#always_uv")
    def action_always_uv(self):
        want = not self.always_uv
        text = ("Always ask for the PIN: every registration and sign-in needs it, and U2F (the old second-factor "
                "mode) stops working. Some sites only support U2F.\nSwitch it on?" if want else
                "Switch off 'always ask for the PIN'? U2F works again and some sites will not ask for the PIN.")
        self.app.confirm(text, lambda: self.app.with_pin(lambda pin: qk_fido.set_always_uv(pin, want),
                                                         lambda _: self.load()), ok="Switch on" if want else "Switch off")

    @on(Button.Pressed, "#blobs")
    def action_blobs(self):
        def show(res):
            n, size, cap = res
            msg = f"The large blob array holds {n} entries, {size} bytes of data (capacity {cap} bytes)."
            if n:
                self.app.confirm(msg + "\nSites store data here (for example, certificates). Erase it all?",
                                 lambda: self.app.with_pin(qk_fido.clear_large_blobs,
                                                           lambda _: self.app.notify("large blobs erased")),
                                 ok="Erase")
            else:
                self.app.notify(msg, title="Large blobs")
        self.app.device(qk_fido.large_blobs, show)

    @on(Button.Pressed, "#reset")
    def reset(self):
        self.app.confirm("Erase ALL passkeys? The key accepts this only within 10 s after plugging it in: "
                         "re-plug it first. The PIN stays.",
                         lambda: self.app.device(lambda: qk.fido_ctap().reset(), lambda _: self.load(),
                                                 press="to erase all passkeys"), ok="Erase passkeys")


class SshTab(Panel):
    BINDINGS = [Binding("n", "create", "New key"), Binding("w", "save", "Save files"), Binding("d", "delete", "Delete")]

    def compose(self) -> ComposeResult:
        yield Static("SSH keys that live on the key (FIDO2, ed25519-sk). The private key never leaves it: every "
                     "login needs the key plugged in and the button pressed. Enter shows the public key. "
                     "OpenSSH 8.2+ is needed (macOS: brew install openssh).", classes="note")
        yield DataTable(cursor_type="row", zebra_stripes=True)
        with Horizontal(classes="buttons"):
            yield Button("New key (n)", variant="primary", id="create")
            yield Button("Save files (w)", id="save")
            yield Button("Delete (d)", id="delete")

    def on_mount(self):
        self.table().add_columns("Name", "Type", "Fingerprint")
        self.keys = {}

    def load(self):
        self.app.with_pin(qk_fido.ssh_list, self.show)

    def show(self, keys):
        self.keys = {k["id"].hex(): k for k in keys}
        t = self.table()
        t.clear()
        for cid, k in self.keys.items():
            t.add_row(k["name"] or "[dim](default)[/dim]", k["key"]["type"].split("@")[0], k["fingerprint"], key=cid)

    def current(self):
        cid = self.selected()
        return self.keys.get(cid) if cid else None

    @on(DataTable.RowSelected)
    def details(self):
        k = self.current()
        if k:
            self.app.ask(TextView(f"SSH public key: {k['name'] or '(default)'}", qk_fido.public_line(k["key"], "quick-key"),
                                  f"{k['fingerprint']}\nAdd this line to ~/.ssh/authorized_keys on a server. "
                                  "On another computer: ssh-keygen -K"))

    @on(Button.Pressed, "#create")
    def action_create(self):
        def go(v):
            if not v:
                return
            resident, path = v["resident"], v["file"].strip()
            if not resident and not path:
                self.app.notify("a key that is not kept on the token needs a file to save it to", severity="error")
                return

            def run(pin):
                return qk_fido.ssh_create(pin, v["algo"], v["name"].strip(), resident, v["verify"], path or None,
                                          "quick-key")

            def done(key):
                if resident:
                    self.load()
                self.app.ask(TextView("SSH key created", qk_fido.public_line(key, "quick-key"),
                                      "Add this line to ~/.ssh/authorized_keys on a server." +
                                      (f"\nFiles written: {path} and {path}.pub" if path else "")))
            self.app.with_pin(run, done, press="to create the SSH key")
        self.app.ask(Form("New SSH key", [
            ("name", "Name (tells keys apart; optional)", "text", ""),
            ("algo", "Type", "select:ed25519,ecdsa", "ed25519"),
            ("resident", "Keep it on the key (recommended; ssh-keygen -K brings it to another computer)", "check", True),
            ("verify", "Every signature needs the PIN too", "check", False),
            ("file", "Also save the key files to (required if not kept on the key)", "text", "")], ok="Create",
            note="You will be asked to press the button on the key."), go)

    @on(Button.Pressed, "#save")
    def action_save(self):
        k = self.current()
        if not k:
            return
        default = f"~/.ssh/id_{'ed25519' if 'ed25519' in k['key']['type'] else 'ecdsa'}_sk" + (f"_{k['name']}" if k["name"] else "")

        def go(v):
            if v and v["file"].strip():
                self.app.device(lambda: qk_fido.save_ssh_key(k["key"], v["file"].strip(), "quick-key"),
                                lambda _: self.app.notify(f"written {v['file'].strip()} and .pub"))
        self.app.ask(Form("Save the key files", [("file", "File", "text", default)], ok="Save",
                          note="Writes the private key file (it holds a handle, not a secret) and the .pub file, "
                               "like ssh-keygen -K. An existing file is not overwritten."), go)

    @on(Button.Pressed, "#delete")
    def action_delete(self):
        k = self.current()
        if not k:
            return
        self.app.confirm(f"Delete the SSH key '{k['name'] or '(default)'}' from the key? Servers that trust it will "
                         "not accept you any more.",
                         lambda: self.app.with_pin(lambda pin: qk.fido_delete(pin, k["id"]), lambda _: self.load()),
                         ok="Delete")


class OtpTab(Panel):
    BINDINGS = [Binding("a", "add", "Add"), Binding("d", "delete", "Delete"), Binding("/", "filter", "Filter"),
                Binding("h", "hmac", "HMAC")]

    def compose(self) -> ComposeResult:
        yield Input(placeholder="Filter by account (/)", compact=True, id="filter")
        yield DataTable(cursor_type="row", zebra_stripes=True)
        yield ProgressBar(total=30, show_eta=False, show_percentage=False, id="otp_time")
        yield Static("Enter copies a code; on a HOTP or button-protected account it computes the code first.",
                     classes="note")
        with Horizontal(classes="buttons"):
            yield Button("Add (a)", id="add")
            yield Button("Delete (d)", id="delete")
            yield Button("Access password", id="password")
            yield Button("HMAC slots (h)", id="hmac")
            yield Button("Reset OTP", variant="error", id="reset")

    def on_mount(self):
        self.table().add_columns("Account", "Type", "Code")
        self.period = None
        self.items = []                 # (account, type, code or None) as last read
        self.computed = {}              # codes computed on request in this 30 s period
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
        self.computed = {}
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
        self.items = rows
        self.render_rows()

    def render_rows(self):
        t = self.table()
        cur = self.selected()
        needle = self.query_one("#filter", Input).value.strip().lower()
        t.clear()
        shown = []
        for name, kind, code in self.items:
            if needle and needle not in name.lower():
                continue
            shown.append(name)
            code = self.computed.get(name, code)
            t.add_row(name, kind, code or "[dim]Enter[/dim]", key=name)
        if cur in shown:
            t.move_cursor(row=t.get_row_index(cur))

    @on(Input.Changed, "#filter")
    def filtered(self):
        self.render_rows()

    @on(Input.Submitted, "#filter")
    def filter_done(self):
        self.table().focus()

    def action_filter(self):
        self.query_one("#filter", Input).focus()

    @on(DataTable.RowSelected)
    def compute(self, ev):
        name = ev.row_key.value
        t = self.table()
        code = str(t.get_row(name)[2])
        if not code.startswith("[dim]"):
            self.app.copy(code)
            self.app.notify(f"{name}: {code} copied", log=False)
            return

        def done(code):
            self.computed[name] = code
            if name in [r.value for r in t.rows]:
                t.update_cell(name, t.ordered_columns[2].key, code)
        self.app.device(lambda: self.oath().calculate(name), done, press=f"if '{name}' needs it")

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

    @on(Button.Pressed, "#hmac")
    def action_hmac(self):
        def go(v, slots):
            if not v:
                return
            slot = int(v["slot"])
            if v["action"] == "delete":
                self.app.device(lambda: self.oath().hmac_set(slot, b""),
                                lambda _: self.app.notify(f"slot {slot} deleted"), press=f"to delete slot {slot}")
                return
            if v["action"] == "given":
                try:
                    secret = bytes.fromhex(v["secret"].replace(" ", ""))
                except ValueError:
                    self.app.notify("the secret must be hex digits", severity="error")
                    return
                if not 1 <= len(secret) <= 64:
                    self.app.notify("the secret must be 1-64 bytes", severity="error")
                    return
            else:
                secret = os.urandom(20)
            self.app.device(lambda: self.oath().hmac_set(slot, secret),
                            lambda _: self.app.ask(TextView(f"Slot {slot} is set", secret.hex(),
                                                            "The secret: keep it to program a backup key. "
                                                            "Use the slot in KeePassXC as YubiKey challenge-response.")),
                            press=f"to overwrite slot {slot}")

        def show(slots):
            state = "   ".join(f"slot {n}: {'set' if n in slots else 'empty'}" for n in (1, 2))
            self.app.ask(Form("HMAC-SHA1 challenge-response", [
                ("slot", "Slot", "select:1,2", "1"),
                ("action", "Action: random (make a secret), given (the secret below), delete", "select:random,given,delete",
                 "random"),
                ("secret", "Secret for 'given' (hex, 1-64 bytes)", "text", "")], ok="Apply",
                note=f"{state}\nThe button on the key confirms every change."), lambda v: go(v, slots))
        self.app.device(lambda: self.oath().hmac_slots(), show, after_error=self.ask_password)

    @on(Button.Pressed, "#reset")
    def reset(self):
        def done(_):
            self.app.oath_password = ""
            self.load()
        self.app.confirm("Erase ALL OTP accounts, HMAC secrets and the OTP access password? This cannot be undone.",
                         lambda: self.app.device(qk.oath_reset, done, press="to erase all OTP accounts"), ok="Erase")


class PasswordsTab(Panel):
    BINDINGS = [Binding("a", "add", "Add"), Binding("e", "edit", "Edit"), Binding("d", "delete", "Delete"),
                Binding("/", "filter", "Filter"), Binding("l", "copy_login", "Copy login"),
                Binding("c", "copy_password", "Copy password")]

    def compose(self) -> ComposeResult:
        yield Static("", id="pwd_info")
        yield Input(placeholder="Filter by name, login or URL (/)", compact=True, id="filter")
        yield DataTable(cursor_type="row", zebra_stripes=True)
        yield Static("Enter opens a record; l copies its login and c its password.", classes="note")
        with Horizontal(classes="buttons"):
            yield Button("Add (a)", id="add")
            yield Button("Edit (e)", id="edit")
            yield Button("Delete (d)", id="delete")
            yield Button("Copy login (l)", id="copy_login")
            yield Button("Copy password (c)", id="copy_password")
        with Horizontal(classes="buttons"):
            yield Button("Generate", id="gen")
            yield Button("Audit", id="audit")
            yield Button("Export", id="export")
            yield Button("Import", id="import")
            yield Button("Erase all", variant="error", id="reset")

    def on_mount(self):
        self.table().add_columns("Name", "Login", "URL", "Button")
        self.records, self.cap = {}, 0

    def load(self):
        def fetch(pin):
            p = qk.Pwd().unlock(pin)
            return p.list(), p.max
        self.app.with_pin(fetch, self.show)

    def show(self, data):
        recs, self.cap = data
        self.records = {str(r["id"]): r for r in recs}
        self.render_rows()

    def render_rows(self):
        needle = self.query_one("#filter", Input).value.strip().lower()
        t = self.table()
        cur = self.selected()
        t.clear()
        shown = 0
        for rid, r in self.records.items():
            if needle and needle not in f"{r['name']} {r.get('login', '')} {r.get('url', '')}".lower():
                continue
            shown += 1
            t.add_row(r["name"], r.get("login", ""), r.get("url", ""), "yes" if r["flags"] & qk.PWD_TOUCH else "", key=rid)
        if cur in self.records and cur in [k.value for k in t.rows]:
            t.move_cursor(row=t.get_row_index(cur))
        shown_of = f"{shown} of " if shown != len(self.records) else ""
        self.query_one("#pwd_info", Static).update(f"{shown_of}{len(self.records)} of {self.cap} records")

    @on(Input.Changed, "#filter")
    def filtered(self):
        self.render_rows()

    @on(Input.Submitted, "#filter")
    def filter_done(self):
        self.table().focus()

    def action_filter(self):
        self.query_one("#filter", Input).focus()

    @on(Button.Pressed, "#copy_login")
    def action_copy_login(self):
        rid = self.selected()
        login = self.records[rid].get("login") if rid else None
        if login:
            self.app.copy(login)
            self.app.notify("login copied to the clipboard")
        elif rid:
            self.app.notify("this record has no login", severity="warning")

    @on(Button.Pressed, "#copy_password")
    def action_copy_password(self):
        rid = self.selected()
        if not rid:
            return
        touch = self.records[rid]["flags"] & qk.PWD_TOUCH

        def done(pw):
            self.app.copy(pw)
            self.app.notify("password copied to the clipboard")
        self.app.with_pin(lambda pin: qk.Pwd().unlock(pin).get(int(rid), with_password=True).get("password", ""), done,
                          press="to read the password" if touch else None)

    @on(Button.Pressed, "#audit")
    def audit(self):
        def run(pin):
            recs, skipped = qk.pwd_audit_records(qk.Pwd().unlock(pin))
            return qk.pwd_audit(recs), len(recs), skipped

        def show(res):
            audit, checked, skipped = res
            lines = [f"{name}: {why}" for name, why in audit["weak"]]
            weak = ["Weak:"] + [f"  {l}" for l in lines] if lines else []
            reused = (["Reused (one password, several records):"] +
                      [f"  {', '.join(names)}" for names in audit["reused"]]) if audit["reused"] else []
            empty = (["No password:"] + [f"  {n}" for n in audit["empty"]]) if audit["empty"] else []
            body = "\n".join(weak + reused + empty) or "No weak or reused passwords found."
            tail = f"Checked {checked} passwords." + (f" {skipped} protected by the button were not read." if skipped else "")
            self.app.ask(TextView("Password audit", body, tail))
        self.app.with_pin(run, show, busy="Reading the passwords on the key...")

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
            self.app.notify(f"{pw}\n(copied to the clipboard)", title="Generated password", timeout=15, log=False)
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
    BINDINGS = [Binding("g", "generate", "Generate"), Binding("i", "import_key", "Import"),
                Binding("s", "ssh", "SSH key"), Binding("x", "export", "Export"),
                Binding("t", "touch", "Touch"), Binding("c", "cardholder", "Cardholder")]

    def compose(self) -> ComposeResult:
        yield Static("", id="pgp_info")
        yield DataTable(cursor_type="row", zebra_stripes=True)
        yield Static("", id="pgp_holder", classes="note")
        with Horizontal(classes="buttons"):
            yield Button("Generate (g)", id="generate")
            yield Button("Import (i)", id="import")
            yield Button("SSH key (s)", id="ssh")
            yield Button("Export public key (x)", id="export")
        with Horizontal(classes="buttons"):
            yield Button("Touch (t)", id="touch")
            yield Button("Cardholder (c)", id="cardholder")
            yield Button("Reset OpenPGP", variant="error", id="reset")

    def on_mount(self):
        self.table().add_columns("Key", "Algorithm", "Origin", "Touch", "Created", "Fingerprint")
        self.st = None

    def load(self):
        self.app.device(qk_pgp.details, self.show)

    def show(self, st):
        self.st = st
        self.query_one("#pgp_info", Static).update(
            f"[b]serial[/b] {st['serial']}   [b]PIN tries[/b] {st['pin_tries']}   "
            f"[b]admin PIN tries[/b] {st['admin_tries']}   [b]signatures made[/b] {st['sig_count']}")
        holder = "  ".join(f"[b]{label}[/b] {st[key]}" for label, key in
                           (("name", "name"), ("language", "lang"), ("URL", "url"), ("login", "login")) if st[key])
        self.query_one("#pgp_holder", Static).update(holder or "No cardholder data (c).")
        t = self.table()
        t.clear()
        for i, k in enumerate(st["keys"]):
            made = time.strftime("%Y-%m-%d", time.gmtime(k["created"])) if k["created"] else ""
            t.add_row(k["name"], k["algo"], k["origin"] if k["fingerprint"] else "[dim]empty[/dim]", k["touch"], made,
                      qk_pgp.fingerprint_text(k["fingerprint"]) if k["fingerprint"] else "", key=str(i))

    def current(self):
        k = self.selected()
        return None if k is None or self.st is None else int(k)

    def after_error(self, _):
        self.load()

    def show_key(self, k, pub):
        self.load()
        fp = qk_pgp.fingerprint_text(pub["fingerprint"])
        if pub["algo"] == "cv25519":
            text, note = fp, "Fingerprint of the decryption key. X25519 is not used for SSH."
        else:
            text = qk_pgp.ssh_public_key(pub, f"quick-key-{qk.PGP_KEYS[k]}")
            note = f"Fingerprint {fp}\nThe line below is the SSH public key: add it to authorized_keys."
        self.app.ask(TextView(f"The {qk.PGP_KEYS[k]} key is on the card", text, note))

    @on(Button.Pressed, "#generate")
    def action_generate(self):
        k = self.current()
        if k is None:
            return
        name, algos, info = qk.PGP_KEYS[k], qk_pgp.SLOT_ALGOS[k], self.st["keys"][k]
        default = info["algo"] if info["fingerprint"] and info["algo"] in algos else algos[0]

        def ask():
            def go(v):
                if v:
                    self.app.device(lambda: qk_pgp.generate(v["admin"], k, v["algo"]), lambda pub: self.show_key(k, pub),
                                    busy="Generating the key on the card..." if v["algo"] != "rsa2048"
                                    else "Generating RSA-2048 on the card: up to 10 seconds...",
                                    after_error=self.after_error)
            self.app.ask(Form(f"Generate the {name} key", [("algo", "Algorithm", "select:" + ",".join(algos), default),
                                                         ("admin", "Admin PIN", "password", "")], ok="Generate",
                              note="The key is made on the card and never leaves it."), go)
        if info["fingerprint"]:
            self.app.confirm(f"The {name} key already exists. Generating a new one destroys it for good.", ask,
                             ok="Replace the key")
        else:
            ask()

    @on(Button.Pressed, "#import")
    def action_import_key(self):
        k = self.current()
        if k is None:
            return
        name, info = qk.PGP_KEYS[k], self.st["keys"][k]

        def ask():
            def go(v):
                if not v:
                    return

                def run():
                    path = os.path.expanduser(v["file"].strip())
                    try:
                        data = open(path, "rb").read()
                    except OSError as e:
                        raise qk.QkError(f"cannot read {path}: {e.strerror}") from None
                    return qk_pgp.import_key(v["admin"], k, data, v["password"] or None)
                self.app.device(run, lambda pub: self.show_key(k, pub), after_error=self.after_error)
            self.app.ask(Form(f"Import the {name} key", [("file", "Private key file (PEM, DER or OpenSSH)", "text", ""),
                                                        ("password", "Key file password (if it has one)", "password", ""),
                                                        ("admin", "Admin PIN", "password", "")], ok="Import",
                              note="Ed25519, X25519 (decryption), NIST P-256 or RSA-2048. The file stays where it is: "
                                   "delete it yourself if the key must only live on the card."), go)
        if info["fingerprint"]:
            self.app.confirm(f"The {name} key already exists. Importing destroys it for good.", ask, ok="Replace the key")
        else:
            ask()

    @on(Button.Pressed, "#ssh")
    def action_ssh(self):
        k = self.current()
        if k is None:
            return
        if not self.st["keys"][k]["fingerprint"]:
            self.app.notify(f"the {qk.PGP_KEYS[k]} key is empty", severity="warning")
            return
        self.app.device(lambda: qk_pgp.ssh_key(k, f"quick-key-{qk.PGP_KEYS[k]}"),
                        lambda line: self.app.ask(TextView(f"SSH public key: {qk.PGP_KEYS[k]}", line,
                                                           "Add this line to ~/.ssh/authorized_keys on a server.")))

    @on(Button.Pressed, "#export")
    def action_export(self):
        if self.st is None or not self.st["keys"][0]["fingerprint"]:
            self.app.notify("the signature key is empty: the OpenPGP key needs it as its primary key",
                            severity="warning")
            return
        press = "for each signature (up to 3)" if self.st["keys"][0]["touch"] != "off" else None

        def go(v):
            if not v:
                return
            if not v["uid"].strip():
                self.app.notify("a user ID is needed", severity="error")
                return
            self.app.with_pin(lambda pin: qk_pgp.export_pgp(v["uid"], pin),
                              lambda text: self.app.ask(TextView("OpenPGP public key", text,
                                                                 "Import it with: gpg --import")),
                              press=press, busy=None if press else "Signing on the card...")
        self.app.ask(Form("Export the OpenPGP public key", [("uid", "User ID", "text", "")], ok="Export",
                          note="For example: Jane Doe <jane@example.org>. The card signs the "
                               "certificate with its signature key."), go)

    @on(Button.Pressed, "#touch")
    def action_touch(self):
        k = self.current()
        if k is None:
            return
        cur = self.st["keys"][k]["touch"]
        if cur == "fixed":
            self.app.notify("touch is fixed for this key: only an OpenPGP reset clears it", severity="warning")
            return

        def go(v):
            if v:
                self.app.device(lambda: qk.pgp_set_touch(v["admin"], k, v["mode"]), lambda _: self.load(),
                                after_error=self.after_error)
        self.app.ask(Form(f"Button for the {qk.PGP_KEYS[k]} key", [
            ("mode", "Every use of the key needs the button", "select:off,on,fixed", cur),
            ("admin", "Admin PIN", "password", "")], ok="Set",
            note="fixed: cannot be switched off again, only erased by an OpenPGP reset."), go)

    @on(Button.Pressed, "#cardholder")
    def action_cardholder(self):
        if self.st is None:
            return
        st = self.st

        def go(v):
            if not v:
                return
            fields = {k: v[k] for k in ("name", "lang", "sex", "url", "login")}
            fields = {k: x for k, x in fields.items() if x != (st[k] or ("0" if k == "sex" else ""))}
            if not fields:
                return
            self.app.device(lambda: qk_pgp.set_cardholder(v["admin"], **fields),
                            lambda _: self.load(), after_error=self.after_error)
        self.app.ask(Form("Cardholder data", [
            ("name", "Name (Surname<<Given, ASCII)", "text", st["name"]),
            ("lang", "Language (en, enru, ...)", "text", st["lang"]),
            ("sex", "Sex: 0 unknown, 1 male, 2 female, 9 n/a", "select:0,1,2,9", st["sex"] or "0"),
            ("url", "URL of the public key", "text", st["url"]),
            ("login", "Login data", "text", st["login"]),
            ("admin", "Admin PIN", "password", "")], ok="Write"), go)

    @on(Button.Pressed, "#reset")
    def reset(self):
        def go(v):
            if v:
                self.app.device(lambda: qk.pgp_reset(v["admin"]), lambda _: self.load(), after_error=self.after_error)
        self.app.ask(Form("Reset OpenPGP", [("admin", "Admin PIN", "password", "")], ok="Erase keys",
                                  note="Erases the OpenPGP keys and card data. The PINs stay."), go)


class PivTab(Panel):
    BINDINGS = [Binding("g", "generate", "Generate"), Binding("s", "self_signed", "Self-signed"),
                Binding("c", "csr", "Request"), Binding("i", "import_cert", "Import cert"),
                Binding("x", "export", "Export"), Binding("d", "delete_cert", "Delete cert"),
                Binding("m", "mgmt", "Mgmt key")]

    def compose(self) -> ComposeResult:
        yield Static("", id="piv_info")
        yield DataTable(cursor_type="row", zebra_stripes=True)
        yield Static("Enter shows the certificate. Keys and certificates change only with the management key "
                     "(factory default until you set your own, m). The key cannot be deleted alone: generate a "
                     "new one or reset PIV.", classes="note")
        with Horizontal(classes="buttons"):
            yield Button("Generate key (g)", id="generate")
            yield Button("Self-signed cert (s)", id="self_signed")
            yield Button("Request (c)", id="csr")
            yield Button("Import cert (i)", id="import")
        with Horizontal(classes="buttons"):
            yield Button("Export (x)", id="export")
            yield Button("Delete cert (d)", id="delete_cert")
            yield Button("Management key (m)", id="mgmt")
            yield Button("Reset PIV", variant="error", id="reset")

    def on_mount(self):
        self.table().add_columns("Slot", "Purpose", "Key", "Button", "PIN", "Certificate")
        self.st = None

    def load(self):
        self.app.device(qk_piv.details, self.show)

    def show(self, st):
        self.st = st
        warn = "  [red]factory management key: change it (m)[/red]" if st["mgmt"]["default"] else ""
        self.query_one("#piv_info", Static).update(
            f"[b]serial[/b] {st['serial']}   [b]management key[/b] {st['mgmt']['algo']}{warn}")
        t = self.table()
        t.clear()
        for s in st["slots"]:
            key = s["key"]["algo"] if s["key"] else "[dim]empty[/dim]"
            cert = f"{s['cert']['subject']} (until {s['cert']['not_after']:%Y-%m-%d})" if s["cert"] else ""
            t.add_row(f"{s['slot']:02X}", s["name"], key, s["touch"] or "", s["pin_policy"] or "", cert,
                      key=f"{s['slot']:02x}")

    def current(self):
        k = self.selected()
        if k is None or self.st is None:
            return None
        return next(s for s in self.st["slots"] if f"{s['slot']:02x}" == k)

    def mgmt_key(self, text):
        """The management key typed in a form (else the one used before, else the factory key);
        None, after a message, if what was typed is not a key."""
        try:
            return qk_piv.parse_mgmt_key(text) if text.strip() else (self.app.mgmt_key or qk_piv.DEFAULT_MGMT)
        except qk.QkError as e:
            self.app.notify(str(e), severity="error")
            return None

    def remember(self, v):
        """After a success the management key typed in the form stays for this session."""
        if v.get("mgmt", "").strip():
            self.app.mgmt_key = qk_piv.parse_mgmt_key(v["mgmt"])

    def after_error(self, _):
        self.load()

    MGMT = ("mgmt", "Management key (hex; empty: " + "the one used before, or the factory key)", "password", "")

    @on(DataTable.RowSelected)
    def details(self):
        s = self.current()
        if s and s["cert"]:
            self.app.ask(TextView(f"Certificate in slot {s['slot']:02X}", qk_piv.cert_text(s["cert_der"]) + "\n\n" +
                                  qk_piv.cert_pem(s["cert_der"])))
        elif s:
            self.app.notify(f"slot {s['slot']:02X} has no certificate", severity="warning")

    @on(Button.Pressed, "#generate")
    def action_generate(self):
        s = self.current()
        if not s:
            return

        def ask():
            def go(v):
                if not v:
                    return
                key = self.mgmt_key(v["mgmt"])
                if key is None:
                    return
                self.app.device(lambda: qk_piv.generate(s["slot"], v["algo"], v["touch"], key),
                                lambda pub: (self.remember(v), self.load(),
                                             self.app.ask(TextView(f"Key made in slot {s['slot']:02X}",
                                                                   qk_piv.pub_pem(pub)))),
                                busy="Generating on the card..." if v["algo"] != "rsa2048"
                                else "Generating RSA-2048 on the card: up to 10 seconds...", after_error=self.after_error)
            self.app.ask(Form(f"Generate a key in slot {s['slot']:02X}", [
                ("algo", "Algorithm", "select:nistp256,rsa2048", "nistp256"),
                ("touch", "Button for every use of the key", "select:never,always,cached", "never"), self.MGMT],
                ok="Generate", note="The key is made on the card and never leaves it. Its certificate, if any, "
                                    "is deleted."), go)
        if s["key"]:
            self.app.confirm(f"Slot {s['slot']:02X} already has a key. Generating a new one destroys it for good.", ask,
                             ok="Replace the key")
        else:
            ask()

    def sign_form(self, title, action, note, certificate=False):
        """A form for the operations that sign on the card: subject and PIN (a certificate also
        asks for its validity and the management key that stores it)."""
        def go(v):
            if not v:
                return
            if not v["subject"].strip():
                self.app.notify("a subject is needed, for example CN=Jane Doe,O=Example", severity="error")
                return
            action(v)
        fields = [("subject", "Subject (CN=Jane Doe,O=Example)", "text", "")]
        if certificate:
            fields.append(("days", "Valid for (days)", "text", "365"))
        fields.append(("pin", "PIN", "password", ""))
        if certificate:
            fields.append(self.MGMT)
        return Form(title, fields, ok="Sign", note=note), go

    @on(Button.Pressed, "#self_signed")
    def action_self_signed(self):
        s = self.current()
        if not s or not s["key"]:
            self.app.notify("generate a key in this slot first", severity="warning")
            return
        press = "to sign" if s["touch"] in ("always", "cached") else None

        def action(v):
            try:
                days = int(v["days"])
            except ValueError:
                self.app.notify("days must be a number", severity="error")
                return
            key = self.mgmt_key(v["mgmt"])
            if key is None:
                return
            self.app.device(lambda: qk_piv.self_signed(s["slot"], v["pin"], v["subject"], days, key),
                            lambda der: (self.remember(v), self.load(),
                                         self.app.ask(TextView("Certificate stored", qk_piv.cert_text(der)))),
                            press=press, after_error=self.after_error)
        form, go = self.sign_form(f"Self-signed certificate for slot {s['slot']:02X}", action,
                                  "The card signs it with the key of the slot; the certificate is stored in the slot.",
                                  certificate=True)
        self.app.ask(form, go)

    @on(Button.Pressed, "#csr")
    def action_csr(self):
        s = self.current()
        if not s or not s["key"]:
            self.app.notify("generate a key in this slot first", severity="warning")
            return
        press = "to sign" if s["touch"] in ("always", "cached") else None

        def action(v):
            self.app.device(lambda: qk_piv.csr(s["slot"], v["pin"], v["subject"]),
                            lambda text: self.app.ask(TextView("Certificate signing request", text,
                                                               "Send it to a certificate authority.")),
                            press=press, after_error=self.after_error)
        form, go = self.sign_form(f"Request for slot {s['slot']:02X}", action,
                                  "The card signs the request with the key of the slot.")
        self.app.ask(form, go)

    @on(Button.Pressed, "#import")
    def action_import_cert(self):
        s = self.current()
        if not s:
            return

        def go(v):
            if not v:
                return

            key = self.mgmt_key(v["mgmt"])
            if key is None:
                return

            def run():
                path = os.path.expanduser(v["file"].strip())
                try:
                    data = open(path, "rb").read()
                except OSError as e:
                    raise qk.QkError(f"cannot read {path}: {e.strerror}") from None
                qk_piv.import_cert(s["slot"], data, key)
            self.app.device(run, lambda _: (self.remember(v), self.load()), after_error=self.after_error)
        self.app.ask(Form(f"Import a certificate into slot {s['slot']:02X}",
                          [("file", "Certificate file (PEM or DER)", "text", ""), self.MGMT], ok="Import",
                          note="It must be the certificate of the key that is in this slot."), go)

    @on(Button.Pressed, "#export")
    def action_export(self):
        s = self.current()
        if not s or not s["key"]:
            self.app.notify("this slot has no key", severity="warning")
            return
        pub = s["key"]
        text = qk_piv.pub_pem(pub)
        note = "Public key (PEM)."
        if s["cert_der"]:
            text += "\n" + qk_piv.cert_pem(s["cert_der"])
            note = "Public key and certificate (PEM)."
        text += "\n" + qk_pgp.ssh_public_key(pub, "quick-key-piv")
        note += " The last line is the SSH public key."
        self.app.ask(TextView(f"Slot {s['slot']:02X}", text, note))

    @on(Button.Pressed, "#delete_cert")
    def action_delete_cert(self):
        s = self.current()
        if not s or not s["cert"]:
            self.app.notify("this slot has no certificate", severity="warning")
            return

        def go(v):
            key = self.mgmt_key(v["mgmt"]) if v else None
            if key is not None:
                self.app.device(lambda: qk_piv.delete_cert(s["slot"], key),
                                lambda _: (self.remember(v), self.load()), after_error=self.after_error)
        self.app.ask(Form(f"Delete the certificate in slot {s['slot']:02X}", [self.MGMT], ok="Delete",
                          note=f"{s['cert']['subject']}\nThe key stays."), go)

    @on(Button.Pressed, "#mgmt")
    def action_mgmt(self):
        def go(v):
            if not v:
                return
            if v["new"].strip() and v["new"] != v["again"]:
                self.app.notify("the new keys do not match", severity="error")
                return
            try:
                new = bytes.fromhex(v["new"].replace(" ", "")) if v["new"].strip() else None
            except ValueError:
                self.app.notify("the new key must be hex digits", severity="error")
                return

            def done(key):
                self.app.mgmt_key = key
                self.load()
                self.app.ask(TextView("Management key changed", key.hex(),
                                      "Write it down: without it keys and certificates cannot be changed. "
                                      "It is kept in memory until you quit."))
            old = self.mgmt_key(v["mgmt"])
            if old is None:
                return
            self.app.device(lambda: qk_piv.set_mgmt_key(old, new, v["algo"]), done,
                            after_error=self.after_error)
        self.app.ask(Form("Change the management key", [
            self.MGMT, ("algo", "New key type", "select:3des,aes128,aes192,aes256", "aes256"),
            ("new", "New key (hex; empty: make a random one)", "password", ""), ("again", "Repeat the new key", "password", "")],
            ok="Change", note="3DES is 48 hex digits, AES-128/192/256 are 32/48/64."), go)

    def after_reset(self, _):
        self.app.mgmt_key = None                    # the card is back to the factory management key
        self.load()

    @on(Button.Pressed, "#reset")
    def reset(self):
        self.app.confirm("Erase PIV keys and certificates? The PINs stay.",
                         lambda: self.app.device(qk.piv_reset, self.after_reset, press="to reset PIV"),
                         ok="Erase PIV")


# ---------------------------------------------------------------- app

class QkCommands(Provider):
    """Entries of the command palette (Ctrl+P): jump to a tab and the app actions."""

    async def search(self, query: str) -> Hits:
        matcher = self.matcher(query)
        app = self.app
        entries = [(f"Go to {title}", lambda tid=tid: app.goto(tid), f"Open the {title} tab")
                   for tid, title, _ in app.TABS]
        entries += [("Refresh", app.action_reload, "Read the current tab from the key again"),
                    ("Help", app.action_help, "Keys of the current tab"),
                    ("Log", app.action_log, "Messages shown in this session"),
                    ("Quit", app.action_quit, "Leave qk")]
        for text, fn, help_ in entries:
            score = matcher.match(text)
            if score > 0:
                yield Hit(score, matcher.highlight(text), fn, help=help_)


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
    Form, Confirm, RecordView, TextView { align: center middle; }
    .dialog { width: 72; height: auto; max-height: 90%; border: thick $primary; background: $surface; padding: 1 2; }
    .wide { width: 96; }
    .dialog-title { text-style: bold; margin-bottom: 1; }
    .dialog Input, .dialog Select, .dialog Checkbox { margin-bottom: 1; }
    .dialog Input, .dialog Select { background: $boost; }
    """
    COMMANDS = App.COMMANDS | {QkCommands}
    BINDINGS = ([Binding("q", "quit", "Quit"), Binding("r", "reload", "Refresh"),
                 Binding("question_mark", "help", "Help"), Binding("f2", "log", "Log")] +
                [Binding(str(n), f"tab({n})", show=False) for n in range(1, 10)])
    TABS = (("device", "Device", DeviceTab), ("pin", "PIN", PinTab), ("passkeys", "Passkeys", PasskeysTab),
            ("ssh", "SSH", SshTab), ("otp", "OTP", OtpTab), ("passwords", "Passwords", PasswordsTab), ("pgp", "OpenPGP", PgpTab),
            ("piv", "PIV", PivTab))

    def __init__(self):
        super().__init__()
        self.lock = threading.Lock()
        self.pin = None                 # the device PIN, kept for this session only
        self.oath_password = ""
        self.mgmt_key = None            # the PIV management key last used, kept for this session only
        self.connected = None           # a key is plugged in: None until the first look
        self.messages = []              # what notify() showed, for the log

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            for tid, title, cls in self.TABS:
                with TabPane(title, id=tid):
                    yield cls(id=f"tab_{tid}")
        yield Footer()

    def on_mount(self):
        self.poll_device()
        self.set_interval(2, self.poll_device)

    def active_tab(self) -> Panel:
        return self.query_one(f"#tab_{self.query_one(TabbedContent).active}", Panel)

    def goto(self, tid):
        self.query_one(TabbedContent).active = tid

    def action_tab(self, n: int):
        if len(self.screen_stack) == 1 and n <= len(self.TABS):
            self.goto(self.TABS[n - 1][0])

    # ---- the key being plugged in and out

    @work(thread=True, exclusive=True, group="poll")
    def poll_device(self):
        if not self.lock.acquire(blocking=False):      # a call is in progress: the key is there
            return
        try:
            present = qk.device_present()
        finally:
            self.lock.release()
        self.call_from_thread(self.connection, present)

    def connection(self, present):
        if present == self.connected:
            return
        first = self.connected is None
        self.connected = present
        self.sub_title = "key plugged in" if present else "no key plugged in"
        if first:
            return
        if present:
            self.notify("Key plugged in", title="Quick-Key")
            for tab in self.query(Panel):
                tab.loaded = False
            tab = self.active_tab()
            tab.loaded = True
            self.call_after_refresh(tab.load)
        else:
            self.notify("Key unplugged", title="Quick-Key", severity="warning")

    # ---- help and log

    def action_help(self):
        tab = self.active_tab()
        lines = ["Tab / Shift+Tab move, Enter acts, the mouse works too.", "",
                 "Everywhere:", "  1-8      go to a tab", "  r        read the tab from the key again",
                 "  Ctrl+P   command palette", "  F2       log of messages", "  ?        this help", "  q        quit"]
        keys = [(b.key, b.description) for b in tab.BINDINGS if isinstance(b, Binding)]
        if keys:
            lines += ["", "In this tab:"] + [f"  {k:8} {d}" for k, d in keys]
        self.ask(TextView("Help", "\n".join(lines)))

    def action_log(self):
        text = "\n".join(reversed(self.messages)) or "Nothing yet."
        self.ask(TextView("Log", text, "Newest first. Passwords, OTP codes, PINs and keys are never logged."))

    def notify(self, message, *args, log=True, **kwargs):
        """Shows a message and keeps it for the log, unless it carries a secret (log=False)."""
        if log:
            self.messages.append(f"{time.strftime('%H:%M:%S')}  {kwargs.get('severity', 'information'):11} "
                                 f"{(kwargs.get('title') + ': ') if kwargs.get('title') else ''}{message}")
            del self.messages[:-200]
        super().notify(message, *args, **kwargs)

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

    def device(self, fn, done=None, press=None, after_error=None, busy=None):
        """Runs fn() in a worker; done(result) or after_error(exception) back on the UI thread.
        press: why the button is needed (shown while waiting); busy: what takes long."""
        self._run(fn, done, press, after_error, busy)

    @work(thread=True)
    def _run(self, fn, done, press, after_error, busy=None):
        if press:
            self.call_from_thread(self.notify, f"Press the button on the key {press}.", title="Button",
                                  severity="warning", timeout=30)
        elif busy:
            self.call_from_thread(self.notify, busy, title="Working", timeout=30)
        with self.lock:
            try:
                result = fn()
            except BaseException as e:  # noqa: BLE001 - shown to the user
                # Clear the "press the button" hint first: it must not wipe the error.
                if press or busy:
                    self.call_from_thread(self.clear_notifications)
                self.call_from_thread(self.failed, e, after_error)
                return
            if press or busy:
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

    def with_pin(self, fn, done=None, press=None, busy=None):
        """Runs fn(pin) with the session PIN, asking for it first if needed."""
        if self.pin:
            self.device(lambda: fn(self.pin), done, press, busy=busy)
            return

        def go(v):
            if v and v["pin"]:
                self.pin = v["pin"]
                self.device(lambda: fn(self.pin), done, press, busy=busy)
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
