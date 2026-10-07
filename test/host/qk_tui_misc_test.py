#!/usr/bin/env python3
"""The Device, OTP and Passwords tabs and the app-wide features of `qk tui` (headless Textual Pilot): update
checks, qk self-update, filters, HMAC slots, quick copy, password audit, help, log, plugging the key in and out."""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeapps  # noqa: E402
import tuikit  # noqa: E402
import qk  # noqa: E402
import qk_tui  # noqa: E402
from textual.widgets import Input  # noqa: E402
from tuikit import dialog, notes, open_tab, rows, set_field, settle, submit  # noqa: E402

PIN = fakeapps.PIN


async def close(pilot, app):
    await pilot.click("#close")
    await settle(pilot, app)


def text(app, sel):
    return str(app.active_tab().query_one(sel).render())


async def main():
    fakeapps.install()
    tuikit.quiet_device()
    copied = []
    state = {"qk": "1.0.0", "installs": []}
    qk.qk_version = lambda: state["qk"]
    qk.update_status = lambda: {"latest": "1.1.0", "qk": state["qk"], "qk_newer": state["qk"] != "1.1.0",
                                "firmware": "1.0.0", "firmware_newer": True}

    def fake_update(version=None, log=print):
        state["installs"].append(version)
        log("installing qk 1.1.0...")
        state["qk"] = "1.1.0"          # like pip: the installed metadata is the new version at once
        return "1.1.0"
    qk.self_update = fake_update
    app = qk_tui.QkApp()
    app.copy = copied.append
    async with app.run_test(size=(130, 45)) as pilot:
        await settle(pilot, app)

        # ---- Device
        assert "qk        1.0.0" in text(app, "#dev_info"), text(app, "#dev_info")
        app.active_tab().query_one("#check").press()
        await settle(pilot, app)
        t = text(app, "#dev_updates")
        assert "Latest release: 1.1.0" in t and "qk 1.0.0 is outdated" in t and "firmware 1.0.0 is outdated" in t, t
        app.active_tab().query_one("#update_qk").press()
        await pilot.pause(0.4)
        await pilot.click("#yes")
        await settle(pilot, app)
        assert state["installs"] == [None] and "1.1.0 is installed" in text(app, "#dev_updates"), text(app, "#dev_updates")
        print("device: update check shows qk and firmware, qk self-update installs and asks for a restart")

        # ---- OTP
        fakeapps.FakeOath.accounts = {"GitHub:alice": {"hotp": False, "touch": False}, "AWS:bob": {"hotp": True, "touch": False},
                                      "Bank": {"hotp": False, "touch": True}}
        await open_tab(pilot, app, "otp")
        assert sorted(r[0] for r in rows(app)) == ["AWS:bob", "Bank", "GitHub:alice"], rows(app)
        tab = app.active_tab()
        tab.query_one("#filter", Input).value = "git"
        await pilot.pause(0.3)
        assert [r[0] for r in rows(app)] == ["GitHub:alice"]
        tab.table().focus()
        await pilot.press("enter")
        await settle(pilot, app)
        assert copied == ["123456"], copied
        tab.query_one("#filter", Input).value = ""
        await pilot.pause(0.3)
        tab.table().move_cursor(row=[r[0] for r in rows(app)].index("Bank"))
        await pilot.press("enter")
        await settle(pilot, app)
        assert "otp Bank" in fakeapps.presses and "654321" in [r[2] for r in rows(app)], rows(app)
        print("otp: filter, code copied, a button-protected code computed on request")

        # HMAC
        await pilot.press("h")
        await settle(pilot, app)
        await pilot.pause(0.4)
        set_field(app, "slot", "2")
        await submit(pilot, app)
        top = dialog(app)
        assert isinstance(top, qk_tui.TextView) and len(top.text) == 40 and fakeapps.FakeOath.hmac[2].hex() == top.text, top
        assert "hmac 2" in fakeapps.presses
        await close(pilot, app)
        await pilot.press("h")
        await settle(pilot, app)
        await pilot.pause(0.4)
        set_field(app, "slot", "1")
        set_field(app, "action", "given")
        set_field(app, "secret", "zz")
        await submit(pilot, app)
        assert any("hex digits" in m for m in notes(app)) and 1 not in fakeapps.FakeOath.hmac
        await pilot.press("h")
        await settle(pilot, app)
        await pilot.pause(0.4)
        set_field(app, "slot", "1")
        set_field(app, "action", "given")
        set_field(app, "secret", "00112233")
        await submit(pilot, app)
        assert fakeapps.FakeOath.hmac[1] == bytes.fromhex("00112233")
        await close(pilot, app)
        await pilot.press("h")
        await settle(pilot, app)
        await pilot.pause(0.4)
        set_field(app, "slot", "2")
        set_field(app, "action", "delete")
        await submit(pilot, app)
        assert 2 not in fakeapps.FakeOath.hmac
        print("otp: HMAC slots set (random, given, bad hex refused) and deleted")

        # reset (with an access password set: reset works without it)
        fakeapps.FakeOath.password = "secret"
        app.oath_password = "wrong"
        app.active_tab().query_one("#reset").press()
        await pilot.pause(0.4)
        await pilot.click("#yes")
        await settle(pilot, app)
        assert fakeapps.FakeOath.accounts == {} and fakeapps.FakeOath.password is None and app.oath_password == ""
        assert "otp reset" in fakeapps.presses
        print("otp: reset works with a forgotten access password")

        # ---- Passwords: filtering before anything was loaded (PIN dialog cancelled) must not fail
        await open_tab(pilot, app, "passwords")
        await pilot.press("escape")
        await settle(pilot, app)
        app.active_tab().query_one("#filter", Input).value = "x"
        await pilot.pause(0.3)
        app.active_tab().query_one("#filter", Input).value = ""
        app.active_tab().loaded = False
        await open_tab(pilot, app, "otp")
        await open_tab(pilot, app, "passwords")
        fakeapps.FakePwd.records = [
            {"id": 0, "name": "Mail", "login": "me@x.org", "url": "https://mail.x.org", "flags": 0, "password": "Tr0ub4dor&3xyz!"},
            {"id": 1, "name": "Forum", "login": "me", "url": "https://forum.x.org", "flags": 0, "password": "Tr0ub4dor&3xyz!"},
            {"id": 2, "name": "Old", "login": "bob", "url": "", "flags": 0, "password": "password"},
            {"id": 3, "name": "Bank", "login": "acct", "url": "", "flags": qk.PWD_TOUCH, "password": "x9$kLm2#pQw8vNrZ"}]
        await open_tab(pilot, app, "passwords")
        assert isinstance(dialog(app), qk_tui.Form)
        await pilot.press(*PIN, "enter")                  # digits typed into the PIN field are not tab shortcuts
        await settle(pilot, app)
        assert app.query_one(qk_tui.TabbedContent).active == "passwords" and app.pin == PIN
        assert len(rows(app)) == 4 and "4 of 100 records" in text(app, "#pwd_info")
        tab = app.active_tab()
        tab.query_one("#filter", Input).value = "forum"
        await pilot.pause(0.3)
        assert [r[0] for r in rows(app)] == ["Forum"] and "1 of 4 of 100" in text(app, "#pwd_info")
        tab.query_one("#filter", Input).value = "acct"                       # by login
        await pilot.pause(0.3)
        assert [r[0] for r in rows(app)] == ["Bank"]
        tab.table().focus()
        await pilot.press("c")
        await settle(pilot, app)
        assert copied[-1] == "x9$kLm2#pQw8vNrZ" and "pwd Bank" in fakeapps.presses
        await pilot.press("l")
        await pilot.pause(0.2)
        assert copied[-1] == "acct"
        tab.query_one("#filter", Input).value = ""
        await pilot.pause(0.3)
        print("passwords: filter by name and login, copy password (button recorded) and login")

        reads = fakeapps.presses.count("pwd Bank")
        tab.query_one("#audit").press()
        await settle(pilot, app)
        top = dialog(app)
        assert isinstance(top, qk_tui.TextView), top
        assert "Old: a very common password" in top.text and "Mail, Forum" in top.text, top.text
        assert "1 protected by the button were not read" in top.note and "Checked 3 passwords" in top.note
        assert fakeapps.presses.count("pwd Bank") == reads, "the audit must not read the button-protected password"
        await close(pilot, app)
        print("passwords: audit finds weak and reused ones and skips the button-protected record")

        # ---- app-wide
        app.action_tab(3)
        await settle(pilot, app)
        assert app.query_one(qk_tui.TabbedContent).active == "passkeys"
        app.action_tab(8)
        await settle(pilot, app)
        assert app.query_one(qk_tui.TabbedContent).active == "piv"
        await open_tab(pilot, app, "pgp")
        await pilot.press("question_mark")
        await pilot.pause(0.4)
        top = dialog(app)
        assert isinstance(top, qk_tui.TextView) and "Generate" in top.text and "command palette" in top.text, top
        await pilot.press("escape")
        await settle(pilot, app)
        print("app: number keys switch tabs, help lists the keys of the current tab")

        app.notify("Something failed", severity="error", title="Error")
        app.notify("secret 123456", log=False)
        await pilot.press("f2")
        await pilot.pause(0.4)
        top = dialog(app)
        assert isinstance(top, qk_tui.TextView) and "Something failed" in top.text and "123456" not in top.text, top.text
        await pilot.press("escape")
        await settle(pilot, app)
        assert not any("x9$kLm2" in m for m in app.messages)
        print("app: the log keeps messages, not the ones that carry a secret")

        # ---- the key unplugged and plugged in again
        app.connection(True)
        reloads = []
        orig = type(app.active_tab()).load
        type(app.active_tab()).load = lambda self: reloads.append(self)
        app.connection(False)
        assert app.sub_title == "no key plugged in" and any("unplugged" in m for m in app.messages)
        app.connection(True)
        await pilot.pause(0.4)
        assert app.sub_title == "key plugged in" and len(reloads) == 1 and reloads[0] is app.active_tab()
        type(app.active_tab()).load = orig
        print("app: unplugging is noticed, plugging in reloads the current tab")
    print("QK TUI MISC TEST DONE")

asyncio.run(main())
