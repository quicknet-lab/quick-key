#!/usr/bin/env python3
"""The Passkeys and SSH tabs of `qk tui` (headless Textual Pilot) on the software authenticator of fakefido.py."""
import asyncio
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakefido  # noqa: E402
import tuikit  # noqa: E402
import qk_fido  # noqa: E402
import qk_tui  # noqa: E402
from textual.widgets import Input  # noqa: E402
from tuikit import dialog, notes, open_tab, rows, set_field, settle, submit  # noqa: E402

PIN = fakefido.PIN


async def main():
    dev = fakefido.install()
    dev.add("github.com", "alice", -7, "Alice", "GitHub", 1)
    dev.add("example.org", "bob", -8, "Bob", "", 3)
    dev.add("gitlab.com", "carol", -7, "", "", 2)
    tuikit.quiet_device()
    app = qk_tui.QkApp()
    async with app.run_test(size=(120, 45)) as pilot:
        await settle(pilot, app)
        await open_tab(pilot, app, "passkeys")
        assert isinstance(dialog(app), qk_tui.Form)                 # asks for the PIN
        set_field(app, "pin", "000000")
        await submit(pilot, app)
        assert app.pin is None and dev.pin_tries == 7
        await pilot.press("r")
        await pilot.pause(0.4)
        set_field(app, "pin", PIN)
        await submit(pilot, app)
        assert sorted(r[0] for r in rows(app)) == ["example.org", "github.com", "gitlab.com"], rows(app)
        assert "3 passkeys" in str(app.active_tab().query_one("#fido_info").render()), "info line"
        print("passkeys listed after a wrong PIN and a right one")

        tab = app.active_tab()
        tab.query_one("#filter", Input).value = "git"
        await pilot.pause(0.3)
        assert sorted(r[0] for r in rows(app)) == ["github.com", "gitlab.com"]
        tab.query_one("#filter", Input).value = "bob"
        await pilot.pause(0.3)
        assert [r[0] for r in rows(app)] == ["example.org"]
        tab.query_one("#filter", Input).value = ""
        await pilot.pause(0.3)
        assert len(rows(app)) == 3
        print("filter by site or user")

        t = tab.table()
        t.move_cursor(row=[r[0] for r in rows(app)].index("github.com"))
        await pilot.press("enter")
        await pilot.pause(0.4)
        top = dialog(app)
        gh = next(c for c in dev.creds if c["rp"] == "github.com")
        assert isinstance(top, qk_tui.TextView) and gh["id"].hex() in top.text and "ES256" in top.text, top
        await pilot.click("#close")
        await settle(pilot, app)
        print("details show the credential id and algorithm")

        await pilot.press("e")
        await pilot.pause(0.4)
        set_field(app, "name", "alice2")
        set_field(app, "display", "Alice Two")
        await submit(pilot, app)
        assert (gh["user"]["name"], gh["user"]["displayName"]) == ("alice2", "Alice Two")
        assert "alice2" in [r[1] for r in rows(app)]
        print("rename")

        await pilot.press("u")
        await pilot.pause(0.4)
        await pilot.click("#yes")
        await settle(pilot, app)
        assert dev.always_uv and "on" in str(tab.query_one("#fido_info").render())
        await pilot.press("u")
        await pilot.pause(0.4)
        await pilot.click("#yes")
        await settle(pilot, app)
        assert not dev.always_uv
        print("always ask for the PIN: on, then off")

        await pilot.press("b")
        await settle(pilot, app)
        await pilot.pause(0.4)
        await pilot.click("#yes")
        await settle(pilot, app)
        assert dev.blobs == []
        print("large blobs erased")

        t.move_cursor(row=[r[0] for r in rows(app)].index("gitlab.com"))
        await pilot.press("d")
        await pilot.pause(0.4)
        await pilot.click("#yes")
        await settle(pilot, app)
        assert "gitlab.com" not in [c["rp"] for c in dev.creds]
        print("delete")

        # ---- SSH tab
        await open_tab(pilot, app, "ssh")
        assert rows(app) == []
        await pilot.press("n")
        await pilot.pause(0.4)
        set_field(app, "name", "work")
        await submit(pilot, app)
        top = dialog(app)
        assert isinstance(top, qk_tui.TextView) and top.text.startswith("sk-ssh-ed25519@openssh.com "), top
        assert dev.presses == 1
        await pilot.click("#close")
        await settle(pilot, app)
        assert [r[0] for r in rows(app)] == ["work"] and rows(app)[0][2].startswith("SHA256:"), rows(app)
        print("new resident SSH key: press, public key shown, listed")

        # a key that is not kept on the key needs a file
        await pilot.press("n")
        await pilot.pause(0.4)
        app.screen.query_one("#f_resident").value = False
        await submit(pilot, app)
        assert any("needs a file" in m for m in notes(app)), notes(app)
        print("non-resident key without a file refused")

        await pilot.press("escape")
        await settle(pilot, app)
        await pilot.press("enter")
        await pilot.pause(0.4)
        top = dialog(app)
        assert isinstance(top, qk_tui.TextView) and top.text.startswith("sk-ssh-")
        await pilot.click("#close")
        await settle(pilot, app)

        out = os.path.join(tempfile.mkdtemp(), "id_work")
        await pilot.press("w")
        await pilot.pause(0.4)
        set_field(app, "file", out)
        await submit(pilot, app)
        key = qk_fido.ssh_list(PIN)[0]["key"]
        assert subprocess.run(["ssh-keygen", "-y", "-f", out], capture_output=True, text=True).stdout.split()[:2] == \
            qk_fido.public_line(key).split()[:2]
        print("key files saved and read back by ssh-keygen")

        await pilot.press("d")
        await pilot.pause(0.4)
        await pilot.click("#yes")
        await settle(pilot, app)
        assert rows(app) == [] and not [c for c in dev.creds if c["rp"].startswith("ssh:")]
        print("SSH key deleted")
    print("QK TUI FIDO TEST DONE")

asyncio.run(main())
