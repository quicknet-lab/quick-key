#!/usr/bin/env python3
"""The OpenPGP tab of `qk tui` (headless Textual Pilot) on the software card of fakecard.py."""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakecard  # noqa: E402
import tuikit  # noqa: E402
import qk_pgp as pgp  # noqa: E402
import qk_tui  # noqa: E402
from cryptography.hazmat.primitives import serialization as ser  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402
from tuikit import dialog, open_tab, rows, set_field, settle, submit  # noqa: E402

ADMIN, PIN = fakecard.ADMIN, fakecard.PIN


async def main():
    card = fakecard.install()
    tuikit.quiet_device()
    app = qk_tui.QkApp()
    async with app.run_test(size=(120, 45)) as pilot:
        await settle(pilot, app)
        await open_tab(pilot, app, "pgp")
        assert len(rows(app)) == 3 and rows(app)[0][2].startswith("[dim]empty"), rows(app)
        print("empty card: three empty slots")

        # generate the signature key as Ed25519, wrong admin PIN first
        t = app.active_tab().table()
        await pilot.press("g")
        await pilot.pause(0.4)
        assert isinstance(dialog(app), qk_tui.Form)
        set_field(app, "algo", "ed25519")
        set_field(app, "admin", "00000000")
        await submit(pilot, app)
        assert card.tries["admin"] == 2 and card.keys[0] is None
        assert app.active_tab().st["admin_tries"] == 2, "counters reloaded after the error"
        await pilot.press("g")
        await pilot.pause(0.4)
        set_field(app, "algo", "ed25519")
        set_field(app, "admin", ADMIN)
        await submit(pilot, app)
        assert card.keys[0] and card.tries["admin"] == 3
        top = dialog(app)
        assert isinstance(top, qk_tui.TextView) and top.text.startswith("ssh-ed25519 "), top
        await pilot.click("#close")
        await settle(pilot, app)
        r = rows(app)[0]
        assert r[1] == "ed25519" and r[2] == "generated" and r[5].count(" ") == 9, r
        print("generate: wrong admin PIN refused and counters refreshed; Ed25519 key made, SSH line shown")

        # decryption key: only the algorithms that fit are offered
        t.move_cursor(row=1)
        await pilot.press("g")
        await pilot.pause(0.4)
        opts = [o[1] for o in app.screen.query_one("#f_algo")._options if o[1] is not None]
        assert opts == ["cv25519", "nistp256", "rsa2048"], opts
        set_field(app, "admin", ADMIN)
        await submit(pilot, app)
        top = dialog(app)
        assert isinstance(top, qk_tui.TextView) and "not used for SSH" in top.note
        await pilot.click("#close")
        await settle(pilot, app)
        assert pgp.details()["keys"][1]["algo"] == "cv25519"
        print("decryption slot offers cv25519 / nistp256 / rsa2048")

        # replacing asks first
        t.move_cursor(row=0)
        before = pgp.details()["keys"][0]["fingerprint"]
        await pilot.press("g")
        await pilot.pause(0.4)
        assert isinstance(dialog(app), qk_tui.Confirm)
        await pilot.click("#no")
        await settle(pilot, app)
        assert pgp.details()["keys"][0]["fingerprint"] == before
        print("replacing an existing key asks first; Cancel keeps it")

        # SSH key of the signature key
        await pilot.press("s")
        await settle(pilot, app)
        top = dialog(app)
        assert isinstance(top, qk_tui.TextView) and top.text == pgp.ssh_key(0, "quick-key-signature"), top
        await pilot.click("#close")
        await settle(pilot, app)
        print("SSH key dialog shows the authorized_keys line")

        # import a PEM into the authentication slot
        t.move_cursor(row=2)
        key = ed25519.Ed25519PrivateKey.generate()
        path = os.path.join(tempfile.mkdtemp(), "k.pem")
        open(path, "wb").write(key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
        await pilot.press("i")
        await pilot.pause(0.4)
        set_field(app, "file", path)
        set_field(app, "admin", ADMIN)
        await submit(pilot, app)
        assert isinstance(dialog(app), qk_tui.TextView)
        await pilot.click("#close")
        await settle(pilot, app)
        assert rows(app)[2][2] == "imported" and pgp.read_public(2)["point"] == key.public_key().public_bytes(
            ser.Encoding.Raw, ser.PublicFormat.Raw)
        print("import: PEM file written to the authentication slot")

        # touch
        t.move_cursor(row=0)
        await pilot.press("t")
        await pilot.pause(0.4)
        set_field(app, "mode", "on")
        set_field(app, "admin", ADMIN)
        await submit(pilot, app)
        assert card.uif[0] == 1 and rows(app)[0][3] == "on", (card.uif, rows(app))
        print("touch policy set from the tab")

        # cardholder
        await pilot.press("c")
        await pilot.pause(0.4)
        set_field(app, "name", "Doe<<Jane")
        set_field(app, "lang", "en")
        set_field(app, "sex", "2")
        set_field(app, "url", "https://example.org/k.asc")
        set_field(app, "admin", ADMIN)
        await submit(pilot, app)
        d = pgp.details()
        assert (d["name"], d["lang"], d["sex"], d["url"]) == ("Doe<<Jane", "en", "2", "https://example.org/k.asc"), d
        print("cardholder data written")

        # export the public key (the signature key asks for the button: the model records it)
        await pilot.press("x")
        await pilot.pause(0.4)
        set_field(app, "uid", "Jane Doe <jane@example.org>")
        await submit(pilot, app)
        assert app.pin is None
        await pilot.pause(0.4)
        assert isinstance(dialog(app), qk_tui.Form) and "PIN" in app.screen.title_text
        set_field(app, "pin", PIN)
        await submit(pilot, app)
        top = dialog(app)
        assert isinstance(top, qk_tui.TextView) and top.text.startswith("-----BEGIN PGP PUBLIC KEY BLOCK-----"), top
        assert card.presses == ["sign"] * 3
        await pilot.click("#close")
        await settle(pilot, app)
        print("export: PIN asked, three card signatures (button each), armored key shown")

        # reset
        app.active_tab().query_one("#reset").press()
        await pilot.pause(0.4)
        set_field(app, "admin", ADMIN)
        await submit(pilot, app)
        assert all(k is None for k in card.keys) and rows(app)[0][2].startswith("[dim]empty")
        print("reset: slots empty again")
    print("QK TUI PGP TEST DONE")

asyncio.run(main())
