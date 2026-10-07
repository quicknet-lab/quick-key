#!/usr/bin/env python3
"""The PIV tab of `qk tui` (headless Textual Pilot) on the software card of fakecard.py."""
import asyncio
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakecard  # noqa: E402
import tuikit  # noqa: E402
import qk_piv as piv  # noqa: E402
import qk_tui  # noqa: E402
from cryptography import x509  # noqa: E402
from tuikit import dialog, notes, open_tab, rows, set_field, settle, submit  # noqa: E402

PIN = fakecard.PIN


async def close(pilot, app):
    await pilot.click("#close")
    await settle(pilot, app)


async def generate_dialog(pilot, app):
    """Presses g; an occupied slot asks first: answer yes."""
    await pilot.press("g")
    await pilot.pause(0.4)
    if isinstance(dialog(app), qk_tui.Confirm):
        await pilot.click("#yes")
        await pilot.pause(0.4)
    assert isinstance(dialog(app), qk_tui.Form), dialog(app)


async def main():
    card = fakecard.install()
    tuikit.quiet_device()
    app = qk_tui.QkApp()
    async with app.run_test(size=(130, 45)) as pilot:
        await settle(pilot, app)
        await open_tab(pilot, app, "piv")
        assert [r[0] for r in rows(app)] == ["9A", "9C", "9D", "9E"] and rows(app)[0][2].startswith("[dim]empty")
        assert "factory management key" in str(app.active_tab().query_one("#piv_info").render())
        print("empty card: four slots, factory management key flagged")

        t = app.active_tab().table()
        await pilot.press("g")
        await pilot.pause(0.4)
        set_field(app, "touch", "cached")
        await submit(pilot, app)
        top = dialog(app)
        assert isinstance(top, qk_tui.TextView) and top.text.startswith("-----BEGIN PUBLIC KEY-----"), top
        await close(pilot, app)
        assert rows(app)[0][2] == "nistp256" and rows(app)[0][3] == "cached", rows(app)[0]
        print("generate: P-256 key with touch cached")

        await pilot.press("g")
        await pilot.pause(0.4)
        assert isinstance(dialog(app), qk_tui.Confirm)
        await pilot.click("#no")
        await settle(pilot, app)
        print("replacing a key asks first")

        # self-signed certificate, wrong PIN first
        await pilot.press("s")
        await pilot.pause(0.4)
        set_field(app, "subject", "CN=Jane Doe,O=Example")
        set_field(app, "days", "30")
        set_field(app, "pin", "000000")
        await submit(pilot, app)
        assert any("wrong PIN" in m for m in notes(app)), notes(app)
        await pilot.press("s")
        await pilot.pause(0.4)
        set_field(app, "subject", "CN=Jane Doe,O=Example")
        set_field(app, "days", "30")
        set_field(app, "pin", PIN)
        await submit(pilot, app)
        top = dialog(app)
        assert isinstance(top, qk_tui.TextView) and "Jane Doe" in top.text, top
        await close(pilot, app)
        assert "Jane Doe" in rows(app)[0][5] and card.presses == ["piv9a"], (rows(app)[0], card.presses)
        print("self-signed certificate: wrong PIN refused, signed on the card, stored, shown in the table")

        await pilot.press("enter")
        await pilot.pause(0.4)
        top = dialog(app)
        assert isinstance(top, qk_tui.TextView) and "-----BEGIN CERTIFICATE-----" in top.text and "SHA-256" in top.text
        await close(pilot, app)

        await pilot.press("c")
        await pilot.pause(0.4)
        set_field(app, "subject", "CN=Req")
        set_field(app, "pin", PIN)
        await submit(pilot, app)
        top = dialog(app)
        assert isinstance(top, qk_tui.TextView) and top.text.startswith("-----BEGIN CERTIFICATE REQUEST-----"), top
        assert x509.load_pem_x509_csr(top.text.encode()).is_signature_valid
        await close(pilot, app)
        print("certificate signing request signed on the card")

        await pilot.press("x")
        await pilot.pause(0.4)
        top = dialog(app)
        assert isinstance(top, qk_tui.TextView) and "BEGIN PUBLIC KEY" in top.text and "BEGIN CERTIFICATE" in top.text \
            and top.text.strip().splitlines()[-1].startswith("ecdsa-sha2-nistp256 ")
        saved = top.text[top.text.index("-----BEGIN CERTIFICATE-----"):top.text.index("-----END CERTIFICATE-----") + 25]
        await close(pilot, app)
        print("export shows public key, certificate and SSH line")

        # delete the certificate and import it back
        await pilot.press("d")
        await pilot.pause(0.4)
        await submit(pilot, app)
        assert piv.read_cert(0x9A) is None and rows(app)[0][5] == ""
        path = os.path.join(tempfile.mkdtemp(), "c.pem")
        open(path, "w").write(saved + "\n")
        await pilot.press("i")
        await pilot.pause(0.4)
        set_field(app, "file", path)
        await submit(pilot, app)
        assert piv.read_cert(0x9A) and "Jane Doe" in rows(app)[0][5]
        print("certificate deleted, then imported back from a file")

        # RSA key in 9D takes the busy path
        t.move_cursor(row=2)
        await pilot.press("g")
        await pilot.pause(0.4)
        set_field(app, "algo", "rsa2048")
        await submit(pilot, app)
        await close(pilot, app)
        assert rows(app)[2][2] == "rsa2048"

        # a management key that is not hex must not crash the app
        t.move_cursor(row=0)
        await generate_dialog(pilot, app)
        set_field(app, "mgmt", "xyz")
        await submit(pilot, app)
        assert any("hex digits only" in m for m in notes(app)), notes(app)
        await settle(pilot, app)
        print("a malformed management key is reported, not fatal")

        # management key: a wrong one is refused; changing it is remembered for the session
        t.move_cursor(row=0)
        await generate_dialog(pilot, app)
        set_field(app, "mgmt", "00" * 24)
        await submit(pilot, app)
        assert any("wrong management key" in m for m in notes(app)), notes(app)
        assert not isinstance(dialog(app), qk_tui.TextView)
        await pilot.press("m")
        await pilot.pause(0.4)
        set_field(app, "algo", "aes256")
        await submit(pilot, app)
        top = dialog(app)
        assert isinstance(top, qk_tui.TextView) and len(top.text) == 64 and app.mgmt_key.hex() == top.text
        await close(pilot, app)
        assert card.mgmt_alg == 0x0C and "aes256" in str(app.active_tab().query_one("#piv_info").render())
        await generate_dialog(pilot, app)
        await submit(pilot, app)                  # empty management key field: the remembered one is used
        assert isinstance(dialog(app), qk_tui.TextView), notes(app)
        await close(pilot, app)
        print("management key: wrong one refused, AES-256 set, remembered for the session")

        app.active_tab().query_one("#reset").press()
        await pilot.pause(0.4)
        await pilot.click("#yes")
        await settle(pilot, app)
        assert card.piv_keys == {} and rows(app)[0][2].startswith("[dim]empty") and "piv reset" in card.presses
        assert app.mgmt_key is None, "the remembered management key must not outlive a reset"
        print("reset PIV")
    print("QK TUI PIV TEST DONE")

asyncio.run(main())
