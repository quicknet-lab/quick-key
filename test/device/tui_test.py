# qk tui (Textual) driven headless against the key: wrong PIN and asking again,
# password add / edit / delete through the forms, PIN change in the PIN tab,
# OTP account added through the form. Needs PIN 314159 and an empty password
# manager; leaves both as they were. No button presses.
import asyncio, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools"))
import qk, qk_tui
from textual.widgets import TabbedContent


async def settle(pilot, app, secs=8.0):
    t = 0
    await pilot.pause(0.3)
    while t < secs:
        if not [w for w in app.workers if w.is_running]:
            break
        await pilot.pause(0.2)
        t += 0.2
    await pilot.pause(0.3)


def rows(app):
    t = app.active_tab().table()
    return [list(map(str, t.get_row_at(i))) for i in range(t.row_count)]


async def main():
    app = qk_tui.QkApp()
    async with app.run_test(size=(110, 40)) as pilot:
        await settle(pilot, app)
        app.query_one(TabbedContent).active = "passwords"
        await pilot.pause(0.5)
        await pilot.press(*"000000", "enter")                 # wrong PIN
        await settle(pilot, app)
        assert app.pin is None
        assert qk.pin_tries()[0] == 7
        await pilot.press("r")                                # asks again
        await pilot.pause(0.5)
        await pilot.press(*"314159", "enter")
        await settle(pilot, app)
        assert qk.pin_tries()[0] == 8 and rows(app) == []
        print("wrong PIN: error, asked again; right PIN restores tries")

        # add through the form: name, url, login, password, (generate), note, otp, (touch), Add
        await pilot.press("a")
        await pilot.pause(0.4)
        await pilot.press(*"Mail", "tab", *"https://mail.example", "tab", *"me", "tab", *"Secret-9", "enter")
        await settle(pilot, app)
        r = [x for x in rows(app) if x[0] == "Mail"]
        assert r and r[0][1] == "me", rows(app)
        p = qk.Pwd().unlock("314159")
        mid = [x for x in p.list() if x["name"] == "Mail"][0]["id"]
        assert p.get(mid, True)["password"] == "Secret-9"
        print("added Mail through the form")

        # edit: cursor on Mail, change the login, keep the password
        t = app.active_tab().table()
        t.move_cursor(row=t.get_row_index(str(mid)))
        await pilot.press("e")
        await settle(pilot, app)
        await pilot.press("tab", "tab")                       # to Login
        await pilot.press("end")
        for _ in range(2):
            await pilot.press("backspace")
        await pilot.press(*"me2", "enter")
        await settle(pilot, app)
        rec = qk.Pwd().unlock("314159").get(mid, True)
        assert rec["login"] == "me2" and rec["password"] == "Secret-9", rec
        print("edited the login, password kept")

        # delete with confirmation
        t.move_cursor(row=t.get_row_index(str(mid)))
        await pilot.press("d")
        await pilot.pause(0.4)
        await pilot.click("#yes")
        await settle(pilot, app)
        assert not [x for x in rows(app) if x[0] == "Mail"]
        print("deleted Mail")

        # PIN tab: change and change back
        app.query_one(TabbedContent).active = "pin"
        await settle(pilot, app)
        await pilot.click("#change")
        await pilot.pause(0.4)
        await pilot.press(*"314159", "tab", *"Qk-pin7", "tab", *"Qk-pin7", "enter")
        await settle(pilot, app)
        assert app.pin == "Qk-pin7"
        qk.pin_change("Qk-pin7", "314159")
        print("PIN changed in the PIN tab, session PIN updated")

        # OTP: add through the form, the code shows up, delete with confirmation
        app.query_one(TabbedContent).active = "otp"
        await settle(pilot, app)
        await pilot.press("a")
        await pilot.pause(0.4)
        await pilot.press(*"tui-test", "tab", *"JBSWY3DPEHPK3PXP", "enter")
        await settle(pilot, app)
        r = [x for x in rows(app) if x[0] == "tui-test"]
        assert r and r[0][2].isdigit(), rows(app)
        t = app.active_tab().table()
        t.move_cursor(row=t.get_row_index("tui-test"))
        await pilot.press("d")
        await pilot.pause(0.4)
        await pilot.click("#yes")
        await settle(pilot, app)
        assert not [x for x in rows(app) if x[0] == "tui-test"]
        print("OTP account added and deleted through the TUI")
    print("tui tests passed")


asyncio.run(main())
