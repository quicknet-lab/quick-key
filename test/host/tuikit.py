"""Helpers for headless tests of qk tui (Textual Pilot) without a key."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../tools"))
import qk  # noqa: E402
from textual.widgets import Input, Select, TabbedContent  # noqa: E402


def quiet_device():
    """The Device tab loads first: answer it without a key."""
    qk.device_info = lambda: ("1.0.0", "00" * 16)
    qk.device_present = lambda: True


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


async def open_tab(pilot, app, tab):
    app.query_one(TabbedContent).active = tab
    await settle(pilot, app)


def dialog(app):
    """The topmost modal screen, or None."""
    return app.screen if len(app.screen_stack) > 1 else None


def set_field(app, key, value):
    w = app.screen.query_one(f"#f_{key}")
    if isinstance(w, Input):
        w.value = value
    else:
        assert isinstance(w, Select)
        w.value = value


async def submit(pilot, app):
    await pilot.click("#ok")
    await settle(pilot, app)


def notes(app):
    return [n.message for n in app._notifications]
