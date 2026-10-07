#!/usr/bin/env python3
"""Runs the hardware script test/device/manage_test.py against the software models of the key's applications:
it finds mistakes in the script's own logic before it meets a real key (the models know nothing about the
firmware's quirks, so a pass here is not a pass on the key)."""
import os
import runpy
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fakeapps  # noqa: E402
import fakecard  # noqa: E402
import fakefido  # noqa: E402
import qk  # noqa: E402

fakecard.install()
fakefido.install()
fakeapps.install()
sys.argv.append("--erase-everything")
qk.piv_reset = lambda: qk.piv_card().send(0x00, 0xFB, 0x00, 0x00)
runpy.run_path(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "device", "manage_test.py"))
