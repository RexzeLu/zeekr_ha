"""Static guard for the bug that turned the options dialog into a 500.

``config_flow.py`` used ``cv.multi_select(...)`` without ever importing ``cv``.
Nothing in this suite imported that module, so the ``NameError`` survived every
run and only showed up when a user opened the dialog — where Home Assistant had
no schema left to render and answered 500 instead of showing a form.

A linter catches the whole class of mistake, so this test runs pyflakes over
the package and fails on any undefined name.  Unused imports are ignored: they
are noise next to a name that does not exist at all.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parents[1] / "custom_components" / "zeekr_ev"


def test_the_package_has_no_undefined_names():
    pytest.importorskip("pyflakes")

    proc = subprocess.run(
        [sys.executable, "-m", "pyflakes", str(PACKAGE)],
        capture_output=True,
        text=True,
    )
    undefined = [
        line for line in proc.stdout.splitlines() if "undefined name" in line
    ]
    assert not undefined, "\n".join(undefined)
