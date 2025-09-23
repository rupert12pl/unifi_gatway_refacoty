"""Pytest configuration for the test suite."""

from __future__ import annotations

import sys
from pathlib import Path


TESTS_DIR = Path(__file__).resolve().parent
ROOT = TESTS_DIR.parents[0]

for target in (TESTS_DIR, ROOT):
    if str(target) not in sys.path:
        sys.path.insert(0, str(target))


from stubs import ensure_homeassistant_stubs


ensure_homeassistant_stubs()

