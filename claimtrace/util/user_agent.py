# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import os

from claimtrace import __version__

_PROJECT_URL = os.environ.get("CLAIMTRACE_PROJECT_URL", "").strip()


def user_agent() -> str:
    contact = os.environ.get("CLAIMTRACE_CONTACT_EMAIL", "").strip()
    if contact:
        return f"claimtrace/{__version__} (contact: {contact})"
    if _PROJECT_URL:
        return f"claimtrace/{__version__} (+{_PROJECT_URL})"
    return f"claimtrace/{__version__}"
