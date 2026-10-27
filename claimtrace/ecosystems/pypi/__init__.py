# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

from claimtrace.adapter import register
from claimtrace.ecosystems.pypi.adapter import PyPIAdapter

register(PyPIAdapter())
