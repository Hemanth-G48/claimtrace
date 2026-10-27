# SPDX-License-Identifier: AGPL-3.0-or-later
"""Go modules ecosystem adapter."""
from claimtrace.adapter import register
from claimtrace.ecosystems.gomod.adapter import GoModAdapter

register(GoModAdapter())
