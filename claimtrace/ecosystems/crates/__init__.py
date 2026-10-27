# SPDX-License-Identifier: AGPL-3.0-or-later
"""Crates.io ecosystem adapter."""
from claimtrace.adapter import register
from claimtrace.ecosystems.crates.adapter import CratesAdapter

register(CratesAdapter())
