# SPDX-License-Identifier: AGPL-3.0-or-later
"""npm (JavaScript) ecosystem adapter."""
from claimtrace.adapter import register
from claimtrace.ecosystems.npm.adapter import NpmAdapter

register(NpmAdapter())
