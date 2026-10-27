# SPDX-License-Identifier: AGPL-3.0-or-later
"""Local-artifact claim/behavior assessment (ARCHITECTURE.md sections G–J)."""
from __future__ import annotations

from claimtrace.assessment.report import render, report_hash
from claimtrace.assessment.runner import assess

__all__ = ["assess", "render", "report_hash"]
