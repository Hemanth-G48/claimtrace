# SPDX-License-Identifier: AGPL-3.0-or-later
"""Auto-register all ecosystem adapters on import."""
import claimtrace.ecosystems.pypi    # noqa: F401
import claimtrace.ecosystems.crates  # noqa: F401
import claimtrace.ecosystems.gomod   # noqa: F401
import claimtrace.ecosystems.npm     # noqa: F401
