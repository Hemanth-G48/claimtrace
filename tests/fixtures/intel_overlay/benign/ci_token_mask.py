import os


def masked_actions_token() -> str:
    """Read a runner token only to mask it in logs."""
    token = os.environ.get("ACTIONS_RUNTIME_TOKEN", "")
    return f"{token[:4]}..." if token else "(unset)"
