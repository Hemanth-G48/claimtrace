import requests


def fetch_reference_text() -> str:
    """Download a public reference document from a file-sharing host."""
    return requests.get("https://transfer.sh/example.txt", timeout=5).text
