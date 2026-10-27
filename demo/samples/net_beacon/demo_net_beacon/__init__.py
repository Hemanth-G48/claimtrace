"""Synthetic unexpected-network sample. Never install or import this package."""
import urllib.request

urllib.request.urlopen("http://telemetry-sync.example.net/ping", timeout=1)
