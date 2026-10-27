# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deterministic claim extraction for the local-artifact assessment path.

Claims are hypotheses read from the artifact's own metadata and README. They are
never treated as policy overrides; a claim that names a sensitive resource only
makes that observation ``declared-sensitive``.
"""
from __future__ import annotations

import json
import re
import tarfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

EXTRACTOR_VERSION = "deterministic-1"

_SENSITIVE_PATHS = (
    ".ssh", ".aws", ".npmrc", ".pypirc", ".netrc", ".docker/config",
    ".kube/config", ".config/gcloud", ".cargo/credentials", ".env",
)
_HOST_RE = re.compile(
    r"\b(?:https?://)?(?P<host>(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}|(?:\d{1,3}\.){3}\d{1,3})(?::\d+)?\b",
    re.I,
)
_CAPABILITY_WORDS: tuple[tuple[str, str], ...] = (
    ("network", "network.connect"),
    ("http", "network.connect"),
    ("https", "network.connect"),
    ("connect", "network.connect"),
    ("download", "process.spawn.downloader"),
    ("curl", "process.spawn.downloader"),
    ("wget", "process.spawn.downloader"),
    ("shell", "process.spawn.shell"),
    ("subprocess", "process.spawn"),
    ("spawn", "process.spawn"),
    ("read", "file.read"),
    ("write", "file.write"),
    ("file", "file.read"),
    ("environment", "env.read"),
    ("env", "env.read"),
)


@dataclass(frozen=True)
class PackageInfo:
    name: str
    version: str
    description: str
    main: str | None
    bin: dict[str, str]
    scripts: dict[str, str]
    readme: str | None
    readme_path: str | None


@dataclass(frozen=True)
class Claim:
    claim_id: str
    text: str
    source: str
    span: str | None
    expected_capability: tuple[str, ...]
    phase: str
    confidence: str
    ambiguity: str
    status: str
    resource: str | None = None
    destination: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["expected_capability"] = list(self.expected_capability)
        return d


def _read_tar_text(tf: tarfile.TarFile, suffix: str) -> tuple[str | None, str | None]:
    for member in tf.getmembers():
        if not member.isfile():
            continue
        lower = member.name.lower()
        if lower.endswith(suffix):
            try:
                return tf.extractfile(member).read().decode("utf-8", "replace"), member.name
            except Exception:
                return None, member.name
    return None, None


def read_package_info(archive_path: str | Path) -> PackageInfo:
    path = Path(archive_path)
    with tarfile.open(path, "r:*") as tf:
        raw, _ = _read_tar_text(tf, "package.json")
        if raw is None:
            raise ValueError(f"no package.json in {path.name}")
        meta = json.loads(raw)
        readme = None
        readme_path = None
        for name in ("readme.md", "readme.markdown", "readme.txt", "readme"):
            for member in tf.getmembers():
                if member.isfile() and member.name.split("/")[-1].lower() == name:
                    try:
                        readme = tf.extractfile(member).read().decode("utf-8", "replace")
                        readme_path = member.name
                    except Exception:
                        pass
                    break
            if readme is not None:
                break

    name = str(meta.get("name") or "")
    version = str(meta.get("version") or "")
    if not name or not version:
        raise ValueError("package.json missing name/version")
    raw_bin = meta.get("bin")
    bins: dict[str, str] = {}
    if isinstance(raw_bin, str):
        bins[name.split("/")[-1]] = raw_bin
    elif isinstance(raw_bin, dict):
        bins = {str(k): str(v) for k, v in raw_bin.items() if isinstance(v, str)}
    scripts = meta.get("scripts") if isinstance(meta.get("scripts"), dict) else {}
    return PackageInfo(
        name=name,
        version=version,
        description=str(meta.get("description") or ""),
        main=str(meta["main"]) if isinstance(meta.get("main"), str) else None,
        bin=bins,
        scripts={str(k): str(v) for k, v in scripts.items()},
        readme=readme,
        readme_path=readme_path,
    )


def _claim_id(parts: Iterable[str]) -> str:
    import hashlib
    return "claim-" + hashlib.sha256("\x1f".join(parts).encode()).hexdigest()[:16]


def _resource_for_line(line: str) -> str | None:
    for needle in _SENSITIVE_PATHS:
        if needle in line:
            return needle
    source = re.search(r"(?:~|/)[\w./-]{3,}", line)
    return source.group(0) if source else None


def extract_claims(pkg: PackageInfo) -> tuple[list[Claim], bool]:
    """Return (claims, claims_available). Missing README means claims are unavailable."""
    claims: list[Claim] = []
    if not pkg.readme:
        return claims, False
    if pkg.description:
        text = pkg.description.strip()
        caps = tuple(sorted({cap for word, cap in _CAPABILITY_WORDS if word in text.lower()}))
        if caps:
            claims.append(Claim(
                claim_id=_claim_id(("metadata", text)), text=text, source="package.json:description",
                span=None, expected_capability=caps, phase="any", confidence="low",
                ambiguity="metadata description is not a complete behavioral claim",
                status="parsed",
            ))

    for line_no, line in enumerate(pkg.readme.splitlines(), 1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        low = text.lower()
        caps = tuple(sorted({cap for word, cap in _CAPABILITY_WORDS if word in low}))
        resource = _resource_for_line(text)
        hosts = [m.group("host") for m in _HOST_RE.finditer(text)]
        # Do not turn arbitrary domains in examples into claims unless line is a
        # capability sentence; this keeps claims conservative.
        if hosts and not caps:
            caps = ("network.connect",)
        if not caps and not resource:
            continue
        if resource:
            caps = tuple(sorted(set(caps) | {"file.read.sensitive"}))
        if hosts:
            caps = tuple(sorted(set(caps) | {"network.connect"}))
        claims.append(Claim(
            claim_id=_claim_id((pkg.readme_path or "readme", str(line_no), text)),
            text=text,
            source=f"{pkg.readme_path or 'README'}:{line_no}",
            span=f"L{line_no}",
            expected_capability=caps,
            phase="any",
            confidence="medium" if resource or hosts else "low",
            ambiguity="free-text README claim" if not (resource or hosts) else "",
            status="parsed",
            resource=resource,
            destination=hosts[0] if hosts else None,
        ))
    return claims, True
