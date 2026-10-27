"""Build synthetic sdists for the demo from demo/samples/<case>/."""

from __future__ import annotations

import sys
import tarfile
from pathlib import Path

SAMPLES = {
    "benign_math": "demo-benign-math",
    "ssh_beacon": "demo-ssh-beacon",
    "net_beacon": "demo-net-beacon",
    "ci_token": "demo-ci-token",
}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: build_archives.py <output-dir>", file=sys.stderr)
        return 2
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    base = Path(__file__).resolve().parent / "samples"
    for case, dist in SAMPLES.items():
        src = base / case
        archive = out / f"{dist}-1.0.0.tar.gz"
        with tarfile.open(archive, "w:gz") as tf:
            for path in sorted(src.rglob("*")):
                if path.is_file() and "__pycache__" not in path.parts:
                    tf.add(path, arcname=f"{dist}-1.0.0/{path.relative_to(src).as_posix()}")
        print(f"  {archive.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
