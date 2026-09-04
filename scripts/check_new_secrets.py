#!/usr/bin/env python3
"""Fail when a scan finds a secret the reviewed baseline does not already carry.

Why a baseline at all: this repository's security corpora *deliberately* contain
credential-shaped strings — a fixture that proves an audit row redacts a Slack token has to
contain something Slack-token-shaped. A scanner set to hard-fail on every hit would be
permanently red, and a permanently red gate is one people learn to ignore, which is worse
than not having it.

Why not `detect-secrets scan --baseline` alone: that command REWRITES the baseline in place
and exits 0, so a genuinely new secret is absorbed rather than reported. This compares the
fresh scan against the committed baseline and fails on anything new, which is the behaviour
the gate is supposed to have.

The comparison is on `(filename, hashed_secret)`. Line numbers move with every edit; the
hash does not, so an unmoved secret in a shifted file is correctly recognised.

Usage: check_new_secrets.py <fresh-scan.json> <baseline.json>
"""

from __future__ import annotations

import json
import sys


def fingerprints(report: dict) -> set[tuple[str, str]]:
    return {
        (path, hit.get("hashed_secret", ""))
        for path, hits in (report.get("results") or {}).items()
        for hit in hits
    }


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as fh:
        fresh = json.load(fh)
    with open(argv[2], encoding="utf-8") as fh:
        baseline = json.load(fh)

    new = fingerprints(fresh) - fingerprints(baseline)
    if not new:
        print(f"no new secrets ({len(fingerprints(baseline))} known, all accounted for)")
        return 0

    by_path: dict[str, list] = {}
    for path, digest in sorted(new):
        by_path.setdefault(path, []).append(digest)
    for path, digests in by_path.items():
        line = next(
            (
                hit.get("line_number")
                for hit in fresh["results"].get(path, [])
                if hit.get("hashed_secret") in digests
            ),
            None,
        )
        where = f"file={path},line={line}" if line else f"file={path}"
        print(f"::error {where}::new potential secret not in .secrets.baseline")
    print(
        f"\n{len(new)} new finding(s). If they are fixtures, review them and refresh the "
        "baseline in the same commit so a human signs off on each one.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
