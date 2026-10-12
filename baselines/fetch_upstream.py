"""Fetch the public benchmark apps at the exact commits in benchmark.json.

This stores upstream source outside the Mobile Audit distribution and does not
build or execute any downloaded app.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


MANIFEST = Path(__file__).with_name("benchmark.json")


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], capture_output=True, text=True,
                            check=False, timeout=300)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"git exited {result.returncode}")
    return result.stdout.strip()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch pinned public source benchmarks without building them")
    parser.add_argument("--destination", type=Path, required=True, help="Directory for separate upstream Git checkouts")
    parser.add_argument("--app", action="append", help="Fetch one app ID; repeat to select several (default: all external apps)")
    args = parser.parse_args(argv)
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        apps = [item for item in manifest["apps"] if item.get("origin") == "upstream"]
        ids = {item["id"] for item in apps}
        if args.app and not set(args.app) <= ids:
            raise ValueError(f"Unknown upstream app ID: {', '.join(sorted(set(args.app) - ids))}")
        destination = args.destination.expanduser().resolve()
        destination.mkdir(parents=True, exist_ok=True)
        for app in apps:
            if args.app and app["id"] not in args.app:
                continue
            repo = destination / app["directory"]
            if repo.exists():
                if not (repo / ".git").exists():
                    raise ValueError(f"Existing path is not a Git checkout: {repo}")
                head = git("-C", str(repo), "rev-parse", "HEAD")
                if head != app["commit"]:
                    raise ValueError(f"{app['id']} is at {head}, expected {app['commit']}; use a fresh destination")
                print(f"Verified {app['id']} at {head[:12]}")
                continue
            git("clone", "--depth", "1", "--filter=blob:none", "--sparse", app["url"], str(repo))
            head = git("-C", str(repo), "rev-parse", "HEAD")
            if head != app["commit"]:
                git("-C", str(repo), "fetch", "--depth", "1", "origin", app["commit"])
                git("-C", str(repo), "checkout", "--detach", app["commit"])
            git("-C", str(repo), "sparse-checkout", "set", *app["sparse_paths"])
            head = git("-C", str(repo), "rev-parse", "HEAD")
            if head != app["commit"]:
                raise RuntimeError(f"Failed to pin {app['id']} to {app['commit']}")
            print(f"Fetched {app['id']} at {head[:12]}")
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.TimeoutExpired) as exc:
        print(f"benchmark fetch: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
