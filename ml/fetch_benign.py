"""Download the benign installer corpus listed in benign_sources.txt.

Also harvests shell/Python scripts already on this machine (--system), which adds
many real-world administrative scripts. Nothing fetched here is committed.
"""
import argparse
import hashlib
import os
import pathlib
import urllib.request

ROOT = pathlib.Path(__file__).parent
OUT = ROOT / "corpus" / "benign"
SYSTEM_DIRS = ["/usr/bin", "/usr/sbin", "/usr/lib/git-core", "/usr/share", "/etc", "/usr/local/bin",
               "/usr/local/lib", "/opt/node22/lib/node_modules", "/root/.cargo", "/root/.rustup"]
SHEBANGS = (b"#!/bin/sh", b"#!/bin/bash", b"#!/usr/bin/env bash", b"#!/usr/bin/env sh",
            b"#! /bin/sh", b"#!/usr/bin/env python", b"#!/usr/bin/python")


def fetch(url):
    name = url.rstrip("/").split("/", 3)[-1].replace("/", "__").replace("%20", "_")
    dest = OUT / "official" / name
    if dest.exists():
        return True
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            data = r.read()
    except Exception as e:  # noqa: BLE001 - report and continue
        print(f"skip {url}: {e}")
        return False
    dest.write_bytes(data)
    return True


def harvest_system(limit):
    seen, n = set(), 0
    for base in SYSTEM_DIRS:
        for dirpath, _, files in os.walk(base):
            for f in files:
                p = pathlib.Path(dirpath) / f
                try:
                    if not p.is_file() or p.is_symlink() or not (200 < p.stat().st_size < 400_000):
                        continue
                    head = p.open("rb").read(64)
                except OSError:
                    continue
                if not (head.startswith(SHEBANGS) or p.suffix in (".sh", ".ps1", ".psm1", ".cmd", ".bat")):
                    continue
                data = p.read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                if digest in seen:
                    continue
                seen.add(digest)
                suffix = p.suffix if p.suffix in (".sh", ".py", ".ps1", ".psm1", ".cmd", ".bat") else ""
                (OUT / "system" / f"{digest[:12]}_{p.name}{'' if p.suffix else suffix}").write_bytes(data)
                n += 1
                if n >= limit:
                    return n
    return n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--system", type=int, default=600, help="max local system scripts to harvest (0 to skip)")
    args = ap.parse_args()
    (OUT / "official").mkdir(parents=True, exist_ok=True)
    (OUT / "system").mkdir(parents=True, exist_ok=True)
    urls = [l.strip() for l in (ROOT / "benign_sources.txt").read_text().splitlines()
            if l.strip() and not l.startswith("#")]
    ok = sum(fetch(u) for u in urls)
    print(f"official installers: {ok}/{len(urls)}")
    if args.system:
        print(f"system scripts: {harvest_system(args.system)}")


if __name__ == "__main__":
    main()
