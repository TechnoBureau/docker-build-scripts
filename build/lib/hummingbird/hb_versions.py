#!/usr/bin/env python3
"""File-only half of RPM version resolution; get_rpm_versions.sh runs the engine.

A query is scoped to distro AND target RPM architecture. All requested packages
(including arch-specific entries) must resolve in their own query. A common tag
cannot silently describe different package versions on different architectures.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

import yaml

from hb_config import ConfigError, DISTRO_RELEASEVERS, load_yaml
from hb_platforms import entry_arches, rpm_arches


def make_plan(work: Path, builder_image: str) -> dict:
    queries: dict[tuple[str, str], dict[str, set[str]]] = {}
    for path in sorted((work / "images").glob("*/[!.]*/*/rpms/rpms.in.yaml")):
        distro = path.parent.parent.parent.name
        data = load_yaml(path, "rpms.in.yaml")
        for arch in rpm_arches(data.get("arches") or []):
            query = queries.setdefault((distro, arch), {"packages": set(), "repos": set()})
            for entry in data.get("packages") or []:
                if isinstance(entry, str):
                    query["packages"].add(entry)
                elif isinstance(entry, dict) and entry.get("name") and arch in entry_arches(entry):
                    query["packages"].add(entry["name"])
            for repo in (data.get("contentOrigin") or {}).get("repofiles") or []:
                resolved = (path.parent / repo).resolve()
                if not resolved.is_file():
                    raise ConfigError(f"repo file not found: {resolved} (referenced by {path})")
                query["repos"].add(str(resolved))
    plan = {"builder_image": builder_image, "queries": [
        {"distro": distro, "arch": arch, "releasever": DISTRO_RELEASEVERS.get(distro, ""),
         "packages": sorted(values["packages"]), "repos": sorted(values["repos"])}
        for (distro, arch), values in sorted(queries.items()) if values["packages"]
    ]}
    if not plan["queries"]:
        raise ConfigError("No packages found in images/*/*/*/rpms/rpms.in.yaml")
    digest = hashlib.sha256(json.dumps(plan, sort_keys=True).encode())
    for repo in sorted({repo for query in plan["queries"] for repo in query["repos"]}):
        digest.update(Path(repo).read_bytes())
    plan["request_sha256"] = digest.hexdigest()
    return plan


def write_plan(plan: dict, output: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    (output / "requests.tsv").write_text("".join(
        f"{q['distro']}\t{q['arch']}\t{q['releasever'] or '-'}\t{' '.join(q['packages'])}\n" for q in plan["queries"]
    ))
    (output / "repos.tsv").write_text("".join(
        f"{q['distro']}\t{q['arch']}\t{repo}\n" for q in plan["queries"] for repo in q["repos"]
    ))


def cache_is_fresh(plan: dict, cache: Path, ttl: int) -> bool:
    if ttl <= 0 or not cache.is_file() or time.time() - cache.stat().st_mtime >= ttl:
        return False
    data = load_yaml(cache, "RPM versions cache")
    return data.get("request_sha256") == plan["request_sha256"]


def collect_results(plan: dict, results: Path) -> dict:
    architectures: dict[str, dict[str, dict[str, str]]] = {}
    for query in plan["queries"]:
        distro, arch = query["distro"], query["arch"]
        result = results / f"{distro}--{arch}.versions"
        versions: dict[str, str] = {}
        if result.is_file():
            for line in result.read_text().splitlines():
                name, _, evr = line.strip().partition(" ")
                if name in query["packages"] and evr.strip():
                    value = evr.strip().split(":", 1)[-1]
                    if name in versions and versions[name] != value:
                        raise ConfigError(f"ambiguous versions for {distro}/{arch}/{name}; check selected repositories")
                    versions[name] = value
        missing = sorted(set(query["packages"]) - versions.keys())
        if missing:
            raise ConfigError("No version resolved for: " + ", ".join(
                f"{distro}/{name} (architecture {arch})" for name in missing
            ))
        architectures.setdefault(distro, {})[arch] = versions

    distros: dict[str, dict[str, str]] = {}
    for distro, arches in architectures.items():
        shared = distros.setdefault(distro, {})
        for arch, packages in arches.items():
            for name, evr in packages.items():
                if name in shared and shared[name] != evr:
                    raise ConfigError(
                        f"{distro}/{name} differs across requested architectures "
                        f"({shared[name]} vs {arch}: {evr}); align the repositories or build single architectures separately"
                    )
                shared[name] = evr
    return {"request_sha256": plan["request_sha256"], "distros": distros, "architectures": architectures}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--work", type=Path, default=Path.cwd())
    plan.add_argument("--output", type=Path, required=True)
    plan.add_argument("--builder-image", required=True)
    for name in ("fresh", "cache"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--plan", type=Path, required=True)
        cmd.add_argument("--cache", type=Path, required=True)
        if name == "fresh":
            cmd.add_argument("--ttl", type=int, required=True)
        else:
            cmd.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "plan":
            write_plan(make_plan(args.work, args.builder_image), args.output)
        else:
            data = json.loads(args.plan.read_text())
            if args.command == "fresh":
                return 0 if cache_is_fresh(data, args.cache, args.ttl) else 1
            cache = collect_results(data, args.results)
            args.cache.parent.mkdir(parents=True, exist_ok=True)
            temporary = args.cache.with_suffix(".tmp")
            temporary.write_text("# Generated by get_rpm_versions.sh; do not edit.\n" + yaml.safe_dump(cache, sort_keys=True))
            temporary.replace(args.cache)
            print(f"Wrote {args.cache} ({len(cache['architectures'])} distro(s), {len(data['queries'])} distro/architecture queries)")
    except (ConfigError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
