#!/usr/bin/env python3
"""Harvest public CI workflow YAMLs into an ignored, deduplicated test corpus.

Default output:
  corpus/workflow-yaml-testbed/{gha,ado,bb,gl}/

The script is intentionally resumable. It keeps a JSONL manifest, scans already
downloaded files for content hashes, and skips duplicate bodies globally across
all platforms. Search starts with GitHub code/repo search because the repo
already has authenticated `gh` available in normal maintainer environments.
GitLab and Bitbucket also have provider fallbacks for public repositories.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable


PLATFORMS = ("gha", "ado", "bb", "gl")
DEFAULT_ROOT = Path("corpus/workflow-yaml-testbed")
MAX_BYTES = 2 * 1024 * 1024


@dataclasses.dataclass(frozen=True)
class Candidate:
    platform: str
    repo: str
    path: str
    html_url: str


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def run_gh_api(path: str, params: dict[str, str] | None = None) -> dict:
    cmd = ["gh", "api", "-X", "GET", path]
    if params:
        for k, v in params.items():
            cmd.extend(["-f", f"{k}={v}"])
    while True:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            return json.loads(result.stdout)
        stderr = result.stderr.strip()
        if "rate limit" in stderr.lower() or "secondary rate" in stderr.lower():
            wait = 65
            print(f"rate limited by GitHub; sleeping {wait}s", file=sys.stderr, flush=True)
            time.sleep(wait)
            continue
        raise RuntimeError(f"gh api failed: {' '.join(cmd)}\n{stderr}")


def code_search_cli(query: str, limit: int) -> list[dict] | None:
    cmd = [
        "gh",
        "search",
        "code",
        query,
        "--limit",
        str(limit),
        "--json",
        "path,repository,url",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return None
    try:
        rows = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(rows, list):
        return None
    items = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        repo = row.get("repository")
        repo_name = repo.get("nameWithOwner") if isinstance(repo, dict) else None
        html_url = row.get("url")
        path = row.get("path")
        if repo_name and html_url and path:
            items.append({"html_url": html_url, "path": path, "repository": {"full_name": repo_name}})
    return items


def code_search(query: str, per_page: int = 100, max_pages: int = 10) -> Iterable[dict]:
    if max_pages <= 0:
        return
    cli_items = code_search_cli(query, limit=min(per_page * max_pages, 1000))
    if cli_items is not None:
        for item in cli_items:
            yield item
        return
    if os.environ.get("TAUDIT_GH_API_FALLBACK") != "1":
        return

    for page in range(1, max_pages + 1):
        data = run_gh_api(
            "/search/code",
            {
                "q": query,
                "per_page": str(per_page),
                "page": str(page),
            },
        )
        items = data.get("items", [])
        if not items:
            return
        for item in items:
            yield item
        if len(items) < per_page:
            return
        # Authenticated code search is still a low-rate endpoint. Pace pages so
        # long harvests finish predictably instead of hitting secondary limits.
        time.sleep(6.5)


def repo_search(query: str, per_page: int = 100, max_pages: int = 10) -> Iterable[dict]:
    for page in range(1, max_pages + 1):
        data = run_gh_api(
            "/search/repositories",
            {
                "q": query,
                "sort": "stars",
                "order": "desc",
                "per_page": str(per_page),
                "page": str(page),
            },
        )
        items = data.get("items", [])
        if not items:
            return
        for item in items:
            yield item
        if len(items) < per_page:
            return
        time.sleep(2.2)


def gh_json(path: str) -> dict | list | None:
    result = subprocess.run(["gh", "api", "-X", "GET", path], capture_output=True, text=True)
    if result.returncode != 0:
        return None
    return json.loads(result.stdout)


def raw_url_from_html(html_url: str) -> str | None:
    # https://github.com/owner/repo/blob/ref/path -> raw.githubusercontent.com/owner/repo/ref/path
    parsed = urllib.parse.urlparse(html_url)
    if parsed.netloc != "github.com":
        return None
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 5 or parts[2] != "blob":
        return None
    owner, repo, _, ref = parts[:4]
    rest = "/".join(parts[4:])
    return f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{rest}"


def fetch_url(url: str, timeout: int = 25) -> bytes | None:
    req = urllib.request.Request(url, headers={"User-Agent": "taudit-corpus-harvester"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                size = resp.headers.get("Content-Length")
                if size and int(size) > MAX_BYTES:
                    return None
                data = resp.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    return None
                return data
        except urllib.error.HTTPError as err:
            if err.code in {429, 500, 502, 503, 504} and attempt < 2:
                retry_after = err.headers.get("Retry-After")
                try:
                    wait = float(retry_after) if retry_after else 2.0 * (attempt + 1)
                except ValueError:
                    wait = 2.0 * (attempt + 1)
                time.sleep(max(wait, 1.0))
                continue
            return None
        except (urllib.error.URLError, TimeoutError, ValueError):
            return None
    return None


def fetch_json_url(url: str, timeout: int = 25) -> dict | list | None:
    data = fetch_url(url, timeout=timeout)
    if data is None:
        return None
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def textish(data: bytes) -> bool:
    if not data or b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def platform_accepts(platform: str, path: str, data: bytes) -> bool:
    if not textish(data):
        return False
    text = data.decode("utf-8", errors="replace")
    lower_path = path.lower()
    lower = text.lower()
    if platform == "gha":
        return "/.github/workflows/" in f"/{lower_path}" and re.search(r"(?m)^on\s*:", text) and re.search(r"(?m)^jobs\s*:", text)
    if platform == "ado":
        if "azure-pipelines" not in lower_path and ".azure-pipelines" not in lower_path:
            return False
        return any(re.search(rf"(?m)^{key}\s*:", text) for key in ("trigger", "pr", "stages", "jobs", "pool", "steps", "resources"))
    if platform == "bb":
        name = Path(lower_path).name
        return name.startswith("bitbucket-pipelines.yml") and re.search(r"(?m)^pipelines\s*:", text)
    if platform == "gl":
        return lower_path.endswith(".gitlab-ci.yml") and any(
            re.search(rf"(?m)^{key}\s*:", text)
            for key in ("stages", "include", "variables", "image", "default", "workflow")
        )
    raise ValueError(platform)


def safe_name(repo: str, path: str, digest: str) -> str:
    stem = f"{repo}__{path}".replace("/", "_")
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._-")
    if len(stem) > 180:
        stem = stem[:180]
    suffix = Path(path).suffix.lower()
    if suffix not in (".yml", ".yaml"):
        suffix = ".yml"
    return f"{stem}__{digest[:12]}{suffix}"


def load_existing(root: Path) -> tuple[set[str], dict[str, int]]:
    seen: set[str] = set()
    counts = {p: 0 for p in PLATFORMS}
    for platform in PLATFORMS:
        pdir = root / platform
        if not pdir.exists():
            continue
        for path in pdir.glob("*.y*ml"):
            data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if digest not in seen:
                counts[platform] += 1
            seen.add(digest)
    return seen, counts


def load_manifest_urls(manifest: Path) -> set[str]:
    urls: set[str] = set()
    if not manifest.exists():
        return urls
    for line in manifest.read_text().splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if url := obj.get("html_url"):
            urls.add(url)
    return urls


def append_manifest(manifest: Path, record: dict) -> None:
    with manifest.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def queries_for(platform: str) -> list[str]:
    if platform == "gha":
        return [
            "path:.github/workflows extension:yml size:<10",
            "path:.github/workflows extension:yml size:10..20",
            "path:.github/workflows extension:yml size:20..50",
            "path:.github/workflows extension:yml size:50..2000",
            "path:.github/workflows extension:yaml size:<10",
            "path:.github/workflows extension:yaml size:10..20",
            "path:.github/workflows extension:yaml size:20..50",
            "path:.github/workflows extension:yaml size:50..2000",
        ]
    if platform == "ado":
        return [
            "filename:azure-pipelines.yml",
            "filename:azure-pipelines.yaml",
            "path:.azure-pipelines extension:yml",
            "path:.azure-pipelines extension:yaml",
            "filename:azure-pipelines.yml trigger",
            "filename:azure-pipelines.yml stages",
            "filename:azure-pipelines.yml jobs",
            "filename:azure-pipelines.yml resources",
            "filename:azure-pipelines.yml pool",
            "filename:azure-pipelines.yml variables",
            "filename:azure-pipelines.yaml trigger",
            "filename:azure-pipelines.yaml stages",
            "filename:azure-pipelines.yml vmImage",
            "filename:azure-pipelines.yml task",
            "filename:azure-pipelines.yml script",
            "filename:azure-pipelines.yml checkout",
            "filename:azure-pipelines.yml displayName",
            "filename:azure-pipelines.yml condition",
            "filename:azure-pipelines.yml dependsOn",
            "filename:azure-pipelines.yml template",
            "filename:azure-pipelines.yml extends",
            "filename:azure-pipelines.yml deployment",
            "filename:azure-pipelines.yml environment",
            "filename:azure-pipelines.yaml vmImage",
            "filename:azure-pipelines.yaml task",
            "filename:azure-pipelines.yaml script",
            "filename:azure-pipelines.yaml template",
            "filename:azure-pipelines.yaml deployment",
        ]
    if platform == "bb":
        base = [
            "filename:bitbucket-pipelines.yml",
            "filename:bitbucket-pipelines.yaml",
            "filename:bitbucket-pipelines.yml.example",
            "filename:bitbucket-pipelines.yml.sample",
            "filename:bitbucket-pipelines.yml.template",
            "filename:bitbucket-pipelines.yml.j2",
            "filename:bitbucket-pipelines.yml.liquid",
            "filename:bitbucket-pipelines.yml.bak",
            "filename:bitbucket-pipelines.yml.backup",
            "filename:bitbucket-pipelines.yml pipelines",
            "filename:bitbucket-pipelines.yml definitions",
            "filename:bitbucket-pipelines.yml branches",
            "filename:bitbucket-pipelines.yml pull-requests",
            "filename:bitbucket-pipelines.yml caches",
            "filename:bitbucket-pipelines.yml docker",
            "filename:bitbucket-pipelines.yml deployment",
            "filename:bitbucket-pipelines.yml step",
            "filename:bitbucket-pipelines.yml image",
        ]
        size_buckets = ["<5", "5..10", "10..20", "20..50", "50..100", "100..500", "500..2000"]
        suffixes = ["yml", "yaml", "yml.example", "yml.sample", "yml.template", "yml.j2", "yml.liquid", "yml.bak"]
        return [
            f"filename:bitbucket-pipelines.{suffix} size:{bucket}"
            for suffix in suffixes
            for bucket in size_buckets
        ] + base
    if platform == "gl":
        base = [
            "filename:.gitlab-ci.yml",
            "filename:.gitlab-ci.yml stages",
            "filename:.gitlab-ci.yml include",
            "filename:.gitlab-ci.yml variables",
            "filename:.gitlab-ci.yml image",
            "filename:.gitlab-ci.yml services",
            "filename:.gitlab-ci.yml workflow",
            "filename:.gitlab-ci.yml artifacts",
            "filename:.gitlab-ci.yml deploy",
            "filename:.gitlab-ci.yml test",
            "filename:.gitlab-ci.yml docker",
            "filename:.gitlab-ci.yml kubernetes",
        ]
        size_buckets = ["<5", "5..10", "10..20", "20..50", "50..100", "100..500", "500..2000"]
        return [f"filename:.gitlab-ci.yml size:{bucket}" for bucket in size_buckets] + base
    raise ValueError(platform)


def gha_repo_queries() -> list[str]:
    # Repository search is a much higher-yield GHA source than code search:
    # one tree listing can produce many workflow files from the default branch.
    return [
        "stars:>500 archived:false",
        "stars:100..500 archived:false language:Rust",
        "stars:100..500 archived:false language:Go",
        "stars:100..500 archived:false language:Python",
        "stars:100..500 archived:false language:JavaScript",
        "stars:100..500 archived:false language:TypeScript",
        "stars:100..500 archived:false language:Java",
        "stars:100..500 archived:false language:C++",
        "stars:100..500 archived:false language:C#",
        "stars:100..500 archived:false language:PHP",
        "stars:50..100 archived:false language:Rust",
        "stars:50..100 archived:false language:Go",
        "stars:50..100 archived:false language:Python",
        "stars:50..100 archived:false language:JavaScript",
        "stars:50..100 archived:false language:TypeScript",
    ]


def harvest_gha_repo_trees(root: Path, manifest: Path, target: int, max_pages: int) -> int:
    seen_hashes, counts = load_existing(root)
    seen_urls = load_manifest_urls(manifest)
    pdir = root / "gha"
    pdir.mkdir(parents=True, exist_ok=True)
    accepted = counts["gha"]
    if accepted >= target:
        return accepted

    seen_repos: set[str] = set()
    for query in gha_repo_queries():
        if accepted >= target:
            break
        print(f"repo-search[gha]: {query}", file=sys.stderr, flush=True)
        for repo_item in repo_search(query, max_pages=max_pages):
            if accepted >= target:
                break
            repo = repo_item.get("full_name")
            default_branch = repo_item.get("default_branch") or "HEAD"
            if not repo or repo in seen_repos:
                continue
            seen_repos.add(repo)
            tree = gh_json(f"/repos/{repo}/contents/.github/workflows?ref={urllib.parse.quote(default_branch, safe='')}")
            if not isinstance(tree, list):
                continue
            for entry in tree:
                if accepted >= target:
                    break
                if entry.get("type") != "file":
                    continue
                path = entry.get("path") or ""
                if not path.endswith((".yml", ".yaml")):
                    continue
                raw_url = entry.get("download_url")
                html_url = entry.get("html_url")
                if not raw_url or not html_url or html_url in seen_urls:
                    continue
                data = fetch_url(raw_url)
                if data is None or not platform_accepts("gha", path, data):
                    continue
                digest = hashlib.sha256(data).hexdigest()
                if digest in seen_hashes:
                    continue
                seen_hashes.add(digest)
                seen_urls.add(html_url)
                out = pdir / safe_name(repo, path, digest)
                out.write_bytes(data)
                accepted += 1
                append_manifest(
                    manifest,
                    {
                        "platform": "gha",
                        "repo": repo,
                        "path": path,
                        "html_url": html_url,
                        "raw_url": raw_url,
                        "sha256": digest,
                        "bytes": len(data),
                        "local_path": str(out),
                        "source": "github_repo_tree",
                        "fetched_at": now_iso(),
                    },
                )
                if accepted % 100 == 0 or accepted == target:
                    print(f"accepted[gha]={accepted}/{target}", file=sys.stderr, flush=True)
    return accepted


def candidates_for(platform: str, seen_urls: set[str], max_pages: int) -> Iterable[Candidate]:
    for query in queries_for(platform):
        print(f"search[{platform}]: {query}", file=sys.stderr, flush=True)
        for item in code_search(query, max_pages=max_pages):
            html_url = item.get("html_url")
            repo = item.get("repository", {}).get("full_name")
            path = item.get("path")
            if not html_url or not repo or not path or html_url in seen_urls:
                continue
            seen_urls.add(html_url)
            yield Candidate(platform=platform, repo=repo, path=path, html_url=html_url)


def harvest_platform(root: Path, manifest: Path, platform: str, target: int, max_pages: int) -> int:
    seen_hashes, counts = load_existing(root)
    seen_urls = load_manifest_urls(manifest)
    pdir = root / platform
    pdir.mkdir(parents=True, exist_ok=True)
    accepted = counts[platform]
    if accepted >= target:
        return accepted

    for cand in candidates_for(platform, seen_urls, max_pages=max_pages):
        if accepted >= target:
            break
        raw_url = raw_url_from_html(cand.html_url)
        if not raw_url:
            continue
        data = fetch_url(raw_url)
        if data is None or not platform_accepts(platform, cand.path, data):
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)
        filename = safe_name(cand.repo, cand.path, digest)
        out = pdir / filename
        if out.exists():
            continue
        out.write_bytes(data)
        accepted += 1
        append_manifest(
            manifest,
            {
                "platform": platform,
                "repo": cand.repo,
                "path": cand.path,
                "html_url": cand.html_url,
                "raw_url": raw_url,
                "sha256": digest,
                "bytes": len(data),
                "local_path": str(out),
                "fetched_at": now_iso(),
            },
        )
        if accepted % 100 == 0 or accepted == target:
            print(f"accepted[{platform}]={accepted}/{target}", file=sys.stderr, flush=True)
    return accepted


def harvest_gitlab_public_projects(
    root: Path,
    manifest: Path,
    target: int,
    provider_pages: int,
    start_page: int,
    jobs: int,
) -> int:
    seen_hashes, counts = load_existing(root)
    seen_urls = load_manifest_urls(manifest)
    pdir = root / "gl"
    pdir.mkdir(parents=True, exist_ok=True)
    accepted = counts["gl"]
    if accepted >= target:
        return accepted

    def candidate_from_project(project: dict) -> dict | None:
        project_id = project.get("id")
        repo = project.get("path_with_namespace")
        branch = project.get("default_branch") or "main"
        web_url = project.get("web_url")
        if not project_id or not repo or not web_url:
            return None
        html_url = f"{web_url}/-/blob/{urllib.parse.quote(branch, safe='')}/.gitlab-ci.yml"
        raw_url = (
            f"https://gitlab.com/api/v4/projects/{project_id}/repository/files/"
            f"{urllib.parse.quote('.gitlab-ci.yml', safe='')}/raw?ref={urllib.parse.quote(branch, safe='')}"
        )
        data = fetch_url(raw_url, timeout=8)
        if data is None or not platform_accepts("gl", ".gitlab-ci.yml", data):
            return None
        return {
            "repo": repo,
            "html_url": html_url,
            "raw_url": raw_url,
            "data": data,
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    for page in range(start_page, provider_pages + 1):
        if accepted >= target:
            break
        url = (
            "https://gitlab.com/api/v4/projects?"
            f"visibility=public&simple=true&archived=false&order_by=last_activity_at&sort=desc&per_page=100&page={page}"
        )
        projects = fetch_json_url(url)
        if not isinstance(projects, list) or not projects:
            break
        print(f"provider-search[gl]: page={page}", file=sys.stderr, flush=True)
        project_batch = [
            p for p in projects
            if isinstance(p, dict)
            and p.get("web_url")
            and f"{p.get('web_url')}/-/blob/{urllib.parse.quote(p.get('default_branch') or 'main', safe='')}/.gitlab-ci.yml" not in seen_urls
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            futures = [pool.submit(candidate_from_project, project) for project in project_batch]
            candidates = [f.result() for f in concurrent.futures.as_completed(futures)]
        for cand in candidates:
            if accepted >= target:
                break
            if not cand:
                continue
            repo = cand["repo"]
            html_url = cand["html_url"]
            if html_url in seen_urls:
                continue
            data = cand["data"]
            digest = cand["sha256"]
            if digest in seen_hashes:
                continue
            seen_hashes.add(digest)
            seen_urls.add(html_url)
            out = pdir / safe_name(repo, ".gitlab-ci.yml", digest)
            out.write_bytes(data)
            accepted += 1
            append_manifest(
                manifest,
                {
                    "platform": "gl",
                    "repo": repo,
                    "path": ".gitlab-ci.yml",
                    "html_url": html_url,
                    "raw_url": cand["raw_url"],
                    "sha256": digest,
                    "bytes": len(data),
                    "local_path": str(out),
                    "source": "gitlab_public_projects",
                    "fetched_at": now_iso(),
                },
            )
            if accepted % 100 == 0 or accepted == target:
                print(f"accepted[gl]={accepted}/{target}", file=sys.stderr, flush=True)
    return accepted


def harvest_bitbucket_public_projects(root: Path, manifest: Path, target: int, provider_pages: int) -> int:
    seen_hashes, counts = load_existing(root)
    seen_urls = load_manifest_urls(manifest)
    pdir = root / "bb"
    pdir.mkdir(parents=True, exist_ok=True)
    accepted = counts["bb"]
    if accepted >= target:
        return accepted

    next_url: str | None = "https://api.bitbucket.org/2.0/repositories?pagelen=100&sort=-updated_on"
    for page in range(1, provider_pages + 1):
        if accepted >= target or not next_url:
            break
        data_obj = fetch_json_url(next_url)
        if not isinstance(data_obj, dict):
            break
        repos = data_obj.get("values")
        if not isinstance(repos, list) or not repos:
            break
        print(f"provider-search[bb]: page={page}", file=sys.stderr, flush=True)
        for repo_obj in repos:
            if accepted >= target:
                break
            if not isinstance(repo_obj, dict):
                continue
            full_name = repo_obj.get("full_name")
            mainbranch = repo_obj.get("mainbranch")
            branch = mainbranch.get("name") if isinstance(mainbranch, dict) else None
            branch = branch or "master"
            links = repo_obj.get("links")
            html_link = links.get("html") if isinstance(links, dict) else None
            html_base = html_link.get("href") if isinstance(html_link, dict) else None
            if not full_name or "/" not in full_name or not html_base:
                continue
            workspace, repo_slug = full_name.split("/", 1)
            branches = []
            for b in [branch, "master", "main", "develop"]:
                if b and b not in branches:
                    branches.append(b)
            for branch_name in branches:
                if accepted >= target:
                    break
                tree_url = (
                    "https://api.bitbucket.org/2.0/repositories/"
                    f"{urllib.parse.quote(workspace, safe='')}/{urllib.parse.quote(repo_slug, safe='')}/"
                    f"src/{urllib.parse.quote(branch_name, safe='')}/?pagelen=100"
                )
                tree = fetch_json_url(tree_url, timeout=8)
                paths = ["bitbucket-pipelines.yml", "bitbucket-pipelines.yaml"]
                if isinstance(tree, dict):
                    values = tree.get("values")
                    if isinstance(values, list):
                        discovered = []
                        for entry in values:
                            if not isinstance(entry, dict):
                                continue
                            path_name = entry.get("path")
                            if isinstance(path_name, str) and Path(path_name.lower()).name.startswith("bitbucket-pipelines.y"):
                                discovered.append(path_name)
                        paths = discovered or paths
                for path in paths:
                    if accepted >= target:
                        break
                    html_url = f"{html_base}/src/{urllib.parse.quote(branch_name, safe='')}/{path}"
                    if html_url in seen_urls:
                        continue
                    raw_url = (
                        "https://api.bitbucket.org/2.0/repositories/"
                        f"{urllib.parse.quote(workspace, safe='')}/{urllib.parse.quote(repo_slug, safe='')}/"
                        f"src/{urllib.parse.quote(branch_name, safe='')}/{urllib.parse.quote(path, safe='/')}"
                    )
                    data = fetch_url(raw_url, timeout=8)
                    if data is None or not platform_accepts("bb", path, data):
                        continue
                    digest = hashlib.sha256(data).hexdigest()
                    if digest in seen_hashes:
                        continue
                    seen_hashes.add(digest)
                    seen_urls.add(html_url)
                    out = pdir / safe_name(full_name, path, digest)
                    out.write_bytes(data)
                    accepted += 1
                    append_manifest(
                        manifest,
                        {
                            "platform": "bb",
                            "repo": full_name,
                            "path": path,
                            "html_url": html_url,
                            "raw_url": raw_url,
                            "sha256": digest,
                            "bytes": len(data),
                            "local_path": str(out),
                            "source": "bitbucket_public_projects",
                            "fetched_at": now_iso(),
                        },
                    )
                    if accepted % 100 == 0 or accepted == target:
                        print(f"accepted[bb]={accepted}/{target}", file=sys.stderr, flush=True)
        next_url = data_obj.get("next") if isinstance(data_obj.get("next"), str) else None
    return accepted


def seed_existing_platform(root: Path, manifest: Path, platform: str, source_dir: Path, target: int) -> int:
    """Copy unique local corpus files into the testbed as a starting point."""
    seen_hashes, counts = load_existing(root)
    accepted = counts[platform]
    if not source_dir.exists() or accepted >= target:
        return accepted
    pdir = root / platform
    pdir.mkdir(parents=True, exist_ok=True)
    for src in sorted(source_dir.glob("*.y*ml")):
        if accepted >= target:
            break
        data = src.read_bytes()
        if not platform_accepts(platform, src.name, data):
            # Existing local corpus names do not include the original
            # .github/workflows path, so GHA needs a content-only fallback.
            if not (
                platform == "gha"
                and textish(data)
                and re.search(r"(?m)^['\"]?on['\"]?\s*:", data.decode("utf-8", errors="replace"))
                and re.search(r"(?m)^jobs\s*:", data.decode("utf-8", errors="replace"))
            ):
                continue
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen_hashes:
            continue
        seen_hashes.add(digest)
        out = pdir / safe_name("local-corpus", src.name, digest)
        out.write_bytes(data)
        accepted += 1
        append_manifest(
            manifest,
            {
                "platform": platform,
                "repo": None,
                "path": str(src),
                "html_url": None,
                "raw_url": None,
                "sha256": digest,
                "bytes": len(data),
                "local_path": str(out),
                "source": "existing_local_corpus",
                "fetched_at": now_iso(),
            },
        )
    return accepted


def write_summary(root: Path, manifest: Path) -> None:
    seen, counts = load_existing(root)
    by_platform_hashes: dict[str, set[str]] = {p: set() for p in PLATFORMS}
    duplicate_files = 0
    all_hashes: set[str] = set()
    for platform in PLATFORMS:
        for path in (root / platform).glob("*.y*ml"):
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest in all_hashes:
                duplicate_files += 1
            all_hashes.add(digest)
            by_platform_hashes[platform].add(digest)
    summary = {
        "updated_at": now_iso(),
        "root": str(root),
        "manifest": str(manifest),
        "counts": {p: len(by_platform_hashes[p]) for p in PLATFORMS},
        "global_unique_hashes": len(all_hashes),
        "duplicate_files": duplicate_files,
    }
    (root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--target", type=int, default=5000)
    parser.add_argument("--platform", choices=PLATFORMS, action="append")
    parser.add_argument("--max-pages", type=int, default=10, help="GitHub search pages per query")
    parser.add_argument("--provider-pages", type=int, default=100, help="provider fallback pages for GitLab/Bitbucket")
    parser.add_argument("--provider-start-page", type=int, default=1, help="first provider fallback page to scan")
    parser.add_argument("--provider-jobs", type=int, default=8, help="provider fallback concurrent fetches")
    parser.add_argument(
        "--seed-existing",
        action="store_true",
        help="seed testbed from existing corpus/<platform> files before downloading",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root: Path = args.root
    root.mkdir(parents=True, exist_ok=True)
    manifest = root / "manifest.jsonl"

    platforms = args.platform or list(PLATFORMS)
    for platform in platforms:
        if args.seed_existing:
            seeded = seed_existing_platform(root, manifest, platform, Path("corpus") / platform, args.target)
            print(f"{platform}: seeded {seeded}/{args.target}", flush=True)
            write_summary(root, manifest)
        if platform == "gha":
            count = harvest_gha_repo_trees(root, manifest, args.target, args.max_pages)
            print(f"{platform}: repo-tree {count}/{args.target}", flush=True)
            write_summary(root, manifest)
            if count >= args.target:
                continue
        count = harvest_platform(root, manifest, platform, args.target, args.max_pages)
        print(f"{platform}: {count}/{args.target}", flush=True)
        write_summary(root, manifest)
        if platform == "gl" and count < args.target:
            count = harvest_gitlab_public_projects(
                root,
                manifest,
                args.target,
                args.provider_pages,
                args.provider_start_page,
                args.provider_jobs,
            )
            print(f"{platform}: provider {count}/{args.target}", flush=True)
            write_summary(root, manifest)
        if platform == "bb" and count < args.target:
            count = harvest_bitbucket_public_projects(root, manifest, args.target, args.provider_pages)
            print(f"{platform}: provider {count}/{args.target}", flush=True)
            write_summary(root, manifest)
    write_summary(root, manifest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
