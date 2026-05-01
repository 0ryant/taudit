#!/usr/bin/env python3
"""
Sample public GitHub workflows that contain `pull_request_target` and run `taudit scan` on each.

Designed for the "1% scan" style study: GitHub code search returns at most 1,000 hits per query;
use `--limit` to cap runtime. Requires `GITHUB_TOKEN` or `gh auth token` for API access.

Usage:
  export GITHUB_TOKEN=$(gh auth token)   # optional if gh is logged in
  ./scripts/research/prt_repo_sample_scan.py --limit 50 --json-out /tmp/prt-scan.json

Does not clone repos — fetches workflow YAML via the Contents API (raw).
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Row:
    repo: str
    path: str
    ok_fetch: bool
    taudit_ok: bool
    findings: int
    critical: int
    high: int
    error: str | None


def _token() -> str:
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        return tok.strip()
    try:
        out = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        return out.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return ""


def _github_get_json(url: str, token: str) -> dict:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "taudit-prt-research-script",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode())


def _github_get_raw(url: str, token: str) -> bytes:
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.raw",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "taudit-prt-research-script",
        },
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def _fetch_workflow(token: str, full_name: str, path: str) -> tuple[bool, bytes, str | None]:
    """Return (ok, raw_bytes, error_message)."""
    enc_path = urllib.parse.quote(path, safe="/")
    meta_url = f"https://api.github.com/repos/{full_name}/contents/{enc_path}"
    try:
        meta = _github_get_json(meta_url, token)
    except urllib.error.HTTPError as e:
        return False, b"", f"contents meta HTTP {e.code}"
    except Exception as e:  # noqa: BLE001 — research script
        return False, b"", str(e)

    if meta.get("type") != "file":
        return False, b"", "not a file"
    dl = meta.get("download_url")
    if dl:
        try:
            return True, _github_get_raw(dl, token), None
        except Exception as e:  # noqa: BLE001
            return False, b"", f"download_url: {e}"
    # fallback: base64 content in JSON
    b64 = meta.get("content")
    if not b64:
        return False, b"", "no download_url or content"
    try:
        raw = base64.b64decode(b64.replace("\n", ""))
        return True, raw, None
    except Exception as e:  # noqa: BLE001
        return False, b"", f"base64: {e}"


def _run_taudit(taudit_bin: Path, yaml_path: Path) -> tuple[bool, int, int, int, str | None]:
    try:
        out = subprocess.run(
            [str(taudit_bin), "scan", str(yaml_path), "--format", "json"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if out.returncode != 0:
            return False, 0, 0, 0, (out.stderr or out.stdout or "taudit non-zero")[:500]
        data = json.loads(out.stdout)
        summ = data.get("summary") or {}
        return (
            True,
            int(summ.get("total_findings") or 0),
            int(summ.get("critical") or 0),
            int(summ.get("high") or 0),
            None,
        )
    except Exception as e:  # noqa: BLE001
        return False, 0, 0, 0, str(e)[:500]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--limit", type=int, default=50, help="Max workflows to scan (default 50)")
    p.add_argument(
        "--taudit",
        type=Path,
        default=None,
        help="Path to taudit binary (default: target/debug/taudit or taudit on PATH)",
    )
    p.add_argument("--json-out", type=Path, default=None, help="Write full results JSON here")
    args = p.parse_args()

    token = _token()
    if not token:
        print("error: set GITHUB_TOKEN or run `gh auth login`", file=sys.stderr)
        return 2

    taudit_bin = args.taudit
    if taudit_bin is None:
        root = Path(__file__).resolve().parents[2]
        cand = root / "target" / "debug" / "taudit"
        taudit_bin = cand if cand.is_file() else Path(shutil.which("taudit") or "taudit")

    rows: list[Row] = []
    seen: set[tuple[str, str]] = set()
    per_page = min(100, args.limit)
    page = 1

    while len(rows) < args.limit:
        q = urllib.parse.quote("pull_request_target path:.github/workflows extension:yml")
        url = f"https://api.github.com/search/code?q={q}&per_page={per_page}&page={page}"
        try:
            payload = _github_get_json(url, token)
        except urllib.error.HTTPError as e:
            if e.code == 403:
                body = e.read().decode(errors="replace")[:800]
                print(f"GitHub API 403 (rate limit or search unavailable): {body}", file=sys.stderr)
                return 1
            raise
        items = payload.get("items") or []
        if not items:
            break
        for it in items:
            if len(rows) >= args.limit:
                break
            repo = it.get("repository") or {}
            full_name = repo.get("full_name") or ""
            path = it.get("path") or ""
            key = (full_name, path)
            if not full_name or not path or key in seen:
                continue
            seen.add(key)

            ok_f, raw, err = _fetch_workflow(token, full_name, path)
            if not ok_f:
                rows.append(
                    Row(
                        repo=full_name,
                        path=path,
                        ok_fetch=False,
                        taudit_ok=False,
                        findings=0,
                        critical=0,
                        high=0,
                        error=err or "fetch failed",
                    )
                )
                time.sleep(0.15)
                continue

            with tempfile.NamedTemporaryFile(
                suffix=".yml", delete=False, mode="wb"
            ) as tmp:
                tmp.write(raw)
                tmp_path = Path(tmp.name)
            try:
                tok, n, c, h, terr = _run_taudit(taudit_bin, tmp_path)
                rows.append(
                    Row(
                        repo=full_name,
                        path=path,
                        ok_fetch=True,
                        taudit_ok=tok,
                        findings=n,
                        critical=c,
                        high=h,
                        error=terr,
                    )
                )
            finally:
                tmp_path.unlink(missing_ok=True)

            time.sleep(0.12)

        if len(items) < per_page:
            break
        page += 1
        if page > 10:
            break

    fetched = [r for r in rows if r.ok_fetch]
    scanned = [r for r in rows if r.ok_fetch and r.taudit_ok]
    flagged = [r for r in scanned if r.findings > 0]
    pct = 100.0 * len(flagged) / len(scanned) if scanned else 0.0

    print(f"sample_size: {len(rows)}")
    print(f"fetched_yaml: {len(fetched)}")
    print(f"taudit_json_ok: {len(scanned)}")
    print(f"repos_with_findings_gt_0: {len(flagged)}")
    print(f"pct_flagged_among_scanned: {pct:.1f}%")

    if args.json_out:
        out_obj = {
            "query": "pull_request_target path:.github/workflows extension:yml",
            "limit_requested": args.limit,
            "summary": {
                "sample_size": len(rows),
                "fetched_yaml": len(fetched),
                "taudit_json_ok": len(scanned),
                "repos_with_findings_gt_0": len(flagged),
                "pct_flagged_among_scanned": round(pct, 2),
            },
            "rows": [asdict(r) for r in rows],
        }
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(out_obj, indent=2), encoding="utf-8")
        print(f"wrote {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
