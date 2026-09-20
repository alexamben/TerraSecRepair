# -*- coding: utf-8 -*-
"""Fetch Terraform files from GitHub: repo URL (tarball), file URL, or local path.

Accepted sources:
  https://github.com/owner/repo                     -> every .tf in the default branch
  https://github.com/owner/repo/tree/main/tools     -> every .tf under tools/
  https://github.com/owner/repo/blob/main/vpc.tf    -> that single file
  https://raw.githubusercontent.com/owner/repo/main/vpc.tf
  owner/repo  ·  owner/repo@branch                  -> shorthand forms

Public repositories need no credentials; private ones use GITHUB_TOKEN / GH_TOKEN.
Repositories are downloaded from codeload as a tarball, so git is not required.
"""
import io
import os
import re
import tarfile

import requests

MAX_BYTES = 300 * 1024 * 1024   # repo tarball download cap
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_FILES = 1000                # stop collecting .tf files beyond this

_REPO = re.compile(r"^https?://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$", re.I)
_TREE = re.compile(r"^https?://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/tree/([^/]+)(/[^#?]+)?/?$", re.I)
_BLOB = re.compile(r"^https?://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/blob/([^/]+)/([^#?]+?)$", re.I)
_RAW = re.compile(r"^https?://raw\.githubusercontent\.com/([\w.-]+)/([\w.-]+?)/([^/]+)/([^#?]+?)$", re.I)
_SHORT = re.compile(r"^([\w.-]+)/([\w.-]+?)(?:@([\w.\-/]+))?$")


def is_github_source(s):
    s = (s or "").strip()
    return s.lower().startswith(("http://", "https://")) and (
        "github.com" in s.lower() or "raw.githubusercontent.com" in s.lower())


def parse_url(url):
    """-> (owner, repo, ref, subpath, single_file_path or None). ref defaults to HEAD."""
    url = url.strip()
    m = _BLOB.match(url) or _RAW.match(url)
    if m:
        return m.group(1), m.group(2), m.group(3), "", m.group(4)
    m = _TREE.match(url)
    if m:
        return m.group(1), m.group(2), m.group(3), (m.group(4) or "").strip("/"), None
    m = _REPO.match(url)
    if m:
        return m.group(1), m.group(2), "HEAD", "", None
    if not url.lower().startswith(("http://", "https://")):
        m = _SHORT.match(url)
        if m:
            return m.group(1), m.group(2), m.group(3) or "HEAD", "", None
    raise ValueError(f"not a recognisable GitHub URL: {url!r}")


def _headers():
    h = {}
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def fetch_repo(owner, repo, ref="HEAD", subpath=""):
    """Return [(repo-relative path, code), ...] for every .tf file in the tarball."""
    url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/{ref}"
    r = requests.get(url, headers=_headers(), stream=True, timeout=180)
    if r.status_code == 404:
        raise ValueError(f"repo/ref not found (or private without GITHUB_TOKEN): "
                         f"{owner}/{repo}@{ref}")
    r.raise_for_status()
    buf = io.BytesIO()
    got = 0
    for chunk in r.iter_content(64 * 1024):
        got += len(chunk)
        if got > MAX_BYTES:
            raise ValueError(f"tarball exceeds {MAX_BYTES // (1024 * 1024)} MB cap")
        buf.write(chunk)
    buf.seek(0)
    prefix = (subpath + "/") if subpath else ""
    out = []
    with tarfile.open(fileobj=buf, mode="r:gz") as tf:
        for m in tf:
            if not m.isfile() or not m.name.endswith((".tf", ".tfvars")):
                continue
            # codeload prefixes every member with "<repo>-<ref>/"
            parts = m.name.split("/", 1)
            rel = parts[1] if len(parts) == 2 else m.name
            if prefix and not rel.startswith(prefix):
                continue
            if m.size > MAX_FILE_BYTES:
                continue
            f = tf.extractfile(m)
            if f is None:
                continue
            out.append((rel, f.read().decode("utf-8", "replace")))
            if len(out) >= MAX_FILES:
                break
    if not out:
        raise ValueError(f"no .tf files in {owner}/{repo}@{ref}"
                         + (f" under {subpath}/" if subpath else ""))
    return out


def fetch_file(owner, repo, ref, path):
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    r = requests.get(url, headers=_headers(), timeout=120)
    if r.status_code == 404:
        raise ValueError(f"file not found (or private without GITHUB_TOKEN): {url}")
    r.raise_for_status()
    if len(r.content) > MAX_FILE_BYTES:
        raise ValueError("file exceeds 5 MB cap")
    return path, r.content.decode("utf-8", "replace")


def resolve(source):
    """Resolve a local .tf path or a GitHub URL into [(display name, code), ...]."""
    source = source.strip()
    if os.path.exists(source):
        with open(source, encoding="utf-8") as f:
            return [(source, f.read())]
    owner, repo, ref, sub, single = parse_url(source)
    if single:
        return [fetch_file(owner, repo, ref, single)]
    return fetch_repo(owner, repo, ref, sub)
