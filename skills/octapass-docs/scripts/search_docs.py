#!/usr/bin/env python3
"""Search the Octa Pass documentation, locally (repo checkout) or remotely (website).

Zero dependencies (Python 3.9+ standard library only).

  python3 search_docs.py "account recovery"          # search; local docs if found, else the website
  python3 search_docs.py --remote "passkeys android" # force the website
  python3 search_docs.py --page security/encryption  # print one full page
  python3 search_docs.py --list                      # list every page with its status

Results show page title, section, status, URL and a snippet. Read the full page with --page before answering.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import re
import sys
import time
import urllib.request
from pathlib import Path

DEFAULT_BASE_URL = "https://vault.octap.app"
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "octapass-docs"
CACHE_TTL_SECONDS = 24 * 3600
STOPWORDS = set(
    "a an and are as at be by can do does for from how i if in into is it of on or so that the this to what when "
    "where which who why will with you your".split()
)


class Page:
    def __init__(self, slug: str, title: str, description: str, status: str, body: str, url: str):
        self.slug, self.title, self.description, self.status, self.body, self.url = slug, title, description, status, body, url


# ---------- loading ----------

def parse_front_matter(text: str) -> tuple[dict, str]:
    match = re.match(r"^---\n(.*?)\n---\n?", text, re.S)
    if not match:
        return {}, text
    data = {}
    for line in match.group(1).splitlines():
        m = re.match(r"^(\w[\w-]*):\s*(.*)$", line)
        if m and m.group(2):
            data[m.group(1)] = m.group(2).strip().strip("'\"")
    return data, text[match.end():]


def find_local_docs(explicit: str | None) -> Path | None:
    if explicit:
        path = Path(explicit).expanduser().resolve()
        return path if path.is_dir() else None
    starts = [Path.cwd(), Path(__file__).resolve().parent]
    for start in starts:
        for directory in [start, *start.parents]:
            candidate = directory / "docs"
            if (candidate / "index.md").is_file() and (directory / "skills" / "octapass-docs").is_dir():
                return candidate
    return None


def load_local(docs_dir: Path, base_url: str) -> list[Page]:
    pages = []
    for file in sorted(docs_dir.rglob("*.md*")):
        # Translations live in docs/<language>/; this searches the English pages.
        if file.name.startswith("_") or file.relative_to(docs_dir).parts[0] == "ar":
            continue
        meta, body = parse_front_matter(file.read_text(encoding="utf-8"))
        slug = re.sub(r"(^|/)index$", "", file.relative_to(docs_dir).with_suffix("").as_posix())
        url = f"{base_url}/docs/{slug}/" if slug else f"{base_url}/docs/"
        pages.append(Page(slug, meta.get("title", slug), meta.get("description", ""), meta.get("status", "planned"), body, url))
    return pages


def fetch(url: str) -> str:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cached = CACHE_DIR / hashlib.sha256(url.encode()).hexdigest()
    if cached.exists() and time.time() - cached.stat().st_mtime < CACHE_TTL_SECONDS:
        return cached.read_text(encoding="utf-8")
    request = urllib.request.Request(url, headers={"User-Agent": "octapass-docs-skill/1.0"})
    with urllib.request.urlopen(request, timeout=20) as response:
        text = response.read().decode("utf-8")
    cached.write_text(text, encoding="utf-8")
    return text


def load_remote(base_url: str) -> list[Page]:
    index = fetch(f"{base_url}/llms.txt")
    links = re.findall(r"^- \[([^\]]+)\]\((\S+?\.md)\):\s*(.*?)(?:\s*\(status: ([\w-]+)\))?$", index, re.M)
    links = [link for link in links if link[1].startswith(base_url)]
    if not links:
        sys.exit(f"No page index found in {base_url}/llms.txt")

    def build(link):
        title, md_url, description, status = link
        text = fetch(md_url)
        path = md_url[len(base_url):].removesuffix(".md")  # /docs/security/encryption or /docs
        slug = path.removeprefix("/docs").strip("/")
        body = re.sub(r"^# .*?\n\n> .*?\n\n(?:Source|Status|Project):.*?\n\n", "", text, count=1, flags=re.S)
        return Page(slug, title, description, status or "planned", body, f"{base_url}{path}/")

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        return list(pool.map(build, links))


# ---------- search ----------

def tokenize(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9][a-z0-9\-]*", text.lower()) if t not in STOPWORDS and len(t) > 1]


def anchor(heading: str) -> str:
    slug = re.sub(r"[^\w\- ]", "", heading.lower()).strip()
    return re.sub(r"\s", "-", slug)


def sections(page: Page) -> list[tuple[str, str]]:
    """Split a page into (heading, text) sections on ## / ### headings outside code fences."""
    result, heading, buffer, fenced = [], "", [], False
    for line in page.body.splitlines():
        if line.lstrip().startswith("```"):
            fenced = not fenced
        m = None if fenced else re.match(r"^#{2,3}\s+(.*)", line)
        if m:
            result.append((heading, "\n".join(buffer)))
            heading, buffer = m.group(1).strip(), []
        else:
            buffer.append(line)
    result.append((heading, "\n".join(buffer)))
    return [(h, t) for h, t in result if t.strip() or h]


def search(pages: list[Page], query: str, limit: int) -> list[dict]:
    terms = tokenize(query)
    if not terms:
        return []
    docs = []
    for page in pages:
        for heading, text in sections(page):
            docs.append((page, heading, text, tokenize(f"{heading} {text}")))
    avg_len = sum(len(d[3]) for d in docs) / max(len(docs), 1)
    df = {t: sum(1 for d in docs if t in d[3]) for t in terms}
    scored = []
    for page, heading, text, tokens in docs:
        score = 0.0
        for term in terms:
            tf = tokens.count(term)
            if not tf:
                continue
            idf = math.log(1 + (len(docs) - df[term] + 0.5) / (df[term] + 0.5))
            score += idf * tf * 2.2 / (tf + 1.2 * (0.25 + 0.75 * len(tokens) / avg_len))
        title_tokens = set(tokenize(f"{page.title} {page.description} {heading}"))
        score += sum(1.5 for t in terms if t in title_tokens)
        if query.lower() in text.lower():
            score += 3
        if score > 0:
            scored.append((score, page, heading, text))
    scored.sort(key=lambda s: s[0], reverse=True)

    results = []
    for score, page, heading, text in scored[:limit]:
        lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith(("```", ":::"))]
        best = sorted(lines, key=lambda l: -sum(t in l.lower() for t in terms))[:3]
        results.append({
            "title": page.title,
            "section": heading or None,
            "status": page.status,
            "url": page.url + (f"#{anchor(heading)}" if heading else ""),
            "page": page.slug or "index",
            "score": round(score, 2),
            "snippet": " … ".join(l[:220] for l in best),
        })
    return results


def find_page(pages: list[Page], wanted: str) -> Page | None:
    """The page with this slug, as `security/encryption`, `/docs/security/encryption.md` or `index`."""
    wanted = wanted.strip("/").removeprefix("docs/").removesuffix(".md").strip("/")
    wanted = "" if wanted in ("index", "docs") else wanted
    return next((p for p in pages if p.slug == wanted), None)


def similar_pages(pages: list[Page], wanted: str) -> list[str]:
    last = wanted.strip("/").removesuffix(".md").split("/")[-1]
    return [p.slug for p in pages if last and last in p.slug]


def format_page(page: Page) -> str:
    return f"# {page.title}\n\nURL: {page.url}\nStatus: {page.status}\n\n{page.body.strip()}"


# ---------- cli ----------

def main() -> None:
    parser = argparse.ArgumentParser(description="Search the Octa Pass docs.")
    parser.add_argument("query", nargs="*", help="search terms")
    parser.add_argument("--remote", action="store_true", help="search the website instead of a local checkout")
    parser.add_argument("--docs-dir", help="path to a local docs/ folder")
    parser.add_argument("--base-url", default=os.environ.get("OCTAPASS_DOCS_URL", DEFAULT_BASE_URL))
    parser.add_argument("--page", help="print one page in full, e.g. security/encryption")
    parser.add_argument("--list", action="store_true", help="list all pages")
    parser.add_argument("-n", "--limit", type=int, default=6)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")

    docs_dir = None if args.remote else find_local_docs(args.docs_dir)
    pages = load_local(docs_dir, base_url) if docs_dir else load_remote(base_url)
    source = str(docs_dir) if docs_dir else f"{base_url}/llms.txt"

    if args.list:
        for p in sorted(pages, key=lambda p: p.slug):
            print(f"{p.slug or 'index':45} [{p.status}] {p.title}: {p.description}")
        return

    if args.page:
        match = find_page(pages, args.page)
        if not match:
            close = similar_pages(pages, args.page)
            sys.exit(f"No page '{args.page}'. Similar: {', '.join(close) or 'none'} (use --list)")
        print(format_page(match))
        return

    query = " ".join(args.query)
    if not query:
        parser.error("give a query, --page or --list")
    results = search(pages, query, args.limit)
    if args.json:
        print(json.dumps({"source": source, "query": query, "results": results}, indent=2))
        return
    print(f"Source: {source}\n")
    if not results:
        print("No matches. Try other words, or --list to browse pages.")
    for i, r in enumerate(results, 1):
        section = f" › {r['section']}" if r["section"] else ""
        print(f"{i}. {r['title']}{section}  [{r['status']}]\n   {r['url']}\n   page: {r['page']}\n   {r['snippet']}\n")


if __name__ == "__main__":
    main()
