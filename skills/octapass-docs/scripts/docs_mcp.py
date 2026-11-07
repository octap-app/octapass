#!/usr/bin/env python3
"""octapass-docs-mcp: the Octa Pass docs as a Model Context Protocol server, over stdio.

Zero dependencies (Python 3.9+ standard library only). It's the search in search_docs.py with three
read-only tools: search_docs, get_page and list_pages.

  python3 docs_mcp.py                     # local docs if found, else the website
  python3 docs_mcp.py --remote            # force the website
  python3 docs_mcp.py --docs-dir PATH     # a docs/ folder
  python3 docs_mcp.py --base-url URL      # another website

Messages are one JSON-RPC 2.0 object per line. Only protocol messages go to stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import search_docs as docs  # noqa: E402

VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
MAX_MESSAGE = 1 << 20
MAX_LIMIT = 20
READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True}

TOOLS = [
    {
        "name": "search_docs",
        "description": "Search the Octa Pass documentation. Returns matching sections with title, status, URL, "
        "page and snippet. Read the whole page with get_page before answering, and tell the user when a "
        "page's status isn't stable.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "What to look for, in plain words"},
                "limit": {"type": "integer", "minimum": 1, "maximum": MAX_LIMIT, "description": "How many results (default 6)"},
            },
            "required": ["query"],
        },
        "annotations": READ_ONLY,
    },
    {
        "name": "get_page",
        "description": "One full Octa Pass docs page in Markdown, with its URL and status.",
        "inputSchema": {
            "type": "object",
            "properties": {"page": {"type": "string", "description": "The page, such as security/encryption"}},
            "required": ["page"],
        },
        "annotations": READ_ONLY,
    },
    {
        "name": "list_pages",
        "description": "Every Octa Pass docs page, with its status and description.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": READ_ONLY,
    },
]


class Unusable(Exception):
    """The request can't be run: the client gets the reason as a tool error."""


class Server:
    def __init__(self, docs_dir: Path | None, base_url: str):
        self.docs_dir, self.base_url = docs_dir, base_url
        self.remote_pages = None

    def pages(self) -> list:
        # Local files are read every time, so edits show up. Remote pages have their own cache.
        if self.docs_dir:
            return docs.load_local(self.docs_dir, self.base_url)
        if self.remote_pages is None:
            try:
                self.remote_pages = docs.load_remote(self.base_url)
            except (OSError, SystemExit, ValueError) as error:
                raise Unusable(f"The docs couldn't be loaded from {self.base_url}: {error}") from error
        return self.remote_pages

    def call(self, name: str, arguments: dict) -> str:
        if name == "search_docs":
            query = arguments.get("query")
            limit = arguments.get("limit", 6)
            if not isinstance(query, str) or not query.strip():
                raise Unusable("query must be some text.")
            if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_LIMIT:
                raise Unusable(f"limit must be a whole number from 1 to {MAX_LIMIT}.")
            return json.dumps({"query": query, "results": docs.search(self.pages(), query, limit)}, ensure_ascii=False, indent=2)
        if name == "get_page":
            wanted = arguments.get("page")
            if not isinstance(wanted, str):
                raise Unusable("page must be text, such as security/encryption.")
            pages = self.pages()
            page = docs.find_page(pages, wanted)
            if page is None:
                similar = ", ".join(docs.similar_pages(pages, wanted)) or "none"
                raise Unusable(f"No page '{wanted}'. Similar: {similar}. list_pages shows them all.")
            return docs.format_page(page)
        rows = [
            {"page": p.slug or "index", "title": p.title, "status": p.status, "description": p.description, "url": p.url}
            for p in sorted(self.pages(), key=lambda p: p.slug)
        ]
        return json.dumps(rows, ensure_ascii=False, indent=2)

    def handle(self, message: object) -> dict | None:
        if not isinstance(message, dict):
            return failure(None, -32600, "A message must be a JSON object.")
        method, request_id, params = message.get("method"), message.get("id"), message.get("params")
        if not isinstance(method, str):
            # A client's answer to a request: this server sends none.
            return None if "result" in message or "error" in message else failure(request_id, -32600, "There's no method.")
        if "id" not in message:
            return None  # A notification.
        params = params if isinstance(params, dict) else {}
        if method == "initialize":
            asked = params.get("protocolVersion")
            return success(request_id, {
                "protocolVersion": asked if asked in VERSIONS else VERSIONS[0],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "octapass-docs-mcp", "version": "1.0.0"},
                "instructions": "Answer from these docs only, cite the page URL, and say when a page's status isn't stable.",
            })
        if method == "ping":
            return success(request_id, {})
        if method == "tools/list":
            return success(request_id, {"tools": TOOLS})
        if method == "tools/call":
            name, arguments = params.get("name"), params.get("arguments", {})
            if name not in {tool["name"] for tool in TOOLS}:
                return failure(request_id, -32602, f"Unknown tool: {name}")
            if not isinstance(arguments, dict):
                return failure(request_id, -32602, "arguments must be an object.")
            try:
                return success(request_id, {"content": [{"type": "text", "text": self.call(name, arguments)}]})
            except Unusable as error:
                return success(request_id, {"content": [{"type": "text", "text": str(error)}], "isError": True})
        return failure(request_id, -32601, f"Unknown method: {method}")


def success(request_id: object, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def failure(request_id: object, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def serve(server: Server, reader, writer) -> None:
    while True:
        line = reader.readline(MAX_MESSAGE + 1)
        if not line:
            return
        if len(line) > MAX_MESSAGE:
            # Skip the rest of the line, or it would be read as more messages.
            while line and not line.endswith(b"\n"):
                line = reader.readline(MAX_MESSAGE)
            reply = failure(None, -32600, "That message is too long.")
        elif not line.strip():
            continue
        else:
            try:
                reply = server.handle(json.loads(line))
            except (ValueError, RecursionError):
                reply = failure(None, -32700, "That isn't valid JSON.")
        if reply is not None:
            writer.write(json.dumps(reply, ensure_ascii=False).encode("utf-8") + b"\n")
            writer.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="The Octa Pass docs as an MCP server, over stdio.")
    parser.add_argument("--remote", action="store_true", help="read the website instead of a local checkout")
    parser.add_argument("--docs-dir", help="path to a local docs/ folder")
    parser.add_argument("--base-url", default=os.environ.get("OCTAPASS_DOCS_URL", docs.DEFAULT_BASE_URL))
    args = parser.parse_args()
    docs_dir = None if args.remote else docs.find_local_docs(args.docs_dir)
    serve(Server(docs_dir, args.base_url.rstrip("/")), sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    main()
