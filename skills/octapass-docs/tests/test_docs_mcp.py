"""The MCP server as a client sees it: a real process, speaking JSON lines over stdio.

    python3 -m unittest discover -s skills/octapass-docs/tests
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SERVER = Path(__file__).resolve().parents[1] / "scripts" / "docs_mcp.py"
REPO_DOCS = Path(__file__).resolve().parents[3] / "docs"
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}}}


def call(tool, arguments, request_id=2):
    return {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": tool, "arguments": arguments}}


class DocsMcp(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.docs = Path(folder.name)
        (self.docs / "index.md").write_text("---\ntitle: Home\ndescription: Start\nstatus: stable\n---\nWelcome.\n", encoding="utf-8")
        (self.docs / "security").mkdir()
        (self.docs / "security" / "encryption.md").write_text(
            "---\ntitle: Encryption\ndescription: How items are encrypted\nstatus: beta\n---\nIntro.\n\n## Argon2id\n\nThe Secret Key and Argon2id make the unlock key.\n\n## Arabic\n\nالتشفير على جهازك.\n",
            encoding="utf-8",
        )
        (Path(folder.name).parent / "secret-outside-docs.md").unlink(missing_ok=True)

    def exchange(self, *messages, raw=b"", args=None):
        lines = b"".join(json.dumps(m).encode() + b"\n" for m in messages) + raw
        done = subprocess.run([sys.executable, str(SERVER), *(args or ["--docs-dir", str(self.docs)])], input=lines, capture_output=True, timeout=60, check=True)
        return [json.loads(line) for line in done.stdout.splitlines()]

    def text(self, reply):
        return reply["result"]["content"][0]["text"]

    def test_initialize_answers_with_the_clients_version(self):
        reply = self.exchange(INIT)[0]["result"]
        self.assertEqual(reply["protocolVersion"], "2025-03-26")
        self.assertEqual(reply["capabilities"], {"tools": {}})
        self.assertEqual(reply["serverInfo"]["name"], "octapass-docs-mcp")

    def test_an_unknown_version_gets_the_newest(self):
        message = {**INIT, "params": {"protocolVersion": "1999-01-01"}}
        self.assertEqual(self.exchange(message)[0]["result"]["protocolVersion"], "2025-06-18")

    def test_notifications_get_no_reply_and_ping_does(self):
        replies = self.exchange({"jsonrpc": "2.0", "method": "notifications/initialized"}, {"jsonrpc": "2.0", "id": 9, "method": "ping"})
        self.assertEqual(replies, [{"jsonrpc": "2.0", "id": 9, "result": {}}])

    def test_tools_are_listed_read_only(self):
        tools = self.exchange({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})[0]["result"]["tools"]
        self.assertEqual([t["name"] for t in tools], ["search_docs", "get_page", "list_pages"])
        self.assertTrue(all(t["annotations"]["readOnlyHint"] for t in tools))

    def test_search_finds_the_section(self):
        results = json.loads(self.text(self.exchange(call("search_docs", {"query": "secret key argon2id", "limit": 1}))[0]))["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["section"], "Argon2id")
        self.assertEqual(results[0]["page"], "security/encryption")
        self.assertEqual(results[0]["status"], "beta")

    def test_get_page_keeps_unicode(self):
        for page in ["security/encryption", "/docs/security/encryption.md"]:
            text = self.text(self.exchange(call("get_page", {"page": page}))[0])
            self.assertIn("Status: beta", text)
            self.assertIn("التشفير على جهازك", text)

    def test_get_page_index(self):
        self.assertIn("Welcome.", self.text(self.exchange(call("get_page", {"page": "index"}))[0]))

    def test_a_page_can_only_be_a_known_page(self):
        outside = self.docs.parent / "secret-outside-docs.md"
        outside.write_text("do not read", encoding="utf-8")
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        for page in ["../secret-outside-docs", "../../etc/passwd", str(outside)]:
            reply = self.exchange(call("get_page", {"page": page}))[0]["result"]
            self.assertTrue(reply["isError"], page)
            self.assertNotIn("do not read", reply["content"][0]["text"])

    def test_list_pages(self):
        rows = json.loads(self.text(self.exchange(call("list_pages", {}))[0]))
        self.assertEqual([r["page"] for r in rows], ["index", "security/encryption"])

    def test_bad_arguments_are_tool_errors(self):
        for arguments in [{}, {"query": "  "}, {"query": 1}, {"query": "a", "limit": 0}, {"query": "a", "limit": 99}, {"query": "a", "limit": True}]:
            reply = self.exchange(call("search_docs", arguments))[0]["result"]
            self.assertTrue(reply["isError"], arguments)

    def test_protocol_errors(self):
        replies = self.exchange(
            {"jsonrpc": "2.0", "id": 3, "method": "resources/list"},
            call("delete_everything", {}, 4),
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "list_pages", "arguments": "x"}},
            raw=b"not json\n[1,2]\n",
        )
        self.assertEqual([r["error"]["code"] for r in replies], [-32601, -32602, -32602, -32700, -32600])

    def test_an_oversized_message_is_one_error_and_the_server_goes_on(self):
        huge = b'{"x":"' + b"a" * (2 << 20) + b'"}\n'
        tail = json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"}).encode() + b"\n"
        replies = self.exchange(raw=huge + tail)
        self.assertEqual(len(replies), 2)
        self.assertEqual(replies[0]["error"]["code"], -32600)
        self.assertEqual(replies[1]["id"], 7)

    def test_the_repository_docs_load(self):
        reply = self.exchange(call("search_docs", {"query": "secret key"}), args=["--docs-dir", str(REPO_DOCS)])[0]
        self.assertTrue(json.loads(self.text(reply))["results"])

    def test_an_unreachable_site_is_a_tool_error(self):
        reply = self.exchange(call("list_pages", {}), args=["--remote", "--base-url", "http://127.0.0.1:9"])[0]["result"]
        self.assertTrue(reply["isError"])


if __name__ == "__main__":
    unittest.main()
