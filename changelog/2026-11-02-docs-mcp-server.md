---
title: The docs as an MCP server
date: 2026-11-02
summary: AI tools that speak the Model Context Protocol can now search and read the Octa Pass docs through a small local server.
tags: [docs]
---

`octapass-docs-mcp` is one Python file with no dependencies. It runs on your computer over stdio and gives MCP clients `search_docs`, `get_page` and `list_pages`, on the same search as the [octapass-docs skill](/docs/contributing/ai-agents/). It only reads, and no search query leaves your computer.
