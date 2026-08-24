"""MCP server exposing the seven tool contracts of spec 5.4.

    python -m tools.server            # serve over stdio
    python -m tools.server --list     # print the tool schemas and exit

Why MCP matters here (spec 5.4): the *identical* interface must serve the local test
environment and the real company stack. If the agent talks to SQLite in testing and to a
different hand-written client in production, the evaluation stops predicting production
behaviour -- the transferability property Cleric identify as necessary for evaluation to mean
anything. The tool bodies live in tools/api.py; this file is only transport.

Every tool here is read-only. There is no mutation tool to expose, by construction (5.9.1).
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from ledger.ledger import Ledger
from tools.api import Tools, ToolContext, ToolError

#: JSON Schema for each tool, mirroring the signatures in spec 5.4.
TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "name": "changes_between",
        "description": (
            "What did any human do anywhere in this organisation between two timestamps? "
            "Spans every change source, not only version control. Over `limit`, returns "
            "grouped counts plus a handle -- never a silent truncation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "t0": {"type": "string", "description": "window start, ISO 8601"},
                "t1": {"type": "string", "description": "window end, ISO 8601"},
                "sources": {
                    "type": "array", "items": {"type": "string"},
                    "description": "git|iac|k8s|cloudtrail|flag|package|external",
                },
                "repos": {"type": "array", "items": {"type": "string"}},
                "teams": {"type": "array", "items": {"type": "string"}},
                "limit": {"type": "integer", "default": 200},
            },
            "required": ["t0", "t1"],
        },
    },
    {
        "name": "who_mentions",
        "description": (
            "Which files, in EVERY indexed repository, mention this literal? Hostnames, "
            "table names, queue names, environment-variable keys, ARNs, bucket names, "
            "secret names, feature-flag keys. Indexes config, IaC and docs, not only source. "
            "There is deliberately no repo filter: scoping to one repository defeats the "
            "purpose of a cross-repository index."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "literal": {"type": "string"},
                "kinds": {
                    "type": "array", "items": {"type": "string"},
                    "description": "code|config|iac|docs",
                },
                "limit": {"type": "integer", "default": 100},
            },
            "required": ["literal"],
        },
    },
    {
        "name": "owner_of",
        "description": "Team, on-call handle, Slack channel and escalation path for a "
                       "path, repository or service.",
        "inputSchema": {
            "type": "object",
            "properties": {"path_or_repo_or_service": {"type": "string"}},
            "required": ["path_or_repo_or_service"],
        },
    },
    {
        "name": "get_diff",
        "description": "Fetch the diff behind a ledger row, by change id. Bounded; a large "
                       "diff returns a handle.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "change_id": {"type": "string"},
                "max_lines": {"type": "integer", "default": 200},
            },
            "required": ["change_id"],
        },
    },
    {
        "name": "get_handle",
        "description": "Page through a payload a previous call had to withhold.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "handle": {"type": "string"},
                "offset": {"type": "integer", "default": 0},
                "limit": {"type": "integer", "default": 50},
            },
            "required": ["handle"],
        },
    },
]

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "hisev-resolver", "version": "1.0.0"}


class MCPServer:
    """Minimal MCP over stdio: initialize, tools/list, tools/call.

    Hand-rolled rather than pulled from an SDK so the wire format stays visible and the
    build keeps its "plain Python, SQLite and one model" starting stack (spec 0.2).
    """

    def __init__(self, tools: Tools):
        self.tools = tools

    def handle(self, req: dict) -> dict | None:
        method = req.get("method")
        rid = req.get("id")

        if method == "initialize":
            return self._ok(rid, {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            })
        if method in ("notifications/initialized", "initialized"):
            return None  # notification: no response
        if method == "ping":
            return self._ok(rid, {})
        if method == "tools/list":
            return self._ok(rid, {"tools": TOOL_SCHEMAS})
        if method == "tools/call":
            return self._call(rid, req.get("params") or {})
        return self._err(rid, -32601, "method not found: {}".format(method))

    def _call(self, rid: Any, params: dict) -> dict:
        name = params.get("name")
        args = params.get("arguments") or {}
        fn = getattr(self.tools, name, None)
        if fn is None or not hasattr(fn, "tool_name"):
            return self._err(rid, -32602, "unknown tool: {}".format(name))
        try:
            result = fn(**args)
        except ToolError as e:
            # Spec 5.9.3: a tool failure is recorded as unknown, not reasoned over. It is
            # surfaced as an MCP tool error so the caller halts rather than treating the
            # message as evidence.
            return self._ok(rid, {
                "isError": True,
                "content": [{"type": "text", "text": "TOOL_FAILED: {}".format(e)}],
            })
        except TypeError as e:
            return self._err(rid, -32602, "bad arguments for {}: {}".format(name, e))
        return self._ok(rid, {
            "content": [{"type": "text",
                         "text": json.dumps(result, indent=2, default=str)}],
            "isError": False,
        })

    @staticmethod
    def _ok(rid: Any, result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    @staticmethod
    def _err(rid: Any, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}}

    def serve_stdio(self) -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                sys.stdout.write(json.dumps(
                    self._err(None, -32700, "parse error")) + "\n")
                sys.stdout.flush()
                continue
            resp = self.handle(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp, default=str) + "\n")
                sys.stdout.flush()


def build_server(run_id: str = "mcp", incident_id: str = "unknown") -> MCPServer:
    ctx = ToolContext(ledger=Ledger(), run_id=run_id, incident_id=incident_id)
    return MCPServer(Tools(ctx))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="MCP server for the HiSev tool contracts.")
    ap.add_argument("--list", action="store_true", help="print tool schemas and exit")
    args = ap.parse_args(argv)

    if args.list:
        for t in TOOL_SCHEMAS:
            required = ", ".join(t["inputSchema"].get("required", []))
            print("{:<18} ({})".format(t["name"], required))
            print("    {}".format(" ".join(t["description"].split())[:150]))
        return 0

    build_server().serve_stdio()
    return 0


if __name__ == "__main__":
    sys.exit(main())
