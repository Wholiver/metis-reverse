"""Tests for performance optimizations and stdio responsiveness."""

import sys
import json
from metis_reverse.server import MetisMCPServer
from metis_reverse.security.sandbox import HypothesisSandbox

def test_sandbox_does_not_mutate_process_stdout():
    """Verify HypothesisSandbox does not hijack global sys.stdout."""
    original_stdout = sys.stdout
    sandbox = HypothesisSandbox()
    res = sandbox.execute_script(
        script_code='print("Hello from sandbox")\nresult = "ok"',
        memory_slice=b"test_data",
        va="0x1000",
    )
    assert res["success"] is True
    assert "Hello from sandbox" in res["stdout"]
    assert sys.stdout is original_stdout

def test_server_preserves_request_id_on_tool_error():
    """Verify MCP JSON-RPC returns matching req_id even when tools fail or are unknown."""
    server = MetisMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": "req-uuid-1234",
        "method": "tools/call",
        "params": {
            "name": "non_existent_tool_xyz",
            "arguments": {}
        }
    }
    resp = server.handle_request(req)
    assert resp is not None
    assert resp["id"] == "req-uuid-1234"
    assert "result" in resp
    assert resp["result"]["isError"] is True
