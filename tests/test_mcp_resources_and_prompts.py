"""Tests for Metis Reverse MCP Server Resources and Prompts endpoints.

Validates:
- Capabilities advertising tools, resources, prompts
- resources/list and resources/read for metis://docs/skill-manual and references
- prompts/list and prompts/get for metis-reverse-skill
- JSON-RPC protocol compliance and error handling
"""

import json
from pathlib import Path
from metis_reverse.server import MetisMCPServer

def test_mcp_capabilities_include_resources_and_prompts():
    server = MetisMCPServer()
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }
    resp = server.handle_request(init_req)
    assert resp["id"] == 1
    caps = resp["result"]["capabilities"]
    assert "tools" in caps
    assert "resources" in caps
    assert "prompts" in caps

def test_mcp_resources_list():
    server = MetisMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "resources/list",
        "params": {}
    }
    resp = server.handle_request(req)
    assert resp["id"] == 2
    assert "result" in resp
    resources = resp["result"]["resources"]
    uris = [r["uri"] for r in resources]
    
    assert "metis://docs/skill-manual" in uris
    assert "metis://docs/tools-catalog" in uris
    assert "metis://docs/probe-recipes" in uris
    assert "metis://docs/polyglot-guide" in uris

    for r in resources:
        assert r["mimeType"] == "text/markdown"
        assert len(r["name"]) > 0
        assert len(r["description"]) > 0

def test_mcp_resources_read_skill_manual():
    server = MetisMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "resources/read",
        "params": {
            "uri": "metis://docs/skill-manual"
        }
    }
    resp = server.handle_request(req)
    assert resp["id"] == 3
    assert "result" in resp
    contents = resp["result"]["contents"]
    assert len(contents) == 1
    content = contents[0]
    assert content["uri"] == "metis://docs/skill-manual"
    assert content["mimeType"] == "text/markdown"
    text = content["text"]
    assert "metis-reverse-mcp" in text
    assert "Cardinal Rules" in text
    assert "Zero Hallucination" in text
    assert "SOP 1" in text

def test_mcp_resources_read_references():
    server = MetisMCPServer()
    for uri in ["metis://docs/tools-catalog", "metis://docs/probe-recipes", "metis://docs/polyglot-guide"]:
        req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "resources/read",
            "params": {"uri": uri}
        }
        resp = server.handle_request(req)
        assert resp["id"] == 4
        assert "result" in resp
        assert len(resp["result"]["contents"]) == 1
        assert len(resp["result"]["contents"][0]["text"]) > 100

def test_mcp_resources_read_invalid_uri():
    server = MetisMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "resources/read",
        "params": {"uri": "metis://docs/non-existent"}
    }
    resp = server.handle_request(req)
    assert resp["id"] == 5
    assert "error" in resp
    assert resp["error"]["code"] == -32602

def test_mcp_prompts_list():
    server = MetisMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "prompts/list",
        "params": {}
    }
    resp = server.handle_request(req)
    assert resp["id"] == 6
    assert "result" in resp
    prompts = resp["result"]["prompts"]
    names = [p["name"] for p in prompts]
    assert "metis-reverse-skill" in names

def test_mcp_prompts_get():
    server = MetisMCPServer()
    req = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "prompts/get",
        "params": {
            "name": "metis-reverse-skill",
            "arguments": {
                "sample_path": "/tmp/test_target.bin",
                "focus_area": "crypto"
            }
        }
    }
    resp = server.handle_request(req)
    assert resp["id"] == 7
    assert "result" in resp
    messages = resp["result"]["messages"]
    assert len(messages) == 1
    text = messages[0]["content"]["text"]
    assert "metis-reverse-mcp" in text
    assert "/tmp/test_target.bin" in text
    assert "crypto" in text
