"""End-to-end tests for all 9 task-level Metis Reverse MCP tools."""

import tempfile
from pathlib import Path
from metis_reverse.tools.handlers import MetisToolDispatcher
from metis_reverse.config import MetisConfig
from metis_reverse.server import MetisMCPServer
from metis_reverse.engine.mock_engine import MockEngine

def test_mcp_tool_definitions_count():
    dispatcher = MetisToolDispatcher()
    tools = dispatcher.get_tool_definitions()
    assert len(tools) >= 9
    tool_names = [t["name"] for t in tools]
    expected_tools = [
        "re_session_manager",
        "re_triage",
        "re_query_function",
        "re_hunt_crypto_and_hashes",
        "re_verify_hypothesis",
        "re_emulate_slice",
        "re_refine_model",
        "re_diff_and_transfer",
        "re_query_evidence",
    ]
    for exp in expected_tools:
        assert exp in tool_names

def test_end_to_end_mcp_session_and_reasoning_flow():
    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg, engine=MockEngine())

        # Create dummy binary containing real AES S-box sequence for crypto hunt
        dummy_bin = Path(tmp_dir) / "test_sample.bin"
        aes_sbox = bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5])
        dummy_bin.write_bytes(b"MZ\x90\x00" + b"\x00" * 60 + aes_sbox + b"\x00" * 400)

        session_id = "test_sess_01"

        # 1. re_session_manager open
        r1 = dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": str(dummy_bin),
            "session_id": session_id,
        })
        assert r1["status"] == "ready"
        assert r1["session_id"] == session_id

        # 2. re_triage
        r2 = dispatcher.dispatch("re_triage", {
            "file_path": str(dummy_bin),
            "tool_feedback": {
                "tool_name": "yara",
                "exit_code": 1,
                "stdout": "rule_suspicious_xor matched"
            }
        })
        assert r2["status"] == "success"
        assert r2["external_tool_semantics"]["semantic_status"] == "MATCHES_FOUND"

        # 3. re_query_function
        r3 = dispatcher.dispatch("re_query_function", {
            "session_id": session_id,
            "va_or_name": "0x140001000",
        })
        assert r3["status"] == "success"
        assert "decompiled_code" in r3
        assert "referenced_strings_shielded" in r3

        # 4. re_hunt_crypto_and_hashes
        r4 = dispatcher.dispatch("re_hunt_crypto_and_hashes", {
            "session_id": session_id,
        })
        assert r4["status"] == "success"
        assert r4["findings_count"] > 0

        # 5. re_verify_hypothesis
        decrypt_script = """
def verify(data):
    return bytes([b ^ 0x5a for b in data])
"""
        r5 = dispatcher.dispatch("re_verify_hypothesis", {
            "session_id": session_id,
            "script_code": decrypt_script,
            "target_va": "0x140004000",
            "slice_size": 18,
            "expected_output": "Hello_From_Payload"
        })
        assert r5["success"] is True
        assert r5["hypothesis_confirmed"] is True
        assert r5["returned_value"] == "Hello_From_Payload"

        # 6. re_emulate_slice
        r6 = dispatcher.dispatch("re_emulate_slice", {
            "session_id": session_id,
            "start_va": "0x140001200",
            "stop_va": "0x140001220",
        })
        assert r6["status"] == "breakpoint_reached"
        assert "final_registers" in r6

        # 7. re_refine_model
        r7 = dispatcher.dispatch("re_refine_model", {
            "session_id": session_id,
            "function_renames": {"0x140001200": "decrypt_core_config"},
            "struct_definitions": [{
                "name": "CONFIG_HEADER",
                "size": 16,
                "fields": [{"offset": 0, "name": "magic", "field_type": "DWORD", "size": 4}],
                "evidence_va": "0x140004000"
            }]
        })
        assert r7["status"] == "success"
        assert r7["applied_count"] >= 2

        # 8. re_query_evidence
        r8 = dispatcher.dispatch("re_query_evidence", {
            "session_id": session_id,
            "query": "decrypt_core_config"
        })
        assert r8["status"] == "found"
        assert r8["provenance_verified"] is True

        # Negative query evidence
        r8_neg = dispatcher.dispatch("re_query_evidence", {
            "session_id": session_id,
            "query": "fake_unknown_token"
        })
        assert r8_neg["status"] == "not_found"
        assert r8_neg["provenance_verified"] is False

        # 9. re_session_manager export_sidecar
        r9 = dispatcher.dispatch("re_session_manager", {
            "action": "export_sidecar",
            "session_id": session_id,
            "format": "yaml"
        })
        assert r9["status"] == "exported"
        assert Path(r9["path"]).exists()

def test_mcp_json_rpc_server_protocol():
    server = MetisMCPServer()

    # Test initialize
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    }
    resp = server.handle_request(init_req)
    assert resp["id"] == 1
    assert resp["result"]["serverInfo"]["name"] == "metis-reverse"

    # Test tools/list
    list_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }
    list_resp = server.handle_request(list_req)
    assert len(list_resp["result"]["tools"]) >= 9
