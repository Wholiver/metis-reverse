"""Tests for re_inspect_binary_structure and sandbox guardrail improvements."""

import sys
import tempfile
from pathlib import Path
from metis_reverse.tools.handlers import MetisToolDispatcher
from metis_reverse.config import MetisConfig
from metis_reverse.engine.mock_engine import MockEngine
from metis_reverse.engine.native_engine import NativeEngine
from metis_reverse.security.sandbox import HypothesisSandbox


def test_sandbox_safe_import_and_block():
    sandbox = HypothesisSandbox()

    # 1. Allowed imports: json, struct, math, hashlib, etc.
    allowed_script = """
import json, struct, math, hashlib
def verify(data):
    obj = json.loads('{"val": 42}')
    packed = struct.pack(">I", obj["val"])
    return len(packed) == 4 and math.sqrt(16) == 4.0
"""
    res1 = sandbox.execute_script(
        script_code=allowed_script,
        memory_slice=b"ABCD",
    )
    assert res1["success"] is True
    assert res1["hypothesis_confirmed"] is True

    # 2. Blocked import: os
    blocked_script = """
import os
def verify(data):
    return True
"""
    res2 = sandbox.execute_script(
        script_code=blocked_script,
        memory_slice=b"ABCD",
    )
    assert res2["success"] is False
    assert "Importing 'os' is disabled in sandbox" in res2["error"]
    assert "Allowed pre-injected modules" in res2["error"]


def test_sandbox_probe_script_globals_and_imports():
    sandbox = HypothesisSandbox()

    probe_code = """
import json, math
def probe():
    res = {
        "has_path": bool(session_path),
        "calc": math.floor(3.14),
        "bytes_read": len(read_file_range(0, 16)),
    }
    return json.dumps(res)
"""
    res = sandbox.execute_probe_script(
        script_code=probe_code,
        read_file_func=lambda off, sz: b"\x90" * sz,
        custom_vars={"session_path": "/fake/path/to/binary"},
    )
    assert res["success"] is True
    import json
    val = json.loads(res["returned_value"])
    assert val["has_path"] is True
    assert val["calc"] == 3
    assert val["bytes_read"] == 16


def test_re_inspect_binary_structure_mock_engine():
    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg, engine=MockEngine())

        dummy_bin = Path(tmp_dir) / "sample.bin"
        dummy_bin.write_bytes(b"MZ\x90\x00" + b"\x00" * 200)

        r_open = dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": str(dummy_bin),
            "session_id": "sess_struct_test",
        })
        assert r_open["status"] == "ready"

        # Test scope="headers"
        r_hdr = dispatcher.dispatch("re_inspect_binary_structure", {
            "session_id": "sess_struct_test",
            "scope": "headers",
        })
        assert r_hdr["status"] == "success"
        assert "headers" in r_hdr
        assert r_hdr["headers"]["format"] == "PE64 / ELF64"
        assert "encryption" in r_hdr["headers"]

        # Test scope="sections"
        r_sec = dispatcher.dispatch("re_inspect_binary_structure", {
            "session_id": "sess_struct_test",
            "scope": "sections",
        })
        assert r_sec["status"] == "success"
        assert "sections" in r_sec

        # Test scope="symbols" with query
        r_sym = dispatcher.dispatch("re_inspect_binary_structure", {
            "session_id": "sess_struct_test",
            "scope": "symbols",
            "query": "entry",
        })
        assert r_sym["status"] == "success"
        assert r_sym["symbols"]["total_exported"] >= 1
        assert any("entry" in s["name"] for s in r_sym["symbols"]["exported"])

        # Test scope="all"
        r_all = dispatcher.dispatch("re_inspect_binary_structure", {
            "session_id": "sess_struct_test",
            "scope": "all",
        })
        assert r_all["status"] == "success"
        assert "headers" in r_all
        assert "segments" in r_all
        assert "sections" in r_all
        assert "dependencies" in r_all
        assert "symbols" in r_all


def test_re_inspect_binary_structure_native_engine():
    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg, engine=NativeEngine())

        # Use current Python interpreter binary which is a valid executable
        py_bin = sys.executable

        r_open = dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": py_bin,
            "session_id": "sess_py_bin",
        })
        assert r_open["status"] == "ready"

        r_struct = dispatcher.dispatch("re_inspect_binary_structure", {
            "session_id": "sess_py_bin",
            "scope": "all",
            "limit": 10,
        })
        assert r_struct["status"] == "success"
        assert "headers" in r_struct
        assert "segments" in r_struct
        assert "sections" in r_struct
        assert "dependencies" in r_struct
        assert "symbols" in r_struct

        # Test probe script receiving binary_path and session_path
        probe_code = """
import lief
def probe():
    return {
        "session_path_set": bool(session_path),
        "target_binary_present": target_binary is not None,
    }
"""
        r_probe = dispatcher.dispatch("re_run_probe_script", {
            "session_id": "sess_py_bin",
            "script_code": probe_code,
        })
        assert r_probe["success"] is True
        assert r_probe["returned_value"]["session_path_set"] is True
