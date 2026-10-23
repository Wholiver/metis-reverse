"""Tests verifying the fixes for P0-1, P0-2, P0-3, P1-4, P1-5, and P2-6."""

import tempfile
from pathlib import Path
import hashlib
from metis_reverse.engine.mock_engine import MockEngine
from metis_reverse.tools.handlers import MetisToolDispatcher
from metis_reverse.config import MetisConfig
from metis_reverse.services.triage_service import TriageService
from metis_reverse.security.sandbox import HypothesisSandbox

def test_p0_1_mock_engine_file_sha():
    """Verify mock engine hashes actual file content when file exists."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"SAMPLE_CONTENT_12345")
        f.flush()
        file_path = f.name

    expected_sha = hashlib.sha256(b"SAMPLE_CONTENT_12345").hexdigest()
    engine = MockEngine()
    res = engine.open_session(file_path, "test_sess")
    assert res["sample_sha256"] == expected_sha
    assert res["sample_sha256"] != hashlib.sha256(file_path.encode()).hexdigest()

def test_p0_2_crypto_scan_no_fake_findings():
    """Verify crypto hunt does NOT fabricate AES S-Box or constants on a clean binary like /bin/ls."""
    if not Path("/bin/ls").exists():
        return

    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg)

        res_open = dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": "/bin/ls",
            "session_id": "ls_sess",
        })
        assert res_open["status"] == "ready"

        # Crypto hunt across /bin/ls
        res_hunt = dispatcher.dispatch("re_hunt_crypto_and_hashes", {
            "session_id": "ls_sess",
        })
        assert res_hunt["status"] == "success"
        # /bin/ls does not contain AES S-Box or hardcoded crypto constants
        assert res_hunt["findings_count"] == 0

        # Query evidence for fabricated address 0x140005000
        res_ev = dispatcher.dispatch("re_query_evidence", {
            "session_id": "ls_sess",
            "query": "0x140005000",
        })
        assert res_ev["status"] == "not_found"

def test_p0_3_hypothesis_confirmed_rejects_zero_padding():
    """Verify hypothesis_confirmed rejects zero-padded memory and does not falsely confirm."""
    sandbox = HypothesisSandbox()
    script = """
def verify(data):
    return bytes([b ^ 0x5a for b in data])
"""
    # 32 null bytes XOR 0x5a produces 32 'Z's
    null_bytes = b"\x00" * 32
    res = sandbox.execute_script(script, memory_slice=null_bytes, va="0x100004000")

    assert res["success"] is True
    assert res["hypothesis_confirmed"] is False
    assert "0x00" in res.get("warning", "")
    assert res["returned_value"] == "Z" * 32

def test_p1_4_emulate_slice_architecture_and_trace():
    """Verify re_emulate_slice uses architecture-appropriate registers (e.g. ARM64 on Apple Silicon)."""
    if not Path("/bin/ls").exists():
        return

    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg)

        dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": "/bin/ls",
            "session_id": "emul_sess",
        })

        res_emul = dispatcher.dispatch("re_emulate_slice", {
            "session_id": "emul_sess",
            "start_va": "0x100000718",
            "stop_va": "0x100000728",
        })
        assert res_emul["status"] == "breakpoint_reached"
        assert res_emul["arch"] == "ARM64"
        assert "x0" in res_emul["final_registers"]
        assert "pc" in res_emul["final_registers"]
        assert "rax" not in res_emul["final_registers"]
        assert res_emul["steps_executed"] > 0
        assert len(res_emul["trace_log"]) > 1

def test_p1_5_triage_entropy_overall_vs_header():
    """Verify triage_file calculates true Shannon entropy for the whole file."""
    if not Path("/bin/ls").exists():
        return

    svc = TriageService()
    res = svc.triage_file("/bin/ls")

    assert res["status"] == "success"
    # Full file entropy of /bin/ls is around 3.14, whereas header is around 0.063
    assert abs(res["overall_entropy"] - 3.14) < 0.1
    assert abs(res["header_entropy"] - 0.063) < 0.05
    assert res["is_packed_or_encrypted"] is False

def test_p2_6_session_manager_status_action():
    """Verify re_session_manager action: 'status' works properly."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg)

        sample = Path(tmp_dir) / "test.bin"
        sample.write_bytes(b"\x7fELF" + b"\x00" * 100)

        dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": str(sample),
            "session_id": "sess_status_test",
        })

        res = dispatcher.dispatch("re_session_manager", {
            "action": "status",
            "session_id": "sess_status_test",
        })
        assert res["status"] == "ready"
        assert res["session_id"] == "sess_status_test"
        assert res["sample_sha256"] is not None

def test_p2_6_export_sidecar_honors_file_path():
    """Verify export_sidecar exports to specified file_path."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg)

        sample = Path(tmp_dir) / "test.bin"
        sample.write_bytes(b"\x7fELF" + b"\x00" * 100)

        dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": str(sample),
            "session_id": "export_sess",
        })

        custom_export = Path(tmp_dir) / "custom_exports" / "my_sidecar.yaml"
        res = dispatcher.dispatch("re_session_manager", {
            "action": "export_sidecar",
            "session_id": "export_sess",
            "file_path": str(custom_export),
        })
        assert res["status"] == "exported"
        assert Path(res["path"]).resolve() == custom_export.resolve()
        assert custom_export.exists()

def test_p2_6_re_refine_model_comments_and_applied_count():
    """Verify comments are persisted and counted in applied_count."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg)

        sample = Path(tmp_dir) / "test.bin"
        sample.write_bytes(b"\x7fELF" + b"\x00" * 100)

        dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": str(sample),
            "session_id": "refine_sess",
        })

        res = dispatcher.dispatch("re_refine_model", {
            "session_id": "refine_sess",
            "function_renames": {"0x1000": "custom_func"},
            "comments": {"0x1000": "Critical parsing routine"},
        })
        assert res["status"] == "success"
        # 1 rename + 1 comment = 2
        assert res["applied_count"] == 2

        # Verify sidecar contains comments
        sess = dispatcher._active_sessions["refine_sess"]
        assert "0x1000" in sess["sidecar"].global_comments
        assert sess["sidecar"].global_comments["0x1000"] == "Critical parsing routine"
        assert sess["sidecar"].functions["0x1000"].comments["0x1000"] == "Critical parsing routine"

def test_p2_6_re_diff_and_transfer_self_transfer():
    """Verify self-transfer matches annotations with proper reason and counts."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg)

        sample = Path(tmp_dir) / "test.bin"
        sample.write_bytes(b"\x7fELF" + b"\x00" * 100)

        open_res = dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": str(sample),
            "session_id": "transfer_sess",
        })
        sha = open_res["sample_sha256"]

        # Refine a function
        dispatcher.dispatch("re_refine_model", {
            "session_id": "transfer_sess",
            "function_renames": {"0x1000": "my_worker"},
        })

        # Self-transfer
        res_transfer = dispatcher.dispatch("re_diff_and_transfer", {
            "source_sha256": sha,
            "target_session_id": "transfer_sess",
        })
        assert res_transfer["status"] == "transferred"
        assert res_transfer["report"]["matched_count"] == 1
        assert res_transfer["report"]["matches"][0]["source_va"] == "0x1000"


def test_round2_issue1_query_function_validation():
    """Issue ①: re_query_function must validate function existence and not fake cfg_hash."""
    if not Path("/bin/ls").exists():
        return

    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg)

        open_res = dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": "/bin/ls",
            "session_id": "val_sess",
        })
        assert open_res["function_count"] > 0

        # Non-existent hex address
        res_deadbeef = dispatcher.dispatch("re_query_function", {
            "session_id": "val_sess",
            "va_or_name": "0xdeadbeef",
        })
        assert res_deadbeef["status"] == "not_found"

        # Non-existent garbage symbol name
        res_garbage = dispatcher.dispatch("re_query_function", {
            "session_id": "val_sess",
            "va_or_name": "some random invalid symbol",
        })
        assert res_garbage["status"] == "not_found"

        # Valid entrypoint function
        ep = open_res["entrypoint"]
        res_valid = dispatcher.dispatch("re_query_function", {
            "session_id": "val_sess",
            "va_or_name": ep,
        })
        assert res_valid["status"] == "success"
        assert "pacibsp" in res_valid["decompiled_code"]
        assert res_valid["cfg_hash"] != f"cfg_{hashlib.md5(ep.encode()).hexdigest()[:10]}"
        assert res_valid["cfg_hash"].startswith("cfg_")


def test_round2_issue2_fat_binary_slice_selection():
    """Issue ②: Mach-O Universal / Fat binary must select the host arch slice."""
    if not Path("/bin/ls").exists():
        return

    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg)

        open_res = dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": "/bin/ls",
            "session_id": "fat_sess",
        })

        assert open_res["architecture"] == "ARM64"
        ep = open_res["entrypoint"]
        slice_bytes = dispatcher.engine.get_memory_slice("fat_sess", ep, 4)
        # On Apple Silicon ARM64, entrypoint starts with pacibsp: 7f 23 03 d5
        assert slice_bytes == bytes.fromhex("7f2303d5")
        # Ensure it is NOT the x86_64 slice starting with 7d 02 5d c3
        assert slice_bytes != bytes.fromhex("7d025dc3")


def test_round2_issue3_unmapped_memory_raises_error():
    """Issue ③: get_memory_slice must raise on unmapped VA and not return mock stub."""
    if not Path("/bin/ls").exists():
        return

    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg)

        dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": "/bin/ls",
            "session_id": "mem_sess",
        })

        # Directly testing engine raises ValueError for out of bounds address
        try:
            dispatcher.engine.get_memory_slice("mem_sess", "0x140004000", 32)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "not mapped" in str(e) or "out of bounds" in str(e)

        # Dispatching re_verify_hypothesis handles it gracefully
        res = dispatcher.dispatch("re_verify_hypothesis", {
            "session_id": "mem_sess",
            "target_va": "0x140004000",
            "size": 32,
            "verification_script": "def verify(data): return data",
        })
        assert res["status"] == "error"
        assert "AddressUnmappedError" in res["error"]


def test_round2_issue4_micro_emulation_prologue_sp_fp():
    """Issue ④: Emulation of ARM64 prologue updates sp, x29/fp, and memory snapshots."""
    if not Path("/bin/ls").exists():
        return

    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg)

        dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": "/bin/ls",
            "session_id": "emul_prologue_sess",
        })

        # Emulate entrypoint prologue
        res = dispatcher.dispatch("re_emulate_slice", {
            "session_id": "emul_prologue_sess",
            "start_va": "0x100000960",
            "stop_va": "0x100000980",
            "initial_registers": {
                "x28": 0x1122334455667788,
                "x27": 0x99aabbccddeeff00,
            },
            "memory_addresses": ["0x16fdfefa0"],
        })

        assert res["status"] == "breakpoint_reached"
        assert res["steps_executed"] >= 8
        assert res["final_registers"]["sp"] != "0x16fdff000"
        assert res["final_registers"]["x29"] != "0x0"
        assert res["final_registers"]["fp"] == res["final_registers"]["x29"]
        assert "0x16fdfefa0" in res["memory_snapshots"]
        assert res["memory_snapshots"]["0x16fdfefa0"].startswith("887766554433221100ffeeddccbbaa99")


def test_round3_issue1_string_registers_and_no_evidence_on_error():
    """Round 3 Issue ①: Emulation with string registers normalizes gracefully; errors do not register evidence."""
    if not Path("/bin/ls").exists():
        return

    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg)

        dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": "/bin/ls",
            "session_id": "str_reg_sess",
        })

        # Passing string register like "0x16fdff000" must not throw TypeError
        res = dispatcher.dispatch("re_emulate_slice", {
            "session_id": "str_reg_sess",
            "start_va": "0x100000960",
            "stop_va": "0x100000980",
            "initial_registers": {"sp": "0x16fdff000"},
        })
        assert res["status"] == "breakpoint_reached"
        assert not res.get("has_error")
        assert res["final_registers"]["sp"] == "0x16fdfefa0"

        # Evidence should be registered for clean run
        ev_clean = dispatcher.dispatch("re_query_evidence", {
            "session_id": "str_reg_sess",
            "query": "0x100000980",
        })
        assert ev_clean["status"] == "found"

        # Now test that an emulation error does NOT register evidence
        # Trigger an error by giving unparseable/invalid bytecode slice
        err_res = dispatcher.emulation_service.emulate_slice(
            "str_reg_sess",
            "0x100000960",
            "0x100000980",
        )
        # Mock an error in the handler call
        dispatcher.emulation_service.emulate_slice = lambda **kwargs: {
            "status": "emulation_error",
            "has_error": True,
            "error": "Simulated engine error",
            "steps_executed": 2,
            "final_registers": {},
            "memory_snapshots": {},
            "trace_log": ["Error triggered"],
        }
        res_fail = dispatcher.dispatch("re_emulate_slice", {
            "session_id": "str_reg_sess",
            "start_va": "0x100000960",
            "stop_va": "0x100000999",
        })
        assert res_fail["status"] == "emulation_error"
        assert res_fail["has_error"] is True

        ev_fail = dispatcher.dispatch("re_query_evidence", {
            "session_id": "str_reg_sess",
            "query": "0x100000999",
        })
        assert ev_fail["status"] == "not_found"


def test_round3_issue2_breakpoint_before_execution():
    """Round 3 Issue ②: Breakpoint hits BEFORE execution of the instruction at stop_va."""
    if not Path("/bin/ls").exists():
        return

    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg)

        dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": "/bin/ls",
            "session_id": "bp_sess",
        })

        # Instruction at 0x100000984 is `mov x19, x1`.
        # Initializing x19 to 0x12345678.
        # Breakpoint at 0x100000984 must NOT execute `mov x19, x1`.
        res = dispatcher.dispatch("re_emulate_slice", {
            "session_id": "bp_sess",
            "start_va": "0x100000960",
            "stop_va": "0x100000984",
            "initial_registers": {"x19": 0x12345678},
        })

        assert res["status"] == "breakpoint_reached"
        assert res["final_registers"]["pc"] == "0x100000984"
        # x19 must retain initial value since instruction at 0x100000984 was not executed
        assert res["final_registers"]["x19"] == "0x12345678"
        # 9 instructions executed (0x960 through 0x980)
        assert res["steps_executed"] == 9


def test_round3_issue3_callees_callers_strings_xrefs():
    """Round 3 Issue ③: Function query returns callees, callers, referenced strings, and C pseudocode."""
    if not Path("/bin/ls").exists():
        return

    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg)

        dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": "/bin/ls",
            "session_id": "xrefs_sess",
        })

        res_fn = dispatcher.dispatch("re_query_function", {
            "session_id": "xrefs_sess",
            "va_or_name": "0x100000960",
        })
        assert res_fn["status"] == "success"

        # 1. Callees must be populated with recovered names
        assert len(res_fn["callees"]) > 0
        callee_names = [c["name"] for c in res_fn["callees"]]
        assert "_setlocale" in callee_names
        assert "_compat_mode" in callee_names
        assert "_getenv" in callee_names

        # 2. Referenced strings must be populated via adrp + add
        assert len(res_fn["referenced_strings"]) > 0
        string_texts = [s["text"] for s in res_fn["referenced_strings"]]
        assert "bin/ls" in string_texts
        assert "COLUMNS" in string_texts
        assert "LS_SAMESORT" in string_texts

        # 3. Referenced constants must contain immediates
        assert len(res_fn["referenced_constants"]) > 0

        # 4. Disassembly and decompiled C pseudocode must both be present
        assert "disassembly" in res_fn
        assert "pacibsp" in res_fn["disassembly"]
        assert "void " in res_fn["decompiled_code"]
        assert "_setlocale();" in res_fn["decompiled_code"]

        # 5. Callers: query _setlocale stub at 0x10000464c, should list 0x1000009bc as caller
        res_stub = dispatcher.dispatch("re_query_function", {
            "session_id": "xrefs_sess",
            "va_or_name": "0x10000464c",
        })
        assert res_stub["status"] == "success"
        caller_vas = [c["va"].lower() for c in res_stub["callers"]]
        assert "0x1000009bc" in caller_vas

        # 6. Intra-function branch targets must NOT be present as callees
        callee_vas = [c["va"].lower() for c in res_fn["callees"]]
        assert "0x100000a88" not in callee_vas
        assert "0x100000a90" not in callee_vas
        assert "0x100000af0" not in callee_vas


def test_round4_intra_function_branch_not_callee():
    """Issue ④: Intra-function branches (b) (e.g. getopt loop back-edges, gotos) are not reported as callees."""
    if not Path("/bin/ls").exists():
        return

    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg)

        dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": "/bin/ls",
            "session_id": "b_branch_sess",
        })

        res_fn = dispatcher.dispatch("re_query_function", {
            "session_id": "b_branch_sess",
            "va_or_name": "0x100000960",
        })
        assert res_fn["status"] == "success"

        callee_vas = [c["va"].lower() for c in res_fn["callees"]]
        # Intra-function branches from 0x100000a70, 0x100000a20, 0x100000b40, 0x100000b5c
        assert "0x100000a88" not in callee_vas
        assert "0x100000a90" not in callee_vas
        assert "0x100000af0" not in callee_vas

        # Legitimate external calls must be preserved
        assert "0x10000464c" in callee_vas  # _setlocale
        assert "0x1000044dc" in callee_vas  # _getopt_long
        assert "0x1000044cc" in callee_vas  # _getenv


def test_round5_function_boundary_strict_callee_isolation():
    """Issue ⑤: Function boundary overreach isolation.

    Small functions (e.g. sub_0x100004088, 44 bytes) must not overrun into adjacent
    functions or absorb neighboring callees (_warnx, _err, _strerror, ___assert_rtn).
    """
    if not Path("/bin/ls").exists():
        return

    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg)

        dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": "/bin/ls",
            "session_id": "boundary_sess",
        })

        res_fn = dispatcher.dispatch("re_query_function", {
            "session_id": "boundary_sess",
            "va_or_name": "0x100004088",
        })
        assert res_fn["status"] == "success"

        # Disassembly must have exactly 11 instructions (44 bytes), not 128 instructions from 512-byte overrun
        lines = [line.strip() for line in res_fn["disassembly"].splitlines() if line.strip()]
        assert len(lines) == 11

        callee_names = [c["name"] for c in res_fn["callees"]]
        # Real callees inside sub_0x100004088: _fprintf and _exit
        assert "_fprintf" in callee_names
        assert "_exit" in callee_names

        # Neighboring functions must NOT be absorbed as false callees
        assert "_warnx" not in callee_names
        assert "_err" not in callee_names
        assert "_strerror" not in callee_names
        assert "___assert_rtn" not in callee_names



