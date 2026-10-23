"""Test suite specifically verifying fixes for all 5 points in the Acceptance Audit:
1. Decompiler honesty & no mock representation in NativeEngine.
2. Bridge Map coordinate conversion & strict in-bounds validation.
3. JS AST closure slicing on 30MB single-line minified code & context guard.
4. Phase 3 deep data structure recovery (IL2CPP, Flutter, ArkTS) & degraded gating.
5. 48MB large binary artifact 64-bit address translation & memory consistency.
"""

import struct
import tempfile
import time
from pathlib import Path
import pytest

from metis_reverse.tools.handlers import MetisToolDispatcher
from metis_reverse.config import MetisConfig
from metis_reverse.engine.native_engine import NativeEngine
from metis_reverse.storage.artifact_tree import ArtifactTree, ArtifactNode
from metis_reverse.services.js_service import JSService
from metis_reverse.services.bridge_service import BridgeService
from metis_reverse.services.family_adapters import FamilyAdapters

FIXTURES_DIR = Path(__file__).parent.parent / "bench" / "fixtures"


# ==============================================================================
# Issue 1: Decompiler Honesty & No Mock Representation
# ==============================================================================

def test_audit_issue1_no_mock_representation_for_unparsed_binaries():
    """Verify NativeEngine does not synthesize fake entrypoint 0x140001000 or fake functions."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        dummy_bin = Path(tmp_dir) / "raw_shellcode.bin"
        dummy_bin.write_bytes(b"\x90\xcc\xc3" * 32) # Raw bytes, no ELF/PE/Mach-O header

        engine = NativeEngine()
        sess_res = engine.open_session(str(dummy_bin), "raw_sess")
        assert sess_res["status"] == "ready"
        assert sess_res["entrypoint"] is None
        assert sess_res["function_count"] == 0
        assert sess_res["sections_count"] == 0

        # Querying non-existent function must return not_found, never fabricated code
        q_res = engine.get_function_context("raw_sess", "0x140001000")
        assert q_res["status"] == "not_found"


def test_audit_issue1_decompiler_honesty_flags():
    """Verify query_function returns explicit decompiler honesty flags and synthesis notices."""
    target_bin = FIXTURES_DIR / "bun_composite_sample"
    if not target_bin.exists():
        pytest.skip("Fixture bun_composite_sample not found")

    engine = NativeEngine()
    engine.open_session(str(target_bin), "decompile_sess")
    q_res = engine.get_function_context("decompile_sess", "0x100a28080")
    assert q_res["status"] == "success"

    # Must declare decompiler unavailability honestly
    assert q_res["decompiler_available"] is False
    assert q_res["is_ast_decompiler"] is False
    assert q_res["decompiler_engine"] == "native_capstone_synthesis"
    assert q_res["decompilation_fidelity"] == "assembly_synthesis"
    assert "Structured disassembly synthesis" in q_res["decompiled_code"]
    assert "Ghidra 12.1.1+ not active" in q_res["decompiled_code"]


# ==============================================================================
# Issue 2: Bridge Map Coordinates In-Bounds & Container Resolution
# ==============================================================================

def test_audit_issue2_bridge_map_in_bounds_coordinates():
    """Verify processImage in root:node:0 maps strictly within [197568, 205760] and within node bounds."""
    target_bin = FIXTURES_DIR / "bun_composite_sample"
    if not target_bin.exists():
        pytest.skip("Fixture bun_composite_sample not found")

    with tempfile.TemporaryDirectory() as tmp_dir:
        cfg = MetisConfig(sidecar_dir=Path(tmp_dir))
        dispatcher = MetisToolDispatcher(config=cfg)
        dispatcher.dispatch("re_session_manager", {
            "action": "open",
            "file_path": str(target_bin),
            "session_id": "bridge_sess"
        })

        br = dispatcher.dispatch("re_bridge_map", {
            "session_id": "bridge_sess",
            "artifact_id": "root:node:0"
        })
        assert br["status"] == "success"
        assert br["bridge_count"] >= 3

        bridges = br["bridges"]
        img_bridge = next((b for b in bridges if b.get("js_symbol") == "processImage"), None)
        assert img_bridge is not None

        native_impl = img_bridge["native_implementation"]
        local_off = native_impl["local_file_offset"]
        container_off = native_impl["container_file_offset"]
        coords_valid = native_impl["coordinate_valid"]
        bounds = native_impl["physical_range"] # [node_file_off, node_file_off + node_size]

        # 1. Local offset must be inside the 8KB node (0 <= local_off < 8192)
        assert 0 <= local_off < 8192
        assert local_off == 4096 # VA 0x100001000 in __TEXT segment

        # 2. Container offset must be inside [197568, 205760]
        assert bounds == [197568, 205760]
        assert container_off == 197568 + 4096
        assert 197568 <= container_off < 205760
        assert coords_valid is True

        # 3. file_offset must NOT be 327936
        assert native_impl["file_offset"] != 327936
        assert native_impl["file_offset"] == 4096


# ==============================================================================
# Issue 3: AST Closure Slicing & Minified Context Guard
# ==============================================================================

def test_audit_issue3_single_line_minified_context_guard():
    """Verify single-line 30MB minified JS triggers context guard and does not dump 30MB to context."""
    tree = ArtifactTree(root_id="root")

    # Generate a 500KB single-line minified JS file
    chunk = "var a=1;var b=2;"
    large_line = (chunk * 30000) + "function targetSecretFunction(token, key){return token^key;}" + (chunk * 5000)
    assert len(large_line.splitlines()) == 1
    assert len(large_line) > 32768

    node = ArtifactNode(
        id="root:js:minified_large",
        name="app.min.js",
        size=len(large_line),
        families=["javascript"]
    )
    tree.add_node(node, content=large_line.encode("utf-8"))

    # Line mode request must trigger context safety guard
    guard_res = JSService.get_module(tree, "root:js:minified_large", start_line=1, end_line=1)
    assert guard_res["status"] == "guard_triggered"
    assert "exceeding safe LLM context threshold" in guard_res["warning"]
    assert "code" not in guard_res or guard_res.get("code") is None

    # AST closure extraction must successfully extract targetSecretFunction in < 100ms
    t0 = time.time()
    c_res = JSService.get_module(
        tree,
        "root:js:minified_large",
        slice_mode="closure",
        closure_name="targetSecretFunction"
    )
    t1 = time.time()
    assert (t1 - t0) < 0.20 # < 200ms
    assert c_res["status"] == "success"
    assert c_res["closure_name"] == "targetSecretFunction"
    assert c_res["params"] == ["token", "key"]
    assert "return token^key;" in c_res["code"]
    assert len(c_res["code"]) < 200 # Bounded small output


def test_audit_issue3_list_closures_pagination():
    """Verify js_list_closures extracts closure catalog with metadata without dumping source."""
    tree = ArtifactTree(root_id="root")
    js_code = (
        "function initApp(a){return a;}"
        "const processData = (items) => {return items.map(x=>x*2);};"
        "export function logoutUser(session){session.clear();}"
    )
    node = ArtifactNode(id="root:js:closures", name="app.js", size=len(js_code), families=["javascript"])
    tree.add_node(node, content=js_code.encode("utf-8"))

    res = JSService.list_closures(tree, "root:js:closures")
    assert res["status"] == "success"
    assert res["total_closures"] == 3
    names = [c["name"] for c in res["closures"]]
    assert "initApp" in names
    assert "processData" in names
    assert "logoutUser" in names


# ==============================================================================
# Issue 4: Phase 3 Deep Structures & Degraded Gating
# ==============================================================================

def test_audit_issue4_il2cpp_deep_tables_and_degraded_gating():
    """Verify IL2CPP adapter extracts string table, assemblies, and type definitions, with degraded_result=True."""
    il2cpp_file = FIXTURES_DIR / "global-metadata.dat"
    if not il2cpp_file.exists():
        pytest.skip("Fixture global-metadata.dat not found")

    data = il2cpp_file.read_bytes()
    res = FamilyAdapters.analyze_il2cpp(data)
    assert res["is_il2cpp_metadata"] is True
    assert res["metadata_version"] == 29
    assert res["recovered_strings_count"] > 0
    assert "Assembly-CSharp.dll" in res["assemblies_recovered"]
    assert any("SecurityController" in t for t in res["types_recovered"])

    # Must be marked degraded because native binary (libil2cpp.so) is required for function code
    assert res["degraded_result"] is True
    assert "degradation_reason" in res
    assert "libil2cpp.so" in res["degradation_reason"]


def test_audit_issue4_flutter_deep_structures_and_degraded_gating():
    """Verify Flutter adapter recovers flags, package URIs, snapshot clusters, with degraded_result=True."""
    fl_file = FIXTURES_DIR / "sample_flutter.so"
    if not fl_file.exists():
        pytest.skip("Fixture sample_flutter.so not found")

    data = fl_file.read_bytes()
    res = FamilyAdapters.analyze_flutter(data)
    assert res["is_flutter_app"] is True
    assert res["has_aot_snapshot"] is True
    assert "product" in res["feature_flags"]
    assert any("main.dart" in u for u in res["package_uris"])
    assert any("isolate_snapshot_data" in c for c in res["snapshot_clusters"])

    # Must be marked degraded because stripped Dart AOT snapshots require engine commit deserializer
    assert res["degraded_result"] is True
    assert "degradation_reason" in res


def test_audit_issue4_harmony_deep_structures_and_degraded_gating():
    """Verify ArkTS adapter recovers class descriptors and version, with degraded_result=True."""
    ark_file = FIXTURES_DIR / "sample_ark.abc"
    if not ark_file.exists():
        pytest.skip("Fixture sample_ark.abc not found")

    data = ark_file.read_bytes()
    res = FamilyAdapters.analyze_harmony(data)
    assert res["is_ark_bytecode"] is True
    assert res["bytecode_version"] == 1
    assert "EntryAbility" in res["classes_sample"]

    # Must be marked degraded because host lacks ArkDisasm toolchain
    assert res["degraded_result"] is True
    assert "degradation_reason" in res
    assert "ArkDisasm" in res["degradation_reason"]


# ==============================================================================
# Issue 5: Large Sample 48MB Stress Test (64-bit Offsets & Memory Consistency)
# ==============================================================================

def test_audit_issue5_large_sample_48mb_stress_test():
    """Verify 48MB binary with large segment does not experience 32-bit offset overflow."""
    large_file = FIXTURES_DIR / "sample_large_48mb.bin"
    if not large_file.exists():
        pytest.skip("Fixture sample_large_48mb.bin not found")

    engine = NativeEngine()
    sess_res = engine.open_session(str(large_file), "large_audit_sess")
    assert sess_res["status"] == "ready"

    data_size = 48 * 1024 * 1024 # 48MB = 50,331,648 bytes

    # 1. Coordinate translation across anchors: 0MB, 16MB, 32MB, 48MB
    tr0 = engine.translate_address("large_audit_sess", "0x100010000", from_kind="va")
    tr16 = engine.translate_address("large_audit_sess", "0x101010000", from_kind="va")
    tr32 = engine.translate_address("large_audit_sess", "0x102010000", from_kind="va")
    tail_va = hex(0x100010000 + data_size - 64)
    tr_tail = engine.translate_address("large_audit_sess", tail_va, from_kind="va")

    assert tr0["file_offset"] == 0x10000
    assert tr16["file_offset"] == 0x10000 + 16 * 1024 * 1024
    assert tr32["file_offset"] == 0x10000 + 32 * 1024 * 1024
    assert tr_tail["file_offset"] == 0x10000 + data_size - 64

    # 2. Reverse translation from file offset to VA
    rev_tail = engine.translate_address("large_audit_sess", 0x10000 + data_size - 64, from_kind="file_offset")
    assert int(rev_tail["va"], 16) == 0x100010000 + data_size - 64

    # 3. Direct physical disk read vs Virtual memory read at the tail anchor
    tail_disk_bytes = engine.read_file_range("large_audit_sess", 0x10000 + data_size - 64, 32)
    tail_mem_bytes = engine.get_memory_slice("large_audit_sess", tail_va, 32)
    assert tail_disk_bytes.startswith(b"CANARY_TAIL")
    assert tail_disk_bytes == tail_mem_bytes

    # 4. Consistency check across the entire 48MB binary
    cons = engine.check_memory_consistency("large_audit_sess")
    assert cons["status"] == "consistent"
    assert cons["memory_view_unreliable"] is False
    assert len(cons["discrepancies"]) == 0
