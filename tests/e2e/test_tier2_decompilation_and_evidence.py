"""
Tier 2 E2E Tests: Decompilation & Multi-Evidence Grounding Engine.

Tests FastMCP server tools:
- decompile(session_id, function_address)
- query_evidence(session_id, symbol_or_addr)
- Grounding: Format string reverse inference (printf), assert macros, Go pclntab
- Immutable evidence tags and confidence scoring (1.0 for grounded evidence).
"""

from __future__ import annotations

from pathlib import Path

import pytest

mr_server = pytest.importorskip(
    "metis_reverse.server",
    reason="metis_reverse.server is scheduled for implementation in Milestone 1/2",
)


def test_tier2_decompile_function(c_service_stripped_path: Path) -> None:
    """Verify decompile tool produces structured decompilation result."""
    session = mr_server.open_session(str(c_service_stripped_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]
    functions = mr_server.list_functions(session_id)
    assert len(functions) > 0

    first_addr = getattr(functions[0], "address", None) or functions[0].get("address")
    decomp = mr_server.decompile(session_id, first_addr)

    assert decomp is not None
    code = getattr(decomp, "decompiled_code", None) or decomp.get("decompiled_code")
    assert isinstance(code, str)
    assert len(code) > 0


def test_tier2_format_string_evidence_grounding(
    c_service_stripped_path: Path,
    c_service_ground_truth_symbols: dict,
) -> None:
    """Verify format string reverse inference detects printf strings and assigns confidence 1.0."""
    session = mr_server.open_session(str(c_service_stripped_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]

    # Query evidence across the session
    evidence_list = mr_server.query_evidence(session_id, symbol_or_addr="all")
    assert isinstance(evidence_list, list)

    evidence_types = [
        getattr(e, "evidence_type", None) or e.get("evidence_type")
        for e in evidence_list
    ]
    assert len(evidence_types) >= 0

    raw_anchors = [
        getattr(e, "raw_anchor", None) or e.get("raw_anchor", "")
        for e in evidence_list
    ]

    # Verify format string detection
    expected_substr = "Service starting on port %u"
    found_anchor = any(expected_substr in str(anchor) for anchor in raw_anchors)
    assert found_anchor, f"Expected format string '{expected_substr}' not found in anchors: {raw_anchors}"

    # Verify confidence is 1.0 for grounded evidence
    for e in evidence_list:
        etype = getattr(e, "evidence_type", None) or e.get("evidence_type")
        if etype == "FORMAT_STRING":
            conf = getattr(e, "confidence", None) or e.get("confidence")
            assert conf == 1.0, f"Expected confidence 1.0, got {conf}"
            is_immutable = getattr(e, "is_immutable", None) or e.get("is_immutable")
            assert is_immutable is True


def test_tier2_assert_macro_extraction(
    c_service_stripped_path: Path,
    c_service_ground_truth_symbols: dict,
) -> None:
    """Verify assert macro strings (e.g. 'len_check', 'http_magic_check') are extracted."""
    session = mr_server.open_session(str(c_service_stripped_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]

    evidence_list = mr_server.query_evidence(session_id, symbol_or_addr="all")
    raw_anchors = [
        getattr(e, "raw_anchor", None) or e.get("raw_anchor", "")
        for e in evidence_list
    ]

    assert_conditions = c_service_ground_truth_symbols["assert_conditions"]
    matched = [cond for cond in assert_conditions if any(cond in str(a) for a in raw_anchors)]
    assert len(matched) >= 2, f"Failed to extract assert conditions. Found: {matched}"


def test_tier2_go_pclntab_metadata_extraction(
    go_pipeline_stripped_path: Path,
    go_pipeline_ground_truth_symbols: dict,
) -> None:
    """Verify Go pclntab parser extracts exact function signatures from stripped Go binary."""
    session = mr_server.open_session(str(go_pipeline_stripped_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]

    functions = mr_server.list_functions(session_id)
    func_names = [
        getattr(f, "name", None) or f.get("name")
        for f in functions
    ]

    # Verify exact function names extracted from pclntab despite -ldflags="-s -w"
    expected_funcs = go_pipeline_ground_truth_symbols["pclntab_functions"]
    found_matches = [name for name in expected_funcs if any(name in fn for fn in func_names)]
    assert len(found_matches) > 0, f"No Go pclntab symbols found in: {func_names[:20]}"


def test_tier2_syscall_libc_propagation(c_service_stripped_path: Path) -> None:
    """Verify POSIX syscalls and libc functions are discovered and propagated."""
    session = mr_server.open_session(str(c_service_stripped_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]

    evidence_list = mr_server.query_evidence(session_id, symbol_or_addr="all", source="SYSCALL_ABI")
    assert isinstance(evidence_list, list)
    assert len(evidence_list) > 0, "No SYSCALL_ABI evidence tags generated"
    for e in evidence_list:
        conf = getattr(e, "confidence", None) or e.get("confidence")
        assert conf == 1.0
        assert (getattr(e, "is_immutable", None) or e.get("is_immutable")) is True


def test_tier2_go_pclntab_function_recovery(
    go_pipeline_stripped_path: Path,
    go_pipeline_ground_truth_symbols: dict,
) -> None:
    """Verify Go pclntab parser extracts exact function signatures from stripped Go binary."""
    session = mr_server.open_session(str(go_pipeline_stripped_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]

    evidence_list = mr_server.query_evidence(session_id, symbol_or_addr="all", source="GO_PCLNTAB")
    assert len(evidence_list) > 0, "No GO_PCLNTAB evidence tags generated"

    recovered_names = [getattr(e, "suggested_name", "") or e.get("suggested_name", "") for e in evidence_list]
    expected_funcs = [
        "main.main",
        "metis/pipeline/pkg/config.ParseFlags",
        "metis/pipeline/pkg/metrics.(*MetricsCounter).ToJSON",
        "metis/pipeline/pkg/processor.(*PipelinePool).Run",
        "metis/pipeline/pkg/processor.(*PipelinePool).workerProcess",
        "metis/pipeline/pkg/processor.(*PipelinePool).processSingleTask",
    ]
    for fn in expected_funcs:
        assert fn in recovered_names, f"Expected Go function '{fn}' not found in recovered names: {recovered_names[:10]}"

    for e in evidence_list:
        assert (getattr(e, "confidence", None) or e.get("confidence")) == 1.0
        assert (getattr(e, "is_immutable", None) or e.get("is_immutable")) is True


def test_tier2_go_pclntab_source_anchors(go_pipeline_stripped_path: Path) -> None:
    """Verify Go pclntab extracts source file paths and line numbers."""
    session = mr_server.open_session(str(go_pipeline_stripped_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]

    evidence_list = mr_server.query_evidence(session_id, symbol_or_addr="main.main")
    assert len(evidence_list) > 0
    main_tag = evidence_list[0]
    raw_anchor = getattr(main_tag, "raw_anchor", "") or main_tag.get("raw_anchor", "")
    assert "main.go" in raw_anchor or "pipeline" in raw_anchor or ".go" in raw_anchor


def test_tier2_cpp_rtti_and_vtables() -> None:
    """Verify C++ Itanium RTTI and VTable extraction."""
    cpp_sample = Path("tests/fixtures/cpp_vtable_sample")
    if not cpp_sample.exists():
        pytest.skip("tests/fixtures/cpp_vtable_sample binary not found")
    session = mr_server.open_session(str(cpp_sample))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]

    evidence_list = mr_server.query_evidence(session_id, symbol_or_addr="all", source="CPP_RTTI")
    assert len(evidence_list) > 0, "No CPP_RTTI evidence tags generated"
    names = [getattr(e, "suggested_name", "") or e.get("suggested_name", "") for e in evidence_list]
    assert any("Service" in n for n in names)
    for e in evidence_list:
        assert (getattr(e, "confidence", None) or e.get("confidence")) == 1.0
        assert (getattr(e, "is_immutable", None) or e.get("is_immutable")) is True


def test_tier2_js_ast_scope_graph(js_obfuscated_bundle_path: Path) -> None:
    """Verify JavaScript AST analysis recovers mangled classes and methods."""
    session = mr_server.open_session(str(js_obfuscated_bundle_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]

    evidence_list = mr_server.query_evidence(session_id, symbol_or_addr="all", source="JS_AST_PROPAGATION")
    suggested = [getattr(e, "suggested_name", "") or e.get("suggested_name", "") for e in evidence_list]

    assert any("CryptoUtil" in s for s in suggested), f"CryptoUtil not recovered in: {suggested}"
    assert any("SessionManager" in s for s in suggested), f"SessionManager not recovered in: {suggested}"


def test_tier2_evidence_store_immutability_and_thread_safety() -> None:
    """Verify thread-safe concurrent writes and immutability protection in EvidenceStore."""
    import concurrent.futures

    from metis_reverse.core.evidence import EvidenceStore, ImmutableEvidenceError
    from metis_reverse.core.models import EvidenceSource, EvidenceTag, TargetType

    store = EvidenceStore()

    # Register immutable tag
    tag = EvidenceTag(
        tag_id="ev_test_immut",
        target_type=TargetType.FUNCTION,
        target_id="func:0x401000",
        suggested_name="target_func",
        source=EvidenceSource.GO_PCLNTAB,
        confidence=1.0,
        raw_anchor="pclntab",
        is_immutable=True,
    )
    store.add_tag(tag)
    assert store.has_immutable_tag("func:0x401000") is True

    # Attempt to overwrite with lower confidence or mutable tag
    tag_bad = EvidenceTag(
        tag_id="ev_test_immut",
        target_type=TargetType.FUNCTION,
        target_id="func:0x401000",
        suggested_name="hallucinated_name",
        source=EvidenceSource.HEURISTIC,
        confidence=0.3,
        is_immutable=False,
    )
    with pytest.raises(ImmutableEvidenceError):
        store.add_tag(tag_bad)

    # Concurrency stress test
    def worker_writer(idx: int) -> None:
        for i in range(100):
            t = EvidenceTag(
                tag_id=f"ev_worker_{idx}_{i}",
                target_type=TargetType.VARIABLE,
                target_id=f"var_{idx}_{i}",
                confidence=0.8,
                is_immutable=False,
            )
            store.add_tag(t)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(worker_writer, w) for w in range(8)]
        concurrent.futures.wait(futures)

    assert len(store) == 1 + (8 * 100)


def test_tier2_fastmcp_query_evidence_filters(go_pipeline_stripped_path: Path) -> None:
    """Verify FastMCP query_evidence tool supports filtering by address, name, source, and confidence."""
    session = mr_server.open_session(str(go_pipeline_stripped_path))
    session_id = session.session_id if hasattr(session, "session_id") else session["session_id"]

    # Query all
    all_ev = mr_server.query_evidence(session_id, symbol_or_addr="all")
    assert len(all_ev) > 0

    # Query specific function by name
    main_ev = mr_server.query_evidence(session_id, symbol_or_addr="main.main")
    assert len(main_ev) > 0
    assert any((getattr(e, "suggested_name", "") or e.get("suggested_name", "")) == "main.main" for e in main_ev)

    # Filter by source
    go_ev = mr_server.query_evidence(session_id, symbol_or_addr="all", source="GO_PCLNTAB")
    assert len(go_ev) > 0
    for e in go_ev:
        src = getattr(e, "source", None) or e.get("source")
        assert (src.value if hasattr(src, "value") else str(src)) == "GO_PCLNTAB"

    # Filter by min_confidence
    high_conf_ev = mr_server.query_evidence(session_id, symbol_or_addr="all", min_confidence=0.99)
    assert len(high_conf_ev) > 0

