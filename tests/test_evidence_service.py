"""Tests for EvidenceService provenance tracking and negative search auditing."""

from metis_reverse.services.evidence_service import EvidenceService
from metis_reverse.storage.models import EvidencePointer, SidecarDatabase, FunctionAnnotation

def test_evidence_service_finds_registered_evidence():
    svc = EvidenceService()
    session_key = "test_sess"

    ptr = EvidencePointer(
        va="0x140001050",
        evidence_type="crypto_sbox",
        description="AES S-Box table discovered",
        confidence=1.0,
    )
    svc.register_evidence(session_key, ptr)

    res = svc.query("0x140001050", session_key)
    assert res["status"] == "found"
    assert res["provenance_verified"] is True
    assert res["evidence_count"] == 1
    assert res["evidence"][0]["va"] == "0x140001050"

def test_evidence_service_negative_audit_report():
    svc = EvidenceService()
    session_key = "test_sess"

    # Query for nonexistent entity
    res = svc.query("nonexistent_symbol_or_key", session_key)

    assert res["status"] == "not_found"
    assert res["provenance_verified"] is False
    assert "searched_locations" in res
    assert "ephemeral_evidence_cache" in res["searched_locations"]
    assert "Do NOT fabricate" in res["instruction_for_agent"]
