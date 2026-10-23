"""EvidenceService: Tracking provenance for every symbol, type, and algorithm deduction."""

from typing import Dict, Any, List, Optional
from ..storage.models import EvidencePointer, SidecarDatabase

class EvidenceService:
    """Manages explicit evidence linkage and produces strict negative search audits."""

    def __init__(self):
        # Ephemeral evidence cache keyed by session/sha256
        self._evidence_cache: Dict[str, List[EvidencePointer]] = {}

    def register_evidence(self, session_key: str, pointer: EvidencePointer) -> None:
        """Registers a verified evidence pointer."""
        if session_key not in self._evidence_cache:
            self._evidence_cache[session_key] = []
        self._evidence_cache[session_key].append(pointer)

    def query(
        self,
        query_target: str,
        session_key: str,
        sidecar_db: Optional[SidecarDatabase] = None,
    ) -> Dict[str, Any]:
        """Queries for provenance of an address, symbol, or conclusion.
        
        Strictly returns 'not_found' with audited search locations rather than guessing.
        """
        searched_locations = [
            "ephemeral_evidence_cache",
            "sidecar_functions_registry",
            "sidecar_struct_definitions",
            "sidecar_crypto_findings",
            "sidecar_api_hashes",
            "sidecar_findings_registry",
        ]

        matched_evidence: List[Dict[str, Any]] = []

        # 1. Search ephemeral cache
        cached_ptrs = self._evidence_cache.get(session_key, [])
        for ptr in cached_ptrs:
            if (query_target.lower() in ptr.va.lower() or 
                query_target.lower() in ptr.description.lower() or 
                query_target.lower() in ptr.evidence_type.lower()):
                matched_evidence.append(ptr.to_dict())

        # 2. Search sidecar database if available
        if sidecar_db:
            # Check functions
            for va, fn in sidecar_db.functions.items():
                if (query_target.lower() in va.lower() or 
                    (fn.renamed_to and query_target.lower() in fn.renamed_to.lower()) or 
                    query_target.lower() in fn.original_name.lower()):
                    for ev in fn.evidence:
                        matched_evidence.append(ev.to_dict())
                # Check variables inside function
                for var in fn.variables:
                    if (query_target.lower() in var.renamed_to.lower() or 
                        query_target.lower() in var.original_name.lower()):
                        matched_evidence.append({
                            "va": var.evidence_va,
                            "evidence_type": "variable_annotation",
                            "description": f"Variable '{var.original_name}' typed as '{var.inferred_type}' and renamed to '{var.renamed_to}' inside {fn.renamed_to or fn.original_name}",
                            "confidence": 0.95,
                        })

            # Check structs
            for s_name, s_def in sidecar_db.structs.items():
                if query_target.lower() in s_name.lower():
                    matched_evidence.append({
                        "va": s_def.evidence_va,
                        "evidence_type": "struct_definition",
                        "description": f"Struct '{s_name}' (size {s_def.size} bytes) defined at {s_def.evidence_va}",
                        "confidence": 0.9,
                    })

            # Check crypto findings
            for cf in sidecar_db.crypto_findings:
                if (query_target.lower() in str(cf.get("algorithm", "")).lower() or 
                    query_target.lower() in str(cf.get("va", "")).lower()):
                    matched_evidence.append({
                        "va": cf.get("va", "N/A"),
                        "evidence_type": "crypto_detection",
                        "description": f"Cryptographic primitive '{cf.get('algorithm')}' verified with confidence {cf.get('confidence', 1.0)}",
                        "confidence": cf.get("confidence", 1.0),
                    })

            # Check API hashes
            for h_val, api_name in sidecar_db.api_hashes.items():
                if query_target.lower() in h_val.lower() or query_target.lower() in api_name.lower():
                    matched_evidence.append({
                        "va": "N/A",
                        "evidence_type": "api_hash_resolved",
                        "description": f"API Hash {h_val} resolved to Windows export '{api_name}'",
                        "confidence": 1.0,
                    })

            # Check tiered findings (R1)
            for f_item in getattr(sidecar_db, "findings", []):
                if (query_target.lower() in str(f_item.get("claim", "")).lower() or
                    query_target.lower() in str(f_item.get("status", "")).lower()):
                    matched_evidence.append({
                        "va": f_item.get("evidence", [{}])[0].get("va", "N/A") if f_item.get("evidence") else "N/A",
                        "evidence_type": f"tiered_finding_{f_item.get('status', 'hypothesis')}",
                        "description": f"[{f_item.get('status', 'hypothesis').upper()}] {f_item.get('claim', '')}",
                        "confidence": f_item.get("confidence", 0.8),
                        "status": f_item.get("status", "hypothesis"),
                    })

        if matched_evidence:
            return {
                "status": "found",
                "query": query_target,
                "evidence_count": len(matched_evidence),
                "evidence": matched_evidence,
                "provenance_verified": True
            }

        # Definite negative audit report
        return {
            "status": "not_found",
            "query": query_target,
            "searched_locations": searched_locations,
            "diagnostic_message": f"No concrete evidence, address binding, or verified annotation exists for '{query_target}'.",
            "instruction_for_agent": "Do NOT fabricate or hallucinate any algorithm, variable name, or memory layout. Verify with re_query_function or re_verify_hypothesis first.",
            "provenance_verified": False
        }

    def add_finding(
        self,
        session_key: str,
        claim: str,
        evidence: List[Dict[str, Any]],
        confidence: float = 1.0,
        status: str = "proven", # "proven", "corroborated", "hypothesis" (R1)
        sidecar_db: Optional[SidecarDatabase] = None,
    ) -> Dict[str, Any]:
        """Adds a tiered finding per R1: proven, corroborated, or hypothesis."""
        valid_statuses = ("proven", "corroborated", "hypothesis")
        if status not in valid_statuses:
            status = "hypothesis"

        finding = {
            "claim": claim,
            "evidence": evidence,
            "confidence": max(0.0, min(1.0, float(confidence))),
            "status": status,
        }

        # Register evidence pointers into ephemeral cache
        for ev in evidence:
            ptr = EvidencePointer(
                va=ev.get("va", "N/A"),
                evidence_type=ev.get("type", "finding_evidence"),
                description=f"Evidence for [{status}]: {claim}",
                confidence=confidence,
                raw_bytes_hex=ev.get("raw_bytes_hex"),
                status=status,
                claim=claim,
            )
            self.register_evidence(session_key, ptr)

        if sidecar_db is not None:
            sidecar_db.findings.append(finding)

        return {
            "status": "recorded",
            "finding": finding,
            "message": f"Finding registered with tier '{status}' (confidence {confidence}).",
        }
