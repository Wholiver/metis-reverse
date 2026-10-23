"""Data models for Evidence-grounded annotations and persistent Sidecar stores."""

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
import datetime

@dataclass
class EvidencePointer:
    """Explicit evidence pointer binding every finding to concrete addresses."""
    va: str                                # Virtual address (e.g., "0x140001050")
    evidence_type: str                     # e.g., "string_ref", "const_sbox", "call_graph", "emulation"
    description: str
    confidence: float = 1.0               # 0.0 - 1.0
    raw_bytes_hex: Optional[str] = None
    source_component: str = "static_analysis"
    status: str = "proven"                 # "proven", "corroborated", "hypothesis" (R1)
    claim: str = ""                        # Finding claim or hypothesis statement
    provenance: Optional[str] = None       # e.g. "transferred", "manual", "decompiled" (R7)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class VariableAnnotation:
    """Local variable or parameter type refinement."""
    original_name: str                     # e.g. "uVar1"
    renamed_to: str                        # e.g. "pDecryptedBuffer"
    inferred_type: str                     # e.g. "BYTE*"
    evidence_va: str = "N/A"
    comment: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class StructField:
    """Field inside an inferred structure."""
    offset: int
    name: str
    field_type: str
    size: int
    comment: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class StructDefinition:
    """Recovered data structure definition."""
    name: str
    size: int
    fields: List[StructField] = field(default_factory=list)
    evidence_va: str = "N/A"
    comment: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "size": self.size,
            "fields": [f.to_dict() for f in self.fields],
            "evidence_va": self.evidence_va,
            "comment": self.comment,
        }

@dataclass
class FunctionAnnotation:
    """Comprehensive annotation for a function."""
    original_va: str
    original_name: str
    renamed_to: Optional[str] = None
    signature: Optional[str] = None
    return_type: Optional[str] = None
    cfg_hash: Optional[str] = None         # Normalized CFG hash for cross-version matching
    constants_fingerprint: List[int] = field(default_factory=list)
    callees: List[str] = field(default_factory=list)
    variables: List[VariableAnnotation] = field(default_factory=list)
    comments: Dict[str, str] = field(default_factory=dict) # VA -> comment
    algorithm_tags: List[str] = field(default_factory=list)
    evidence: List[EvidencePointer] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_va": self.original_va,
            "original_name": self.original_name,
            "renamed_to": self.renamed_to,
            "signature": self.signature,
            "return_type": self.return_type,
            "cfg_hash": self.cfg_hash,
            "constants_fingerprint": self.constants_fingerprint,
            "callees": self.callees,
            "variables": [v.to_dict() for v in self.variables],
            "comments": self.comments,
            "algorithm_tags": self.algorithm_tags,
            "evidence": [e.to_dict() for e in self.evidence],
        }

@dataclass
class SidecarDatabase:
    """Decoupled annotation database stored as sidecar JSON/YAML."""
    sample_sha256: str
    sample_name: str
    schema_version: str = "2.0"
    created_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat())
    functions: Dict[str, FunctionAnnotation] = field(default_factory=dict)
    structs: Dict[str, StructDefinition] = field(default_factory=dict)
    global_comments: Dict[str, str] = field(default_factory=dict) # VA -> comment
    crypto_findings: List[Dict[str, Any]] = field(default_factory=list)
    api_hashes: Dict[str, str] = field(default_factory=dict)     # HashHex -> ApiName
    findings: List[Dict[str, Any]] = field(default_factory=list) # Tiered evidence findings (R1)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sample_sha256": self.sample_sha256,
            "sample_name": self.sample_name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "functions": {k: v.to_dict() for k, v in self.functions.items()},
            "structs": {k: v.to_dict() for k, v in self.structs.items()},
            "global_comments": self.global_comments,
            "crypto_findings": self.crypto_findings,
            "api_hashes": self.api_hashes,
            "findings": self.findings,
        }
