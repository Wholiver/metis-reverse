"""SidecarStore: Independent storage, snapshot, and cross-version transfer for annotations."""

import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
import datetime

from .models import (
    SidecarDatabase,
    FunctionAnnotation,
    StructDefinition,
    StructField,
    VariableAnnotation,
    EvidencePointer,
)

class SidecarStore:
    """Manages reading, writing, snapshotting, and transferring annotation sidecars."""

    def __init__(self, storage_dir: Path):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _get_path(self, sha256_hash: str, ext: str = "yaml") -> Path:
        return self.storage_dir / f"{sha256_hash}.metis.{ext}"

    def save(self, db: SidecarDatabase, format_type: str = "yaml", custom_path: Optional[Path] = None) -> Path:
        """Persists the sidecar database to disk."""
        db.updated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        data = db.to_dict()
        file_path = Path(custom_path) if custom_path else self._get_path(db.sample_sha256, ext=format_type)
        file_path.parent.mkdir(parents=True, exist_ok=True)

        if format_type == "yaml" or str(file_path).endswith(".yaml") or str(file_path).endswith(".yml"):
            with open(file_path, "w", encoding="utf-8") as f:
                yaml.dump(data, f, sort_keys=False, allow_unicode=True)
        else:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

        return file_path

    def load(self, sha256_hash: str) -> Optional[SidecarDatabase]:
        """Loads a sidecar database from disk, checking YAML then JSON."""
        yaml_path = self._get_path(sha256_hash, "yaml")
        json_path = self._get_path(sha256_hash, "json")

        raw_data = None
        if yaml_path.exists():
            with open(yaml_path, "r", encoding="utf-8") as f:
                raw_data = yaml.safe_load(f)
        elif json_path.exists():
            with open(json_path, "r", encoding="utf-8") as f:
                raw_data = json.load(f)

        if not raw_data:
            return None

        return self._deserialize(raw_data)

    def get_or_create(self, sha256_hash: str, sample_name: str) -> SidecarDatabase:
        """Loads existing sidecar or creates a new empty one."""
        existing = self.load(sha256_hash)
        if existing:
            return existing
        db = SidecarDatabase(sample_sha256=sha256_hash, sample_name=sample_name)
        self.save(db)
        return db

    def _deserialize(self, data: Dict[str, Any]) -> SidecarDatabase:
        db = SidecarDatabase(
            sample_sha256=data.get("sample_sha256", ""),
            sample_name=data.get("sample_name", ""),
            schema_version=data.get("schema_version", "2.0"),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
            global_comments=data.get("global_comments", {}),
            crypto_findings=data.get("crypto_findings", []),
            api_hashes=data.get("api_hashes", {}),
            findings=data.get("findings", []),
        )

        for va, f_data in data.get("functions", {}).items():
            fn = FunctionAnnotation(
                original_va=f_data.get("original_va", va),
                original_name=f_data.get("original_name", ""),
                renamed_to=f_data.get("renamed_to"),
                signature=f_data.get("signature"),
                return_type=f_data.get("return_type"),
                cfg_hash=f_data.get("cfg_hash"),
                constants_fingerprint=f_data.get("constants_fingerprint", []),
                callees=f_data.get("callees", []),
                comments=f_data.get("comments", {}),
                algorithm_tags=f_data.get("algorithm_tags", []),
            )
            for v_data in f_data.get("variables", []):
                fn.variables.append(VariableAnnotation(**v_data))
            for e_data in f_data.get("evidence", []):
                fn.evidence.append(EvidencePointer(**e_data))
            db.functions[va] = fn

        for name, s_data in data.get("structs", {}).items():
            st = StructDefinition(
                name=s_data.get("name", name),
                size=s_data.get("size", 0),
                evidence_va=s_data.get("evidence_va", "N/A"),
                comment=s_data.get("comment", ""),
            )
            for fld in s_data.get("fields", []):
                st.fields.append(StructField(**fld))
            db.structs[name] = st

        return db

    def transfer_to_target(
        self,
        source_db: SidecarDatabase,
        target_functions: List[Dict[str, Any]],
        target_sha256: str,
        target_name: str,
    ) -> Tuple[SidecarDatabase, Dict[str, Any]]:
        """Transfers annotations from source_db to a target binary based on heuristic matching.
        
        Matches by:
        1. Exact CFG Hash
        2. High overlap of constants fingerprint
        3. Callee set similarity
        """
        target_db = self.get_or_create(target_sha256, target_name)
        # Migrate all structs directly (data structures are typically invariant across patch versions)
        for s_name, s_def in source_db.structs.items():
            target_db.structs[s_name] = s_def

        # Migrate known crypto patterns and API hashes
        target_db.crypto_findings.extend(source_db.crypto_findings)
        target_db.api_hashes.update(source_db.api_hashes)

        matched_records = []
        unmatched_source = []

        is_self_transfer = (source_db.sample_sha256 == target_sha256)

        # Index target functions by cfg_hash, constants, va, and name
        target_by_cfg = {}
        target_by_va = {}
        target_by_name = {}
        for tf in target_functions:
            cfg = tf.get("cfg_hash")
            if cfg:
                target_by_cfg[cfg] = tf
            t_va = tf.get("va")
            if t_va:
                target_by_va[t_va] = tf
            t_name = tf.get("name")
            if t_name and not t_name.startswith("FUN_") and not t_name.startswith("sub_"):
                target_by_name[t_name] = tf

        for src_va, src_fn in source_db.functions.items():
            # If no meaningful annotation, skip
            if not src_fn.renamed_to and not src_fn.signature and not src_fn.variables and not src_fn.comments:
                continue

            matched_target_va = None
            match_reason = None

            if is_self_transfer:
                matched_target_va = src_va
                match_reason = "self_transfer_identical_sha"
            # 1. Exact CFG Hash match
            elif src_fn.cfg_hash and src_fn.cfg_hash in target_by_cfg:
                matched_target_va = target_by_cfg[src_fn.cfg_hash]["va"]
                match_reason = "exact_cfg_hash"
            # 2. Check constant fingerprint intersection
            else:
                best_score = 0.0
                best_candidate = None
                src_consts = set(src_fn.constants_fingerprint)
                if len(src_consts) >= 2:
                    for tf in target_functions:
                        tgt_consts = set(tf.get("constants_fingerprint", []))
                        if tgt_consts:
                            overlap = len(src_consts & tgt_consts)
                            union = len(src_consts | tgt_consts)
                            jaccard = overlap / union if union > 0 else 0
                            if jaccard > 0.6 and jaccard > best_score:
                                best_score = jaccard
                                best_candidate = tf["va"]
                    if best_candidate:
                        matched_target_va = best_candidate
                        match_reason = f"constants_similarity_{round(best_score, 2)}"

                # 3. Same symbol name if known
                if not matched_target_va and src_fn.original_name in target_by_name:
                    matched_target_va = target_by_name[src_fn.original_name]["va"]
                    match_reason = "symbol_name_match"

                # 4. Same VA if function exists at same address in target
                if not matched_target_va and src_va in target_by_va:
                    matched_target_va = src_va
                    match_reason = "same_virtual_address"

            if matched_target_va:
                # Clone annotation with updated target VA
                new_fn = FunctionAnnotation(
                    original_va=matched_target_va,
                    original_name=target_by_cfg.get(src_fn.cfg_hash, {}).get("name", src_fn.original_name),
                    renamed_to=src_fn.renamed_to,
                    signature=src_fn.signature,
                    return_type=src_fn.return_type,
                    cfg_hash=src_fn.cfg_hash,
                    constants_fingerprint=src_fn.constants_fingerprint,
                    callees=src_fn.callees,
                    variables=src_fn.variables,
                    comments=src_fn.comments,
                    algorithm_tags=src_fn.algorithm_tags,
                    evidence=[
                        EvidencePointer(
                            va=matched_target_va,
                            evidence_type="cross_version_transfer",
                            description=f"Transferred from {source_db.sample_name}:{src_va} via {match_reason}",
                            confidence=0.9 if match_reason == "exact_cfg_hash" else 0.75,
                            status="corroborated",
                            provenance="transferred",
                        )
                    ],
                )
                target_db.functions[matched_target_va] = new_fn
                matched_records.append({
                    "source_va": src_va,
                    "target_va": matched_target_va,
                    "renamed_to": src_fn.renamed_to,
                    "match_reason": match_reason,
                })
            else:
                unmatched_source.append({
                    "source_va": src_va,
                    "name": src_fn.renamed_to or src_fn.original_name,
                })

        self.save(target_db)

        report = {
            "source_sample": source_db.sample_sha256,
            "target_sample": target_sha256,
            "matched_count": len(matched_records),
            "unmatched_count": len(unmatched_source),
            "matches": matched_records,
            "unmatched": unmatched_source,
            "structs_migrated": len(target_db.structs),
        }
        return target_db, report
