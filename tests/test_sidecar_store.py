"""Tests for SidecarStore annotation persistence and cross-version transfer."""

import tempfile
from pathlib import Path
from metis_reverse.storage.models import (
    SidecarDatabase,
    FunctionAnnotation,
    VariableAnnotation,
    StructDefinition,
    StructField,
    EvidencePointer,
)
from metis_reverse.storage.sidecar_store import SidecarStore

def test_sidecar_save_load_yaml():
    with tempfile.TemporaryDirectory() as tmp_dir:
        store = SidecarStore(storage_dir=Path(tmp_dir))
        sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

        db = store.get_or_create(sha, "sample_v1.exe")
        db.functions["0x140001000"] = FunctionAnnotation(
            original_va="0x140001000",
            original_name="FUN_140001000",
            renamed_to="decrypt_aes_block",
            signature="void decrypt_aes_block(BYTE* buf, int len)",
            cfg_hash="cfg_hash_12345",
            constants_fingerprint=[0x637c777b, 0x5a],
        )
        db.structs["MALWARE_HEADER"] = StructDefinition(
            name="MALWARE_HEADER",
            size=16,
            fields=[
                StructField(offset=0, name="magic", field_type="DWORD", size=4),
                StructField(offset=4, name="payload_len", field_type="DWORD", size=4),
            ],
            evidence_va="0x140002000"
        )

        saved_path = store.save(db, format_type="yaml")
        assert saved_path.exists()

        # Reload
        loaded = store.load(sha)
        assert loaded is not None
        assert loaded.sample_name == "sample_v1.exe"
        assert "0x140001000" in loaded.functions
        assert loaded.functions["0x140001000"].renamed_to == "decrypt_aes_block"
        assert "MALWARE_HEADER" in loaded.structs
        assert len(loaded.structs["MALWARE_HEADER"].fields) == 2

def test_sidecar_cross_version_transfer():
    with tempfile.TemporaryDirectory() as tmp_dir:
        store = SidecarStore(storage_dir=Path(tmp_dir))
        sha_v1 = "1111111111111111111111111111111111111111111111111111111111111111"
        sha_v2 = "2222222222222222222222222222222222222222222222222222222222222222"

        db_v1 = store.get_or_create(sha_v1, "sample_v1.exe")
        db_v1.functions["0x140001200"] = FunctionAnnotation(
            original_va="0x140001200",
            original_name="FUN_140001200",
            renamed_to="unpack_second_stage",
            cfg_hash="cfg_unique_unpack_alg",
            constants_fingerprint=[0x9e3779b9, 0x1000],
        )

        # In target v2, function shifted to 0x140001800, but has identical CFG hash
        target_functions = [
            {
                "va": "0x140001800",
                "name": "FUN_140001800",
                "cfg_hash": "cfg_unique_unpack_alg",
                "constants_fingerprint": [0x9e3779b9, 0x1000],
            }
        ]

        target_db, report = store.transfer_to_target(
            source_db=db_v1,
            target_functions=target_functions,
            target_sha256=sha_v2,
            target_name="sample_v2.exe"
        )

        assert report["matched_count"] == 1
        assert "0x140001800" in target_db.functions
        assert target_db.functions["0x140001800"].renamed_to == "unpack_second_stage"
        assert target_db.functions["0x140001800"].evidence[0].evidence_type == "cross_version_transfer"
