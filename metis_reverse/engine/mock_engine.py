"""MockEngine: High-fidelity simulation engine for offline testing and fallback."""

import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional
from .base import BaseReEngine

class MockEngine(BaseReEngine):
    """Simulates a full-featured Ghidra backend for automated tests and development."""

    def __init__(self):
        self._sessions: Dict[str, Dict[str, Any]] = {}

    def open_session(self, binary_path: str, session_id: str) -> Dict[str, Any]:
        # Compute real file sha256 if file exists, fallback to path hash
        p = Path(binary_path)
        if p.is_file():
            with open(p, "rb") as f:
                sha = hashlib.sha256(f.read()).hexdigest()
        else:
            sha = hashlib.sha256(binary_path.encode()).hexdigest()
        
        # Pre-seed realistic functions and analysis data
        self._sessions[session_id] = {
            "binary_path": binary_path,
            "session_id": session_id,
            "sha256": sha,
            "format": "PE64 / ELF64",
            "arch": "x86_64",
            "entrypoint": "0x140001000",
            "functions": {
                "0x140001000": {
                    "va": "0x140001000",
                    "name": "entry",
                    "code": "void entry(void) {\n  init_runtime();\n  FUN_140001200();\n  return;\n}",
                    "callers": [],
                    "callees": [{"va": "0x140001100", "name": "init_runtime"}, {"va": "0x140001200", "name": "FUN_140001200"}],
                    "strings": [{"va": "0x140003010", "text": "Starting worker thread..."}],
                    "constants": [0x1000, 0x0],
                    "cfg_hash": "cfg_a1b2c3d4e5",
                },
                "0x140001200": {
                    "va": "0x140001200",
                    "name": "FUN_140001200",
                    "code": "int FUN_140001200(void) {\n  byte *buf = (byte *)0x140004000;\n  for (int i = 0; i < 32; i++) {\n    buf[i] ^= 0x5a;\n  }\n  return 0;\n}",
                    "callers": [{"va": "0x140001000", "name": "entry"}],
                    "callees": [],
                    "strings": [{"va": "0x140003050", "text": "encrypted_blob_marker"}],
                    "constants": [0x5a, 32, 0x140004000],
                    "cfg_hash": "cfg_f6e5d4c3b2",
                },
                "0x140001500": {
                    "va": "0x140001500",
                    "name": "FUN_140001500",
                    "code": "void FUN_140001500(void) {\n  // AES S-Box constant reference\n  unsigned int sbox_ref = 0x637c777b;\n  process_data();\n}",
                    "callers": [],
                    "callees": [{"va": "0x140001600", "name": "process_data"}],
                    "strings": [],
                    "constants": [0x637c777b],
                    "cfg_hash": "cfg_9988776655",
                }
            },
            # Simulated memory: at 0x140004000 put XORed string "Hello_From_Payload" with key 0x5a
            "memory": {
                "0x140001200": bytes([
                    0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20,
                    0xb8, 0x01, 0x00, 0x00, 0x00, 0x83, 0xc0, 0x02,
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
                ]),
                "0x140004000": bytes([b ^ 0x5a for b in b"Hello_From_Payload\x00\x00\x00\x00"]),
                "0x140005000": bytes([0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5]), # AES S-box prefix
            }
        }
        return {
            "session_id": session_id,
            "status": "ready",
            "sample_sha256": sha,
            "architecture": "x86_64",
            "format": "PE64 / ELF64",
            "function_count": 3,
        }

    def close_session(self, session_id: str) -> None:
        if session_id in self._sessions:
            del self._sessions[session_id]

    def get_metadata(self, session_id: str) -> Dict[str, Any]:
        sess = self._sessions.get(session_id)
        if not sess:
            raise KeyError(f"Session {session_id} not found")
        return {
            "sha256": sess["sha256"],
            "format": sess["format"],
            "arch": sess["arch"],
            "entrypoint": sess["entrypoint"],
            "binary_path": sess["binary_path"],
        }

    def list_functions(self, session_id: str, offset: int = 0, limit: int = 50) -> Dict[str, Any]:
        sess = self._sessions.get(session_id)
        if not sess:
            raise KeyError(f"Session {session_id} not found")
        fn_list = list(sess["functions"].values())
        total = len(fn_list)
        paged = fn_list[offset:offset + limit]
        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "functions": [{"va": f["va"], "name": f["name"], "cfg_hash": f["cfg_hash"]} for f in paged]
        }

    def get_function_context(self, session_id: str, va: str, max_tokens: int = 2048) -> Dict[str, Any]:
        sess = self._sessions.get(session_id)
        if not sess:
            raise KeyError(f"Session {session_id} not found")
        fn = sess["functions"].get(va)
        if not fn:
            # Try searching by name
            for f in sess["functions"].values():
                if f["name"] == va:
                    fn = f
                    break
        if not fn:
            return {
                "status": "not_found",
                "va": va,
                "message": f"Function at '{va}' not found in binary"
            }

        return {
            "status": "success",
            "va": fn["va"],
            "name": fn["name"],
            "decompiled_code": fn["code"],
            "callers": fn["callers"],
            "callees": fn["callees"],
            "referenced_strings": fn["strings"],
            "referenced_constants": fn["constants"],
            "cfg_hash": fn["cfg_hash"],
        }

    def get_memory_slice(self, session_id: str, va: str, size: int) -> bytes:
        sess = self._sessions.get(session_id)
        if not sess:
            return b""
        mem = sess.get("memory", {})
        if va in mem:
            return mem[va][:size]
        return b"\x00" * size

    def apply_refinements(self, session_id: str, refinements: Dict[str, Any]) -> Dict[str, Any]:
        sess = self._sessions.get(session_id)
        if not sess:
            raise KeyError(f"Session {session_id} not found")
        
        applied = []
        fn_renames = refinements.get("function_renames", {})
        for va, new_name in fn_renames.items():
            if va in sess["functions"]:
                old_name = sess["functions"][va]["name"]
                sess["functions"][va]["name"] = new_name
                applied.append(f"Renamed function {old_name} -> {new_name} at {va}")

        return {"applied_count": len(applied), "details": applied}

    def read_file_range(self, session_id: str, offset: int, length: int) -> bytes:
        sess = self._sessions.get(session_id)
        if not sess:
            return b""
        p = Path(sess.get("binary_path", ""))
        if p.is_file():
            try:
                with open(p, "rb") as f:
                    f.seek(offset)
                    return f.read(length)
            except Exception:
                pass
        return b"\x00" * length

    def translate_address(self, session_id: str, value: Any, from_kind: str = "va") -> Dict[str, Any]:
        val_str = str(value)
        val_int = int(val_str, 16) if val_str.startswith("0x") else int(val_str)
        img_base = 0x140000000
        if from_kind == "va":
            va = val_int
            rva = max(0, va - img_base)
            file_off = rva
        elif from_kind == "rva":
            rva = val_int
            va = img_base + rva
            file_off = rva
        else: # file_offset
            file_off = val_int
            rva = file_off
            va = img_base + rva

        return {
            "va": hex(va),
            "rva": hex(rva),
            "file_offset": file_off,
            "segment": ".text" if rva < 0x2000 else ".data",
            "section": ".text" if rva < 0x2000 else ".data",
            "is_zero_fill": False,
            "image_base": hex(img_base),
        }

    def check_memory_consistency(self, session_id: str) -> Dict[str, Any]:
        return {
            "status": "consistent",
            "memory_view_unreliable": False,
            "discrepancies": [],
        }
