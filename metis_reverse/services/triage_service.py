"""TriageService: Initial triage, packer detection, and domain-aware tool semantics."""

import math
import struct
from pathlib import Path
from typing import Dict, Any, List, Optional

def calculate_entropy(data: bytes) -> float:
    """Calculates Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    total = len(data)
    for count in freq:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 3)

class TriageService:
    """Performs rapid triage, packer detection, and domain-aware exit code translation."""

    @staticmethod
    def parse_tool_exit_code(tool_name: str, exit_code: int, stdout: str) -> Dict[str, Any]:
        """Translates reverse engineering tool exit codes with domain awareness.
        
        For example: YARA exit code 1 or grep exit code 0 often indicates 'MATCH_FOUND',
        not an execution failure.
        """
        tool = tool_name.lower()
        if "yara" in tool:
            # YARA returns 0 if no match, or matches printed.
            # Some wrappers or plugins return exit code 1 or non-zero when matches occur.
            if "match" in stdout.lower() or exit_code == 1 or len(stdout.strip()) > 0:
                return {
                    "tool": tool_name,
                    "semantic_status": "MATCHES_FOUND",
                    "has_findings": True,
                    "raw_exit_code": exit_code,
                    "explanation": "Tool returned non-zero or output indicating signature detection, treated as positive findings.",
                }
            return {
                "tool": tool_name,
                "semantic_status": "CLEAN_NO_MATCH",
                "has_findings": False,
                "raw_exit_code": exit_code,
                "explanation": "No matching signatures found.",
            }
        elif "die" in tool or "detectiteasy" in tool:
            # DIE CLI returns detection results
            return {
                "tool": tool_name,
                "semantic_status": "SIGNATURES_PARSED",
                "has_findings": True,
                "raw_exit_code": exit_code,
                "explanation": "Compiler/Packer signatures extracted.",
            }

        # Default fallback
        return {
            "tool": tool_name,
            "semantic_status": "SUCCESS" if exit_code == 0 else "ERROR",
            "has_findings": exit_code == 0,
            "raw_exit_code": exit_code,
            "explanation": "Standard process completion.",
        }

    def triage_file(self, file_path: str) -> Dict[str, Any]:
        """Performs initial triage on a binary file."""
        p = Path(file_path)
        if not p.is_file():
            return {"status": "error", "message": f"File not found: {file_path}"}

        size = p.stat().st_size
        freq = [0] * 256
        total_bytes = 0
        header = b""
        max_block_entropy = 0.0
        upx_found = False

        # Read entire file in 4096-byte blocks to compute full-file Shannon entropy and block heatmaps
        with open(p, "rb") as f:
            while True:
                block = f.read(4096)
                if not block:
                    break
                if not header:
                    header = block
                total_bytes += len(block)
                for b in block:
                    freq[b] += 1

                block_ent = calculate_entropy(block)
                if block_ent > max_block_entropy:
                    max_block_entropy = block_ent

                if not upx_found and (b"UPX0" in block or b"UPX1" in block or b"UPX!" in block):
                    upx_found = True

        overall_entropy = 0.0
        if total_bytes > 0:
            for count in freq:
                if count > 0:
                    p_c = count / total_bytes
                    overall_entropy -= p_c * math.log2(p_c)
            overall_entropy = round(overall_entropy, 3)

        header_entropy = calculate_entropy(header)
        detected_format = "Unknown / Raw Binary"
        indicators = []

        if header.startswith(b"MZ"):
            detected_format = "PE (Portable Executable - Windows)"
            if len(header) > 0x3c + 4:
                pe_offset = struct.unpack("<I", header[0x3c:0x40])[0]
                if pe_offset < len(header) - 4 and header[pe_offset:pe_offset+4] == b"PE\x00\x00":
                    indicators.append("Valid PE Header confirmed")
        elif header.startswith(b"\x7fELF"):
            detected_format = "ELF (Executable and Linkable Format - Linux/Unix)"
            indicators.append("Valid ELF Magic confirmed")
        elif (header.startswith(b"\xfe\xed\xfa\xce") or 
              header.startswith(b"\xce\xfa\xed\xfe") or
              header.startswith(b"\xfe\xed\xfa\xcf") or
              header.startswith(b"\xcf\xfa\xed\xfe") or 
              header.startswith(b"\xca\xfe\xba\xbe")):
            detected_format = "Mach-O (macOS/iOS)"
            indicators.append("Valid Mach-O Magic confirmed")

        is_packed = overall_entropy > 7.0 or max_block_entropy > 7.2 or upx_found

        if overall_entropy > 7.0:
            indicators.append(f"High overall file entropy ({overall_entropy} / 8.0) strongly suggests encryption or packing")
        elif max_block_entropy > 7.2:
            indicators.append(f"High block entropy detected ({max_block_entropy} / 8.0) indicating packed/encrypted payload section")

        if upx_found:
            indicators.append("UPX Packer section signature identified")

        is_bun = False
        if header.startswith(b"\xfe\xed") or header.startswith(b"\xcf\xfa") or b"ELF" in header or b"MZ" in header:
            # Check for Bun trailer
            if size > 1024:
                try:
                    with open(p, "rb") as f:
                        f.seek(max(0, size - 4096))
                        tail = f.read(4096)
                        if b"---- Bun! ----" in tail or b"Bun!" in tail:
                            is_bun = True
                            indicators.append("Bun standalone composite executable detected with embedded JS modules and native libraries")
                except Exception:
                    pass

        return {
            "status": "success",
            "file_name": p.name,
            "file_size_bytes": size,
            "detected_format": detected_format,
            "overall_entropy": overall_entropy,
            "header_entropy": header_entropy,
            "max_block_entropy": max_block_entropy,
            "is_packed_or_encrypted": is_packed,
            "is_bun_standalone": is_bun,
            "memory_view_unreliable": False,
            "triage_indicators": indicators,
            "recommended_next_step": "re_hunt_crypto_and_hashes" if is_packed else "re_query_function",
        }
