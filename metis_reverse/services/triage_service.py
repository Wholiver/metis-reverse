"""TriageService: Initial triage, packer detection, and domain-aware tool semantics."""

import math
import struct
import collections
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
        """Performs initial triage on a binary file, directory, or .app bundle."""
        p = Path(file_path)
        if not p.exists():
            return {"status": "error", "message": f"Path not found: {file_path}"}

        # 1. Directory / .app Bundle Triage
        if p.is_dir():
            is_app = p.name.endswith(".app") or (p / "Contents" / "Info.plist").is_file() or (p / "Info.plist").is_file()
            info_plist_p = p / "Contents" / "Info.plist" if (p / "Contents" / "Info.plist").is_file() else (p / "Info.plist" if (p / "Info.plist").is_file() else None)
            parsed_plist = {}
            main_exec = None
            if info_plist_p:
                try:
                    import plistlib
                    plist_data = info_plist_p.read_bytes()
                    parsed_plist = plistlib.loads(plist_data)
                    main_exec = parsed_plist.get("CFBundleExecutable")
                except Exception:
                    pass

            dyn_libs = []
            databases = []
            resources = []
            node_addons = []
            total_size = 0

            for f in p.rglob("*"):
                if f.is_file():
                    try:
                        sz = f.stat().st_size
                        total_size += sz
                        f_name_low = f.name.lower()
                        if f_name_low.endswith((".dylib", ".so", ".dll")):
                            dyn_libs.append(f.name)
                        elif f_name_low.endswith(".node"):
                            node_addons.append(f.name)
                        elif f_name_low.endswith((".sqlite", ".sqlite3", ".db")):
                            databases.append(f.name)
                        elif f_name_low in ("app.asar", "assets.car"):
                            resources.append(f.name)
                    except Exception:
                        pass

            indicators = [
                f"Directory bundle containing {len(dyn_libs)} libraries, {len(node_addons)} native addons, {len(databases)} embedded databases",
            ]
            if is_app:
                indicators.insert(0, f"macOS Application Bundle identified (executable: '{main_exec or 'unknown'}')")
            if resources:
                indicators.append(f"Significant embedded resources detected: {', '.join(resources)}")

            return {
                "status": "success",
                "file_name": p.name,
                "file_size_bytes": total_size,
                "is_directory_bundle": True,
                "is_macos_app": is_app,
                "detected_format": "macOS Application Bundle (.app)" if is_app else "Directory Bundle",
                "bundle_identifier": parsed_plist.get("CFBundleIdentifier") if parsed_plist else None,
                "bundle_executable": main_exec,
                "info_plist_parsed": parsed_plist if parsed_plist else None,
                "dynamic_libraries": list(dict.fromkeys(dyn_libs))[:20],
                "node_addons": list(dict.fromkeys(node_addons))[:20],
                "embedded_databases": list(dict.fromkeys(databases))[:10],
                "resources": list(dict.fromkeys(resources)),
                "overall_entropy": 5.0,
                "header_entropy": 4.5,
                "max_block_entropy": 5.5,
                "is_packed_or_encrypted": False,
                "is_bun_standalone": False,
                "memory_view_unreliable": False,
                "triage_indicators": indicators,
                "recommended_next_step": "re_inspect",
            }

        size = p.stat().st_size
        freq = [0] * 256
        total_bytes = 0
        header = b""
        max_block_entropy = 0.0
        upx_found = False

        # Efficient chunked streaming with C-level byte frequency counting and bounded entropy sampling
        chunk_size = 65536
        sample_interval = max(1, (size // 4096) // 128) if size > 0 else 1
        block_idx = 0

        with open(p, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                if not header:
                    header = chunk[:4096]
                total_bytes += len(chunk)

                # Fast C-level byte frequency counting
                for b, count in collections.Counter(chunk).items():
                    freq[b] += count

                if not upx_found and (b"UPX0" in chunk or b"UPX1" in chunk or b"UPX!" in chunk):
                    upx_found = True

                # Sample blocks to compute max block entropy without pinning CPU on large files
                for off in range(0, len(chunk), 4096):
                    sub_block = chunk[off:off + 4096]
                    if block_idx % sample_interval == 0:
                        block_ent = calculate_entropy(sub_block)
                        if block_ent > max_block_entropy:
                            max_block_entropy = block_ent
                    block_idx += 1

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
        elif (header.startswith(b"\xca\xfe\xba\xbe") and len(header) >= 8 and (header[4:6] == b"\x00\x00" or header[6:8] >= b"\x00\x28")):
            detected_format = "Java Class File (.class)"
            indicators.append("Standard Java Class bytecode confirmed")
        elif (header.startswith(b"\xfe\xed\xfa\xce") or 
              header.startswith(b"\xce\xfa\xed\xfe") or
              header.startswith(b"\xfe\xed\xfa\xcf") or
              header.startswith(b"\xcf\xfa\xed\xfe") or 
              header.startswith(b"\xca\xfe\xba\xbe")):
            detected_format = "Mach-O (macOS/iOS)"
            indicators.append("Valid Mach-O Magic confirmed")
        elif header.startswith(b"\x00asm"):
            detected_format = "WebAssembly Module (.wasm)"
            indicators.append("Valid WebAssembly Module Magic confirmed")
        elif header.startswith(b"dex\n"):
            detected_format = "Android Dalvik Executable (.dex)"
            indicators.append("Valid Dalvik Executable (DEX) Magic confirmed")
        elif header.startswith(b"SQLite format 3\x00"):
            detected_format = "SQLite3 Database (.sqlite/.db)"
            indicators.append("Valid SQLite3 Storage Header confirmed")
        elif header.startswith(b"Cr24"):
            detected_format = "Chrome Extension Package (.crx)"
            indicators.append("Valid Chrome Extension (CRX) Header confirmed")
        elif header.startswith(b"PK\x03\x04"):
            if b"BOOT-INF/" in header:
                detected_format = "Spring Boot Fat Jar (.jar)"
                indicators.append("Spring Boot BOOT-INF structure confirmed")
            elif b"extension/" in header:
                detected_format = "VS Code Extension (.vsix)"
                indicators.append("VS Code Extension package confirmed")
            elif b".dist-info/METADATA" in header:
                detected_format = "Python Wheel Package (.whl)"
                indicators.append("Python Wheel archive confirmed")
            else:
                detected_format = "ZIP Container / Archive"
                indicators.append("Valid ZIP Archive Magic confirmed")

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
