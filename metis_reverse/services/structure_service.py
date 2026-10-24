"""StructureService: Inspects binary headers, segments, sections, dependencies, and symbols."""

import math
from typing import Dict, Any, List, Optional

try:
    import lief
    HAS_LIEF = True
except ImportError:
    lief = None
    HAS_LIEF = False


class StructureService:
    """Provides structured inspection of binary layout, metadata, sections, dylibs, and symbols."""

    @staticmethod
    def inspect(
        session_data: Dict[str, Any],
        scope: str = "all",
        query: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Inspects structural binary layout for an active session."""
        scope = (scope or "all").lower()
        limit = max(1, min(limit or 100, 1000))
        query_clean = query.strip() if query else None

        parsed = session_data.get("parsed")
        binary_path = session_data.get("binary_path")
        raw_bytes = session_data.get("raw_bytes", b"")
        session_id = session_data.get("session_id", "unknown")

        # Reparse via LIEF if parsed object is not cached
        if parsed is None and HAS_LIEF and binary_path:
            try:
                parsed = lief.parse(binary_path)
            except Exception:
                parsed = None

        # 1. Headers & General Info
        headers: Dict[str, Any] = {
            "session_id": session_id,
            "binary_path": binary_path,
            "format": session_data.get("format", "Unknown"),
            "architecture": session_data.get("arch", "Unknown"),
            "file_size": len(raw_bytes),
            "sha256": session_data.get("sha256", ""),
        }

        entrypoint = session_data.get("entrypoint")
        if entrypoint:
            headers["entrypoint"] = hex(entrypoint) if isinstance(entrypoint, int) else str(entrypoint)

        img_base = session_data.get("image_base", 0)
        headers["image_base"] = hex(img_base) if isinstance(img_base, int) else str(img_base)

        if parsed and hasattr(parsed, "header"):
            hdr = parsed.header
            cpu_val = getattr(hdr, "cpu_type", getattr(hdr, "machine_type", getattr(hdr, "machine", None)))
            if cpu_val is not None:
                headers["cpu_type"] = str(cpu_val)
            if hasattr(hdr, "cpu_subtype"):
                headers["cpu_subtype"] = str(hdr.cpu_subtype)
            if hasattr(hdr, "file_type"):
                headers["file_type"] = str(hdr.file_type)
            load_cmds = getattr(hdr, "nb_cmds", getattr(hdr, "nb_cmd", None))
            if load_cmds is not None:
                headers["load_commands_count"] = load_cmds
            if hasattr(hdr, "flags"):
                headers["flags"] = int(hdr.flags) if isinstance(hdr.flags, int) else str(hdr.flags)

        # Fat Mach-O check
        fat = session_data.get("fat_binary_holder") or session_data.get("fat")
        if fat and hasattr(fat, "__iter__"):
            fat_archs = []
            for item in fat:
                if hasattr(item, "header") and hasattr(item.header, "cpu_type"):
                    fat_archs.append(str(item.header.cpu_type))
            if fat_archs:
                headers["fat_architectures"] = fat_archs

        # UUID & Build version
        if parsed and hasattr(parsed, "uuid"):
            headers["uuid"] = str(getattr(parsed.uuid, "uuid", ""))
        if parsed and hasattr(parsed, "build_version"):
            bv = parsed.build_version
            headers["build_version"] = {
                "platform": str(getattr(bv, "platform", "")),
                "minos": str(getattr(bv, "minos", "")),
                "sdk": str(getattr(bv, "sdk", "")),
            }

        # 2. Encryption info
        enc_info: Dict[str, Any] = {
            "has_encryption_info": False,
            "is_encrypted": False,
            "status": "No encryption headers detected",
        }
        if parsed and hasattr(parsed, "has_encryption_info"):
            has_enc = bool(parsed.has_encryption_info)
            enc_info["has_encryption_info"] = has_enc
            if has_enc and hasattr(parsed, "encryption_info"):
                e_obj = parsed.encryption_info
                crypt_id = getattr(e_obj, "crypt_id", 0)
                enc_info["crypt_id"] = crypt_id
                enc_info["crypt_offset"] = getattr(e_obj, "crypt_offset", 0)
                enc_info["crypt_size"] = getattr(e_obj, "crypt_size", 0)
                enc_info["is_encrypted"] = bool(crypt_id != 0)
                enc_info["status"] = (
                    f"Encrypted (FairPlay / AppStore cryptid={crypt_id})"
                    if crypt_id != 0
                    else "Decrypted / Inactive (cryptid=0)"
                )
            else:
                enc_info["status"] = "Plaintext / Unencrypted Mach-O binary (no active cryptid)"
        headers["encryption"] = enc_info

        # 3. Segments
        slice_base_offset = getattr(parsed, "fat_offset", 0) or 0
        segments: List[Dict[str, Any]] = []
        if parsed and hasattr(parsed, "segments"):
            for s in parsed.segments:
                seg_info = {
                    "name": getattr(s, "name", ""),
                    "virtual_address": hex(getattr(s, "virtual_address", 0)),
                    "virtual_size": getattr(s, "virtual_size", 0),
                    "file_offset": slice_base_offset + getattr(s, "file_offset", 0),
                    "file_size": getattr(s, "file_size", getattr(s, "physical_size", 0)),
                    "sections_count": len(s.sections) if hasattr(s, "sections") else 0,
                }
                if hasattr(s, "max_protection"):
                    seg_info["max_protection"] = getattr(s, "max_protection", 0)
                if hasattr(s, "init_protection"):
                    seg_info["init_protection"] = getattr(s, "init_protection", 0)
                segments.append(seg_info)
        elif session_data.get("segments_data"):
            for s in session_data["segments_data"]:
                segments.append({
                    "name": s.get("name", ""),
                    "virtual_address": hex(s.get("virtual_address", 0)),
                    "virtual_size": s.get("virtual_size", 0),
                    "file_offset": s.get("file_offset", 0),
                    "file_size": s.get("file_size", 0),
                    "is_executable": s.get("is_executable", False),
                })

        # 4. Sections
        sections: List[Dict[str, Any]] = []
        if parsed and hasattr(parsed, "sections"):
            for s in parsed.sections:
                sec_name = getattr(s, "name", "")
                if query_clean and query_clean.lower() not in sec_name.lower():
                    continue
                s_off = getattr(s, "offset", getattr(s, "file_offset", getattr(s, "pointerto_raw_data", 0)))
                sec_info = {
                    "name": sec_name,
                    "segment_name": getattr(s, "segment_name", ""),
                    "virtual_address": hex(getattr(s, "virtual_address", 0)),
                    "size": getattr(s, "size", 0),
                    "file_offset": slice_base_offset + s_off,
                }
                try:
                    sec_info["entropy"] = round(float(getattr(s, "entropy", 0.0)), 3)
                except Exception:
                    pass
                if hasattr(s, "flags"):
                    sec_info["flags"] = int(s.flags) if isinstance(s.flags, int) else str(s.flags)
                sections.append(sec_info)
        elif session_data.get("sections_data"):
            for s in session_data["sections_data"]:
                sec_name = s.get("name", "")
                if query_clean and query_clean.lower() not in sec_name.lower():
                    continue
                sections.append({
                    "name": sec_name,
                    "virtual_address": hex(s.get("virtual_address", 0)),
                    "size": s.get("size", 0),
                    "entropy": s.get("entropy", 0.0),
                    "is_executable": s.get("is_executable", False),
                })

        # 5. Dependencies / Dylibs / Imports
        deps: List[Dict[str, Any]] = []
        if parsed and hasattr(parsed, "libraries"):
            for lib in parsed.libraries:
                lib_name = getattr(lib, "name", str(lib))
                if query_clean and query_clean.lower() not in lib_name.lower():
                    continue
                lib_info: Dict[str, Any] = {"name": lib_name}
                if hasattr(lib, "current_version"):
                    lib_info["current_version"] = str(lib.current_version)
                if hasattr(lib, "compatibility_version"):
                    lib_info["compatibility_version"] = str(lib.compatibility_version)
                if hasattr(lib, "timestamp") and lib.timestamp:
                    lib_info["timestamp"] = lib.timestamp
                deps.append(lib_info)
        elif parsed and hasattr(parsed, "imports"):
            for imp in parsed.imports:
                imp_name = getattr(imp, "name", str(imp))
                if query_clean and query_clean.lower() not in imp_name.lower():
                    continue
                deps.append({"name": imp_name, "entries_count": len(getattr(imp, "entries", []))})

        # 6. Symbols
        exported_symbols: List[Dict[str, Any]] = []
        imported_symbols: List[Dict[str, Any]] = []

        if parsed and hasattr(parsed, "exported_symbols"):
            for sym in parsed.exported_symbols:
                s_name = getattr(sym, "name", "")
                if query_clean and query_clean.lower() not in s_name.lower():
                    continue
                exported_symbols.append({
                    "name": s_name,
                    "address": hex(getattr(sym, "value", 0)),
                })
        elif parsed and hasattr(parsed, "exported_functions"):
            for ef in parsed.exported_functions:
                s_name = getattr(ef, "name", "")
                if query_clean and query_clean.lower() not in s_name.lower():
                    continue
                exported_symbols.append({
                    "name": s_name,
                    "address": hex(getattr(ef, "address", 0)),
                })

        if parsed and hasattr(parsed, "imported_symbols"):
            for sym in parsed.imported_symbols:
                s_name = getattr(sym, "name", "")
                if query_clean and query_clean.lower() not in s_name.lower():
                    continue
                imported_symbols.append({
                    "name": s_name,
                    "address": hex(getattr(sym, "value", 0)),
                })
        elif parsed and hasattr(parsed, "imported_functions"):
            for inf in parsed.imported_functions:
                s_name = getattr(inf, "name", "")
                if query_clean and query_clean.lower() not in s_name.lower():
                    continue
                imported_symbols.append({
                    "name": s_name,
                    "address": hex(getattr(inf, "address", 0)),
                })

        # Fallback if symbols were not found on parsed object
        if not exported_symbols and not imported_symbols:
            if session_data.get("symbols_by_va"):
                for va_hex, s_name in session_data["symbols_by_va"].items():
                    if query_clean and query_clean.lower() not in s_name.lower():
                        continue
                    exported_symbols.append({"name": s_name, "address": va_hex})
            elif session_data.get("functions"):
                fn_data = session_data["functions"]
                if isinstance(fn_data, dict):
                    for va_hex, f_meta in fn_data.items():
                        s_name = f_meta.get("name", "") if isinstance(f_meta, dict) else str(f_meta)
                        if query_clean and query_clean.lower() not in s_name.lower():
                            continue
                        exported_symbols.append({"name": s_name, "address": va_hex})
                elif isinstance(fn_data, list):
                    for f_meta in fn_data:
                        if isinstance(f_meta, dict):
                            s_name = f_meta.get("name", "")
                            if query_clean and query_clean.lower() not in s_name.lower():
                                continue
                            exported_symbols.append({"name": s_name, "address": f_meta.get("va", "0x0")})

        symbols_result = {
            "query": query_clean,
            "total_exported": len(exported_symbols),
            "total_imported": len(imported_symbols),
            "exported": exported_symbols[:limit],
            "imported": imported_symbols[:limit],
            "has_more": len(exported_symbols) > limit or len(imported_symbols) > limit,
        }

        # Format output by requested scope
        if scope == "headers":
            return {"status": "success", "session_id": session_id, "headers": headers}
        elif scope == "encryption":
            return {"status": "success", "session_id": session_id, "encryption": enc_info}
        elif scope == "segments":
            return {"status": "success", "session_id": session_id, "count": len(segments), "segments": segments}
        elif scope == "sections":
            return {"status": "success", "session_id": session_id, "count": len(sections), "sections": sections}
        elif scope == "dependencies":
            return {"status": "success", "session_id": session_id, "count": len(deps), "dependencies": deps}
        elif scope == "symbols":
            return {"status": "success", "session_id": session_id, "symbols": symbols_result}
        else:
            return {
                "status": "success",
                "session_id": session_id,
                "headers": headers,
                "segments": segments,
                "sections": sections,
                "dependencies": deps,
                "symbols": symbols_result,
            }
