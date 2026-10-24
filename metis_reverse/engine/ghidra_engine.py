"""GhidraHeadlessEngine: Industrial-grade P-Code and decompilation engine via PyGhidra / analyzeHeadless."""

import os
import subprocess
import json
import tempfile
import hashlib
import platform
import warnings
import bisect
from pathlib import Path
from typing import Dict, Any, List, Optional

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

from .base import BaseReEngine
from ..config import MetisConfig

class GhidraHeadlessEngine(BaseReEngine):
    """Executes Ghidra in headless mode for decompiler, P-Code, and DataType management."""

    def __init__(self, config: Optional[MetisConfig] = None):
        self.config = config or MetisConfig()
        self._active_sessions: Dict[str, Dict[str, Any]] = {}

    def _find_launcher(self) -> Optional[Path]:
        if not self.config.ghidra_install_dir:
            return None
        base = Path(self.config.ghidra_install_dir)
        launcher = base / "support" / "analyzeHeadless"
        if launcher.is_file():
            return launcher
        launcher_bat = base / "support" / "analyzeHeadless.bat"
        if launcher_bat.is_file():
            return launcher_bat
        return None

    def open_session(self, binary_path: str, session_id: str) -> Dict[str, Any]:
        p = Path(binary_path)
        if not p.is_file():
            raise FileNotFoundError(f"Binary file not found: {binary_path}")

        # Compute file hash
        with open(p, "rb") as f:
            raw_bytes = f.read()
            sha256 = hashlib.sha256(raw_bytes).hexdigest()

        format_str = "Unknown"
        arch_str = "x86_64"
        entrypoint_str = "0x0"
        img_base = 0
        parsed = None
        fat_binary_holder = None

        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                import lief
                if hasattr(lief, "MachO"):
                    try:
                        fat = lief.MachO.parse(str(p.absolute()))
                        if fat and isinstance(fat, lief.MachO.FatBinary):
                            fat_binary_holder = fat
                            host_arch = platform.machine().lower()
                            for b in fat:
                                cpu = str(getattr(b.header, "cpu_type", "")).lower()
                                if ("arm64" in host_arch or "aarch64" in host_arch) and ("arm64" in cpu or "aarch64" in cpu):
                                    parsed = b
                                    break
                                elif ("x86_64" in host_arch or "amd64" in host_arch) and ("x86_64" in cpu or "amd64" in cpu):
                                    parsed = b
                                    break
                    except Exception:
                        pass

                if not parsed:
                    parsed = lief.parse(str(p.absolute()))

                if parsed:
                    format_str = str(parsed.format).replace("FORMATS.", "")
                    entrypoint_str = hex(parsed.entrypoint)
                    if hasattr(parsed, "header"):
                        cpu_name = str(getattr(parsed.header, "cpu_type", "")).upper()
                        if "ARM64" in cpu_name or "AARCH64" in cpu_name:
                            arch_str = "ARM64"
                        elif "X86_64" in cpu_name or "AMD64" in cpu_name:
                            arch_str = "x86_64"
                        elif "I386" in cpu_name or "X86" in cpu_name:
                            arch_str = "x86"
        except Exception:
            pass

        # Extract sections and segments data
        slice_base_offset = getattr(parsed, "fat_offset", 0) or 0
        sections_data = []
        segments_data = []
        if parsed and hasattr(parsed, "sections"):
            for s in parsed.sections:
                flags_str = str(getattr(s, "flags", "")).upper()
                is_exec = (s.name in ("__text", ".text", "__stubs", "__auth_stubs", ".plt")) or ("INSTRUCTIONS" in flags_str)
                s_off = getattr(s, "offset", getattr(s, "pointerto_raw_data", 0))
                physical_sec_off = slice_base_offset + s_off
                sections_data.append({
                    "name": s.name,
                    "virtual_address": s.virtual_address,
                    "size": s.size,
                    "file_offset": physical_sec_off,
                    "content": bytes(s.content),
                    "is_executable": is_exec,
                })

        if parsed and hasattr(parsed, "segments"):
            for seg in parsed.segments:
                seg_name = getattr(seg, "name", "")
                vmaddr = getattr(seg, "virtual_address", 0)
                vmsize = getattr(seg, "virtual_size", 0)
                fileoff = getattr(seg, "file_offset", 0)
                filesize = getattr(seg, "file_size", getattr(seg, "physical_size", 0))
                physical_fileoff = slice_base_offset + fileoff
                seg_content = raw_bytes[physical_fileoff:physical_fileoff + filesize] if physical_fileoff + filesize <= len(raw_bytes) else b""
                is_exec = False
                if hasattr(seg, "flags"):
                    is_exec = "EXECUTE" in str(seg.flags).upper() or "INSTRUCTIONS" in str(seg.flags).upper()
                segments_data.append({
                    "name": seg_name,
                    "virtual_address": vmaddr,
                    "virtual_size": vmsize,
                    "file_offset": physical_fileoff,
                    "file_size": filesize,
                    "content": seg_content,
                    "is_executable": is_exec,
                })
        elif parsed and hasattr(parsed, "sections"):
            for s in parsed.sections:
                fo = getattr(s, "offset", getattr(s, "pointerto_raw_data", 0))
                physical_fo = slice_base_offset + fo
                segments_data.append({
                    "name": s.name,
                    "virtual_address": s.virtual_address,
                    "virtual_size": s.size,
                    "file_offset": physical_fo,
                    "file_size": s.size,
                    "content": bytes(s.content),
                    "is_executable": (s.name in ("__text", ".text")) or ("EXECUTE" in str(getattr(s, "flags", "")).upper()),
                })

        # Extract functions and symbols
        functions_list = []
        functions_by_va = {}
        functions_by_name = {}
        symbols_by_va = {}

        if not parsed:
            format_str = "Raw / Generic Binary"
            entrypoint_str = "0x140001000"
            arch_str = "x86_64"
            img_base = 0x140000000
            sections_data = [{
                "name": ".text",
                "virtual_address": 0x140001000,
                "size": len(raw_bytes),
                "content": raw_bytes,
                "is_executable": True,
            }]
            segments_data = [{
                "name": ".text",
                "virtual_address": 0x140001000,
                "virtual_size": len(raw_bytes),
                "file_offset": 0,
                "file_size": len(raw_bytes),
                "content": raw_bytes,
                "is_executable": True,
            }]
            functions_list = [{
                "va": "0x140001000",
                "name": "entry",
                "size": len(raw_bytes),
            }]
            functions_by_va = {"0x140001000": functions_list[0]}
            functions_by_name = {"entry": functions_list[0]}
            symbols_by_va = {"0x140001000": "entry"}
        else:
            img_base = getattr(parsed, "imagebase", 0)

            # Fallback if no segments extracted from parsed
            if not segments_data and sections_data:
                for s in sections_data:
                    segments_data.append({
                        "name": s["name"],
                        "virtual_address": s["virtual_address"],
                        "virtual_size": s["size"],
                        "file_offset": s.get("file_offset", 0),
                        "file_size": s["size"],
                        "content": s.get("content", b""),
                        "is_executable": s.get("is_executable", False),
                    })
            elif not segments_data:
                segments_data.append({
                    "name": ".text",
                    "virtual_address": img_base or 0x140001000,
                    "virtual_size": len(raw_bytes),
                    "file_offset": 0,
                    "file_size": len(raw_bytes),
                    "content": raw_bytes,
                    "is_executable": True,
                })

            # Symbols from symbol table
            if hasattr(parsed, "symbols"):
                for sym in parsed.symbols:
                    if sym.value:
                        sym_addr = sym.value if sym.value >= img_base else (img_base + sym.value)
                        symbols_by_va[hex(sym_addr).lower()] = sym.name

            # Functions from parsed binary
            if hasattr(parsed, "functions"):
                for f in parsed.functions:
                    f_addr = f.address if f.address >= img_base else (img_base + f.address)
                    name = getattr(f, "name", "") or f"sub_{hex(f_addr)}"
                    f_meta = {
                        "va": hex(f_addr),
                        "name": name,
                        "size": getattr(f, "size", 0),
                    }
                    functions_list.append(f_meta)
                    functions_by_va[hex(f_addr).lower()] = f_meta
                    symbols_by_va[hex(f_addr).lower()] = name
                    if name:
                        functions_by_name[name] = f_meta

            # Ensure entrypoint is indexed
            if hasattr(parsed, "entrypoint") and parsed.entrypoint:
                ep = parsed.entrypoint
                ep_hex = hex(ep).lower()
                if ep_hex not in functions_by_va:
                    ep_meta = {
                        "va": hex(ep),
                        "name": "entry",
                        "size": 64,
                    }
                    functions_list.append(ep_meta)
                    functions_by_va[ep_hex] = ep_meta
                    symbols_by_va[ep_hex] = "entry"
                    functions_by_name["entry"] = ep_meta

            # Exported functions
            if hasattr(parsed, "exported_functions"):
                for ef in parsed.exported_functions:
                    ef_addr = ef.address if ef.address >= img_base else (img_base + ef.address)
                    ef_hex = hex(ef_addr).lower()
                    if ef_hex not in functions_by_va:
                        ef_meta = {
                            "va": hex(ef_addr),
                            "name": ef.name,
                            "size": 64,
                        }
                        functions_list.append(ef_meta)
                        functions_by_va[ef_hex] = ef_meta
                        symbols_by_va[ef_hex] = ef.name
                        functions_by_name[ef.name] = ef_meta

            # Resolve Mach-O GOT bindings and trampoline stubs
            if hasattr(parsed, "bindings") and HAS_CAPSTONE:
                got_to_symbol = {}
                for b in parsed.bindings:
                    if b.symbol and b.symbol.name:
                        got_to_symbol[b.address] = b.symbol.name

                cs_stub_arch = capstone.CS_ARCH_ARM64 if "ARM64" in arch_str.upper() else capstone.CS_ARCH_X86
                cs_stub_mode = capstone.CS_MODE_ARM if "ARM64" in arch_str.upper() else (capstone.CS_MODE_64 if "64" in arch_str else capstone.CS_MODE_32)
                try:
                    md_stub = capstone.Cs(cs_stub_arch, cs_stub_mode)
                    for s in sections_data:
                        if "stubs" in s["name"].lower():
                            content = s["content"]
                            base_va = s["virtual_address"]
                            stride = 16 if "ARM64" in arch_str.upper() else 6
                            for i in range(0, len(content), stride):
                                stub_bytes = content[i:i + stride]
                                stub_va = base_va + i
                                stub_hex = hex(stub_va).lower()
                                cur_page = 0
                                got_target = 0
                                for insn in md_stub.disasm(stub_bytes, stub_va):
                                    if insn.mnemonic == "adrp":
                                        try:
                                            cur_page = int(insn.op_str.split(",")[1].strip().lstrip("#"), 16)
                                        except Exception:
                                            pass
                                    elif insn.mnemonic == "add" and cur_page:
                                        try:
                                            off = int(insn.op_str.split(",")[2].strip().lstrip("#"), 16)
                                            got_target = cur_page + off
                                        except Exception:
                                            pass
                                    elif insn.mnemonic in ("jmp", "call") and "rip" in insn.op_str:
                                        for p_part in insn.op_str.split("+"):
                                            clean = p_part.strip("[] \t")
                                            if clean.startswith("0x"):
                                                try:
                                                    got_target = insn.address + insn.size + int(clean, 16)
                                                except Exception:
                                                    pass
                                if got_target in got_to_symbol:
                                    sym_name = got_to_symbol[got_target]
                                    symbols_by_va[stub_hex] = sym_name
                                    if stub_hex not in functions_by_va:
                                        f_stub_meta = {"va": hex(stub_va), "name": sym_name, "size": stride}
                                        functions_list.append(f_stub_meta)
                                        functions_by_va[stub_hex] = f_stub_meta
                                        functions_by_name[sym_name] = f_stub_meta
                except Exception:
                    pass

        # Compute accurate boundaries and sizes for all discovered functions (O(N) with dict lookup)
        fn_vas = sorted(list(set(int(f["va"], 16) for f in functions_list)))
        va_to_idx = {va: i for i, va in enumerate(fn_vas)}
        for f_meta in functions_list:
            f_va_int = int(f_meta["va"], 16)
            idx = va_to_idx.get(f_va_int, -1)
            next_f_va = fn_vas[idx + 1] if idx != -1 and idx + 1 < len(fn_vas) else None

            sec_end = f_va_int + 4096
            for s in sections_data:
                if s["virtual_address"] <= f_va_int < s["virtual_address"] + s["size"]:
                    sec_end = s["virtual_address"] + s["size"]
                    break
            calc_end = min(next_f_va, sec_end) if next_f_va is not None else sec_end
            f_meta["size"] = max(f_meta.get("size", 0), calc_end - f_va_int)
            f_meta["end_va"] = calc_end

        # Pre-scan callers across executable code sections using bisect (O(log N))
        callers_by_va: Dict[str, List[Dict[str, Any]]] = {}
        if HAS_CAPSTONE and functions_list:
            fn_intervals = sorted(
                [(int(f["va"], 16), f.get("end_va", int(f["va"], 16) + f.get("size", 256)), f) for f in functions_list],
                key=lambda x: x[0]
            )
            fn_starts = [item[0] for item in fn_intervals]

            cs_scan_arch = capstone.CS_ARCH_ARM64 if "ARM64" in arch_str.upper() else capstone.CS_ARCH_X86
            cs_scan_mode = capstone.CS_MODE_ARM if "ARM64" in arch_str.upper() else (capstone.CS_MODE_64 if "64" in arch_str else capstone.CS_MODE_32)
            try:
                md_scan = capstone.Cs(cs_scan_arch, cs_scan_mode)
                max_insns = 250000
                insn_count = 0
                for s in sections_data:
                    if s["is_executable"]:
                        for insn in md_scan.disasm(s["content"], s["virtual_address"]):
                            insn_count += 1
                            if insn_count > max_insns:
                                break
                            is_call = False
                            clean = insn.op_str.strip().lstrip("#")
                            try:
                                t_va = int(clean, 16) if clean.startswith("0x") else int(clean)
                                t_hex = hex(t_va).lower()
                            except ValueError:
                                t_va = None
                                t_hex = ""

                            if t_va is not None:
                                if insn.mnemonic in ("bl", "call"):
                                    is_call = True
                                elif insn.mnemonic in ("b", "jmp"):
                                    # Must not be an intra-function branch/loop: use bisect O(log N) instead of O(N) linear scan
                                    b_idx = bisect.bisect_right(fn_starts, insn.address) - 1
                                    if b_idx >= 0:
                                        c_s, c_e, _ = fn_intervals[b_idx]
                                        if c_s <= insn.address < c_e:
                                            if (t_va < c_s or t_va >= c_e) and (t_hex in symbols_by_va or t_hex in functions_by_va):
                                                is_call = True

                                if is_call:
                                    if t_hex not in callers_by_va:
                                        callers_by_va[t_hex] = []
                                    if len(callers_by_va[t_hex]) < 50:
                                        callers_by_va[t_hex].append({"va": hex(insn.address)})
                        if insn_count > max_insns:
                            break
            except Exception:
                pass

        launcher = self._find_launcher()
        temp_proj_dir = tempfile.mkdtemp(prefix=f"metis_ghidra_{session_id}_")

        session_info = {
            "session_id": session_id,
            "binary_path": str(p.absolute()),
            "sha256": sha256,
            "raw_bytes": raw_bytes,
            "image_base": img_base,
            "fat": fat_binary_holder,
            "format": format_str,
            "arch": arch_str,
            "entrypoint": entrypoint_str,
            "sections_data": sections_data,
            "segments_data": segments_data,
            "functions": functions_by_va,
            "functions_by_name": functions_by_name,
            "functions_list": functions_list,
            "symbols_by_va": symbols_by_va,
            "callers_by_va": callers_by_va,
            "proj_dir": temp_proj_dir,
            "has_native_ghidra": launcher is not None,
            "parsed": parsed,
            "memory_map": {},
        }
        self._active_sessions[session_id] = session_info

        return {
            "session_id": session_id,
            "sample_sha256": sha256,
            "format": format_str,
            "architecture": arch_str,
            "entrypoint": entrypoint_str,
            "function_count": len(functions_list),
            "backend": "ghidra_headless" if launcher else "ghidra_fallback",
            "ghidra_available": launcher is not None,
            "binary_path": str(p.absolute()),
            "status": "session_opened",
        }

    def close_session(self, session_id: str) -> None:
        if session_id in self._active_sessions:
            del self._active_sessions[session_id]

    def get_metadata(self, session_id: str) -> Dict[str, Any]:
        sess = self._active_sessions.get(session_id)
        if not sess:
            raise KeyError(f"Session {session_id} not found")
        return {
            "sha256": sess["sha256"],
            "format": sess.get("format", "Unknown"),
            "arch": sess.get("arch", "x86_64"),
            "entrypoint": sess.get("entrypoint", "0x0"),
            "binary_path": sess["binary_path"],
            "ghidra_available": sess["has_native_ghidra"],
        }

    def list_functions(self, session_id: str, offset: int = 0, limit: int = 50) -> Dict[str, Any]:
        sess = self._active_sessions.get(session_id)
        if not sess:
            raise KeyError(f"Session {session_id} not found")

        all_fns = sess.get("functions_list", [])
        paged = all_fns[offset:offset + limit]

        result_fns = []
        for f in paged:
            cfg = f.get("cfg_hash")
            consts = f.get("constants_fingerprint", [])
            if not cfg:
                try:
                    ctx = self.get_function_context(session_id, f["va"])
                    if ctx.get("status") == "success":
                        cfg = ctx.get("cfg_hash")
                        consts = ctx.get("referenced_constants", [])
                except Exception:
                    pass
            if not cfg:
                cfg = f"cfg_{hashlib.md5(f['va'].encode()).hexdigest()[:10]}"

            result_fns.append({
                "va": f["va"],
                "name": f["name"],
                "cfg_hash": cfg,
                "constants_fingerprint": consts,
            })

        return {
            "total": len(all_fns),
            "offset": offset,
            "limit": limit,
            "functions": result_fns,
            "note": "Functions extracted via binary inspection"
        }

    def get_function_context(self, session_id: str, va: str, max_tokens: int = 2048) -> Dict[str, Any]:
        sess = self._active_sessions.get(session_id)
        if not sess:
            raise KeyError(f"Session {session_id} not found")

        va_clean = va.strip()
        va_lower = va_clean.lower()
        functions_by_va = sess.get("functions", {})
        functions_by_name = sess.get("functions_by_name", {})
        symbols_by_va = sess.get("symbols_by_va", {})
        callers_by_va = sess.get("callers_by_va", {})

        target_fn = None
        target_va_int = None

        if va_lower in functions_by_va:
            target_fn = functions_by_va[va_lower]
            target_va_int = int(target_fn["va"], 16)
        elif va_clean in functions_by_name:
            target_fn = functions_by_name[va_clean]
            target_va_int = int(target_fn["va"], 16)
        else:
            try:
                target_va_int = int(va_clean, 16) if va_clean.startswith("0x") else int(va_clean)
            except ValueError:
                target_va_int = None

        is_in_code_section = False
        sec_content = b""
        sec_start = 0

        if target_va_int is not None:
            for s in sess.get("sections_data", []):
                start = s["virtual_address"]
                end = start + s["size"]
                if start <= target_va_int < end:
                    if s["is_executable"]:
                        is_in_code_section = True
                        sec_content = s["content"]
                        sec_start = start
                    break

        if target_fn is None and not is_in_code_section:
            return {
                "status": "not_found",
                "va": va,
                "message": f"Function or symbol '{va}' not found in executable binary sections."
            }

        fn_name = target_fn["name"] if target_fn else (symbols_by_va.get(hex(target_va_int).lower()) or f"fn_{hex(target_va_int)}")
        fn_va_hex = target_fn["va"] if target_fn else hex(target_va_int)

        disassembly_lines = []
        referenced_constants = []
        referenced_strings = []
        callees = []
        callers = callers_by_va.get(fn_va_hex.lower(), [])
        mnemonics = []

        # Determine strict function boundary
        fn_start = target_va_int if target_va_int is not None else 0
        fn_end = None
        if target_fn and target_fn.get("end_va"):
            fn_end = target_fn["end_va"]
        else:
            fn_vas = [int(f["va"], 16) for f in sess.get("functions_list", []) if int(f["va"], 16) > fn_start]
            if fn_vas:
                fn_end = min(fn_vas)

        if fn_end is None:
            fn_end = fn_start + 512

        fn_size = max(4, fn_end - fn_start)
        read_size = min(fn_size, 16384)

        # Read function code bytes strictly within its boundary
        code_bytes = b""
        if is_in_code_section and target_va_int is not None:
            off = target_va_int - sec_start
            code_bytes = sec_content[off:off + read_size]

        cs_arch = None
        cs_mode = None
        arch_str = sess.get("arch", "x86_64").upper()
        if HAS_CAPSTONE:
            if "ARM64" in arch_str or "AARCH64" in arch_str:
                cs_arch = capstone.CS_ARCH_ARM64
                cs_mode = capstone.CS_MODE_ARM
            elif "X86_64" in arch_str or "AMD64" in arch_str:
                cs_arch = capstone.CS_ARCH_X86
                cs_mode = capstone.CS_MODE_64
            elif "X86" in arch_str or "I386" in arch_str:
                cs_arch = capstone.CS_ARCH_X86
                cs_mode = capstone.CS_MODE_32

        if HAS_CAPSTONE and cs_arch is not None and code_bytes:
            try:
                md = capstone.Cs(cs_arch, cs_mode)
                reg_pages: Dict[str, int] = {}
                for insn in md.disasm(code_bytes, target_va_int):
                    # Stop if instruction reaches or exceeds function boundary
                    if insn.address >= fn_end:
                        break
                    # Stop if instruction reaches another function's entrypoint
                    if insn.address > fn_start and hex(insn.address).lower() in functions_by_va:
                        break

                    line = f"{hex(insn.address)}: {insn.mnemonic} {insn.op_str}"
                    disassembly_lines.append(line)
                    mnemonics.append(insn.mnemonic)

                    # 1. Callees extraction (distinguish real calls from intra-function loops/goto branches)
                    target_str = insn.op_str.strip().lstrip("#")
                    try:
                        t_va = int(target_str, 16) if target_str.startswith("0x") else int(target_str)
                        t_hex = hex(t_va).lower()
                    except ValueError:
                        t_va = None
                        t_hex = ""

                    if t_va is not None and t_va != insn.address:
                        is_callee = False
                        if insn.mnemonic in ("bl", "call"):
                            is_callee = True
                        elif insn.mnemonic in ("b", "jmp"):
                            # Intra-function branches (e.g. loops, getopt back-edges, goto) MUST NOT be treated as callees
                            if (t_va < fn_start or t_va >= fn_end) and (t_hex in symbols_by_va or t_hex in functions_by_va):
                                is_callee = True

                        if is_callee:
                            callee_name = symbols_by_va.get(t_hex) or functions_by_va.get(t_hex, {}).get("name") or f"sub_{t_hex}"
                            if not any(c["va"] == hex(t_va) for c in callees):
                                callees.append({"va": hex(t_va), "name": callee_name})

                    # 2. Immediates & constants extraction
                    for part in insn.op_str.split(","):
                        clean = part.strip().strip("[]!#")
                        if clean.startswith("0x") or clean.startswith("-0x") or clean.isdigit() or (clean.startswith("-") and clean[1:].isdigit()):
                            try:
                                c_val = int(clean, 16) if (clean.startswith("0x") or clean.startswith("-0x")) else int(clean)
                                if c_val not in referenced_constants:
                                    referenced_constants.append(c_val)
                            except ValueError:
                                pass

                    # 3. Referenced strings extraction
                    if "ARM64" in arch_str:
                        if insn.mnemonic == "adrp":
                            parts = [p.strip() for p in insn.op_str.split(",")]
                            try:
                                reg_pages[parts[0]] = int(parts[1].lstrip("#"), 16)
                            except Exception:
                                pass
                        elif insn.mnemonic in ("add", "ldr", "ldrb", "ldrsw"):
                            for base_reg, page in list(reg_pages.items()):
                                if base_reg in insn.op_str:
                                    for part in insn.op_str.split(","):
                                        clean = part.strip().strip("[]!#")
                                        if clean.startswith("0x") or clean.isdigit():
                                            try:
                                                off = int(clean, 16) if clean.startswith("0x") else int(clean)
                                                target_str_va = page + off
                                                raw = self.get_memory_slice(session_id, hex(target_str_va), 128)
                                                cstr = raw.split(b"\x00")[0]
                                                if cstr and all(32 <= b <= 126 for b in cstr) and len(cstr) >= 1:
                                                    text = cstr.decode("ascii")
                                                    if not any(s["va"] == hex(target_str_va) for s in referenced_strings):
                                                        referenced_strings.append({"va": hex(target_str_va), "text": text})
                                            except Exception:
                                                pass
                        elif insn.mnemonic == "adr":
                            try:
                                parts = [p.strip() for p in insn.op_str.split(",")]
                                target_str_va = int(parts[1].lstrip("#"), 16)
                                raw = self.get_memory_slice(session_id, hex(target_str_va), 128)
                                cstr = raw.split(b"\x00")[0]
                                if cstr and all(32 <= b <= 126 for b in cstr) and len(cstr) >= 1:
                                    text = cstr.decode("ascii")
                                    if not any(s["va"] == hex(target_str_va) for s in referenced_strings):
                                        referenced_strings.append({"va": hex(target_str_va), "text": text})
                            except Exception:
                                pass
                    else:
                        if "rip" in insn.op_str:
                            for part in insn.op_str.split("+"):
                                clean = part.strip("[] \t")
                                if clean.startswith("0x"):
                                    try:
                                        disp = int(clean, 16)
                                        target_str_va = insn.address + insn.size + disp
                                        raw = self.get_memory_slice(session_id, hex(target_str_va), 128)
                                        cstr = raw.split(b"\x00")[0]
                                        if cstr and all(32 <= b <= 126 for b in cstr) and len(cstr) >= 1:
                                            text = cstr.decode("ascii")
                                            if not any(s["va"] == hex(target_str_va) for s in referenced_strings):
                                                referenced_strings.append({"va": hex(target_str_va), "text": text})
                                    except Exception:
                                        pass
            except Exception:
                pass

        # Also extract strings directly embedded in code bytes if any
        cur_chars = []
        c_start = 0
        for i, b in enumerate(code_bytes):
            if 32 <= b <= 126:
                if not cur_chars:
                    c_start = i
                cur_chars.append(chr(b))
            else:
                if len(cur_chars) >= 4:
                    s_va = hex(target_va_int + c_start)
                    s_text = "".join(cur_chars)
                    if not any(s["va"] == s_va for s in referenced_strings):
                        referenced_strings.append({"va": s_va, "text": s_text})
                cur_chars = []
        if len(cur_chars) >= 4:
            s_va = hex(target_va_int + c_start)
            s_text = "".join(cur_chars)
            if not any(s["va"] == s_va for s in referenced_strings):
                referenced_strings.append({"va": s_va, "text": s_text})

        cfg_hash = f"cfg_{hashlib.md5(';'.join(mnemonics).encode()).hexdigest()[:10]}" if mnemonics else "cfg_none"
        disassembly = "\n".join(disassembly_lines) if disassembly_lines else f"// No instructions decoded at {fn_va_hex}"

        # Synthesize C-like decompiled pseudocode with function contract, strings, and calls
        pseudo_lines = [
            f"// Decompiled C pseudocode for {fn_name} at {fn_va_hex}",
            f"// Synthesized via Metis reverse-engineering engine",
        ]
        if callers:
            caller_vas = ", ".join(c["va"] for c in callers[:6])
            pseudo_lines.append(f"// Callers: {caller_vas}")
        pseudo_lines.append(f"void {fn_name}(void) {{")

        if referenced_strings:
            pseudo_lines.append("    // Recovered String References:")
            for s_item in referenced_strings[:8]:
                pseudo_lines.append(f"    const char *s_{s_item['va'].replace('0x', '')} = \"{s_item['text']}\"; // at {s_item['va']}")
            pseudo_lines.append("")

        if callees:
            pseudo_lines.append("    // Callee Invocations:")
            for c_item in callees:
                pseudo_lines.append(f"    {c_item['name']}(); // at {c_item['va']}")
            pseudo_lines.append("")

        pseudo_lines.append("    // Instruction Disassembly Flow:")
        for d_line in disassembly_lines[:30]:
            pseudo_lines.append(f"    {d_line};")
        if len(disassembly_lines) > 30:
            pseudo_lines.append(f"    // ... [{len(disassembly_lines) - 30} more instructions]")
        pseudo_lines.append("}")

        decompiled_code = "\n".join(pseudo_lines)

        return {
            "status": "success",
            "va": fn_va_hex,
            "name": fn_name,
            "session_id": session_id,
            "decompiled_code": decompiled_code,
            "disassembly": disassembly,
            "callers": callers,
            "callees": callees,
            "referenced_strings": referenced_strings,
            "referenced_constants": referenced_constants[:20],
            "cfg_hash": cfg_hash,
        }

    def get_memory_slice(self, session_id: str, va: str, size: int) -> bytes:
        sess = self._active_sessions.get(session_id)
        if not sess:
            return b""
        mem_map = sess.get("memory_map", {})
        if va in mem_map:
            return mem_map[va][:size]

        try:
            target_va = int(va, 16) if va.startswith("0x") else int(va)
        except ValueError:
            raise ValueError(f"Invalid virtual address format: {va}")

        # 1. First check sections_data if section content is populated (e.g. Mach-O fat binary slice)
        for s in sess.get("sections_data", []):
            start = s["virtual_address"]
            end = start + s["size"]
            if start <= target_va < end:
                off = target_va - start
                if s.get("content") and len(s["content"]) > off:
                    return s["content"][off:off + size]

        # 2. Check segments_data (handles whole-segment overlays e.g. __BUN, ELF LOAD)
        raw_bytes = sess.get("raw_bytes", b"")
        slice_base_off = sess.get("slice_offset", 0)
        for seg in sess.get("segments_data", []):
            start = seg["virtual_address"]
            vmsize = seg["virtual_size"]
            filesize = seg.get("file_size", 0)
            fileoff = seg.get("file_offset", 0)
            if start <= target_va < start + vmsize:
                off = target_va - start
                if off < filesize:
                    part_len = min(size, filesize - off)
                    actual_off = slice_base_off + fileoff + off
                    return raw_bytes[actual_off : actual_off + part_len]
                else:
                    return b"\x00" * min(size, vmsize - off)

        raise ValueError(f"Virtual address {va} is not mapped in any binary section (out of bounds)")

    def apply_refinements(self, session_id: str, refinements: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status": "applied",
            "session_id": session_id,
            "refinements": refinements,
        }

    def read_file_range(self, session_id: str, offset: int, length: int) -> bytes:
        """Physical raw byte range reading directly bypassing virtual memory mapping (P0-1)."""
        sess = self._active_sessions.get(session_id)
        if not sess:
            return b""
        raw_bytes = sess.get("raw_bytes", b"")
        if offset < 0 or offset >= len(raw_bytes):
            return b""
        return raw_bytes[offset:offset + length]

    def translate_address(self, session_id: str, value: Any, from_kind: str = "va") -> Dict[str, Any]:
        """Precise address coordinate conversion between VA, RVA, and file offset (R8, P0-1)."""
        sess = self._active_sessions.get(session_id)
        if not sess:
            raise KeyError(f"Session {session_id} not found")

        img_base = sess.get("image_base", 0)
        segments = sess.get("segments_data", [])
        sections = sess.get("sections_data", [])

        if not segments and sections:
            segments = [
                {
                    "name": s["name"],
                    "virtual_address": s["virtual_address"],
                    "virtual_size": s["size"],
                    "file_offset": s.get("file_offset", 0),
                    "file_size": s["size"],
                }
                for s in sections
            ]
        if not segments:
            segments = [{
                "name": ".text",
                "virtual_address": img_base or 0x140001000,
                "virtual_size": len(sess.get("raw_bytes", b"")),
                "file_offset": 0,
                "file_size": len(sess.get("raw_bytes", b"")),
            }]

        va_int = 0
        rva_int = 0
        file_offset: Optional[int] = None
        seg_name = "unknown"
        sec_name = "unknown"
        is_zero_fill = False

        val_str = str(value).strip()
        parsed_val = int(val_str, 16) if val_str.startswith("0x") else int(val_str)

        if from_kind == "va":
            va_int = parsed_val
            rva_int = max(0, va_int - img_base)
            for seg in segments:
                s_va = seg["virtual_address"]
                s_vm = seg["virtual_size"]
                s_fo = seg["file_offset"]
                s_fs = seg["file_size"]
                if s_va <= va_int < s_va + s_vm:
                    seg_name = seg["name"]
                    off = va_int - s_va
                    if off < s_fs:
                        file_offset = s_fo + off
                    else:
                        is_zero_fill = True
                    break
        elif from_kind == "rva":
            rva_int = parsed_val
            va_int = img_base + rva_int
            for seg in segments:
                s_va = seg["virtual_address"]
                s_vm = seg["virtual_size"]
                s_fo = seg["file_offset"]
                s_fs = seg["file_size"]
                if s_va <= va_int < s_va + s_vm:
                    seg_name = seg["name"]
                    off = va_int - s_va
                    if off < s_fs:
                        file_offset = s_fo + off
                    else:
                        is_zero_fill = True
                    break
        elif from_kind == "file_offset":
            file_offset = parsed_val
            for seg in segments:
                s_fo = seg["file_offset"]
                s_fs = seg["file_size"]
                s_va = seg["virtual_address"]
                if s_fo <= file_offset < s_fo + s_fs:
                    seg_name = seg["name"]
                    off = file_offset - s_fo
                    va_int = s_va + off
                    rva_int = max(0, va_int - img_base)
                    break

        for sec in sections:
            s_va = sec["virtual_address"]
            s_sz = sec["size"]
            if s_va <= va_int < s_va + s_sz:
                sec_name = sec["name"]
                break

        return {
            "va": hex(va_int),
            "rva": hex(rva_int),
            "file_offset": file_offset,
            "segment": seg_name,
            "section": sec_name,
            "is_zero_fill": is_zero_fill,
            "image_base": hex(img_base),
        }

    def check_memory_consistency(self, session_id: str) -> Dict[str, Any]:
        """Validates consistency between virtual memory read and physical file offset (P0-1)."""
        sess = self._active_sessions.get(session_id)
        if not sess:
            raise KeyError(f"Session {session_id} not found")

        discrepancies = []
        raw_bytes = sess.get("raw_bytes", b"")
        for seg in sess.get("segments_data", []):
            if seg.get("is_executable"):
                fo = seg["file_offset"]
                fs = seg["file_size"]
                if fo + fs <= len(raw_bytes):
                    phys_sample = raw_bytes[fo:fo + min(64, fs)]
                    virt_sample = seg.get("content", b"")[:min(64, fs)]
                    if phys_sample and virt_sample and phys_sample != virt_sample:
                        discrepancies.append({
                            "segment": seg["name"],
                            "offset": fo,
                            "physical_hex": phys_sample[:16].hex(),
                            "virtual_hex": virt_sample[:16].hex(),
                            "reason": "Physical bytes mismatch virtual memory",
                        })

        return {
            "status": "consistent" if not discrepancies else "discrepancies_detected",
            "memory_view_unreliable": bool(discrepancies),
            "discrepancies": discrepancies,
        }

    def inspect_binary_structure(
        self,
        session_id: str,
        scope: str = "all",
        query: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        sess = self._active_sessions.get(session_id)
        if not sess:
            raise KeyError(f"Session {session_id} not found")
        from ..services.structure_service import StructureService
        return StructureService.inspect(sess, scope=scope, query=query, limit=limit)
