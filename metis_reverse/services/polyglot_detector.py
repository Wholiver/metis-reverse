"""PolyglotDetector: Multi-label recognition, capability declaration (R3), and library identification (R13).

Implements P0-4:
- Comprehensive multi-label classification (languages, runtimes, formats, packers).
- Capability declarations per artifact (supported / degraded / unsupported / experimental).
- Known standard library and runtime identification for toggleable folding (R13).
"""

import re
from typing import Dict, Any, List, Optional, Tuple


class PolyglotDetector:
    """Performs polyglot feature extraction, multi-label classification, and capability mapping."""

    KNOWN_LIBRARY_PATTERNS = [
        re.compile(r"std::|__cxa_|__gxx_|boost::|llvm::", re.IGNORECASE),
        re.compile(r"core::|alloc::|rust_begin_unwind|___rust_", re.IGNORECASE),
        re.compile(r"runtime\.|sync/atomic|internal/cpu|syscall\.", re.IGNORECASE),
        re.compile(r"System\.|Microsoft\.|Newtonsoft\.", re.IGNORECASE),
        re.compile(r"org\.apache\.|com\.google\.|java\.lang\.", re.IGNORECASE),
        re.compile(r"malloc|free|calloc|realloc|printf|sprintf|memcpy|memset|strlen|strcmp", re.IGNORECASE),
        re.compile(r"jemalloc|mimalloc|libuv|zlib|openssl|sqlite3", re.IGNORECASE),
    ]

    @classmethod
    def detect_labels(cls, raw_bytes: bytes, symbol_names: Optional[List[str]] = None, section_names: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """Extracts multi-label classification covering formats, languages, runtimes, and packers."""
        labels: List[Dict[str, Any]] = []
        syms_str = " ".join(symbol_names) if symbol_names else ""
        secs_str = " ".join(section_names) if section_names else ""

        # 1. Format Detection
        if raw_bytes.startswith(b"MZ"):
            labels.append({"category": "format", "name": "PE", "confidence": 1.0, "details": "Windows Portable Executable"})
        elif raw_bytes.startswith(b"\x7fELF"):
            labels.append({"category": "format", "name": "ELF", "confidence": 1.0, "details": "Linux/Unix ELF"})
        elif (raw_bytes.startswith(b"\xfe\xed\xfa\xce") or raw_bytes.startswith(b"\xce\xfa\xed\xfe") or
              raw_bytes.startswith(b"\xfe\xed\xfa\xcf") or raw_bytes.startswith(b"\xcf\xfa\xed\xfe") or
              raw_bytes.startswith(b"\xca\xfe\xba\xbe")):
            labels.append({"category": "format", "name": "Mach-O", "confidence": 1.0, "details": "Apple Mach-O Binary"})
        elif raw_bytes.startswith(b"\x00asm"):
            labels.append({"category": "format", "name": "WebAssembly", "confidence": 1.0, "details": "Wasm Bytecode"})
        elif raw_bytes.startswith(b"dex\n"):
            labels.append({"category": "format", "name": "DEX", "confidence": 1.0, "details": "Android Dalvik Executable"})
        elif raw_bytes.startswith(b"\xca\xfe\xba\xbe") and len(raw_bytes) > 8 and raw_bytes[6:8] in (b"\x00\x34", b"\x00\x35", b"\x00\x36", b"\x00\x37", b"\x00\x38", b"\x00\x39", b"\x00\x3a", b"\x00\x3b", b"\x00\x3c", b"\x00\x3d"):
            labels.append({"category": "format", "name": "JavaClass", "confidence": 1.0, "details": "JVM Class File"})

        # Bun single file check
        if b"---- Bun! ----" in raw_bytes or b"__BUN" in raw_bytes[:0x1000] or ".bun" in secs_str:
            labels.append({"category": "container", "name": "Bun", "confidence": 0.98, "details": "Bun Standalone Executable"})

        # Electron asar check
        if b"\"files\":" in raw_bytes[:0x1000] and b"\x04\x00\x00\x00" in raw_bytes[:16]:
            labels.append({"category": "container", "name": "ElectronAsar", "confidence": 0.95, "details": "Electron Asar Archive"})

        # PyInstaller check
        if b"MEI\x0c\x0b\x0a\x0b\x0e" in raw_bytes or b"PyInstaller" in raw_bytes:
            labels.append({"category": "container", "name": "PyInstaller", "confidence": 0.98, "details": "PyInstaller Executable"})

        # 2. Language & Runtime Multi-Detection
        # Rust Detection
        if (
            b"rust_begin_unwind" in raw_bytes
            or b"$crate$" in raw_bytes
            or "_ZN" in syms_str and "17h" in syms_str
            or b"/rustc/" in raw_bytes
            or b".cargo" in raw_bytes
        ):
            labels.append({"category": "language", "name": "Rust", "confidence": 0.95, "details": "Rust runtime/mangling detected"})

        # Go Detection
        if (
            b"Go buildinf:" in raw_bytes
            or b"runtime.main" in raw_bytes
            or b"runtime.gopanic" in raw_bytes
            or ".gopclntab" in secs_str
            or b"go.buildid" in raw_bytes
        ):
            labels.append({"category": "language", "name": "Go", "confidence": 0.98, "details": "Golang runtime/pclntab detected"})

        # Swift Detection
        if (
            "$s" in syms_str
            or "_$s" in syms_str
            or b"swift_" in raw_bytes
            or "__swift" in secs_str
            or b"libswiftCore" in raw_bytes
        ):
            labels.append({"category": "language", "name": "Swift", "confidence": 0.92, "details": "Swift runtime/metadata detected"})

        # Objective-C Detection
        if (
            b"objc_msgSend" in raw_bytes
            or "__objc_classlist" in secs_str
            or "OBJC_CLASS_$" in syms_str
        ):
            labels.append({"category": "language", "name": "Objective-C", "confidence": 0.95, "details": "ObjC runtime/selectors detected"})

        # C++ Detection
        if (
            "_ZTV" in syms_str
            or b"std::string" in raw_bytes
            or b"__cxa_throw" in raw_bytes
            or b"typeinfo for " in raw_bytes
            or "??" in syms_str # MSVC mangling
        ):
            labels.append({"category": "language", "name": "C++", "confidence": 0.90, "details": "C++ RTTI/vtable/mangling detected"})

        # JavaScript / TypeScript / Node Detection
        if (
            b"napi_create_function" in raw_bytes
            or b"napi_register_module" in raw_bytes
            or b"node_module_register" in raw_bytes
            or b"console.log" in raw_bytes
            or b"module.exports" in raw_bytes
            or b"webpackChunk" in raw_bytes
        ):
            labels.append({"category": "language", "name": "JavaScript", "confidence": 0.92, "details": "JS runtime/N-API detected"})

        # .NET Detection
        if (
            b"mscoree.dll" in raw_bytes
            or b"_CorExeMain" in raw_bytes
            or b"BSJB" in raw_bytes # .NET Metadata Header
            or ".clr" in secs_str
        ):
            labels.append({"category": "language", "name": ".NET", "confidence": 0.98, "details": "CLR .NET Managed Assembly"})

        # Python Detection
        if (
            b"Py_Initialize" in raw_bytes
            or b"PyEval_EvalCode" in raw_bytes
            or b"Python" in raw_bytes and b"libpython" in raw_bytes
        ):
            labels.append({"category": "language", "name": "Python", "confidence": 0.90, "details": "Python C-API / Embedded interpreter"})

        # Default C fallback if native binary without heavy C++/Rust/Go features
        has_native_format = any(l["category"] == "format" and l["name"] in ("Mach-O", "ELF", "PE") for l in labels)
        if has_native_format and not any(l["category"] == "language" for l in labels):
            labels.append({"category": "language", "name": "C", "confidence": 0.75, "details": "Standard native compiled C binary"})

        # 3. Packer / Protector Detection
        if b"UPX0" in raw_bytes or b"UPX!" in raw_bytes:
            labels.append({"category": "packer", "name": "UPX", "confidence": 1.0, "details": "UPX executable compressor"})
        if ".vmp" in secs_str or b"VMProtect" in raw_bytes:
            labels.append({"category": "packer", "name": "VMProtect", "confidence": 0.95, "details": "VMProtect virtualization wrapper"})
        if b"ConfuserEx" in raw_bytes:
            labels.append({"category": "packer", "name": "ConfuserEx", "confidence": 0.95, "details": "ConfuserEx .NET Obfuscator"})

        return labels

    @classmethod
    def get_capabilities(cls, labels: List[Dict[str, Any]], is_activated: bool = True) -> Dict[str, Any]:
        """Implements R3 Capability Declaration for an artifact."""
        lang_names = [l["name"] for l in labels if l["category"] == "language"]
        fmt_names = [l["name"] for l in labels if l["category"] == "format"]
        packer_names = [l["name"] for l in labels if l["category"] == "packer"]

        capabilities = {
            "re_read_file_range": {
                "status": "supported",
                "confidence": 1.0,
                "description": "Physical raw byte reading directly from storage without virtual mapping distortion."
            },
            "re_translate_address": {
                "status": "supported" if fmt_names else "degraded",
                "confidence": 0.98 if fmt_names else 0.5,
                "description": "Precise conversion between VA, RVA, and file offset coordinates."
            },
            "re_query_function": {
                "status": "supported" if any(f in ("Mach-O", "ELF", "PE") for f in fmt_names) else "degraded",
                "confidence": 0.95,
                "fallback": "Use re_read_file_range and Capstone disassembly or sandbox Python probe."
            },
            "re_hunt_crypto_and_hashes": {
                "status": "supported",
                "confidence": 0.95,
                "description": "Cryptographic primitive & API hash scan."
            },
            "re_verify_hypothesis": {
                "status": "supported",
                "confidence": 1.0,
                "description": "Sandboxed Python execution testing algorithm hypotheses."
            },
            "re_run_probe_script": {
                "status": "supported",
                "confidence": 1.0,
                "description": "Universal escape hatch for custom struct unpacking, scanning, and dynamic child mounting."
            },
        }

        # Language specific capabilities
        if "JavaScript" in lang_names or "Bun" in [l["name"] for l in labels if l["category"] == "container"]:
            capabilities["js_ast_analysis"] = {"status": "supported", "confidence": 0.95}
            capabilities["bun_unpacking"] = {"status": "supported", "confidence": 0.92}
        else:
            capabilities["js_ast_analysis"] = {"status": "unsupported", "confidence": 0.0, "fallback": "Native binary; use re_query_function."}

        if "Rust" in lang_names:
            capabilities["rust_demangle"] = {"status": "supported", "confidence": 0.98}
            capabilities["rust_str_slice_recovery"] = {"status": "supported", "confidence": 0.90}

        if "Swift" in lang_names:
            capabilities["swift_demangle"] = {"status": "supported", "confidence": 0.90}

        if "Objective-C" in lang_names:
            capabilities["objc_selector_recovery"] = {"status": "supported", "confidence": 0.95}

        if "Go" in lang_names:
            capabilities["go_pclntab_recovery"] = {"status": "supported", "confidence": 0.95}

        if ".NET" in lang_names:
            capabilities["dotnet_metadata_recovery"] = {"status": "supported", "confidence": 0.90}

        if packer_names:
            capabilities["decompilation"] = {
                "status": "degraded",
                "confidence": 0.4,
                "warning": f"Artifact packed with {', '.join(packer_names)}; decompile output is packed stub code. Unpack payload first."
            }

        return capabilities

    @classmethod
    def is_library_symbol(cls, symbol_name: str) -> bool:
        """Determines if a symbol belongs to a standard library or common runtime (R13)."""
        if not symbol_name:
            return False
        for pat in cls.KNOWN_LIBRARY_PATTERNS:
            if pat.search(symbol_name):
                return True
        return False
