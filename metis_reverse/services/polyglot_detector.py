"""PolyglotDetector: Multi-label recognition, capability declaration (R3), and library identification (R13).

Implements P0-4 and Full Polyglot Coverage:
- Comprehensive multi-label classification (languages, runtimes, formats, packers, shaders, games, databases).
- Capability declarations per artifact (supported / degraded / unsupported / experimental).
- Safe sampling on large files to prevent memory exhaustion.
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
        """Extracts multi-label classification covering formats, languages, runtimes, containers, and shaders."""
        labels: List[Dict[str, Any]] = []
        syms_str = " ".join(symbol_names) if symbol_names else ""
        secs_str = " ".join(section_names) if section_names else ""

        # Safe bounded inspection window (header + tail) to avoid memory explosion on multi-GB inputs
        header = raw_bytes[:65536] if len(raw_bytes) > 65536 else raw_bytes
        tail = raw_bytes[-4096:] if len(raw_bytes) > 4096 else raw_bytes

        # 1. Format Detection
        is_java_class = (
            header.startswith(b"\xca\xfe\xba\xbe")
            and len(header) >= 8
            and (header[4:6] == b"\x00\x00" or header[6:8] >= b"\x00\x28")
        )

        if header.startswith(b"MZ"):
            labels.append({"category": "format", "name": "PE", "confidence": 1.0, "details": "Windows Portable Executable"})
        elif header.startswith(b"\x7fELF"):
            if len(header) >= 20 and header[18] == 247:
                labels.append({"category": "format", "name": "eBPF", "confidence": 1.0, "details": "Linux eBPF ELF Object (EM_BPF = 247)"})
            else:
                labels.append({"category": "format", "name": "ELF", "confidence": 1.0, "details": "Linux/Unix ELF"})
        elif is_java_class:
            labels.append({"category": "format", "name": "JavaClass", "confidence": 1.0, "details": "JVM Class File"})
            labels.append({"category": "language", "name": "Java", "confidence": 1.0, "details": "Java Bytecode"})
        elif (
            header.startswith(b"\xfe\xed\xfa\xce") or header.startswith(b"\xce\xfa\xed\xfe") or
            header.startswith(b"\xfe\xed\xfa\xcf") or header.startswith(b"\xcf\xfa\xed\xfe") or
            header.startswith(b"\xca\xfe\xba\xbe")
        ):
            labels.append({"category": "format", "name": "Mach-O", "confidence": 1.0, "details": "Apple Mach-O Binary"})
        elif header.startswith(b"\x00asm"):
            labels.append({"category": "format", "name": "WebAssembly", "confidence": 1.0, "details": "Wasm Bytecode"})
        elif header.startswith(b"dex\n"):
            labels.append({"category": "format", "name": "DEX", "confidence": 1.0, "details": "Android Dalvik Executable"})
        elif header.startswith(b"SQLite format 3\x00"):
            labels.append({"category": "format", "name": "SQLite", "confidence": 1.0, "details": "SQLite3 Database"})
        elif header.startswith(b"Cr24"):
            labels.append({"category": "container", "name": "CRX", "confidence": 1.0, "details": "Chrome Extension Package (.crx)"})
        elif header.startswith(b"MTLB") or header.startswith(b"\x4d\x54\x4c\x42"):
            labels.append({"category": "format", "name": "MetalShader", "confidence": 1.0, "details": "Apple Metal Shader Library (.metallib)"})
        elif header.startswith(b"\x03\x02\x23\x07") or header.startswith(b"\x07\x23\x02\x03"):
            labels.append({"category": "format", "name": "SPIR-V", "confidence": 1.0, "details": "Vulkan / OpenGL SPIR-V Shader Bytecode"})
        elif header.startswith(b"DXBC"):
            labels.append({"category": "format", "name": "DXBC", "confidence": 1.0, "details": "DirectX Shader Bytecode"})
        elif header.startswith(b"GDPC") or header.startswith(b"\x47\x44\x50\x43"):
            labels.append({"category": "container", "name": "GodotPCK", "confidence": 1.0, "details": "Godot Engine PCK Archive"})
        elif header.startswith(b"UnityFS") or header.startswith(b"UnityWeb"):
            labels.append({"category": "container", "name": "UnityAssetBundle", "confidence": 1.0, "details": "Unity AssetBundle (UnityFS)"})
        elif header.startswith(b"FOR1") and b"BEAM" in header[:16]:
            labels.append({"category": "format", "name": "BEAM", "confidence": 1.0, "details": "Erlang / Elixir BEAM Bytecode"})
        elif header.startswith(b"YARB"):
            labels.append({"category": "format", "name": "RubyYARV", "confidence": 1.0, "details": "Ruby YARV Bytecode"})
        elif header.startswith(b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f") or header.startswith(b"\x1f\x19\x03\xc1\x03\xbc\x1f\xc6"):
            labels.append({"category": "format", "name": "Hermes", "confidence": 1.0, "details": "Hermes Bytecode (.hbc)"})
            labels.append({"category": "language", "name": "JavaScript", "confidence": 0.95, "details": "React Native Hermes Engine"})
        elif header.startswith(b"TPF0"):
            labels.append({"category": "format", "name": "DelphiDFM", "confidence": 1.0, "details": "Delphi Binary Form (TPF0)"})
            labels.append({"category": "language", "name": "Delphi", "confidence": 0.95, "details": "Borland / Embarcadero Delphi"})

        # Container / Archive Check
        if header.startswith(b"PK\x03\x04"):
            if b"BOOT-INF/" in header:
                labels.append({"category": "container", "name": "SpringBootJar", "confidence": 0.98, "details": "Spring Boot Fat Jar (BOOT-INF/)"})
            elif b"extension/package.json" in header or b"extension/" in header:
                labels.append({"category": "container", "name": "VSIX", "confidence": 0.98, "details": "VS Code Extension (.vsix)"})
            elif b".dist-info/METADATA" in header or b"RECORD" in header:
                labels.append({"category": "container", "name": "PythonWheel", "confidence": 0.98, "details": "Python Wheel Package (.whl)"})
            elif b"Payload/" in header:
                labels.append({"category": "container", "name": "IPA", "confidence": 0.98, "details": "iOS App Package (.ipa)"})
            elif b"META-INF/MANIFEST.MF" in header:
                labels.append({"category": "container", "name": "JAR", "confidence": 0.95, "details": "Java Archive (.jar)"})
            else:
                labels.append({"category": "container", "name": "ZIP", "confidence": 0.90, "details": "ZIP Archive Container"})

        # Bun standalone check
        if b"---- Bun! ----" in tail or b"---- Bun! ----" in header or b"__BUN" in header[:0x1000] or ".bun" in secs_str:
            labels.append({"category": "container", "name": "Bun", "confidence": 0.98, "details": "Bun Standalone Executable"})

        # Electron asar check
        if b"\"files\":" in header[:0x1000] and b"\x04\x00\x00\x00" in header[:16]:
            labels.append({"category": "container", "name": "ElectronAsar", "confidence": 0.95, "details": "Electron Asar Archive"})

        # PyInstaller check
        if b"MEI\x0c\x0b\x0a\x0b\x0e" in header or b"PyInstaller" in header:
            labels.append({"category": "container", "name": "PyInstaller", "confidence": 0.98, "details": "PyInstaller Executable"})

        # Unreal pak check
        if b"\xe1\x12\x6f\x5a" in tail or b"UTOC" in header[:16]:
            labels.append({"category": "container", "name": "UnrealPAK", "confidence": 0.95, "details": "Unreal Engine PAK/UTOC Container"})

        # 2. Language & Runtime Multi-Detection
        # Rust
        if (
            b"rust_begin_unwind" in header
            or b"$crate$" in header
            or ("_ZN" in syms_str and "17h" in syms_str)
            or b"/rustc/" in header
            or b".cargo" in header
        ):
            labels.append({"category": "language", "name": "Rust", "confidence": 0.95, "details": "Rust runtime/mangling detected"})

        # Go
        if (
            b"Go buildinf:" in header
            or b"runtime.main" in header
            or b"runtime.gopanic" in header
            or ".gopclntab" in secs_str
            or b"go.buildid" in header
            or b"\xf1\xff\xff\xff" in header
            or b"\xf0\xff\xff\xff" in header
        ):
            labels.append({"category": "language", "name": "Go", "confidence": 0.98, "details": "Golang runtime/pclntab detected"})

        # Swift
        if (
            "$s" in syms_str
            or "_$s" in syms_str
            or b"swift_" in header
            or "__swift" in secs_str
            or b"libswiftCore" in header
        ):
            labels.append({"category": "language", "name": "Swift", "confidence": 0.92, "details": "Swift runtime/metadata detected"})

        # Objective-C
        if (
            b"objc_msgSend" in header
            or "__objc_classlist" in secs_str
            or "OBJC_CLASS_$" in syms_str
        ):
            labels.append({"category": "language", "name": "Objective-C", "confidence": 0.95, "details": "ObjC runtime/selectors detected"})

        # C++
        if (
            "_ZTV" in syms_str
            or b"std::string" in header
            or b"__cxa_throw" in header
            or b"typeinfo for " in header
            or "??" in syms_str
        ):
            labels.append({"category": "language", "name": "C++", "confidence": 0.90, "details": "C++ RTTI/vtable/mangling detected"})

        # JavaScript / TypeScript / Node
        if (
            b"napi_create_function" in header
            or b"napi_register_module" in header
            or b"node_module_register" in header
            or b"console.log" in header
            or b"module.exports" in header
            or b"webpackChunk" in header
        ):
            labels.append({"category": "language", "name": "JavaScript", "confidence": 0.92, "details": "JS runtime/N-API detected"})

        # .NET
        if (
            b"mscoree.dll" in header
            or b"_CorExeMain" in header
            or b"BSJB" in header
            or ".clr" in secs_str
        ):
            labels.append({"category": "language", "name": ".NET", "confidence": 0.98, "details": "CLR .NET Managed Assembly"})

        # Python
        if (
            b"Py_Initialize" in header
            or b"PyEval_EvalCode" in header
            or (b"Python" in header and b"libpython" in header)
            or b"\xa7\r\r\n" in header[:16]
            or b"\xcb\x0e\r\n" in header[:16]
        ):
            labels.append({"category": "language", "name": "Python", "confidence": 0.90, "details": "Python C-API / Bytecode interpreter"})

        # Delphi / Borland
        if (
            b"Borland" in header
            or b"Embarcadero" in header
            or b"DVCLAL" in header
            or b"PACKAGEINFO" in header
        ):
            if not any(l["name"] == "Delphi" for l in labels):
                labels.append({"category": "language", "name": "Delphi", "confidence": 0.95, "details": "Borland / Embarcadero Delphi"})

        # VB6
        if b"VB5!" in header[:1024]:
            labels.append({"category": "language", "name": "VB6", "confidence": 1.0, "details": "Visual Basic 6.0"})

        # shc Encrypted Script
        if b"shc" in header[:2048].lower() or (b"arc4" in header and b"execvp" in header):
            labels.append({"category": "container", "name": "shc", "confidence": 0.95, "details": "shc Encrypted Shell Script"})

        # Default C fallback if native binary without heavy C++/Rust/Go features
        has_native_format = any(l["category"] == "format" and l["name"] in ("Mach-O", "ELF", "PE") for l in labels)
        if has_native_format and not any(l["category"] == "language" for l in labels):
            labels.append({"category": "language", "name": "C", "confidence": 0.75, "details": "Standard native compiled C binary"})

        # 3. Packer / Protector Detection
        if b"UPX0" in header or b"UPX!" in header:
            labels.append({"category": "packer", "name": "UPX", "confidence": 1.0, "details": "UPX executable compressor"})
        if ".vmp" in secs_str or b"VMProtect" in header:
            labels.append({"category": "packer", "name": "VMProtect", "confidence": 0.95, "details": "VMProtect virtualization wrapper"})
        if b"ConfuserEx" in header:
            labels.append({"category": "packer", "name": "ConfuserEx", "confidence": 0.95, "details": "ConfuserEx .NET Obfuscator"})

        return labels

    @classmethod
    def get_capabilities(cls, labels: List[Dict[str, Any]], is_activated: bool = True) -> Dict[str, Any]:
        """Implements R3 Capability Declaration for an artifact across all software types."""
        lang_names = [l["name"] for l in labels if l["category"] == "language"]
        fmt_names = [l["name"] for l in labels if l["category"] == "format"]
        packer_names = [l["name"] for l in labels if l["category"] == "packer"]
        cont_names = [l["name"] for l in labels if l["category"] == "container"]

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

        # Language and ecosystem specific capabilities
        if "JavaScript" in lang_names or "Bun" in cont_names or "ElectronAsar" in cont_names:
            capabilities["js_ast_analysis"] = {"status": "supported", "confidence": 0.95}
            capabilities["bun_unpacking"] = {"status": "supported", "confidence": 0.92}

        if "Rust" in lang_names:
            capabilities["rust_demangle"] = {"status": "supported", "confidence": 0.98}
            capabilities["rust_str_slice_recovery"] = {"status": "supported", "confidence": 0.90}

        if "Swift" in lang_names:
            capabilities["swift_demangle"] = {"status": "supported", "confidence": 0.90}

        if "Objective-C" in lang_names:
            capabilities["objc_selector_recovery"] = {"status": "supported", "confidence": 0.95}

        if "Go" in lang_names:
            capabilities["go_pclntab_recovery"] = {"status": "supported", "confidence": 0.98}

        if ".NET" in lang_names:
            capabilities["dotnet_metadata_recovery"] = {"status": "supported", "confidence": 0.95}

        if "JavaClass" in fmt_names or "Java" in lang_names or "DEX" in fmt_names:
            capabilities["jvm_bytecode_disassembly"] = {"status": "supported", "confidence": 1.0}

        if "WebAssembly" in fmt_names:
            capabilities["wasm_section_analysis"] = {"status": "supported", "confidence": 1.0}

        if "SQLite" in fmt_names:
            capabilities["sqlite_schema_extraction"] = {"status": "supported", "confidence": 1.0}

        if "Delphi" in lang_names or "DelphiDFM" in fmt_names:
            capabilities["delphi_dfm_decompilation"] = {"status": "supported", "confidence": 0.95}

        if "eBPF" in fmt_names:
            capabilities["ebpf_section_analysis"] = {"status": "supported", "confidence": 1.0}

        if "GodotPCK" in cont_names or "UnityAssetBundle" in cont_names or "UnrealPAK" in cont_names:
            capabilities["game_container_extraction"] = {"status": "supported", "confidence": 0.95}

        if "MetalShader" in fmt_names or "SPIR-V" in fmt_names or "DXBC" in fmt_names:
            capabilities["gpu_shader_symbol_extraction"] = {"status": "supported", "confidence": 0.95}

        if "BEAM" in fmt_names:
            capabilities["beam_bytecode_analysis"] = {"status": "supported", "confidence": 1.0}

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
