"""Task-Level MCP Tool Handlers for Metis Reverse.

Implements the 9 high-cohesion, task-level reverse engineering tools designed
specifically for AI reasoning, evidence provenance, and prompt injection defense.
"""

import json
import base64
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from ..config import MetisConfig, load_config
from ..security.prompt_shield import PromptShield
from ..security.sandbox import HypothesisSandbox
from ..storage.models import (
    SidecarDatabase,
    EvidencePointer,
    FunctionAnnotation,
    VariableAnnotation,
    StructDefinition,
    StructField,
)
from ..storage.sidecar_store import SidecarStore
from ..services.evidence_service import EvidenceService
from ..services.triage_service import TriageService
from ..services.crypto_service import CryptoService
from ..services.emulation_service import EmulationService
from ..engine.base import BaseReEngine
from ..engine.ghidra_engine import GhidraHeadlessEngine
from ..engine.native_engine import NativeEngine
from ..engine.mock_engine import MockEngine
from ..storage.artifact_tree import ArtifactTree, ArtifactNode
from ..services.container_extractor import ContainerExtractor
from ..services.polyglot_detector import PolyglotDetector
from ..services.bridge_service import BridgeService
from ..services.js_service import JSService
from ..services.deep_static_service import DeepStaticService
from ..services.family_adapters import FamilyAdapters

class MetisToolDispatcher:
    """Dispatches and executes the 9 task-level reverse engineering MCP tools."""

    def __init__(self, config: Optional[MetisConfig] = None, engine: Optional[BaseReEngine] = None):
        self.config = config or load_config()
        self.shield = PromptShield(aggressive_filter=self.config.enable_prompt_shield)
        self.sandbox = HypothesisSandbox(timeout_seconds=self.config.sandbox_timeout_seconds)
        self.sidecar_store = SidecarStore(storage_dir=self.config.sidecar_dir)
        self.evidence_service = EvidenceService()
        self.triage_service = TriageService()
        self.crypto_service = CryptoService()
        self.trees: Dict[str, ArtifactTree] = {}

        # Engine selection
        if engine:
            self.engine = engine
        elif self.config.has_ghidra:
            self.engine = GhidraHeadlessEngine(self.config)
        else:
            try:
                import lief
                self.engine = NativeEngine()
            except ImportError:
                self.engine = MockEngine()

        self.emulation_service = EmulationService(self.engine)
        self._active_sessions: Dict[str, Dict[str, Any]] = {}

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Returns schemas for the 9 task-level tools."""
        return [
            {
                "name": "re_inspect",
                "description": "Primary universal entry point for all software forms and languages (binaries, directories/.app, bytecode, scripts, containers, databases, shaders). Automatically mounts sessions, builds artifact trees, identifies polyglot families, and returns core structures with next-step tool recommendations. Strictly prefer this over raw shell commands (strings/objdump/unzip/grep).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target_path_or_artifact": {"type": "string", "description": "Path to binary, application package (.app), directory, archive, or artifact ID"},
                        "query_or_focus": {"type": "string", "description": "Optional focus area (e.g. 'structure', 'symbols', 'schemas', 'bytecode', 'crypto')"}
                    }
                }
            },
            {
                "name": "re_session_manager",
                "description": "Manages reverse-engineering sessions, read-only sample/directory mounting (.app, directories, archives, binaries), snapshots, and sidecar export/import.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "enum": ["open", "close", "list", "status", "export_sidecar", "import_sidecar"], "description": "Action to perform"},
                        "file_path": {"type": "string", "description": "Path to binary file or directory bundle (for 'open')"},
                        "session_id": {"type": "string", "description": "Session identifier"},
                        "format": {"type": "string", "enum": ["yaml", "json"], "default": "yaml"}
                    },
                    "required": ["action"]
                }
            },
            {
                "name": "re_triage",
                "description": "Performs initial triage on binaries, directory bundles (.app), or archives, format detection, section entropy heatmaps, packer recognition, and domain tool parsing (YARA/DIE).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "file_path": {"type": "string", "description": "Path to target binary file"},
                        "tool_feedback": {
                            "type": "object",
                            "properties": {
                                "tool_name": {"type": "string"},
                                "exit_code": {"type": "integer"},
                                "stdout": {"type": "string"}
                            },
                            "description": "Optional output from external tools to parse domain-specific exit semantics"
                        }
                    },
                    "required": ["file_path"]
                }
            },
            {
                "name": "re_query_function",
                "description": "Extracts reasoning-optimized function context (token-bounded decompiled code, callers, callees, strings, constants) with prompt-injection defense.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "va_or_name": {"type": "string", "description": "Function virtual address (e.g. '0x140001000') or symbol name"},
                        "max_tokens": {"type": "integer", "default": 2048, "description": "Token budget cap for decompilation context"},
                        "include_libraries": {"type": "boolean", "default": False, "description": "Whether to expand standard library callees/callers (R13)"}
                    },
                    "required": ["session_id", "va_or_name"]
                }
            },
            {
                "name": "re_decompile_function",
                "description": "Decompiles a function, returning pseudocode alongside disassembly and decompiler warnings (P1-3, R14).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "va_or_name": {"type": "string", "description": "Virtual address or symbol name"},
                        "include_libraries": {"type": "boolean", "default": False, "description": "Whether to expand standard library callees/callers (R13)"}
                    },
                    "required": ["va_or_name"]
                }
            },
            {
                "name": "re_hunt_crypto_and_hashes",
                "description": "Identifies cryptographic algorithms (AES S-Boxes, SHA/MD5 IVs, ChaCha20, CRC32) and resolves API hashes with exact address provenance.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "base_va": {"type": "string", "description": "Virtual address to anchor search"},
                        "algorithm_hint": {"type": "string", "description": "Optional algorithm hint (e.g., 'aes', 'ror13', 'crc32')"}
                    },
                    "required": ["session_id"]
                }
            },
            {
                "name": "re_verify_hypothesis",
                "description": "Runs agent-written hypothesis scripts (e.g. XOR/AES decryptor or API hash cracker) in an isolated Python sandbox against real memory slices.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "script_code": {"type": "string", "description": "Python verification script defining verify(memory_slice) or setting result"},
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "target_va": {"type": "string", "description": "Virtual address of memory slice to test against"},
                        "slice_size": {"type": "integer", "default": 64, "description": "Number of bytes to extract for testing"},
                        "expected_output": {"type": "string", "description": "Optional expected plaintext string or hex to assert against"}
                    },
                    "required": ["script_code", "session_id", "target_va"]
                }
            },
            {
                "name": "re_emulate_slice",
                "description": "Executes controlled micro-emulation from start address to a breakpoint, capturing real register states and memory buffer snapshots.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "start_va": {"type": "string", "description": "Starting virtual address"},
                        "stop_va": {"type": "string", "description": "Breakpoint virtual address"},
                        "initial_registers": {"type": "object", "description": "Optional initial register values (e.g. {'rax': 1})"},
                        "memory_addresses": {"type": "array", "items": {"type": "string"}, "description": "Addresses to snapshot after stopping"}
                    },
                    "required": ["session_id", "start_va", "stop_va"]
                }
            },
            {
                "name": "re_refine_model",
                "description": "Commits confirmed reverse-engineering knowledge (renaming functions, setting variable types, defining structs, adding comments) directly into the Sidecar store.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "function_renames": {"type": "object", "description": "Map of VA -> new function name"},
                        "variable_annotations": {"type": "array", "items": {"type": "object"}, "description": "List of variable types and names"},
                        "struct_definitions": {"type": "array", "items": {"type": "object"}, "description": "List of struct definitions with field offsets"},
                        "comments": {"type": "object", "description": "Map of VA -> explanation comment"}
                    },
                    "required": ["session_id"]
                }
            },
            {
                "name": "re_diff_and_transfer",
                "description": "Performs cross-version function matching (via CFG hash and constant fingerprints) and migrates sidecar annotations to a new sample without database diffing.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "source_sha256": {"type": "string", "description": "SHA256 of source analyzed binary with existing sidecar"},
                        "target_session_id": {"type": "string", "description": "Active session ID of the target/newer binary"}
                    },
                    "required": ["source_sha256", "target_session_id"]
                }
            },
            {
                "name": "re_query_evidence",
                "description": "Queries the verified provenance and concrete address of any variable, symbol, struct, or algorithm deduction. Strictly audits search locations if not found.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "query": {"type": "string", "description": "Address, symbol name, variable, or algorithm tag to audit"}
                    },
                    "required": ["session_id", "query"]
                }
            },
            {
                "name": "re_capabilities",
                "description": "Declares supported capabilities, degraded operations, and fallback paths for an artifact (R3).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "artifact_id": {"type": "string", "description": "Artifact node ID (defaults to 'root')"}
                    }
                }
            },
            {
                "name": "re_read_file_range",
                "description": "Reads raw bytes directly from physical storage by file offset, bypassing virtual memory mapping (P0-1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "offset": {"type": "integer", "description": "File offset in bytes"},
                        "length": {"type": "integer", "description": "Number of bytes to read"},
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "artifact_id": {"type": "string", "description": "Artifact node ID"}
                    },
                    "required": ["offset", "length"]
                }
            },
            {
                "name": "re_translate_address",
                "description": "Converts between VA, RVA, and physical file offset coordinates across segments/sections (R8, P0-1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "value": {"description": "Address or offset value (hex string e.g. '0x1000' or int)"},
                        "from_kind": {"type": "string", "enum": ["va", "rva", "file_offset"], "default": "va"},
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "artifact_id": {"type": "string", "description": "Artifact node ID"}
                    },
                    "required": ["value"]
                }
            },
            {
                "name": "re_list_artifacts",
                "description": "Enumerates nodes in the hierarchical Artifact Tree with cursor-based pagination (P0-3, R2).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "parent_id": {"type": "string", "description": "Optional parent artifact ID filter"},
                        "cursor": {"type": "integer", "default": 0},
                        "limit": {"type": "integer", "default": 50}
                    }
                }
            },
            {
                "name": "re_tree_status",
                "description": "Returns full hierarchy, decomposition status, and family distribution of the Artifact Tree (P0-3).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"}
                    }
                }
            },
            {
                "name": "re_inspect_artifact",
                "description": "Inspects detailed metadata, polyglot families, size, and capabilities for a specific artifact node.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "artifact_id": {"type": "string", "description": "Artifact node ID"},
                        "session_id": {"type": "string", "description": "Active session ID"}
                    }
                }
            },
            {
                "name": "re_inspect_binary_structure",
                "description": "Inspects structural binary layout (headers, segments, sections, dependencies/dylibs, imported/exported symbols, encryption info/LC_ENCRYPTION_INFO). Use this instead of terminal commands like otool, readelf, or ad-hoc lief scripts.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "scope": {
                            "type": "string",
                            "enum": ["all", "headers", "segments", "sections", "dependencies", "symbols", "encryption"],
                            "default": "all",
                            "description": "Scope of structural inspection"
                        },
                        "query": {"type": "string", "description": "Optional substring filter for symbol, section, or dependency names"},
                        "limit": {"type": "integer", "default": 100, "description": "Maximum number of symbols to return"}
                    },
                    "required": ["session_id"]
                }
            },
            {
                "name": "re_register_child_artifact",
                "description": "Dynamically mounts a child artifact slice into the Artifact Tree (P0-2, Escape Hatch 1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "parent_id": {"type": "string", "default": "root"},
                        "offset": {"type": "integer", "default": 0},
                        "length": {"type": "integer", "default": 0},
                        "custom_unpacked_bytes": {"type": "string", "description": "Hex or base64 or raw string bytes"},
                        "name": {"type": "string", "description": "Name for child artifact"},
                        "description": {"type": "string", "description": "Description of payload"},
                        "families": {"type": "array", "items": {"type": "string"}},
                        "session_id": {"type": "string", "description": "Active session ID"}
                    },
                    "required": ["custom_unpacked_bytes"]
                }
            },
            {
                "name": "re_run_probe_script",
                "description": "Executes an isolated Python structure probe script with direct binary access and child artifact registration (Escape Hatch 1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "script_code": {"type": "string", "description": "Python script with binary read APIs and register_child()"},
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "artifact_id": {"type": "string", "description": "Target artifact ID"}
                    },
                    "required": ["script_code"]
                }
            },
            {
                "name": "re_bridge_map",
                "description": "Recovers cross-language bridges: N-API (.node), JNI, Electron IPC, Tauri, PyO3, CGO, P/Invoke, and heuristic links (P1-2, Escape Hatch 3).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "artifact_id": {"type": "string", "description": "Artifact node ID"},
                        "bridge_type": {"type": "string", "enum": ["napi", "ipc", "tauri", "jni", "pyo3", "cgo", "pinvoke", "all"], "default": "all"},
                        "heuristic_mode": {"type": "boolean", "default": True}
                    }
                }
            },
            {
                "name": "re_extract_schemas",
                "description": "Extracts embedded schemas: SQLite DDL, JSON Schemas, and Protobuf descriptors (P1-5).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "artifact_id": {"type": "string", "description": "Artifact node ID"}
                    }
                }
            },
            {
                "name": "re_add_finding",
                "description": "Records a tiered evidence finding: proven (verified coordinates), corroborated (multi-source/sandbox), or hypothesis (R1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "claim": {"type": "string", "description": "Assertion or finding statement"},
                        "evidence": {"type": "array", "items": {"type": "object"}, "description": "List of evidence pointers"},
                        "confidence": {"type": "number", "default": 1.0},
                        "status": {"type": "string", "enum": ["proven", "corroborated", "hypothesis"], "default": "proven"},
                        "session_id": {"type": "string", "description": "Active session ID"}
                    },
                    "required": ["claim"]
                }
            },
            {
                "name": "js_list_modules",
                "description": "Lists JavaScript modules embedded in a bundle, single-file binary, or archive (P1-1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "artifact_id": {"type": "string", "description": "Artifact node ID"},
                        "cursor": {"type": "integer", "default": 0},
                        "limit": {"type": "integer", "default": 50}
                    }
                }
            },
            {
                "name": "js_get_module",
                "description": "Retrieves JavaScript module code by line range, AST function closure, or character offset (P1-1). Includes safety guard against single-line minified context overflow.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "artifact_id": {"type": "string", "description": "Artifact node ID"},
                        "module_path": {"type": "string", "description": "Module name or path"},
                        "slice_mode": {"type": "string", "enum": ["line", "closure", "range"], "default": "line", "description": "Slicing mode: 'line' for line range, 'closure' for AST function closure, 'range' for character offsets"},
                        "closure_name": {"type": "string", "description": "Name of function/closure to extract (for 'closure' mode)"},
                        "closure_index": {"type": "integer", "description": "Index of closure to extract (for 'closure' mode)"},
                        "start_line": {"type": "integer", "default": 1},
                        "end_line": {"type": "integer"},
                        "max_lines": {"type": "integer", "default": 200},
                        "start_char": {"type": "integer"},
                        "end_char": {"type": "integer"},
                        "max_chars": {"type": "integer", "default": 4000}
                    }
                }
            },
            {
                "name": "js_list_closures",
                "description": "Lists AST function closures in a JavaScript module without dumping full source, ideal for large minified bundles (P1-1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "artifact_id": {"type": "string", "description": "Artifact node ID"},
                        "module_path": {"type": "string", "description": "Module name or path"},
                        "cursor": {"type": "integer", "default": 0},
                        "limit": {"type": "integer", "default": 50}
                    }
                }
            },
            {
                "name": "js_search",
                "description": "Searches JavaScript source across bundle modules via text or regular expressions (P1-1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "Text or regex search string"},
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "artifact_id": {"type": "string", "description": "Artifact node ID"},
                        "is_regex": {"type": "boolean", "default": False},
                        "cursor": {"type": "integer", "default": 0},
                        "limit": {"type": "integer", "default": 50}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "js_functions",
                "description": "Extracts JavaScript function declarations and closures (P1-1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "artifact_id": {"type": "string", "description": "Artifact node ID"},
                        "module_path": {"type": "string"}
                    }
                }
            },
            {
                "name": "js_strings",
                "description": "Extracts URLs, hostnames, environment variables, and config keys from JavaScript (P1-1).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Active session ID"},
                        "artifact_id": {"type": "string", "description": "Artifact node ID"},
                        "module_path": {"type": "string"}
                    }
                }
            }
        ]

    def dispatch(self, tool_name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches an MCP tool call to its corresponding method."""
        method_name = f"handle_{tool_name}"
        handler = getattr(self, method_name, None)
        if not handler:
            # Check legacy / convenience aliases
            aliases = {
                "open_session": lambda a: self.handle_re_session_manager({"action": "open", **a}),
                "close_session": lambda a: self.handle_re_session_manager({"action": "close", **a}),
                "query_evidence": self.handle_re_query_evidence,
                "inspect_artifact": self.handle_re_inspect_artifact,
                "inspect_binary_structure": self.handle_re_inspect_binary_structure,
                "inspect_structure": self.handle_re_inspect_binary_structure,
                "binary_structure": self.handle_re_inspect_binary_structure,
                "decompile": self.handle_re_decompile_function,
                "analyze_function": self.handle_re_query_function,
                "inspect": self.handle_re_inspect,
                "re_inspect": self.handle_re_inspect,
            }
            if tool_name in aliases:
                handler = aliases[tool_name]
            else:
                return {"status": "error", "error": f"Unknown tool: {tool_name}"}
        try:
            return handler(args)
        except Exception as e:
            return {"status": "error", "error": f"Tool execution failed: {type(e).__name__}: {str(e)}"}

    # 1. re_session_manager
    def handle_re_session_manager(self, args: Dict[str, Any]) -> Dict[str, Any]:
        action = args.get("action")
        session_id = args.get("session_id", "default_sess")
        
        if action == "open":
            file_path = args.get("file_path")
            if not file_path:
                return {"status": "error", "message": "file_path is required for 'open'"}
            p = Path(file_path).resolve()
            tree = None
            root_node = None
            res = {}
            sha = ""
            if p.exists():
                tree = ArtifactTree.build_tree_from_path(str(p))
                root_node = tree.get_node("root")
                if p.is_file():
                    try:
                        res = self.engine.open_session(str(p), session_id)
                        sha = res.get("sample_sha256", "")
                    except Exception:
                        pass
                elif p.is_dir():
                    main_node = tree.get_node("root:main_exec")
                    if main_node and main_node.file_path and Path(main_node.file_path).is_file():
                        try:
                            res = self.engine.open_session(main_node.file_path, session_id)
                            sha = res.get("sample_sha256", "")
                        except Exception:
                            pass
            else:
                # Fallback for virtual or mock samples in test environments
                try:
                    res = self.engine.open_session(file_path, session_id)
                    sha = res.get("sample_sha256", hashlib.sha256(file_path.encode()).hexdigest())
                    tree = ArtifactTree()
                    root_node = ArtifactNode(
                        id="root",
                        name=Path(file_path).name,
                        file_path=file_path,
                        size=1024,
                        sha256=sha,
                        families=["binary"],
                        is_activated=True,
                    )
                    tree.add_node(root_node)
                except Exception:
                    return {"status": "error", "message": f"Path not found: {file_path}"}

            if not sha and root_node and root_node.sha256:
                sha = root_node.sha256
            if not sha:
                sha = hashlib.sha256(p.name.encode()).hexdigest()

            sidecar = self.sidecar_store.get_or_create(sha, p.name)

            families = root_node.families if root_node else []
            caps = root_node.capabilities if root_node else {}

            self._active_sessions[session_id] = {
                "file_path": str(p),
                "sha256": sha,
                "sidecar": sidecar,
                "artifact_tree": tree,
            }
            self.trees[session_id] = tree

            return {
                "status": "ready",
                "session_id": session_id,
                "sample_sha256": sha,
                "binary_path": str(p),
                "entrypoint": res.get("entrypoint", "0x0"),
                "format": res.get("format", "Directory Bundle" if p.is_dir() else "Unknown"),
                "architecture": res.get("architecture", "Unknown"),
                "function_count": res.get("function_count", 0),
                "families": families,
                "capabilities": caps,
                "sub_artifacts_count": len(tree.nodes) - 1,
                "sidecar_persisted": True,
                "message": "Session mounted in read-only mode."
            }

        elif action == "close":
            self.engine.close_session(session_id)
            if session_id in self._active_sessions:
                del self._active_sessions[session_id]
            if session_id in self.trees:
                del self.trees[session_id]
            return {"status": "closed", "session_id": session_id}

        elif action == "list":
            return {
                "active_sessions": list(self._active_sessions.keys()),
                "sessions": [
                    {"session_id": k, "sha256": v["sha256"], "file": v["file_path"]}
                    for k, v in self._active_sessions.items()
                ]
            }

        elif action == "status":
            sess = self._active_sessions.get(session_id)
            if not sess:
                return {"status": "error", "message": f"Session {session_id} not found"}
            meta = {}
            try:
                meta = self.engine.get_metadata(session_id)
            except Exception:
                pass
            return {
                "status": "ready",
                "session_id": session_id,
                "file_path": sess.get("file_path"),
                "sample_sha256": sess.get("sha256"),
                "format": meta.get("format", "Unknown"),
                "architecture": meta.get("arch", "Unknown"),
                "entrypoint": meta.get("entrypoint", "0x0"),
                "metadata": meta,
                "sidecar_functions_count": len(sess["sidecar"].functions) if "sidecar" in sess else 0,
                "sidecar_structs_count": len(sess["sidecar"].structs) if "sidecar" in sess else 0,
            }

        elif action == "export_sidecar":
            sess = self._active_sessions.get(session_id)
            if not sess:
                return {"status": "error", "message": f"Session {session_id} not found"}
            fmt = args.get("format", "yaml")
            custom_path = args.get("file_path")
            target_path = Path(custom_path) if custom_path else None
            path = self.sidecar_store.save(sess["sidecar"], format_type=fmt, custom_path=target_path)
            return {
                "status": "exported",
                "session_id": session_id,
                "path": str(path),
                "format": fmt,
            }

        elif action == "import_sidecar":
            sess = self._active_sessions.get(session_id)
            if not sess:
                return {"status": "error", "message": f"Session {session_id} not found"}
            loaded = self.sidecar_store.load(sess["sha256"])
            if loaded:
                sess["sidecar"] = loaded
                return {"status": "imported", "functions_count": len(loaded.functions), "structs_count": len(loaded.structs)}
            return {"status": "not_found", "message": "No existing sidecar found on disk"}

        return {"status": "error", "message": f"Unsupported action: {action}"}

    # 2. re_triage
    def handle_re_triage(self, args: Dict[str, Any]) -> Dict[str, Any]:
        file_path = args.get("file_path")
        tool_feedback = args.get("tool_feedback")

        triage_report = self.triage_service.triage_file(file_path)

        # Check memory consistency if active session matches file (P0-1)
        for s_id, sess in self._active_sessions.items():
            if sess.get("file_path") == file_path:
                try:
                    chk = self.engine.check_memory_consistency(s_id)
                    triage_report["memory_view_unreliable"] = chk.get("memory_view_unreliable", False)
                    if chk.get("memory_view_unreliable"):
                        triage_report["memory_warning"] = chk.get("warning")
                        triage_report["discrepancies"] = chk.get("discrepancies", [])
                except Exception:
                    pass
                break

        if tool_feedback:
            parsed = self.triage_service.parse_tool_exit_code(
                tool_feedback.get("tool_name", "generic_tool"),
                tool_feedback.get("exit_code", 0),
                tool_feedback.get("stdout", "")
            )
            triage_report["external_tool_semantics"] = parsed

        return triage_report

    # 3. re_query_function & re_decompile_function
    def handle_re_decompile_function(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Alias for re_query_function adhering to P1-3 & R14 decompilation multi-view."""
        return self.handle_re_query_function(args)

    def handle_re_query_function(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        va_or_name = args.get("va_or_name") or args.get("va") or args.get("name")
        max_tokens = args.get("max_tokens", 2048)
        include_libraries = bool(args.get("include_libraries", False))

        fn_ctx = self.engine.get_function_context(session_id, va_or_name, max_tokens=max_tokens)
        if fn_ctx.get("status") == "not_found":
            return fn_ctx

        # Coordinates translation (R8)
        try:
            coords = self.engine.translate_address(session_id, fn_ctx["va"], from_kind="va")
            fn_ctx["triple_coordinates"] = {
                "va": coords["va"],
                "rva": coords["rva"],
                "file_offset": coords["file_offset"],
                "segment": coords.get("segment"),
                "section": coords.get("section"),
            }
        except Exception:
            pass

        # Check for non-standard decompiler warnings (R14)
        warnings = []
        code_str = fn_ctx.get("decompiled_code", "")
        if "unaff_" in code_str:
            warnings.append("Non-standard register calling convention detected (unaff_ variables present). Check disassembly.")
        if len(fn_ctx.get("callees", [])) == 0 and len(fn_ctx.get("callers", [])) > 5 and len(code_str.splitlines()) < 8:
            warnings.append("Possible noreturn truncation; function body is unusually short compared to inbound caller density.")
        if warnings:
            fn_ctx["decompiler_warnings"] = warnings
            # Ensure disassembly is explicitly present side-by-side with pseudocode
            if "disassembly" not in fn_ctx or not fn_ctx["disassembly"]:
                fn_ctx["disassembly"] = f"// Raw disassembly unavailable for {fn_ctx.get('name', 'fn')} at {fn_ctx.get('va')}"

        # Library folding flags (R13)
        all_callees = fn_ctx.get("callees", [])
        all_callers = fn_ctx.get("callers", [])
        for c in all_callees:
            c["is_library"] = PolyglotDetector.is_library_symbol(c.get("name", ""))
        for cl in all_callers:
            cl["is_library"] = PolyglotDetector.is_library_symbol(cl.get("name", ""))

        include_libraries = args.get("include_libraries")
        if include_libraries is False:
            folded_callees = [c for c in all_callees if not c.get("is_library")]
            folded_callers = [cl for cl in all_callers if not cl.get("is_library")]
            fn_ctx["callees"] = folded_callees
            fn_ctx["callers"] = folded_callers
            fn_ctx["libraries_folded"] = {
                "folded": True,
                "callees_folded_count": len(all_callees) - len(folded_callees),
                "callers_folded_count": len(all_callers) - len(folded_callers),
                "hint": "Set include_libraries=true to expand standard library callers/callees (R13)."
            }
        elif include_libraries is True:
            fn_ctx["libraries_folded"] = {
                "folded": False,
                "status": "expanded",
                "include_libraries": True
            }

        # Wrap referenced strings in PromptShield to protect agent against prompt injections
        shielded_strings = []
        for s_item in fn_ctx.get("referenced_strings", []):
            wrapped = self.shield.wrap_evidence(
                content=s_item.get("text", ""),
                va=s_item.get("va", "N/A"),
                evidence_type="string_literal"
            )
            shielded_strings.append(wrapped)

        fn_ctx["referenced_strings_shielded"] = shielded_strings

        # Register evidence pointer
        self.evidence_service.register_evidence(
            session_id,
            EvidencePointer(
                va=fn_ctx["va"],
                evidence_type="decompiled_function",
                description=f"Function {fn_ctx['name']} analyzed at {fn_ctx['va']}",
                confidence=1.0,
            )
        )

        return fn_ctx

    # 4. re_hunt_crypto_and_hashes
    def handle_re_hunt_crypto_and_hashes(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        if not sess:
            return {"status": "error", "message": f"Session {session_id} not found"}

        base_va = args.get("base_va")
        algorithm_hint = (args.get("algorithm_hint") or "").lower()

        sbox_findings = []
        constants_map = {}

        # 1. S-box scanning
        if base_va:
            mem_slice = b""
            try:
                mem_slice = self.engine.get_memory_slice(session_id, base_va, 4096)
            except ValueError:
                mem_slice = b""
            if mem_slice:
                sbox_findings = self.crypto_service.scan_memory_for_sboxes(mem_slice, base_va=base_va)
            fn_ctx = self.engine.get_function_context(session_id, base_va)
            if fn_ctx.get("status") == "success" and fn_ctx.get("referenced_constants"):
                constants_map[fn_ctx["va"]] = fn_ctx["referenced_constants"]
        else:
            # Scan binary/sections for S-boxes across binary
            eng_sess = getattr(self.engine, "_active_sessions", {}).get(session_id) or getattr(self.engine, "_sessions", {}).get(session_id)
            if eng_sess and "sections_data" in eng_sess:
                for s in eng_sess["sections_data"]:
                    s_findings = self.crypto_service.scan_memory_for_sboxes(
                        s["content"],
                        base_va=hex(s["virtual_address"])
                    )
                    sbox_findings.extend(s_findings)
            else:
                file_path = sess.get("file_path")
                if file_path and Path(file_path).is_file():
                    try:
                        import lief
                        parsed = lief.parse(str(Path(file_path).absolute()))
                        if parsed and hasattr(parsed, "sections"):
                            for s in parsed.sections:
                                s_findings = self.crypto_service.scan_memory_for_sboxes(
                                    bytes(s.content),
                                    base_va=hex(s.virtual_address)
                                )
                                sbox_findings.extend(s_findings)
                        else:
                            with open(file_path, "rb") as f:
                                raw = f.read()
                            sbox_findings = self.crypto_service.scan_memory_for_sboxes(raw, base_va="0x0")
                    except Exception:
                        pass

        # 2. Constant & API hash scanning across functions (bounded to prevent MCP timeouts)
        fn_list = self.engine.list_functions(session_id, limit=50).get("functions", [])
        for f_meta in fn_list:
            f_va = f_meta.get("va")
            if f_va and f_va not in constants_map:
                try:
                    fn_ctx = self.engine.get_function_context(session_id, f_va)
                    if fn_ctx.get("status") == "success" and fn_ctx.get("referenced_constants"):
                        constants_map[f_va] = fn_ctx["referenced_constants"]
                except Exception:
                    pass

        const_findings = self.crypto_service.analyze_constants(constants_map)

        # 3. API hash resolution
        api_hash_findings = []
        for f_va, c_list in constants_map.items():
            for c in c_list:
                c_val = c & 0xFFFFFFFF
                resolved_api = self.crypto_service.resolve_api_hash(c_val)
                if resolved_api:
                    api_hash_findings.append({
                        "va": f_va,
                        "constant_hex": hex(c_val),
                        "algorithm": "ror13",
                        "api_name": resolved_api,
                        "confidence": 1.0,
                        "evidence_pointer": EvidencePointer(
                            va=f_va,
                            evidence_type="api_hash_resolved",
                            description=f"Constant {hex(c_val)} matches ROR13 API hash for {resolved_api}",
                            confidence=1.0,
                        ).to_dict()
                    })
                    sess["sidecar"].api_hashes[hex(c_val)] = resolved_api

        all_findings = sbox_findings + const_findings + api_hash_findings

        # Filter by algorithm hint if provided
        if algorithm_hint:
            all_findings = [
                f for f in all_findings
                if algorithm_hint in str(f.get("algorithm", "")).lower()
                or algorithm_hint in str(f.get("primitive", "")).lower()
            ]

        # Sync findings into sidecar (avoiding duplicate findings)
        existing_vas_and_algos = {
            (cf.get("va"), cf.get("algorithm"), cf.get("constant_hex"))
            for cf in sess["sidecar"].crypto_findings
        }
        for f in all_findings:
            key = (f.get("va"), f.get("algorithm"), f.get("constant_hex"))
            if key not in existing_vas_and_algos:
                sess["sidecar"].crypto_findings.append(f)
                existing_vas_and_algos.add(key)
                self.evidence_service.register_evidence(
                    session_id,
                    EvidencePointer(
                        va=f["va"],
                        evidence_type="crypto_detection",
                        description=f"Detected {f.get('algorithm', 'Crypto')} primitive",
                        confidence=f.get("confidence", 0.95),
                    )
                )

        self.sidecar_store.save(sess["sidecar"])

        return {
            "status": "success",
            "findings_count": len(all_findings),
            "crypto_findings": all_findings,
            "sidecar_updated": True,
        }

    # 5. re_verify_hypothesis
    def handle_re_verify_hypothesis(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        script_code = args.get("script_code")
        target_va = args.get("target_va")
        slice_size = args.get("slice_size", 64)
        expected_output = args.get("expected_output")

        # Fetch actual memory bytes from target VA
        try:
            mem_bytes = self.engine.get_memory_slice(session_id, target_va, slice_size)
        except (ValueError, KeyError) as e:
            return {
                "status": "error",
                "error": f"AddressUnmappedError: {str(e)}",
                "va": target_va,
                "hypothesis_confirmed": False,
            }

        # Run in sandbox
        result = self.sandbox.execute_script(
            script_code=script_code,
            memory_slice=mem_bytes,
            expected_output=expected_output,
            va=target_va
        )

        if result.get("hypothesis_confirmed"):
            self.evidence_service.register_evidence(
                session_id,
                EvidencePointer(
                    va=target_va,
                    evidence_type="sandbox_verification",
                    description=f"Hypothesis successfully verified via sandbox script: returned '{result.get('returned_value')}'",
                    confidence=1.0,
                )
            )

        return result

    # 6. re_emulate_slice
    def handle_re_emulate_slice(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        start_va = args.get("start_va")
        stop_va = args.get("stop_va")
        initial_regs = args.get("initial_registers", {})
        mem_addrs = args.get("memory_addresses", [])

        res = self.emulation_service.emulate_slice(
            session_id=session_id,
            start_va=start_va,
            stop_va=stop_va,
            initial_registers=initial_regs,
            memory_inspect_addresses=mem_addrs,
        )

        if (
            res.get("status") == "breakpoint_reached"
            and not res.get("has_error")
            and not res.get("error")
            and res.get("steps_executed", 0) > 0
        ):
            self.evidence_service.register_evidence(
                session_id,
                EvidencePointer(
                    va=stop_va,
                    evidence_type="micro_emulation_trace",
                    description=f"Micro-emulation trace executed {res['steps_executed']} instructions on {res.get('arch', 'CPU')} from {start_va} to {stop_va}",
                    confidence=0.6,
                )
            )

        return res

    # 7. re_refine_model
    def handle_re_refine_model(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        if not sess:
            return {"status": "error", "message": f"Session {session_id} not found"}

        db: SidecarDatabase = sess["sidecar"]
        applied_summary = []

            # 1. Function renames
        fn_renames = args.get("function_renames", {})
        for va, new_name in fn_renames.items():
            if va in db.functions:
                db.functions[va].renamed_to = new_name
            else:
                db.functions[va] = FunctionAnnotation(
                    original_va=va,
                    original_name=f"FUN_{va.replace('0x', '')}",
                    renamed_to=new_name,
                    evidence=[
                        EvidencePointer(
                            va=va,
                            evidence_type="manual_refinement",
                            description=f"Renamed to {new_name}",
                            confidence=1.0,
                        )
                    ]
                )

            # Query engine to fill in cfg_hash, constants_fingerprint, and callees if missing
            if not db.functions[va].cfg_hash or not db.functions[va].constants_fingerprint:
                try:
                    fn_ctx = self.engine.get_function_context(session_id, va)
                    if fn_ctx.get("status") == "success":
                        if not db.functions[va].cfg_hash:
                            db.functions[va].cfg_hash = fn_ctx.get("cfg_hash")
                        if not db.functions[va].constants_fingerprint:
                            db.functions[va].constants_fingerprint = fn_ctx.get("referenced_constants", [])
                        if not db.functions[va].callees:
                            db.functions[va].callees = [
                                c.get("va") if isinstance(c, dict) else str(c)
                                for c in fn_ctx.get("callees", [])
                            ]
                except Exception:
                    pass

            applied_summary.append(f"Renamed function at {va} to '{new_name}'")

        # 2. Variable annotations
        var_annos = args.get("variable_annotations", [])
        for v in var_annos:
            fva = v.get("function_va")
            if fva and fva in db.functions:
                db.functions[fva].variables.append(
                    VariableAnnotation(
                        original_name=v.get("original_name", "uVar"),
                        renamed_to=v.get("renamed_to", "pBuffer"),
                        inferred_type=v.get("inferred_type", "void*"),
                        evidence_va=v.get("evidence_va", fva),
                    )
                )
                applied_summary.append(f"Typed variable {v.get('renamed_to')} inside {fva}")

        # 3. Struct definitions
        structs = args.get("struct_definitions", [])
        for s in structs:
            s_name = s.get("name")
            if s_name:
                st = StructDefinition(
                    name=s_name,
                    size=s.get("size", 0),
                    evidence_va=s.get("evidence_va", "N/A"),
                    comment=s.get("comment", "")
                )
                for fld in s.get("fields", []):
                    st.fields.append(StructField(**fld))
                db.structs[s_name] = st
                applied_summary.append(f"Defined struct '{s_name}' ({st.size} bytes)")

        # 4. Comments
        comments = args.get("comments", {})
        for va, cmt in comments.items():
            db.global_comments[va] = cmt
            if va in db.functions:
                db.functions[va].comments[va] = cmt
            applied_summary.append(f"Added comment at {va}: '{cmt}'")

        # 5. Save sidecar to disk
        path = self.sidecar_store.save(db)

        # Notify engine if applicable
        self.engine.apply_refinements(session_id, {"function_renames": fn_renames})

        return {
            "status": "success",
            "applied_count": len(applied_summary),
            "details": applied_summary,
            "sidecar_file": str(path),
        }

    # 8. re_diff_and_transfer
    def handle_re_diff_and_transfer(self, args: Dict[str, Any]) -> Dict[str, Any]:
        source_sha = args.get("source_sha256")
        target_session_id = args.get("target_session_id")

        source_db = self.sidecar_store.load(source_sha)
        if not source_db:
            return {"status": "error", "message": f"Source sidecar for {source_sha} not found"}

        target_sess = self._active_sessions.get(target_session_id)
        if not target_sess:
            return {"status": "error", "message": f"Target session {target_session_id} not found"}

        # Extract target functions
        target_fns = self.engine.list_functions(target_session_id, limit=500).get("functions", [])
        
        target_db, report = self.sidecar_store.transfer_to_target(
            source_db=source_db,
            target_functions=target_fns,
            target_sha256=target_sess["sha256"],
            target_name=Path(target_sess["file_path"]).name,
        )

        target_sess["sidecar"] = target_db

        matched_count = report.get("matched_count", 0)
        structs_migrated = report.get("structs_migrated", 0)
        status_str = "transferred" if (matched_count > 0 or structs_migrated > 0) else "no_matches_found"

        return {
            "status": status_str,
            "report": report,
            "sidecar_persisted": True
        }

    # 9. re_query_evidence
    def handle_re_query_evidence(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        query_target = args.get("query")

        sidecar_db = sess["sidecar"] if sess else None

        return self.evidence_service.query(query_target, session_id, sidecar_db=sidecar_db)

    def _resolve_session_and_tree(self, args: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], Optional[ArtifactTree], str, str]:
        """Helper resolving session, tree, session_id, and artifact_id from args with Zero-Friction auto-creation."""
        session_id = args.get("session_id")
        artifact_id = args.get("artifact_id", "root")
        path_candidate = args.get("file_path") or args.get("target_path_or_artifact") or args.get("path") or args.get("target")

        # 1. If path candidate points to an existing file/dir on disk, mount or reuse session
        if path_candidate and Path(path_candidate).exists():
            resolved_p = str(Path(path_candidate).resolve())
            for s_id, s_data in self._active_sessions.items():
                if s_data.get("file_path") and str(Path(s_data["file_path"]).resolve()) == resolved_p:
                    session_id = s_id
                    break
            if not session_id or session_id not in self._active_sessions:
                auto_sess_id = f"auto_{hashlib.sha256(resolved_p.encode()).hexdigest()[:10]}"
                self.handle_re_session_manager({"action": "open", "file_path": resolved_p, "session_id": auto_sess_id})
                session_id = auto_sess_id

        # 2. If session_id was passed as a path (common Agent habit)
        elif session_id and Path(session_id).exists():
            resolved_p = str(Path(session_id).resolve())
            for s_id, s_data in self._active_sessions.items():
                if s_data.get("file_path") and str(Path(s_data["file_path"]).resolve()) == resolved_p:
                    session_id = s_id
                    break
            if session_id not in self._active_sessions:
                auto_sess_id = f"auto_{hashlib.sha256(resolved_p.encode()).hexdigest()[:10]}"
                self.handle_re_session_manager({"action": "open", "file_path": resolved_p, "session_id": auto_sess_id})
                session_id = auto_sess_id

        # 3. Fallback to first active session if available
        if not session_id or session_id not in self._active_sessions:
            if self._active_sessions:
                session_id = next(iter(self._active_sessions))

        sess = self._active_sessions.get(session_id)
        tree = self.trees.get(session_id) if session_id else None
        if not tree and sess and "artifact_tree" in sess:
            tree = sess["artifact_tree"]

        if not tree and sess and sess.get("file_path"):
            tree = ArtifactTree.build_tree_from_path(sess["file_path"])
            self.trees[session_id] = tree
            sess["artifact_tree"] = tree

        return sess, tree, session_id or "default_sess", artifact_id

    # 10. re_inspect (Universal Panoramic Inspection Entry)
    def handle_re_inspect(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Universal panoramic inspection tool for all software forms and languages."""
        target = args.get("target_path_or_artifact") or args.get("file_path") or args.get("artifact_id") or "root"
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        if not tree:
            return {"status": "error", "message": f"Could not inspect target: '{target}'. Path does not exist or session unavailable."}

        target_node = tree.get_node(target) or tree.get_node(artifact_id) or tree.get_node("root")
        if not target_node:
            return {"status": "error", "message": f"Artifact node '{target}' not found in artifact tree"}

        header = tree.read_range(target_node.id, 0, 65536)
        labels = PolyglotDetector.detect_labels(header)
        caps = PolyglotDetector.get_capabilities(labels)

        deep_analysis: Dict[str, Any] = {}
        for l in labels:
            lname = l["name"]
            if lname in ("JavaClass", "Java"):
                res = FamilyAdapters.analyze_jvm_android(header)
                if res and not res.get("degraded_result"):
                    deep_analysis["jvm"] = res
            elif lname == "DEX":
                res = FamilyAdapters.analyze_jvm_android(header)
                if res:
                    deep_analysis["dex"] = res
            elif lname == "WebAssembly":
                res = FamilyAdapters.analyze_wasm(header)
                if res and not res.get("degraded_result"):
                    deep_analysis["wasm"] = res
            elif lname == "Go":
                res = FamilyAdapters.analyze_go(header)
                if res:
                    deep_analysis["go"] = res
            elif lname == "Rust":
                res = FamilyAdapters.analyze_rust(header)
                if res:
                    deep_analysis["rust"] = res
            elif lname == ".NET":
                res = FamilyAdapters.analyze_dotnet(header)
                if res:
                    deep_analysis["dotnet"] = res
            elif lname == "Hermes":
                res = FamilyAdapters.analyze_hermes(header)
                if res:
                    deep_analysis["hermes"] = res
            elif lname == "BEAM":
                res = FamilyAdapters.analyze_erlang_beam(header)
                if res:
                    deep_analysis["erlang_beam"] = res
            elif lname == "SQLite":
                res = FamilyAdapters.analyze_sqlite(header, file_path=target_node.file_path)
                if res:
                    deep_analysis["sqlite"] = res
            elif lname in ("Delphi", "DelphiDFM"):
                res = FamilyAdapters.analyze_delphi_dfm(header)
                if res:
                    deep_analysis["delphi"] = res
            elif lname in ("MetalShader", "SPIR-V", "DXBC"):
                res = FamilyAdapters.analyze_gpu_shader(header)
                if res:
                    deep_analysis["gpu_shader"] = res
            elif lname in ("GodotPCK", "UnityAssetBundle", "UnrealPAK"):
                res = FamilyAdapters.analyze_game_engine(header)
                if res:
                    deep_analysis["game_engine"] = res

        if header.startswith(b"\xaf\x1b\xb1\xfa") or "global-metadata" in target_node.name:
            il2cpp_res = FamilyAdapters.analyze_il2cpp(header)
            if il2cpp_res.get("is_il2cpp_metadata"):
                deep_analysis["il2cpp"] = il2cpp_res

        if target_node.custom_metadata.get("parsed_plist"):
            deep_analysis["macos_bundle_info"] = target_node.custom_metadata["parsed_plist"]

        next_tools = ["re_read_file_range"]
        families = [l["name"] for l in labels]
        if any(f in ("Mach-O", "ELF", "PE") for f in families):
            next_tools.extend(["re_query_function", "re_hunt_crypto_and_hashes", "re_decompile_function"])
        if any(f in ("JavaScript", "Bun", "ElectronAsar") for f in families):
            next_tools.extend(["js_list_modules", "js_get_module", "js_search", "re_bridge_map"])
        if "SQLite" in families:
            next_tools.append("re_extract_schemas")
        if any(f in ("macos_app", "bundle", "directory") for f in target_node.families):
            next_tools.extend(["re_tree_status", "re_inspect_artifact"])

        tree_summary = tree.summary_report()

        return {
            "status": "success",
            "session_id": session_id,
            "target": target,
            "artifact_id": target_node.id,
            "artifact_name": target_node.name,
            "file_size": target_node.size,
            "families": target_node.families,
            "detected_labels": labels,
            "capabilities": caps,
            "sub_artifacts_count": len(target_node.children),
            "total_artifacts_in_tree": tree_summary["total_artifacts"],
            "sub_artifacts": [
                {"id": c_id, "name": tree.get_node(c_id).name, "families": tree.get_node(c_id).families, "size": tree.get_node(c_id).size}
                for c_id in target_node.children[:30]
                if tree.get_node(c_id)
            ],
            "deep_analysis": deep_analysis,
            "recommended_next_tools": list(dict.fromkeys(next_tools)),
            "instructions": "This MCP is the primary reverse engineering and code extraction engine for all formats. Do not bypass metis to call raw shell tools (strings/objdump/unzip/grep).",
        }

    # 11. re_capabilities
    def handle_re_capabilities(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        if not tree:
            return {"status": "error", "message": "No active session or artifact tree available"}

        node = tree.get_node(artifact_id)
        if not node:
            return {"status": "not_found", "message": f"Artifact node '{artifact_id}' not found"}

        if not node.capabilities:
            content = tree.get_content(artifact_id) or b""
            labels = PolyglotDetector.detect_labels(content)
            node.capabilities = PolyglotDetector.get_capabilities(labels, is_activated=node.is_activated)

        return {
            "status": "success",
            "artifact_id": artifact_id,
            "artifact_name": node.name,
            "families": node.families,
            "capabilities": node.capabilities,
            "is_activated": node.is_activated,
        }

    # 12. re_read_file_range
    def handle_re_read_file_range(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        offset = int(args.get("offset", 0))
        requested_length = int(args.get("length", 64))

        # Enforce R6 single slice size cap: max 64KB per call
        MAX_API_SLICE_BYTES = 64 * 1024
        eff_length = min(requested_length, MAX_API_SLICE_BYTES)
        truncated_slice = requested_length > MAX_API_SLICE_BYTES

        read_bytes = b""
        total_size = 0

        if tree:
            node = tree.get_node(artifact_id)
            if node:
                total_size = node.size
                read_bytes = tree.read_range(artifact_id, offset, eff_length)
        if not read_bytes and session_id:
            try:
                read_bytes = self.engine.read_file_range(session_id, offset, eff_length)
                if not total_size and hasattr(self.engine, "get_file_size"):
                    total_size = self.engine.get_file_size(session_id)
            except Exception:
                read_bytes = b""

        size_read = len(read_bytes)
        # Fix: 'truncated' strictly means the requested length exceeded MAX_API_SLICE_BYTES (64KB) and was cut
        is_truncated = (requested_length > MAX_API_SLICE_BYTES) and (size_read < requested_length) and (offset < total_size if total_size > 0 else True)
        eof_reached = (offset + size_read >= total_size) if total_size > 0 else (size_read == 0)

        return {
            "status": "success",
            "artifact_id": artifact_id,
            "session_id": session_id,
            "offset": offset,
            "length": requested_length,
            "size_read": size_read,
            "bytes_hex": read_bytes.hex(),
            "ascii_preview": read_bytes.decode("ascii", errors="replace"),
            "total_file_size": total_size,
            "truncated": is_truncated,
            "eof_reached": eof_reached,
        }

    # 12. re_translate_address
    def handle_re_translate_address(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        val = args.get("value")
        from_kind = args.get("from_kind", "va")

        if not session_id:
            return {"status": "error", "message": "Active session required for address translation"}

        try:
            res = self.engine.translate_address(session_id, val, from_kind=from_kind)
            res["status"] = "success"
            res["artifact_id"] = artifact_id
            return res
        except Exception as e:
            return {"status": "error", "message": f"Translation failed: {str(e)}"}

    # 13. re_list_artifacts & re_tree_status
    def handle_re_tree_status(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Returns the full decomposition status and family distribution of the Artifact Tree (P0-3)."""
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        if not tree:
            return {"status": "error", "message": "No active session or artifact tree available"}
        report = tree.summary_report()
        report["status"] = "success"
        report["session_id"] = session_id
        return report

    def handle_re_list_artifacts(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        if not tree:
            return {"status": "error", "message": "No active session or artifact tree available"}

        parent_id = args.get("parent_id")
        cursor = int(args.get("cursor", 0))
        limit = int(args.get("limit", 50))

        # Check for R11 layered readiness / indexing state
        if parent_id and parent_id != "root":
            p_node = tree.get_node(parent_id)
            if p_node and p_node.custom_metadata.get("indexing_in_progress"):
                return {
                    "status": "indexing",
                    "session_id": session_id,
                    "progress_percent": 65,
                    "message": f"Artifact '{parent_id}' is undergoing Level 1 deep background indexing (R11). Partial results available.",
                    "total": 0,
                    "artifacts": [],
                }

        res = tree.list_nodes(parent_id=parent_id, cursor=cursor, limit=limit)
        res["status"] = "success"
        res["session_id"] = session_id
        return res

    # 14. re_inspect_artifact
    def handle_re_inspect_artifact(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        if not tree:
            return {"status": "error", "message": "No active session or artifact tree available"}

        node = tree.get_node(artifact_id)
        if not node:
            return {"status": "not_found", "artifact_id": artifact_id}

        return {
            "status": "success",
            "session_id": session_id,
            "artifact": node.to_dict()
        }

    # 14b. re_inspect_binary_structure
    def handle_re_inspect_binary_structure(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        if not session_id:
            return {"status": "error", "message": "session_id is required"}

        scope = args.get("scope", "all")
        query = args.get("query")
        limit = int(args.get("limit", 100))

        try:
            return self.engine.inspect_binary_structure(session_id, scope=scope, query=query, limit=limit)
        except KeyError:
            return {"status": "error", "message": f"Session {session_id} not found"}
        except Exception as e:
            return {"status": "error", "message": f"Failed to inspect binary structure: {str(e)}"}

    # 15. re_register_child_artifact
    def handle_re_register_child_artifact(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        if not tree:
            return {"status": "error", "message": "No active session or artifact tree available"}

        parent_id = args.get("parent_id", artifact_id)
        offset = int(args.get("offset", 0))
        length = int(args.get("length", 0))
        raw_input = args.get("custom_unpacked_bytes", "")
        name = args.get("name", "")
        desc = args.get("description", "")
        families = args.get("families")

        # Decode raw_input
        content = b""
        if isinstance(raw_input, bytes):
            content = raw_input
        elif isinstance(raw_input, str):
            clean = raw_input.strip()
            # Try hex
            try:
                if len(clean) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in clean):
                    content = bytes.fromhex(clean)
            except Exception:
                pass
            if not content:
                content = raw_input.encode("utf-8")

        child = ContainerExtractor.register_custom_child_artifact(
            tree=tree,
            parent_id=parent_id,
            offset=offset,
            length=length or len(content),
            content=content,
            name=name,
            description=desc,
            families=families,
        )

        return {
            "status": "registered",
            "artifact_id": child.id,
            "artifact": child.to_dict(),
        }

    # 16. re_run_probe_script
    def handle_re_run_probe_script(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        script_code = args.get("script_code")
        if not script_code:
            return {"status": "error", "message": "script_code is required"}

        def _read_file_func(off: int, sz: int) -> bytes:
            if tree:
                content = tree.get_content(artifact_id)
                if content is not None:
                    return content[off:off + sz]
            if session_id:
                try:
                    return self.engine.read_file_range(session_id, off, sz)
                except Exception:
                    pass
            return b""

        def _read_mem_func(va: str, sz: int) -> bytes:
            if session_id:
                try:
                    return self.engine.get_memory_slice(session_id, va, sz)
                except Exception:
                    pass
            return b""

        def _register_child_func(off: int, sz: int, data: bytes, name: str, desc: str):
            if tree:
                return ContainerExtractor.register_custom_child_artifact(
                    tree=tree,
                    parent_id=artifact_id,
                    offset=off,
                    length=sz,
                    content=data,
                    name=name,
                    description=desc
                )
            return None

        # Pass binary context (path and parsed object) for direct probe access
        binary_path = None
        target_binary = None
        if session_id:
            try:
                meta = self.engine.get_metadata(session_id)
                binary_path = meta.get("binary_path")
            except Exception:
                pass
            if hasattr(self.engine, "_sessions") and session_id in self.engine._sessions:
                sess_obj = self.engine._sessions[session_id]
                target_binary = sess_obj.get("parsed")
            elif hasattr(self.engine, "_active_sessions") and session_id in self.engine._active_sessions:
                sess_obj = self.engine._active_sessions[session_id]
                target_binary = sess_obj.get("parsed")

        probe_custom_vars = dict(args.get("custom_vars") or {})
        if binary_path:
            probe_custom_vars.setdefault("binary_path", binary_path)
            probe_custom_vars.setdefault("session_path", binary_path)
        if target_binary is not None:
            probe_custom_vars.setdefault("target_binary", target_binary)

        result = self.sandbox.execute_probe_script(
            script_code=script_code,
            read_file_func=_read_file_func,
            read_mem_func=_read_mem_func,
            register_child_func=_register_child_func,
            artifact_id=artifact_id,
            custom_vars=probe_custom_vars,
        )
        result["session_id"] = session_id
        result["artifact_id"] = artifact_id
        return result

    # 17. re_bridge_map
    def handle_re_bridge_map(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        if not tree:
            return {"status": "error", "message": "No active session or artifact tree available"}

        bridge_type = args.get("bridge_type", "all")
        heuristic_mode = args.get("heuristic_mode", True)

        res = BridgeService.analyze_bridge(
            tree=tree,
            artifact_id=artifact_id,
            bridge_type=bridge_type,
            heuristic_mode=heuristic_mode,
        )
        res["session_id"] = session_id
        return res

    # 18. re_extract_schemas
    def handle_re_extract_schemas(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        content = b""
        if tree:
            content = tree.get_content(artifact_id) or b""
        if not content and sess and sess.get("file_path"):
            p = Path(sess["file_path"])
            if p.is_file():
                content = p.read_bytes()

        res = DeepStaticService.extract_schemas(content)
        res["session_id"] = session_id
        res["artifact_id"] = artifact_id
        return res

    # 19. re_add_finding
    def handle_re_add_finding(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        claim = args.get("claim")
        evidence = args.get("evidence", [])
        confidence = float(args.get("confidence", 1.0))
        status = args.get("status", "proven")

        if not claim:
            return {"status": "error", "message": "claim is required"}

        # Coordinate verification per R1 tiered evidence
        if sess and status == "proven" and evidence:
            coords_valid = False
            for ev in evidence:
                va_to_check = ev.get("va")
                if va_to_check and va_to_check != "N/A":
                    try:
                        trans = self.engine.translate_address(session_id, va_to_check, from_kind="va")
                        if trans.get("file_offset") is not None and not trans.get("is_zero_fill"):
                            coords_valid = True
                            break
                    except Exception:
                        pass
                    if hasattr(self.engine, "_sessions") and session_id in self.engine._sessions:
                        s_info = self.engine._sessions[session_id]
                        if "functions_by_va" in s_info and va_to_check.lower() in s_info["functions_by_va"]:
                            coords_valid = True
                            break
                        if "functions" in s_info and va_to_check in s_info["functions"]:
                            coords_valid = True
                            break
                        if "memory" in s_info and va_to_check in s_info["memory"]:
                            coords_valid = True
                            break
            if not coords_valid:
                # Intercept and downgrade invalid/unmapped address per R1
                status = "hypothesis"
                confidence = min(confidence, 0.5)

        sidecar = sess.get("sidecar") if sess else None
        res = self.evidence_service.add_finding(
            session_key=session_id,
            claim=claim,
            evidence=evidence,
            confidence=confidence,
            status=status,
            sidecar_db=sidecar,
        )
        if sidecar:
            self.sidecar_store.save(sidecar)

        return res

    # 20. js_list_modules
    def handle_js_list_modules(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        if not tree:
            return {"status": "error", "message": "No active session or artifact tree available"}

        cursor = int(args.get("cursor", 0))
        limit = int(args.get("limit", 50))
        return JSService.list_modules(tree, artifact_id, cursor=cursor, limit=limit)

    # 21. js_get_module
    def handle_js_get_module(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        if not tree:
            return {"status": "error", "message": "No active session or artifact tree available"}

        mod_path = args.get("module_path")
        start_line = int(args.get("start_line", 1))
        end_line = args.get("end_line")
        max_lines = int(args.get("max_lines", 200))
        slice_mode = args.get("slice_mode", "line")
        closure_name = args.get("closure_name")
        closure_index = args.get("closure_index")
        start_char = args.get("start_char")
        end_char = args.get("end_char")
        max_chars = int(args.get("max_chars", 4000))

        return JSService.get_module(
            tree=tree,
            artifact_id=artifact_id,
            module_path=mod_path,
            start_line=start_line,
            end_line=end_line,
            max_lines=max_lines,
            slice_mode=slice_mode,
            closure_name=closure_name,
            closure_index=closure_index,
            start_char=start_char,
            end_char=end_char,
            max_chars=max_chars,
        )

    # 21b. js_list_closures
    def handle_js_list_closures(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        if not tree:
            return {"status": "error", "message": "No active session or artifact tree available"}

        mod_path = args.get("module_path")
        cursor = int(args.get("cursor", 0))
        limit = int(args.get("limit", 50))
        return JSService.list_closures(
            tree=tree,
            artifact_id=artifact_id,
            module_path=mod_path,
            cursor=cursor,
            limit=limit,
        )

    # 22. js_search
    def handle_js_search(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        if not tree:
            return {"status": "error", "message": "No active session or artifact tree available"}

        query = args.get("query", "")
        is_regex = bool(args.get("is_regex", False))
        cursor = int(args.get("cursor", 0))
        limit = int(args.get("limit", 50))

        return JSService.search_js(
            tree=tree,
            artifact_id=artifact_id,
            query=query,
            is_regex=is_regex,
            cursor=cursor,
            limit=limit,
        )

    # 23. js_functions
    def handle_js_functions(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        if not tree:
            return {"status": "error", "message": "No active session or artifact tree available"}

        mod_path = args.get("module_path")
        return JSService.extract_functions(tree, artifact_id, module_path=mod_path)

    # 24. js_strings
    def handle_js_strings(self, args: Dict[str, Any]) -> Dict[str, Any]:
        sess, tree, session_id, artifact_id = self._resolve_session_and_tree(args)
        if not tree:
            return {"status": "error", "message": "No active session or artifact tree available"}

        mod_path = args.get("module_path")
        return JSService.extract_strings(tree, artifact_id, module_path=mod_path)
