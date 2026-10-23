# Metis Reverse MCP: Complete Tools Catalog & Schemas

This document is the authoritative schema reference for all **24 task-level MCP tools** exposed by `MetisToolDispatcher`. Every tool is engineered for autonomous AI Agent reasoning, triple-coordinate provenance (`{va, rva, file_offset}`), prompt-injection defense (`PromptShield`), polyglot container navigation, and deterministic degradation.

---

## Table of Contents

- [1. Session & Artifact Topology (6 Tools)](#1-session--artifact-topology-6-tools)
  - [`re_session_manager`](#11-re_session_manager)
  - [`re_triage`](#12-re_triage)
  - [`re_tree_status`](#13-re_tree_status)
  - [`re_list_artifacts`](#14-re_list_artifacts)
  - [`re_inspect_artifact`](#15-re_inspect_artifact)
  - [`re_capabilities`](#16-re_capabilities)
- [2. Physical Slicing & Coordinate Translation (2 Tools)](#2-physical-slicing--coordinate-translation-2-tools)
  - [`re_read_file_range`](#21-re_read_file_range)
  - [`re_translate_address`](#22-re_translate_address)
- [3. Decompilation & Function Context (2 Tools)](#3-decompilation--function-context-2-tools)
  - [`re_query_function`](#31-re_query_function)
  - [`re_decompile_function`](#32-re_decompile_function)
- [4. Cross-Language Bridges & Schema Extraction (2 Tools)](#4-cross-language-bridges--schema-extraction-2-tools)
  - [`re_bridge_map`](#41-re_bridge_map)
  - [`re_extract_schemas`](#42-re_extract_schemas)
- [5. JavaScript / TypeScript AST & Bundle Suite (6 Tools)](#5-javascript--typescript-ast--bundle-suite-6-tools)
  - [`js_list_modules`](#51-js_list_modules)
  - [`js_get_module`](#52-js_get_module)
  - [`js_list_closures`](#53-js_list_closures)
  - [`js_search`](#54-js_search)
  - [`js_functions`](#55-js_functions)
  - [`js_strings`](#56-js_strings)
- [6. Cryptanalysis, Hypothesis Sandbox & Micro-Emulation (3 Tools)](#6-cryptanalysis-hypothesis-sandbox--micro-emulation-3-tools)
  - [`re_hunt_crypto_and_hashes`](#61-re_hunt_crypto_and_hashes)
  - [`re_verify_hypothesis`](#62-re_verify_hypothesis)
  - [`re_emulate_slice`](#63-re_emulate_slice)
- [7. Sidecar Model Refinement & Evidence Provenance (4 Tools)](#7-sidecar-model-refinement--evidence-provenance-4-tools)
  - [`re_refine_model`](#71-re_refine_model)
  - [`re_diff_and_transfer`](#72-re_diff_and_transfer)
  - [`re_query_evidence`](#73-re_query_evidence)
  - [`re_add_finding`](#74-re_add_finding)
- [8. Escape Hatch Primitives (2 Tools)](#8-escape-hatch-primitives-2-tools)
  - [`re_run_probe_script`](#81-re_run_probe_script)
  - [`re_register_child_artifact`](#82-re_register_child_artifact)

---

## 1. Session & Artifact Topology (6 Tools)

### 1.1 `re_session_manager`
Manages headless reverse-engineering sessions, read-only sample mounting, polyglot `ArtifactTree` construction (including automatic Bun standalone container extraction), and `.metis_sidecars/` export/import.

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `action` | `string` | **Yes** | - | One of: `"open"`, `"close"`, `"list"`, `"status"`, `"export_sidecar"`, `"import_sidecar"` |
| `file_path` | `string` | Conditional | - | Target binary path (required when `action="open"`, optional custom output path for `"export_sidecar"`) |
| `session_id` | `string` | No | `"default_sess"` | Unique session identifier |
| `format` | `string` | No | `"yaml"` | Sidecar serialization format: `"yaml"` or `"json"` |

**Example Request (`open`)**:
```json
{
  "action": "open",
  "file_path": "/workspace/samples/target_app",
  "session_id": "sess_target_01"
}
```

**Example Response (`open`)**:
```json
{
  "status": "ready",
  "session_id": "sess_target_01",
  "sample_sha256": "3a4b7f8c...",
  "binary_path": "/workspace/samples/target_app",
  "entrypoint": "0x100001000",
  "format": "Mach-O 64-bit",
  "architecture": "arm64",
  "function_count": 142,
  "families": ["mach-o", "bun", "javascript"],
  "capabilities": {
    "decompile": "supported",
    "bridge_map": "supported"
  },
  "sub_artifacts_count": 2,
  "sidecar_persisted": true,
  "message": "Session mounted in read-only mode."
}
```

---

### 1.2 `re_triage`
Performs static initial triage: format recognition, section entropy heatmaps, packer heuristics, virtual-vs-physical memory consistency checks (`memory_view_unreliable`), and domain-aware exit code interpretation for external tools (YARA, Detect-It-Easy).

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `file_path` | `string` | **Yes** | - | Path to the target binary file |
| `tool_feedback` | `object` | No | - | Optional `{ "tool_name": str, "exit_code": int, "stdout": str }` from external triage CLI tools |

**Example Request**:
```json
{
  "file_path": "/workspace/samples/target_app",
  "tool_feedback": {
    "tool_name": "yara",
    "exit_code": 1,
    "stdout": "rule_packed_upx /workspace/samples/target_app"
  }
}
```

**Example Response**:
```json
{
  "status": "success",
  "format": "Mach-O",
  "architecture": "arm64",
  "overall_entropy": 6.84,
  "is_packed_likely": false,
  "memory_view_unreliable": false,
  "sections": [
    {"name": "__TEXT", "size": 1048576, "entropy": 6.21},
    {"name": "__DATA", "size": 65536, "entropy": 3.42}
  ],
  "external_tool_semantics": {
    "tool": "yara",
    "semantic_status": "MATCHES_FOUND"
  }
}
```

---

### 1.3 `re_tree_status`
Returns the full decomposition hierarchy, node counts, and polyglot family distribution of the session's `ArtifactTree`.

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `session_id` | `string` | No | Active session | Active session ID |

**Example Response**:
```json
{
  "status": "success",
  "session_id": "sess_target_01",
  "root_id": "root",
  "total_nodes": 3,
  "activated_nodes": 3,
  "family_distribution": {
    "mach-o": 1,
    "bun": 1,
    "javascript": 1,
    "napi": 1
  }
}
```

---

### 1.4 `re_list_artifacts`
Enumerates nodes in the hierarchical `ArtifactTree` using cursor-based pagination (R2). Also reports background indexing progress (`status: "indexing"`) if a large container node is still being indexed (R11).

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `session_id` | `string` | No | Active session | Active session ID |
| `parent_id` | `string` | No | `null` (all) | Filter by parent artifact ID (e.g., `"root"`) |
| `cursor` | `integer` | No | `0` | Pagination start index |
| `limit` | `integer` | No | `50` | Maximum items per page |

**Example Response**:
```json
{
  "status": "success",
  "session_id": "sess_target_01",
  "total": 2,
  "cursor": 0,
  "next_cursor": null,
  "artifacts": [
    {
      "id": "root:bun:0",
      "name": "bun_js_bundle.js",
      "parent_id": "root",
      "file_offset": 65536,
      "size": 524288,
      "families": ["bun", "javascript"]
    },
    {
      "id": "root:node:0",
      "name": "crypto_addon.node",
      "parent_id": "root",
      "file_offset": 589824,
      "size": 49152,
      "families": ["mach-o", "napi", "c++"]
    }
  ]
}
```

---

### 1.5 `re_inspect_artifact`
Retrieves detailed node metadata—physical offset within parent, size, SHA-256, polyglot family labels, and capability flags—for a specific `artifact_id`.

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `artifact_id` | `string` | No | `"root"` | Target artifact node ID |
| `session_id` | `string` | No | Active session | Active session ID |

---

### 1.6 `re_capabilities`
Explicitly declares supported capabilities, degraded operations, and fallback paths for an artifact node (R3).

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `session_id` | `string` | No | Active session | Active session ID |
| `artifact_id` | `string` | No | `"root"` | Target artifact node ID |

**Example Response**:
```json
{
  "status": "success",
  "artifact_id": "root",
  "artifact_name": "target_app",
  "families": ["mach-o", "go"],
  "capabilities": {
    "disassembly": "supported",
    "decompilation": "degraded_assembly_synthesis",
    "go_pclntab_recovery": "supported",
    "sandbox_probing": "supported"
  },
  "is_activated": true
}
```

---

## 2. Physical Slicing & Coordinate Translation (2 Tools)

### 2.1 `re_read_file_range`
Reads raw bytes directly from physical storage or an embedded artifact slice by `offset` and `length`, completely bypassing virtual memory mapping (`P0-1`).

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `offset` | `integer` | **Yes** | `0` | Physical byte offset |
| `length` | `integer` | **Yes** | `64` | Number of bytes to read |
| `session_id` | `string` | No | Active session | Active session ID |
| `artifact_id` | `string` | No | `"root"` | Artifact node ID |

**Example Response**:
```json
{
  "status": "success",
  "artifact_id": "root",
  "offset": 4096,
  "length": 16,
  "size_read": 16,
  "bytes_hex": "cffaedfe0c0000010000000002000000",
  "ascii_preview": "................",
  "total_file_size": 1048576
}
```

---

### 2.2 `re_translate_address`
Deterministically converts between virtual address (`va`), relative virtual address (`rva`), and physical file offset (`file_offset`) across PE/ELF/Mach-O sections (`R8`, `P0-1`).

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `value` | `string` \| `int` | **Yes** | - | Coordinate value (e.g., `"0x100001200"` or `4608`) |
| `from_kind` | `string` | No | `"va"` | Source coordinate space: `"va"`, `"rva"`, or `"file_offset"` |
| `session_id` | `string` | No | Active session | Active session ID |
| `artifact_id` | `string` | No | `"root"` | Artifact node ID |

**Example Response**:
```json
{
  "status": "success",
  "artifact_id": "root",
  "va": "0x100001200",
  "rva": "0x1200",
  "file_offset": 4608,
  "segment": "__TEXT",
  "section": "__text"
}
```

---

## 3. Decompilation & Function Context (2 Tools)

### 3.1 `re_query_function`
Extracts reasoning-optimized function context: token-bounded decompiled code, side-by-side disassembly, callers/callees (with automatic standard-library folding when `include_libraries=false`), PromptShield-fenced strings, `triple_coordinates`, and `decompiler_warnings` (`R13`, `R14`).

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `session_id` | `string` | **Yes** | - | Active session ID |
| `va_or_name` | `string` | **Yes** | - | Function entry VA (e.g., `"0x140001000"`) or symbol name |
| `max_tokens` | `integer` | No | `2048` | Token budget cap for decompiled output |
| `include_libraries` | `boolean` | No | `false` | Set `true` to expand standard library callers/callees (`std::`, `runtime.`, `malloc`, etc.) |

**Example Response**:
```json
{
  "status": "success",
  "name": "verify_license_blob",
  "va": "0x140001000",
  "triple_coordinates": {
    "va": "0x140001000",
    "rva": "0x1000",
    "file_offset": 4096,
    "segment": ".text",
    "section": ".text"
  },
  "decompiler_available": true,
  "is_ast_decompiler": true,
  "decompiled_code": "int verify_license_blob(uint8_t *buf, size_t len) { ... }",
  "disassembly": "0x140001000: push rbp\n0x140001001: mov rbp, rsp...",
  "decompiler_warnings": [
    "Non-standard register calling convention detected (unaff_ variables present). Check disassembly."
  ],
  "callers": [{"va": "0x140002100", "name": "main", "is_library": false}],
  "callees": [{"va": "0x140001800", "name": "aes_decrypt_block", "is_library": false}],
  "libraries_folded": {
    "folded": true,
    "callees_folded_count": 4,
    "callers_folded_count": 0,
    "hint": "Set include_libraries=true to expand standard library callers/callees (R13)."
  },
  "referenced_strings_shielded": [
    {
      "va": "0x140009000",
      "shielded_text": "<untrusted_binary_evidence va=\"0x140009000\" type=\"string_literal\" risk=\"LOW\">LICENSE_OK</untrusted_binary_evidence>",
      "suspicious_instruction_like": false
    }
  ]
}
```

---

### 3.2 `re_decompile_function`
Decompiles a target function by `va_or_name`, returning pseudocode side-by-side with disassembly and decompiler diagnostics (`P1-3`, `R14`). Shares the same handler and output enrichment as `re_query_function`, with `session_id` optional when a single session is active.

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `va_or_name` | `string` | **Yes** | - | Function virtual address or symbol name |
| `session_id` | `string` | No | Active session | Active session ID |
| `include_libraries` | `boolean` | No | `false` | Whether to expand standard library callers/callees |

---

## 4. Cross-Language Bridges & Schema Extraction (2 Tools)

### 4.1 `re_bridge_map`
Recovers cross-language bindings across `napi` (`.node` 64-byte `napi_property_descriptor` structs), `jni` (`Java_*` exports and `RegisterNatives` tables), `ipc` (Electron `ipcMain`/`ipcRenderer`/`contextBridge`), `tauri` (`tauri::generate_handler!`), `pyo3` (`PyMethodDef`), `cgo` (`_cgoexp_*`), and `pinvoke` (`DllImport`), plus heuristic cross-layer symbol linking (`P1-2`, `Escape Hatch 3`).

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `session_id` | `string` | No | Active session | Active session ID |
| `artifact_id` | `string` | No | `"root"` | Target artifact node ID |
| `bridge_type` | `string` | No | `"all"` | One of: `"napi"`, `"ipc"`, `"tauri"`, `"jni"`, `"pyo3"`, `"cgo"`, `"pinvoke"`, `"all"` |
| `heuristic_mode` | `boolean` | No | `true` | Enable cross-artifact heuristic route/symbol linking |

**Example Response**:
```json
{
  "status": "success",
  "session_id": "sess_target_01",
  "artifact_id": "root:node:0",
  "artifact_name": "crypto_addon.node",
  "bridge_count": 1,
  "heuristic_links_count": 1,
  "bridges": [
    {
      "bridge_type": "napi",
      "exported_name": "signPayload",
      "handler_va": "0x100003420",
      "local_file_offset": 13344,
      "container_file_offset": 603168,
      "segment": "__TEXT"
    }
  ],
  "heuristic_links": [
    {
      "symbol": "signPayload",
      "source_artifact": "root:bun:0",
      "target_artifact": "root:node:0",
      "target_va": "0x100003420",
      "confidence": 0.92
    }
  ]
}
```

---

### 4.2 `re_extract_schemas`
Scans an artifact for embedded data schemas: SQLite `CREATE TABLE` / `CREATE INDEX` DDLs, JSON Schemas (`"$schema"` / `"properties"`), and Protobuf message/field descriptors (`P1-5`).

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `session_id` | `string` | No | Active session | Active session ID |
| `artifact_id` | `string` | No | `"root"` | Target artifact node ID |

---

## 5. JavaScript / TypeScript AST & Bundle Suite (6 Tools)

### 5.1 `js_list_modules`
Lists embedded JavaScript/TypeScript modules inside a Bun standalone binary, Electron ASAR archive, or Webpack bundle with cursor pagination (`P1-1`).

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `session_id` | `string` | No | Active session | Active session ID |
| `artifact_id` | `string` | No | `"root"` | Target artifact node ID |
| `cursor` | `integer` | No | `0` | Pagination start index |
| `limit` | `integer` | No | `50` | Maximum modules returned |

---

### 5.2 `js_get_module`
Retrieves JavaScript module source code by `"line"`, AST function `"closure"`, or character `"range"`, protected by a `max_chars=4000` context-overflow circuit breaker for single-line minified bundles (`P1-1`).

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `session_id` | `string` | No | Active session | Active session ID |
| `artifact_id` | `string` | No | `"root"` | Target artifact node ID |
| `module_path` | `string` | No | First module | Module name or path |
| `slice_mode` | `string` | No | `"line"` | Slicing mode: `"line"`, `"closure"`, or `"range"` |
| `closure_name` | `string` | No | - | Function/closure name to extract when `slice_mode="closure"` |
| `closure_index` | `integer` | No | - | Closure index from `js_list_closures` when `slice_mode="closure"` |
| `start_line` | `integer` | No | `1` | Starting line number (`slice_mode="line"`) |
| `end_line` | `integer` | No | - | Ending line number (`slice_mode="line"`) |
| `max_lines` | `integer` | No | `200` | Line count cap |
| `start_char` | `integer` | No | - | Starting character offset (`slice_mode="range"`) |
| `end_char` | `integer` | No | - | Ending character offset (`slice_mode="range"`) |
| `max_chars` | `integer` | No | `4000` | Hard character cap to prevent single-line bundle context blowup |

---

### 5.3 `js_list_closures`
Parses AST function closures (`index`, `name`, `params`, `start_char`, `end_char`, `line`) in a JS module without returning full source text—essential before slicing minified bundles (`P1-1`).

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `session_id` | `string` | No | Active session | Active session ID |
| `artifact_id` | `string` | No | `"root"` | Target artifact node ID |
| `module_path` | `string` | No | First module | Module name or path |
| `cursor` | `integer` | No | `0` | Pagination start index |
| `limit` | `integer` | No | `50` | Maximum closures returned |

---

### 5.4 `js_search`
Searches across all embedded JavaScript modules by substring or regular expression (`P1-1`).

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `query` | `string` | **Yes** | - | Substring or regex pattern |
| `session_id` | `string` | No | Active session | Active session ID |
| `artifact_id` | `string` | No | `"root"` | Target artifact node ID |
| `is_regex` | `boolean` | No | `false` | Treat `query` as a regular expression |
| `cursor` | `integer` | No | `0` | Pagination start index |
| `limit` | `integer` | No | `50` | Maximum matches returned |

---

### 5.5 `js_functions`
Extracts function declarations, arrow functions, and class method signatures from a JS module (`P1-1`).

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `session_id` | `string` | No | Active session | Active session ID |
| `artifact_id` | `string` | No | `"root"` | Target artifact node ID |
| `module_path` | `string` | No | All/First | Target module path |

---

### 5.6 `js_strings`
Extracts high-value string literals from JS modules: URLs, hostnames, IPC channel names, `process.env.*` / `Bun.env.*` variables, and secret/config keys (`P1-1`).

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `session_id` | `string` | No | Active session | Active session ID |
| `artifact_id` | `string` | No | `"root"` | Target artifact node ID |
| `module_path` | `string` | No | All/First | Target module path |

---

## 6. Cryptanalysis, Hypothesis Sandbox & Micro-Emulation (3 Tools)

### 6.1 `re_hunt_crypto_and_hashes`
Scans binary sections and function constants for cryptographic primitives (AES Forward S-Boxes, MD5/SHA-1/SHA-256 IVs, ChaCha20 `"expa"`, CRC32 polynomials, TEA/XTEA delta `0x9e3779b9`) and resolves ROR13 Windows API hashes, automatically syncing findings into the Sidecar store.

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `session_id` | `string` | **Yes** | - | Active session ID |
| `base_va` | `string` | No | Full binary | Optional virtual address to anchor the scan |
| `algorithm_hint` | `string` | No | All | Optional filter (`"aes"`, `"sha"`, `"chacha"`, `"ror13"`, `"crc32"`, `"tea"`) |

---

### 6.2 `re_verify_hypothesis`
Executes an agent-written Python verification script in `HypothesisSandbox` against a real memory slice extracted from `target_va`. Prevents mental bitwise hallucination and automatically registers a `sandbox_verification` evidence pointer when `hypothesis_confirmed: true`.

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `script_code` | `string` | **Yes** | - | Python script defining `verify(data)` / `decrypt(data)` or assigning `result` |
| `session_id` | `string` | **Yes** | - | Active session ID |
| `target_va` | `string` | **Yes** | - | Virtual address of the memory slice to extract |
| `slice_size` | `integer` | No | `64` | Number of bytes to extract from `target_va` |
| `expected_output` | `string` | No | `null` | Expected plaintext substring or hex string to assert against |

**Confirmation Semantics**:
- If `memory_slice` is all zero bytes (`0x00`), `hypothesis_confirmed` is forced to `false` (unless `expected_output` is explicitly `"00"`), protecting against unmapped `.bss` false positives.
- If `expected_output` is omitted, `verify(data)` must return `True` or a dict `{"confirmed": True, ...}` (or `{"verified": True, ...}`) for `hypothesis_confirmed` to evaluate to `true`.

---

### 6.3 `re_emulate_slice`
Executes controlled single-threaded user-space micro-emulation from `start_va` to `stop_va`, capturing final register values, memory buffer snapshots, and uninitialized memory access alerts.

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `session_id` | `string` | **Yes** | - | Active session ID |
| `start_va` | `string` | **Yes** | - | Starting instruction virtual address |
| `stop_va` | `string` | **Yes** | - | Breakpoint instruction virtual address |
| `initial_registers` | `object` | No | `{}` | Initial register state map (e.g., `{"rdi": 16, "rsi": 4096}`) |
| `memory_addresses` | `array<string>` | No | `[]` | Virtual addresses to snapshot upon reaching `stop_va` |

---

## 7. Sidecar Model Refinement & Evidence Provenance (4 Tools)

### 7.1 `re_refine_model`
Commits confirmed reverse-engineering refinements—function renames, local variable types, C struct definitions, and analytical comments—into `.metis_sidecars/<sha256>.yaml`, automatically computing CFG hashes and constant fingerprints for future cross-patch transfer.

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `session_id` | `string` | **Yes** | - | Active session ID |
| `function_renames` | `object` | No | `{}` | Map of `{"0xVA": "new_function_name"}` |
| `variable_annotations` | `array<object>` | No | `[]` | List of `{"function_va", "original_name", "renamed_to", "inferred_type", "evidence_va"}` |
| `struct_definitions` | `array<object>` | No | `[]` | List of `{"name", "size", "evidence_va", "comment", "fields": [{"offset", "name", "field_type", "size"}]}` |
| `comments` | `object` | No | `{}` | Map of `{"0xVA": "analytical comment"}` |

---

### 7.2 `re_diff_and_transfer`
Matches functions between an already-analyzed binary (`source_sha256`) and a newly opened patch session (`target_session_id`) using CFG topology hashes, callee graphs, and constant fingerprints, migrating Sidecar annotations and structs automatically.

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `source_sha256` | `string` | **Yes** | - | SHA-256 hash of the previously analyzed binary in `.metis_sidecars/` |
| `target_session_id` | `string` | **Yes** | - | Active session ID of the newer binary version |

---

### 7.3 `re_query_evidence`
Audits the verified provenance and concrete coordinates of any symbol, address, struct, or finding. When a query is not found, returns `status: "not_found"` with an explicit `searched_locations` audit trail to prevent hallucination.

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `session_id` | `string` | **Yes** | - | Active session ID |
| `query` | `string` | **Yes** | - | Address, function name, struct name, or finding keyword to audit |

---

### 7.4 `re_add_finding`
Records a tiered reverse-engineering finding (`proven`, `corroborated`, or `hypothesis`) into the session's evidence chain and Sidecar database (`R1`). Automatically verifies that `proven` claims reference valid mapped, non-zero-fill coordinates; otherwise downgrades status to `hypothesis`.

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `claim` | `string` | **Yes** | - | Concise technical statement of the finding |
| `evidence` | `array<object>` | No | `[]` | List of evidence pointers (e.g., `[{"va": "0x100001200", "file_offset": 4608, "description": "..."}]`) |
| `confidence` | `number` | No | `1.0` | Confidence score (`0.0` to `1.0`) |
| `status` | `string` | No | `"proven"` | Tier: `"proven"`, `"corroborated"`, or `"hypothesis"` |
| `session_id` | `string` | No | Active session | Active session ID |

---

## 8. Escape Hatch Primitives (2 Tools)

### 8.1 `re_run_probe_script`
Executes an isolated Python structure-probing script (`Escape Hatch 1`) with direct read-only access to the target artifact (`read_file_range(off, sz)`, `read_memory(va, sz)`) and dynamic child artifact mounting (`register_child(offset, length, data, name, description)`).

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `script_code` | `string` | **Yes** | - | Python probe script defining `probe()` / `parse()` or setting `result` |
| `session_id` | `string` | No | Active session | Active session ID |
| `artifact_id` | `string` | No | `"root"` | Target artifact node ID |

**Example Response**:
```json
{
  "success": true,
  "returned_value": {"entries_mounted": 1},
  "stdout": "[+] Decompressed 16384 bytes\n",
  "registered_children": [
    {
      "offset": 540680,
      "length": 16384,
      "name": "unpacked_overlay.bin",
      "description": "Decompressed payload",
      "artifact_id": "root:custom:0"
    }
  ],
  "execution_time_ms": 2.41,
  "error": null,
  "session_id": "sess_target_01",
  "artifact_id": "root"
}
```

---

### 8.2 `re_register_child_artifact`
Directly mounts hex-encoded, base64-encoded, or raw unpacked bytes (or a parent offset/length slice) as a new child node in the session's `ArtifactTree` (`P0-2`, `Escape Hatch 1`).

| Parameter | Type | Required | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `custom_unpacked_bytes` | `string` | **Yes** | - | Hex string or raw payload bytes to mount |
| `parent_id` | `string` | No | `"root"` | Parent artifact node ID |
| `offset` | `integer` | No | `0` | Offset within parent artifact |
| `length` | `integer` | No | `0` | Payload byte length |
| `name` | `string` | No | `""` | Display name for the child artifact (no path traversal characters) |
| `description` | `string` | No | `""` | Provenance description |
| `families` | `array<string>` | No | Auto-detected | Optional language/format family tags |
| `session_id` | `string` | No | Active session | Active session ID |
