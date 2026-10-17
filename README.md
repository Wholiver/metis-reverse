# Metis Reverse

<p align="center">
  <strong>High-Fidelity AI-Assisted Deterministic Reverse Engineering MCP Server</strong>
</p>

<p align="center">
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.12+-blue.svg" alt="Python 3.12+"></a>
  <a href="https://github.com/modelcontextprotocol"><img src="https://img.shields.io/badge/MCP-FastMCP-green.svg" alt="MCP Compatible"></a>
</p>

---

## 🌟 Overview

**Metis Reverse** is an AI-native reverse engineering server built on top of [FastMCP](https://github.com/jlowin/fastmcp). It empowers AI coding agents and security researchers with **developer-grade, high-fidelity source code reconstruction capabilities**.

Traditional AI reverse engineering approaches suffer from hallucinated logic, coarse decompiled pseudocode, and anonymous variable names (`v1`, `v2`, `a1`). Metis Reverse shifts the paradigm to **evidence-grounded, deterministic decompilation**:
- **Multi-Source Evidence Grounding**: Recovers original variable names, structs, and types from immutable evidence (format strings, assertion macros, standard library call signatures, and language metadata).
- **Dynamic In-Memory Probing**: Validates and enriches static decompilation with concrete runtime facts using Frida instrumentation and Unicorn micro-emulation.
- **Interactive Decompiler DB Mutation**: Allows agents to incrementally refine the analysis database (renaming symbols, redefining struct fields, updating types) with cascading AST updates.
- **Closed-Loop Equivalence Verification**: Compiles reconstructed source code in a sandbox and verifies 100% black-box behavioral equivalence (exit codes, stdout, stderr) against the original stripped binary.

---

## 🏛️ Architecture

```
                    ┌───────────────────────────────────────────────┐
                    │               AI Agent / Client               │
                    │      (Claude Desktop / Cursor / Antigravity)   │
                    └───────────────────────┬───────────────────────┘
                                            │ FastMCP (stdio / SSE)
                                            ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│                              Metis FastMCP Server                                 │
│  - Session Management (BinarySession, TargetArtifact)                             │
│  - MCP Tools: disassemble, get_cfg, get_decompiled_code, query_evidence,          │
│               rename_symbol, update_variable_type, define_struct, trace_function,  │
│               recompile_and_verify                                                │
└──────────────┬────────────────────────────┬───────────────────────────┬───────────┘
               │                            │                           │
               ▼                            ▼                           ▼
┌─────────────────────────────┐ ┌───────────────────────────┐ ┌─────────────────────┐
│  Tiered RE Backends         │ │ Evidence Grounding Engine │ │ Dynamic Probing     │
│  - Tier 1 (Self-Contained): │ │ - Format String Reverse   │ │ - Frida Host Prober │
│    * LIEF (PE/ELF/Mach-O)   │ │   Inference (printf/log)  │ │ - Unicorn In-Memory │
│    * Capstone (Disassembly) │ │ - Assert Macro Extraction │ │   Emulated Prober   │
│    * Angr (CFG & Decompile) │ │ - Syscall/Libc Semantic   │ │ - Memory / Argument │
│    * Tree-sitter (AST)      │ │   Propagation             │ │   Dump & Backfill   │
│  - Tier 2 (Bridge/Fallback):│ │ - Go pclntab Deep Parser  │ │   into Static DB    │
│    * Ghidra Headless        │ │ - C++ RTTI / VTables      │ └─────────────────────┘
│    * IDA Pro / JADX         │ │ - Immutable EvidenceStore │
│    * Mock Backend (Test)    │ │   & Confidence Tagging    │
└─────────────────────────────┘ └───────────────────────────┘
                                            │
                                            ▼
                    ┌───────────────────────────────────────────────┐
                    │  Equivalence Loop & Verification              │
                    │  - In-memory / On-disk Decompiler DB Mutation │
                    │  - Target Recompilation Sandbox (Clang/GCC)   │
                    │  - Black-box Differential Testing Harness     │
                    │  - Synthetic Benchmarks (C, Go, JS)           │
                    └───────────────────────────────────────────────┘
```

---

## ⚡ Key Features

1. **Multi-Source Evidence Grounding Engine**:
   - **Format String & Log De-anonymization**: Extracts arguments, flags, and format specifiers from `printf`, `spdlog`, `fmt`, and log macros to reconstruct original variable names and types.
   - **Defensive Assertion Grounding**: Inverts `assert(...)` expressions and panic strings to deduce pointer nullability, bounds, and preconditions.
   - **Syscall & POSIX Semantics**: Propagates known signatures (e.g. `read`, `write`, `socket`, `ioctl`) bidirectionally to constrain buffers, lengths, and file descriptors.
   - **Language Metadata Mining**: Extracts Go `pclntab`/`symtab`, C++ RTTI and virtual tables, Objective-C/Swift class descriptors, and JavaScript AST scopes.
   - **Zero-Hallucination Tagging**: Every recovered symbol carries an immutable `EvidenceTag` containing its provenance, extraction method, and confidence score.

2. **Tiered Backend Architecture**:
   - **Tier 1 (Built-in Lightweight Engine)**: Fully standalone Python stack using LIEF, Capstone, Unicorn, Angr, and Tree-sitter. Operates out-of-the-box without external heavy decompiler dependencies.
   - **Tier 2 (Professional Decompiler Bridges)**: Automatically detects and integrates with Ghidra Headless, IDA Pro, or JADX when available on the host.

3. **Dynamic Observation & Memory Probing**:
   - **Frida Live Instrumentation**: Hooks functions at runtime to capture parameters, return values, and decrypted strings.
   - **Unicorn CPU Micro-Emulation**: Executes arbitrary isolated basic blocks or function slices in-memory with register and stack inspections.
   - **Concrete Fact Backfilling**: Feed dynamic discoveries back into the static decompiler database.

4. **Interactive Mutation & Differential Equivalence Loop**:
   - **AST & Symbol Mutations**: Modify decompilation trees incrementally (`rename_symbol`, `update_variable_type`, `define_struct`).
   - **Recompilation Sandbox**: Invokes native compilers (`clang`/`gcc`) with strict verification flags.
   - **Differential Black-Box Testing**: Executes the rebuilt binary against the original stripped binary across multiple test vectors to guarantee 100% equivalent behavior.

---

## 📦 Installation

### System Prerequisites
- **Python**: 3.12 or higher
- **C/C++ Compiler** (optional, for recompilation verification): `clang` or `gcc`
- **Ghidra / IDA** (optional): Detected automatically if present in `PATH` or configured via `GHIDRA_INSTALL_DIR`

### Option 1: Install from Source with uv (Recommended)

```bash
# Clone repository
git clone https://github.com/Wholiver/metis-reverse.git
cd metis-reverse

# Create virtual environment and install dependencies
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Option 2: Install via pip

```bash
# Install directly from GitHub
pip install git+https://github.com/Wholiver/metis-reverse.git

# Or install editable from a local clone
git clone https://github.com/Wholiver/metis-reverse.git
cd metis-reverse
pip install -e .
```

### Verify Installation

```bash
metis-reverse --help
```

---

## 🔌 MCP Client Configuration

Metis Reverse provides an MCP server adhering to the Model Context Protocol specification. You can connect it to any MCP-compliant client.

### 1. Claude Desktop

Add Metis Reverse to your `claude_desktop_config.json`:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "metis-reverse": {
      "command": "metis-reverse",
      "args": ["--transport", "stdio"]
    }
  }
}
```

If using a specific virtual environment:

```json
{
  "mcpServers": {
    "metis-reverse": {
      "command": "/path/to/metis-reverse/.venv/bin/metis-reverse",
      "args": ["--transport", "stdio"]
    }
  }
}
```

### 2. Cursor / Antigravity / Windsurf / Cline

In your MCP configuration file (e.g. `.cursor/mcp.json` or Cline settings):

```json
{
  "mcpServers": {
    "metis-reverse": {
      "command": "metis-reverse",
      "args": ["--transport", "stdio"]
    }
  }
}
```

### 3. SSE / HTTP Remote Mode

You can also run Metis Reverse as an independent SSE service:

```bash
metis-reverse --transport sse --host 127.0.0.1 --port 8000
```

---

## 🛠️ Available MCP Tools

| Tool Name | Parameters | Description |
|:---|:---|:---|
| `open_session` | `file_path`, `backend` | Loads a binary (ELF, PE, Mach-O, WASM, JS) and initializes an analysis session. |
| `close_session` | `session_id` | Closes an active session and frees analysis memory/caches. |
| `list_sessions` | None | Lists all active analysis sessions and metadata. |
| `get_session_info` | `session_id` | Returns metadata, architecture, format, and backend tier for a session. |
| `disassemble` | `session_id`, `address`, `count` | Disassembles machine instructions starting at the given target address. |
| `get_cfg` | `session_id`, `function_address` | Generates a control flow graph (basic blocks and jump edges) for a function. |
| `list_functions` | `session_id` | Returns all detected functions and symbol summaries. |
| `get_decompiled_code` | `session_id`, `function_name_or_address` | Returns decompiled high-level C/pseudo-code for a function. |
| `query_evidence` | `session_id`, `filter_type` | Queries immutable evidence tags (format strings, assert macros, syscalls, metadata). |
| `rename_symbol` | `session_id`, `old_name`, `new_name` | Updates a function or variable symbol in the decompiler database with cascading effects. |
| `update_variable_type` | `session_id`, `function_address`, `var_name`, `new_type` | Adjusts variable type declarations and updates data flow typing. |
| `define_struct` | `session_id`, `struct_name`, `fields` | Registers custom struct definitions and field alignments into the session schema. |
| `trace_function` | `session_id`, `address`, `mode`, `inputs` | Performs dynamic execution probing via Frida or Unicorn emulator. |
| `probe_memory` | `session_id`, `address`, `size` | Inspects memory buffers, stack layouts, or global variables at runtime. |
| `recompile_and_verify` | `session_id`, `source_code`, `compiler_flags`, `test_vectors` | Compiles reconstructed source code in a sandbox and verifies differential test equivalence. |

---

## 🚀 Quick Start Demo

A comprehensive benchmark demo is included in [`demo/`](demo/):

```bash
cd demo
make

# Run the demo binary benchmark
./demo_target --benchmark
```

Ask your MCP-connected AI Agent:

> *"Analyze the stripped binary in `demo/demo_target`. Query evidence from format strings and assertions to deduce the cache record struct layout, then reconstruct the original C source code and verify it with differential testing."*

---

## 🧪 Running the Test Suite

Metis Reverse includes an extensive automated test suite covering unit tests, adversarial security tests, and synthetic benchmark ground-truth tests:

```bash
# Run unit tests
pytest tests/unit/

# Run end-to-end and benchmark verification
pytest tests/e2e/

# Run all tests with coverage
pytest --cov=metis_reverse tests/
```

---

## 🙏 Acknowledgements (鸣谢)

Metis Reverse stands on the shoulders of incredible open-source reverse engineering and binary analysis software:

- **[FastMCP](https://github.com/jlowin/fastmcp)** & **[Model Context Protocol](https://modelcontextprotocol.io/)** — Fast, ergonomic protocol framework for building AI tools.
- **[LIEF](https://github.com/lief-project/LIEF)** — Library to Instrument Executable Formats (ELF, PE, Mach-O).
- **[Capstone Engine](https://www.capstone-engine.org/)** — Multi-platform, multi-architecture disassembly framework.
- **[Unicorn Engine](https://www.unicorn-engine.org/)** — Lightweight CPU emulator framework based on QEMU.
- **[angr](https://angr.io/)** — Powerful binary analysis platform, symbolic execution engine, and decompiler.
- **[Frida](https://frida.re/)** — Dynamic instrumentation toolkit for developers, reverse engineers, and security researchers.
- **[Tree-sitter](https://tree-sitter.github.io/)** — Incremental parsing system for robust AST construction.
- **[Ghidra](https://ghidra-sre.org/)** — NSA's software reverse engineering suite.
- **[Rich](https://github.com/Textualize/rich)** & **[Pydantic](https://docs.pydantic.dev/)** — Beautiful terminal formatting and robust data validation.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) — see the [LICENSE](LICENSE) file for details.
