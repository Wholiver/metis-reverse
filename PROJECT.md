# Project: Metis Reverse

## Architecture
Metis Reverse is an AI-native reverse engineering FastMCP server and high-fidelity source code reconstruction platform. It combines static binary parsing, deep language metadata mining, dynamic execution probing, and differential testing into a closed-loop decompiler engine.

```
                    ┌───────────────────────────────────────────────┐
                    │               AI Agent / Client               │
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

## Feature Inventory
Every feature from the Survey phase is mapped below with its assigned milestone.
| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| F01 | FastMCP Server & Protocol | FastMCP server implementation exposing stdio and SSE transports with session lifecycles | M1 | ORIGINAL_REQUEST §R1 |
| F02 | Unified RE Domain Abstraction | Canonical Pydantic v2 schemas: BinarySession, TargetArtifact, Function, BasicBlock, Instruction, Symbol, DecompiledCode | M1 | ORIGINAL_REQUEST §R1 |
| F03 | Tier 1 Lightweight Native Backend | Self-contained backend using LIEF, Capstone, Unicorn, Angr Decompiler, and Tree-sitter | M1 | ORIGINAL_REQUEST §R1 |
| F04 | Tier 2 Decompiler Integration | Automated discovery for Ghidra Headless, IDA Pro, JADX with graceful fallback & MockBackend | M1 | ORIGINAL_REQUEST §R1 |
| F05 | Format String & Assert Reverse Inference | Reverse inference of variable names, parameter types, and diagnostic flags from printf/spdlog/assert strings | M2 | ORIGINAL_REQUEST §R2 |
| F06 | Syscall & Standard Libc Propagation | Bidirectional propagation of types, buffer lengths, and semantic names from POSIX / system calls | M2 | ORIGINAL_REQUEST §R2 |
| F07 | Language Metadata Extraction | Deep extraction for Go pclntab (1.2-1.23+), C++ RTTI/VTable, DEX symbols, JS AST scopes | M2 | ORIGINAL_REQUEST §R2 |
| F08 | EvidenceTag & Grounding Store | Immutable evidence tagging with confidence scores, source anchors, and anti-hallucination validation | M2 | ORIGINAL_REQUEST §R2 |
| F09 | Dynamic Tracing with Frida | Native process spawning, function hooking, runtime argument/return value extraction | M3 | ORIGINAL_REQUEST §R3 |
| F10 | Emulated Prober with Unicorn | In-memory micro-emulation prober for isolated/cross-platform dynamic execution | M3 | ORIGINAL_REQUEST §R3 |
| F11 | Dynamic-to-Static Fact Backfilling | Reconciling concrete runtime arguments/strings back into static session symbols and decompiler AST | M3 | ORIGINAL_REQUEST §R3 |
| F12 | Interactive Decompiler DB Mutation | MCP mutation tools: rename_symbol, update_variable_type, define_struct with cascade update | M4 | ORIGINAL_REQUEST §R4 |
| F13 | Recompilation Sandbox | Automated compilation runner for reconstructed C source code using clang/gcc with 0 compile errors | M4 | ORIGINAL_REQUEST §R4 |
| F14 | Differential Testing Harness | Multi-vector execution comparing stdout, stderr, and exit code between original and reconstructed binaries | M4 | ORIGINAL_REQUEST §R4 |
| F15 | Synthetic Benchmarks Suite | Ground truth benchmarks: stripped C (-O2 -s), stripped Go (-ldflags="-s -w"), obfuscated JS (Terser) | E2E-Track | ORIGINAL_REQUEST §Verification |
| F16 | 100% E2E Verification & Adversarial Hardening | Comprehensive test pass across Tiers 1-4, followed by Tier 5 adversarial stress testing | M5 | ORIGINAL_REQUEST §Acceptance |

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| E2E | E2E Testing Track | Test infra, synthetic benchmarks (C, Go, JS), ground truth, opaque-box tests -> TEST_READY.md | none | DONE (TEST_READY.md published, 30/30 vectors pass) |
| M1 | Core Abstraction, Tiered Backends & FastMCP Server | F01, F02, F03, F04: Pydantic models, LIEF/Capstone/Angr backend, Tier 2 detector/mock, FastMCP server entrypoint | none | DONE (Certified PASS, 59/59 unit, 7/7 e2e, 13/13 bench, 8/8 stripped bench, 36/36 adversarial, Auditor CLEAN) |
| M2 | Multi-Evidence Grounding Engine | F05, F06, F07, F08: format string/assert inference, syscall propagation, Go pclntab, C++ RTTI, EvidenceStore | M1 | DONE (Certified PASS, 147 unit, 11 tier2 e2e, 6 bench, 57 adversarial, Auditor CLEAN) |
| M3 | Dynamic Tracing & Memory Probing | F09, F10, F11: Frida host hooking, Unicorn emulation prober, dynamic fact extraction and static backfill | M1, M2 | DONE (Certified PASS, 291/291 unit, 2/2 tier3 e2e, 7/7 tier1 e2e, 6/6 bench, 72 adversarial, Auditor CLEAN) |
| M4 | Interactive DB Mutation & Equivalence Loop | F12, F13, F14: rename_symbol, update_variable_type, define_struct, recompilation runner, differential tester | M1, M2, M3 | DONE (Certified PASS, 416/416 tests pass, 5/5 panel APPROVE, Auditor CLEAN) |
| M5 | Final Milestone: 100% E2E Pass & Adversarial Hardening | F16: Phase 1 pass 100% E2E tests (Tiers 1-4); Phase 2 adversarial coverage hardening (Tier 5) | E2E, M4 | DONE (Certified PASS, 44/44 E2E pass, 30/30 bench vectors, 53/53 adversarial pass, 0 mypy/ruff, Auditor CLEAN) |

## Interface Contracts

### 1. Unified Domain Models (`metis_reverse.core.models`)
- `TargetArtifact`: path, architecture (X86, X86_64, ARM, ARM64), format (ELF, MACHO, PE, JS, DEX), entry_point, size.
- `BinarySession`: session_id, artifact, backend_type, functions: Dict[int, Function], symbols: Dict[str, Symbol], evidence_store: EvidenceStore.
- `Function`: address, name, size, is_stripped, basic_blocks: List[BasicBlock], parameters: List[Variable], return_type: str, decompiled_code: Optional[str], evidence_tag_ids: List[str].
- `Symbol`: address, name, type (FUNC, DATA, IMPORT, EXPORT), size, confidence: float, evidence_tags: List[EvidenceTag].
- `EvidenceTag`: tag_id, evidence_type (FORMAT_STRING, ASSERT_MACRO, SYSCALL_INFERENCE, GO_PCLNTAB, CPP_RTTI, DYNAMIC_PROBE), confidence: float (0.0 - 1.0), raw_anchor: str, explanation: str, is_immutable: bool.

### 2. Backend Engine Interface (`metis_reverse.backends.base.BaseBackend`)
```python
class BaseBackend(ABC):
    @abstractmethod
    def load_artifact(self, artifact: TargetArtifact) -> BinarySession: ...
    @abstractmethod
    def disassemble_range(self, session: BinarySession, start_addr: int, size: int) -> List[Instruction]: ...
    @abstractmethod
    def get_cfg(self, session: BinarySession) -> Dict[str, Any]: ...
    @abstractmethod
    def decompile_function(self, session: BinarySession, func_addr: int) -> DecompiledCode: ...
    @abstractmethod
    def mutate_symbol(self, session: BinarySession, addr: int, new_name: str) -> bool: ...
    @abstractmethod
    def mutate_type(self, session: BinarySession, addr: int, new_type: str) -> bool: ...
```

### 3. FastMCP Server API Specification (`metis_reverse.server`)
- `open_session(file_path: str, backend: Optional[str] = "auto") -> SessionInfo`
- `list_functions(session_id: str) -> List[FunctionSummary]`
- `decompile(session_id: str, function_address: int) -> DecompiledFunctionResult`
- `query_evidence(session_id: str, symbol_or_addr: str) -> List[EvidenceTag]`
- `rename_symbol(session_id: str, address: int, new_name: str) -> MutationResult`
- `update_variable_type(session_id: str, function_address: int, var_name: str, new_type: str) -> MutationResult`
- `define_struct(session_id: str, struct_name: str, fields: Dict[str, str]) -> MutationResult`
- `trace_function(session_id: str, function_address: int, args: List[Any], prober: str = "auto") -> TraceResult`
- `recompile_and_verify(session_id: str, reconstructed_source: str, compiler: str = "clang") -> RecompileResult`
- `run_differential_test(session_id: str, original_path: str, reconstructed_binary_path: str, test_vectors: List[Dict]) -> DifferentialResult`

## Code Layout
```
metis-revers/
├── pyproject.toml                     # PEP 621 package definition (Hatchling backend, uv managed)
├── README.md
├── src/
│   └── metis_reverse/
│       ├── __init__.py
│       ├── server.py                  # FastMCP server entrypoint and tool registrations
│       ├── core/                      # Domain models and session orchestration
│       │   ├── __init__.py
│       │   ├── models.py              # Pydantic v2 domain schemas (BinarySession, Symbol, etc.)
│       │   ├── session.py             # Session manager (active sessions, caching)
│       │   └── evidence.py            # EvidenceStore, EvidenceTag, and scoring algorithms
│       ├── backends/                  # Tier 1 and Tier 2 backend integrations
│       │   ├── __init__.py
│       │   ├── base.py                # Abstract BaseBackend interface
│       │   ├── detector.py            # Tier 2 discovery (Ghidra, IDA, JADX) and fallback
│       │   ├── tier1_native/          # LIEF + Capstone + Angr + Tree-sitter native engine
│       │   │   ├── __init__.py
│       │   │   ├── binary_parser.py   # LIEF parser (ELF/Mach-O/PE)
│       │   │   ├── disassembler.py    # Capstone disassembler
│       │   │   └── decompiler.py      # Angr CFGFast & Decompiler wrapper
│       │   └── tier2_bridge/          # Ghidra / IDA / JADX headless connectors
│       │       ├── __init__.py
│       │       ├── ghidra_headless.py
│       │       └── mock_backend.py    # Deterministic test fixture for Tier 2 testing
│       ├── grounding/                 # Multi-evidence grounding engine (R2)
│       │   ├── __init__.py
│       │   ├── format_strings.py      # Printf / spdlog / fmt format reverse parser
│       │   ├── assert_macros.py       # Assert string extractor and condition parser
│       │   ├── syscalls.py            # POSIX / syscall table propagation
│       │   └── metadata/              # Language specific metadata
│       │       ├── __init__.py
│       │       ├── go_pclntab.py      # Go pclntab parser (v1.2, 1.16, 1.18, 1.20, 1.23+)
│       │       ├── cpp_rtti.py        # C++ Itanium RTTI & VTable extractor
│       │       └── js_ast.py          # JavaScript Tree-sitter scope extractor
│       ├── dynamic/                   # Dynamic tracing & memory probing (R3)
│       │   ├── __init__.py
│       │   ├── prober_base.py         # Abstract Prober interface
│       │   ├── frida_prober.py        # Native Frida hooker
│       │   ├── unicorn_prober.py      # Unicorn in-memory micro-emulation prober
│       │   └── backfiller.py          # Reconciling concrete runtime values into static session
│       └── equivalence/               # DB mutation & equivalence loop (R4)
│           ├── __init__.py
│           ├── mutator.py             # Symbol, type, struct cascaded updater
│           ├── recompilation.py       # Clang / GCC compilation runner
│           └── differential.py        # Black-box I/O differential tester
└── tests/
    ├── conftest.py                    # Pytest fixtures and environment setup
    ├── unit/                          # Unit tests per module
    ├── integration/                   # Integration tests across modules
    ├── e2e/                           # End-to-end tests for FastMCP tools
    └── synthetic_benchmarks/          # Ground-truth synthetic targets
        ├── c_service/                 # C program: structs, assert, printf, stripped
        ├── go_pipeline/               # Go program: goroutines, pclntab, stripped (-s -w)
        ├── js_obfuscated/             # JS script: Terser obfuscated, stripped sourcemaps
        └── harness.py                 # Ground truth test vectors and verification runner
```
