# Metis Reverse — Test Infrastructure & Quality Assurance Specification

- **Project**: Metis Reverse (`/Users/huchenrui/metis-revers`)
- **Document**: `TEST_INFRA.md`
- **Owner**: E2E Test & Benchmark Engineer (`test_writer_e2e_1`)
- **Status**: Complete & Verified (Ground Truth Benchmarks 100% Passed)

---

## 1. Test Philosophy & Core Principles

Metis Reverse is an AI-native reverse engineering server designed to provide developer-grade, high-fidelity source code reconstruction. The testing architecture follows four foundational pillars:

### 1.1 Opaque-Box & Requirement-Driven
- All test suites interact with the system strictly through its external, public FastMCP tool interfaces (`open_session`, `list_functions`, `decompile`, `query_evidence`, `rename_symbol`, `update_variable_type`, `define_struct`, `trace_function`, `recompile_and_verify`, `run_differential_test`) as defined in `PROJECT.md`.
- No tests make assumptions about internal unexposed private methods; verification evaluates observable outputs (JSON schemas, return models, exit codes, stdout/stderr streams).
- Every test traces directly to requirements defined in `ORIGINAL_REQUEST.md` (R1-R4) and `PROJECT.md` (F01-F16).

### 1.2 Zero-Hallucination Multi-Evidence Grounding
- Symbol suggestions and recovered types must be backed by concrete, immutable evidence (printf format strings, assert condition strings, Go pclntab tables, POSIX syscall conventions, or dynamic memory dumps).
- Grounded evidence must have an explicit confidence score of `1.0` and `is_immutable: true`. Tests fail if an ungrounded guess is emitted as certain.

### 1.3 Closed-Loop Recompilation & Equivalence
- Reconstructed C source code is compiled inside an automated sandbox using `clang -O2`. Zero compilation errors (`0 errors`) is an absolute gate.
- Reconstructed binaries are subjected to multi-vector black-box differential testing against original stripped binaries. Exit codes, stdout, and stderr must match 100%.

### 1.4 Deterministic Execution & Variance Control
- Benchmark targets and test vectors are strictly deterministic:
  - Timestamps and PIDs are parameterized or cleanly masked via regex sanitization patterns.
  - Concurrent channels in multi-worker benchmarks (e.g. Go pipeline) enforce deterministic sorting on emitted outputs to eliminate race-induced diff false positives.

---

## 2. Feature Inventory Coverage Matrix

| Feature | Feature Name | Test Category | Target Tier | Test Files & Suites | Acceptance Criteria |
|---|---|---|---|---|---|
| **F01** | FastMCP Server & Protocol | Tool API / Protocol | Tier 1 | `tests/e2e/test_tier1_session_and_disassembly.py` | FastMCP server tools callable via stdio/SSE; session lifecycle managed |
| **F02** | Unified RE Domain Abstraction | Model Validation | Tier 1 | `tests/e2e/test_tier1_session_and_disassembly.py` | Pydantic v2 schemas: `TargetArtifact`, `BinarySession`, `Function`, `Symbol` conform to contract |
| **F03** | Tier 1 Native Backend | Binary Parsing | Tier 1 | `tests/e2e/test_tier1_session_and_disassembly.py` | LIEF, Capstone, Angr parse Mach-O/ELF/PE, extract functions and disasm without external GUI |
| **F04** | Tier 2 Decompiler Integration | Decompilation Bridge | Tier 1 / Tier 2 | `tests/e2e/test_tier1_session_and_disassembly.py`, `test_tier2_decompilation_and_evidence.py` | Ghidra/IDA discovery with automated fallback to MockBackend / Angr |
| **F05** | Format String & Assert Reverse Inference | Static Evidence | Tier 2 | `tests/e2e/test_tier2_decompilation_and_evidence.py` | 100% extraction of printf format strings and assert macro conditions with confidence 1.0 |
| **F06** | Syscall & Standard Libc Propagation | Static Evidence | Tier 2 | `tests/e2e/test_tier2_decompilation_and_evidence.py` | Propagation of POSIX types and buffer lengths from standard library calls |
| **F07** | Language Metadata Extraction | Deep Metadata | Tier 2 | `tests/e2e/test_tier2_decompilation_and_evidence.py` | Extraction of Go pclntab symbols from stripped binary; AST scope analysis for JS |
| **F08** | EvidenceTag & Grounding Store | Evidence Integrity | Tier 2 | `tests/e2e/test_tier2_decompilation_and_evidence.py` | Immutable evidence tagging with raw anchors, explanation, and confidence scores |
| **F09** | Dynamic Tracing with Frida | Dynamic Probing | Tier 3 | `tests/e2e/test_tier3_dynamic_probing.py` | Function hooking, argument inspection, return value capture on native processes |
| **F10** | Emulated Prober with Unicorn | Dynamic Probing | Tier 3 | `tests/e2e/test_tier3_dynamic_probing.py` | In-memory micro-emulation prober for isolated execution and memory inspection |
| **F11** | Dynamic-to-Static Fact Backfilling | Fact Reconciliation | Tier 3 | `tests/e2e/test_tier3_dynamic_probing.py` | Concrete runtime values backfilled into static session symbol table as evidence |
| **F12** | Interactive Decompiler DB Mutation | DB Mutation | Tier 4 | `tests/e2e/test_tier4_mutation_and_equivalence.py` | `rename_symbol`, `update_variable_type`, `define_struct` update DB and cascade |
| **F13** | Recompilation Sandbox | Compilation Sandbox | Tier 4 | `tests/e2e/test_tier4_mutation_and_equivalence.py` | `recompile_and_verify` compiles reconstructed C code with 0 errors |
| **F14** | Differential Testing Harness | Equivalence Loop | Tier 4 | `tests/e2e/test_tier4_mutation_and_equivalence.py`, `tests/synthetic_benchmarks/harness.py` | Multi-vector execution verifies exit codes, stdout, stderr match original stripped binary |
| **F15** | Synthetic Benchmarks Suite | Ground Truth | Benchmarks | `tests/synthetic_benchmarks/`, `tests/e2e/test_benchmarks_ground_truth.py` | Stripped C, stripped Go, obfuscated JS compile cleanly and pass 30/30 ground truth vectors |
| **F16** | 100% Verification & Adversarial Hardening | Stress / Robustness | Tier 5 | `tests/e2e/test_tier1_session_and_disassembly.py` (malformed input tests) | Graceful rejection of malformed binary headers, non-existent files, and invalid sessions |

---

## 3. Test Architecture & Tier Structure

```
tests/
├── conftest.py                             # Pytest shared fixtures, target paths, vectors
├── fixtures/                               # Reusable test fixtures and ground-truth artifacts
│   ├── reconstructed_c_service.c           # Single-file clean C ground-truth reconstruction
│   └── malformed_binary.bin                # Corrupted binary header for error testing
├── synthetic_benchmarks/                   # Synthetic benchmark programs
│   ├── c_service/                          # C binary: structs, assert, printf, stripped
│   ├── go_pipeline/                        # Go binary: goroutines, channels, pclntab, stripped
│   ├── js_obfuscated/                      # JS bundle: Terser obfuscated, mangled props
│   └── harness.py                          # Executable build, verification, and differential runner
└── e2e/                                    # Opaque-box FastMCP end-to-end tests
    ├── test_benchmarks_ground_truth.py     # 100% ground-truth execution across all 30 vectors
    ├── test_tier1_session_and_disassembly.py  # Session lifecycle, LIEF/Capstone disassembly
    ├── test_tier2_decompilation_and_evidence.py # Decompile, printf/assert inference, Go pclntab
    ├── test_tier3_dynamic_probing.py       # trace_function, Frida/Unicorn, fact backfill
    └── test_tier4_mutation_and_equivalence.py # DB mutations, recompilation, differential test
```

### Tier Breakdown
- **Tier 1 (Smoke & Protocol)**: Verifies FastMCP server startup, session lifecycle (`open_session`), function listing (`list_functions`), basic disassembly range, and error resilience on non-existent or corrupted files.
- **Tier 2 (Static Analysis & Evidence Grounding)**: Verifies `decompile`, format string reverse inference (`printf`), assert macro condition extraction (`len_check`, `http_magic_check`), and Go pclntab function symbol discovery. Verifies `EvidenceTag` immutability and confidence scoring.
- **Tier 3 (Dynamic Probing & Runtime Backfilling)**: Verifies `trace_function` via native Frida or Unicorn emulation prober. Validates runtime argument capture, return value capture, and dynamic fact backfilling into static session symbols.
- **Tier 4 (Interactive DB Mutation & Equivalence Loop)**: Verifies FastMCP mutation tools (`rename_symbol`, `update_variable_type`, `define_struct`), `recompile_and_verify` (0 compilation errors), and multi-vector differential testing (100% behavioral equivalence).
- **Tier 5 (Adversarial Stress & Hardening)**: Verifies memory limits, timeouts (max 5.0s per vector), malformed binary inputs, and corrupted JSON payloads.

---

## 4. Synthetic Benchmarks Suite Details

### 4.1 C Service Benchmark (`tests/synthetic_benchmarks/c_service/`)
- **Language**: C11
- **Compiler**: `clang -O2 -Wall -Wextra -std=c11 -fno-ident`
- **Stripping**: `/usr/bin/strip bin/c_service_stripped`
- **Components**:
  - `struct ServiceConfig`: Configuration layout with magic `0x53455256` ('SERV'), port, max_clients, secret_token, timeout.
  - `struct SessionData`: Client session state with session_id, client_ip, auth_token, authentication state.
  - `struct HttpRequest` / `HttpResponse`: HTTP request parser and router.
  - **Logging Format Strings**:
    - `"[INFO] Service starting on port %u (max_clients: %u)\n"`
    - `"[DEBUG] Session %u authenticated for client %s\n"`
    - `"[ERROR] Auth failed for client %s (id: %u)\n"`
    - `"[INFO] Handled %s %s -> status %d (bytes: %zu)\n"`
  - **Assert Conditions**:
    - `assert(cfg != NULL && "config_not_null");`
    - `assert(session != NULL && "session_not_null");`
    - `assert(len > 0 && "len_check");`
    - `assert(req->magic == HTTP_REQ_MAGIC && "http_magic_check");`
- **Test Vectors (10 vectors)**:
  - `V01_GET_HEALTH`: Health check GET -> 200 OK
  - `V02_POST_AUTH_SUCCESS`: Bearer auth token -> 200 OK + authenticated session
  - `V03_POST_AUTH_FAILURE`: Invalid token -> 401 Unauthorized + stderr log
  - `V04_GET_ECHO`: Echo API endpoint -> custom headers parsed
  - `V05_GET_NOT_FOUND`: Nonexistent route -> 404 Not Found
  - `V06_EMPTY_STDIN`: Empty stdin payload -> exit code 1 + error log
  - `V07_MALFORMED_METHOD`: Invalid HTTP verb -> exit code 3 + 400 Bad Request
  - `V08_FLAG_DUMP_CONFIG`: CLI flag `--dump-config` -> serialized config dump
  - `V09_FLAG_VERSION`: CLI flag `--version` -> version string
  - `V10_FLAG_HELP`: CLI flag `--help` -> command options usage text

### 4.2 Go Pipeline Benchmark (`tests/synthetic_benchmarks/go_pipeline/`)
- **Language**: Go 1.22+
- **Compiler**: `go build -ldflags="-s -w" -trimpath`
- **Components**:
  - Multi-package layout: `main`, `pkg/config`, `pkg/metrics`, `pkg/processor`.
  - Concurrent worker pool using goroutines and channels (`chan Task`, `chan TaskResult`, `sync.WaitGroup`).
  - Atomic counters (`sync/atomic`) tracking processed, filtered, error, and byte counts.
  - **pclntab Preservation**: Preserves function symbols (`main.main`, `pkg/processor.(*PipelinePool).Run`, `pkg/metrics.NewMetricsCounter`) in `.gopclntab`.
- **Test Vectors (10 vectors)**:
  - `V01_STANDARD_TRANSFORM`: Batch payload transform to uppercase with sha256 digest
  - `V02_FILTER_KEYWORD`: Keyword filtering keeps matching tasks, marks others FILTERED
  - `V03_VALIDATE_MODE`: Validate mode outputs payload byte lengths
  - `V04_ERROR_HANDLING`: `ERR:` prefix triggers structured error status and metrics increment
  - `V05_METRICS_FLAG`: `--metrics` flag outputs JSON metrics summary on exit
  - `V06_CONCURRENCY_WORKERS`: `--workers=8` concurrent execution with deterministic ID ordering
  - `V07_EMPTY_INPUT`: Empty stdin terminates cleanly with exit code 0
  - `V08_VERSION_FLAG`: `--version` displays pipeline release version
  - `V09_ENV_OVERRIDE`: `PIPELINE_WORKERS=2` environment variable override
  - `V10_INVALID_FLAG`: Unknown flag returns exit code 2 and standard usage message

### 4.3 Obfuscated JavaScript Benchmark (`tests/synthetic_benchmarks/js_obfuscated/`)
- **Runtime**: Node.js v24+
- **Minifier / Obfuscator**: `npx terser --compress passes=3 --mangle toplevel=true --mangle-props regex=/^_/`
- **Sourcemaps**: Completely stripped.
- **Components**:
  - `CryptoUtil`: Class managing HMAC-SHA256 signing, SHA-256 hashing, timing-safe equality.
  - `SessionManager`: Class managing token issuance, TTL expiration, session store.
  - Property and identifier mangling reduces methods and properties to single letters (`s`, `o`, `t`, `this.u`, etc.).
- **Test Vectors (10 vectors)**:
  - `V01_CREATE_SESSION`: Session issuance with deterministic timestamp and signature
  - `V02_HASH_DATA`: User data hashing via SHA-256
  - `V03_STDIN_HASH`: JSON command on stdin for hash calculation
  - `V04_STDIN_SIGN`: JSON command on stdin for HMAC signature generation
  - `V05_EMPTY_STDIN`: Empty stdin triggers exit code 1
  - `V06_CORRUPTED_JSON_STDIN`: Malformed JSON triggers parse error exit code 2
  - `V07_VERSION_FLAG`: `--version` flag outputs release string
  - `V08_HELP_FLAG`: `--help` flag displays usage options
  - `V09_VALIDATE_SESSION_SUCCESS`: Validates cryptographic HMAC signature on active session
  - `V10_UNKNOWN_ACTION`: Invalid CLI action argument triggers exit code 1

---

## 5. Tier Thresholds & Gating Criteria

| Tier | Pass Rate Threshold | Compilation Gate | Equivalence Gate | Fail Policy |
|---|---|---|---|---|
| **Benchmarks Ground Truth** | **100% (30 / 30 vectors)** | 0 compiler warnings/errors | 100% match (unstripped vs stripped) | Block release |
| **Tier 1 (Session & Disasm)** | **100% of defined tests** | N/A | N/A | Block Milestone 1 |
| **Tier 2 (Grounding Engine)** | **100% grounded symbols** | N/A | Zero hallucination (confidence 1.0) | Block Milestone 2 |
| **Tier 3 (Dynamic Probing)** | **100% of trace tests** | N/A | Prober captures args/ret without crash | Block Milestone 3 |
| **Tier 4 (Mutation & Equiv)** | **100% of differential tests** | 0 compiler errors | 100% exit/stdout/stderr match | Block Milestone 4 |
| **Tier 5 (Adversarial)** | **>= 95% pass rate** | N/A | No unhandled exceptions / panics | Block Milestone 5 |

---

## 6. Execution Instructions

### 6.1 Build & Verify Synthetic Benchmarks
To compile all benchmarks and verify ground truth execution against stripped binaries:
```bash
python3 tests/synthetic_benchmarks/harness.py --compile --verify
```

### 6.2 Run Pytest Suite
To run the automated E2E tests:
```bash
uv run --python 3.12 --with pytest pytest tests/e2e -v
```

### 6.3 Differential Testing via Python API
```python
from tests.synthetic_benchmarks.harness import run_differential_comparison, load_test_vectors

vectors = load_test_vectors("c_service")
report = run_differential_comparison(
    original_cmd=["tests/synthetic_benchmarks/c_service/bin/c_service_stripped"],
    reconstructed_cmd=["/tmp/reconstructed_binary"],
    vectors=vectors,
)
print(f"Equivalence: {report['equivalence_percentage']}% (All passed: {report['all_passed']})")
```
