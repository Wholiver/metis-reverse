# Metis Reverse — Test Suite Readiness Declaration

- **Document**: `TEST_READY.md`
- **Date**: 2026-10-16
- **Status**: **READY** (Ground Truth Benchmarks 100% Verified)
- **Author**: E2E Test & Benchmark Engineer (`test_writer_e2e_1`)

---

## 1. Executive Summary

The complete end-to-end testing infrastructure, synthetic benchmark suite, and progressive opaque-box E2E test suites for **Metis Reverse** have been created, built, and verified.

All three synthetic benchmarks (`c_service`, `go_pipeline`, `js_obfuscated`) compile cleanly with production-grade aggressive optimizations and stripping (`clang -O2 -s`, `go build -ldflags="-s -w" -trimpath`, `npx terser --mangle toplevel=true --mangle-props`), and achieve **100% test vector execution parity (30 / 30 vectors passed)** between unstripped reference implementations and stripped/obfuscated targets.

---

## 2. Test Runner Commands

### 2.1 Synthetic Benchmarks Ground Truth & Harness Execution
```bash
python3 tests/synthetic_benchmarks/harness.py --compile --verify
```
*Compiles all three targets and verifies all 30 vectors against stripped and unstripped binaries.*

### 2.2 Pytest End-to-End Test Suite Execution
```bash
uv run --python 3.12 --with pytest pytest tests/e2e -v
```
*Executes all benchmark ground truth differential tests and progressive Tier 1-4 tests.*

---

## 3. Test Counts & Status per Tier

| Test Suite / Tier | Test File | Test Count | Current Status | Milestone Gate |
|---|---|---|---|---|
| **Benchmarks Ground Truth** | `tests/e2e/test_benchmarks_ground_truth.py` | 13 test cases (30 vectors) | **13 / 13 PASSED (100%)** | Pre-requisite |
| **Tier 1 (Session & Disasm)** | `tests/e2e/test_tier1_session_and_disassembly.py` | 6 test cases | Ready (Pending M1 Server) | Milestone 1 Gate |
| **Tier 2 (Grounding Engine)** | `tests/e2e/test_tier2_decompilation_and_evidence.py` | 4 test cases | Ready (Pending M2 Engine) | Milestone 2 Gate |
| **Tier 3 (Dynamic Probing)** | `tests/e2e/test_tier3_dynamic_probing.py` | 2 test cases | Ready (Pending M3 Prober) | Milestone 3 Gate |
| **Tier 4 (Mutation & Equiv)** | `tests/e2e/test_tier4_mutation_and_equivalence.py` | 3 test cases | Ready (Pending M4 Loop) | Milestone 4 Gate |
| **Total** | | **28 test cases / 30 vectors** | **Active & Ready** | |

---

## 4. Feature Coverage Checklist

- [x] **F15 Synthetic Benchmarks Suite**:
  - `c_service`: Real C11 program with structs (`ServiceConfig`, `SessionData`), logging (`printf`), assert macros (`assert(len > 0 && "len_check")`), HTTP-like parser, compiled with `clang -O2` and stripped with `/usr/bin/strip`. 10 test vectors verified.
  - `go_pipeline`: Real Go concurrent program with worker goroutines, channels, custom packages, atomic metrics, compiled with `go build -ldflags="-s -w" -trimpath`. 10 test vectors verified.
  - `js_obfuscated`: Real Node.js application with classes (`CryptoUtil`, `SessionManager`), HMAC-SHA256, compiled with `npx terser` aggressive variable & property mangling without sourcemaps. 10 test vectors verified.
  - `harness.py`: Executable harness for compiling, executing, and running differential comparisons.
- [x] **F01-F04 FastMCP Server & Tier 1/2 Backends**: Covered in `tests/e2e/test_tier1_session_and_disassembly.py`.
- [x] **F05-F08 Multi-Evidence Grounding Engine**: Covered in `tests/e2e/test_tier2_decompilation_and_evidence.py`.
- [x] **F09-F11 Dynamic Tracing & Memory Probing**: Covered in `tests/e2e/test_tier3_dynamic_probing.py`.
- [x] **F12-F14 Interactive Mutation, Recompilation & Equivalence**: Covered in `tests/e2e/test_tier4_mutation_and_equivalence.py`.
- [x] **F16 Adversarial Hardening**: Error handling test cases in Tier 1 (`malformed_binary.bin`, non-existent paths, invalid session IDs).

---

## 5. Artifact Directory Tree

```
metis-revers/
├── TEST_INFRA.md
├── TEST_READY.md
├── tests/
│   ├── conftest.py
│   ├── fixtures/
│   │   ├── reconstructed_c_service.c
│   │   └── malformed_binary.bin
│   ├── synthetic_benchmarks/
│   │   ├── harness.py
│   │   ├── c_service/
│   │   │   ├── Makefile
│   │   │   ├── ground_truth_symbols.json
│   │   │   ├── test_vectors.json
│   │   │   ├── src/ (main.c, config.c, config.h, parser.c, parser.h)
│   │   │   └── bin/ (c_service_unstripped, c_service_stripped)
│   │   ├── go_pipeline/
│   │   │   ├── Makefile
│   │   │   ├── go.mod
│   │   │   ├── ground_truth_symbols.json
│   │   │   ├── test_vectors.json
│   │   │   ├── cmd/pipeline/main.go
│   │   │   ├── pkg/ (config, metrics, processor)
│   │   │   └── bin/ (go_pipeline_unstripped, go_pipeline_stripped)
│   │   └── js_obfuscated/
│   │       ├── Makefile
│   │       ├── package.json
│   │       ├── build.sh
│   │       ├── ground_truth_symbols.json
│   │       ├── test_vectors.json
│   │       ├── src/ (index.js, crypto_util.js, session_manager.js)
│   │       └── dist/ (bundle.clean.js, bundle.min.js)
│   └── e2e/
│       ├── test_benchmarks_ground_truth.py
│       ├── test_tier1_session_and_disassembly.py
│       ├── test_tier2_decompilation_and_evidence.py
│       ├── test_tier3_dynamic_probing.py
│       └── test_tier4_mutation_and_equivalence.py
```
