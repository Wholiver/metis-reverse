"""
Adversarial Stress Test Suite for Milestone 4:
- RecompilationSandbox Isolation & Prelude Resilience
- DifferentialTester Subprocess Isolation, Process Groups, & Timeouts
- Stdin Handling, Large Inputs, & EOF Transmission
- Non-Deterministic Output Normalization & Masking
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import tempfile
import time

from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    BinarySession,
    TargetArtifact,
)
from metis_reverse.core.session import global_session_manager
from metis_reverse.equivalence.differential import (
    DifferentialTester,
)
from metis_reverse.equivalence.recompilation import (
    RecompilationSandbox,
    recompile_and_verify,
)

# ============================================================================
# Dimension 1: Compiler Sandbox Isolation & Prelude Resilience
# ============================================================================

class TestRecompilationSandboxAdversarial:
    """Stress tests for RecompilationSandbox against malformed C, prelude edge cases, and warnings."""

    def test_syntax_errors_and_structured_diagnostics(self) -> None:
        """Malformed C source with syntax errors returns structured diagnostics and failure."""
        sandbox = RecompilationSandbox()
        malformed_c = """
        int main() {
            int a = ; // syntax error
            for (int i = 0; i < 10 i++) // missing semicolon
            return 0;
        }
        """
        out = sandbox.compile(source=malformed_c, compiler="clang")
        try:
            assert out.success is False
            assert out.binary_path is None
            assert out.returncode != 0
            assert len(out.diagnostics) >= 2
            errors = [d for d in out.diagnostics if d.severity in ("error", "fatal error")]
            assert len(errors) >= 2
            assert all(d.line > 0 for d in errors)
            assert out.compile_errors_summary != ""
        finally:
            sandbox.cleanup()

    def test_type_mismatches_and_incompatible_pointers(self) -> None:
        """Type mismatch and incompatible pointer assignments produce error diagnostics."""
        sandbox = RecompilationSandbox()
        bad_types_c = """
        struct Foo { int a; };
        int main() {
            struct Foo* f = "incompatible_string_literal";
            int x = f;
            return 0;
        }
        """
        out = sandbox.compile(source=bad_types_c, compiler="clang")
        try:
            assert out.success is False
            assert out.binary_path is None
            assert len(out.diagnostics) >= 1
            assert any("incompatible" in d.message.lower() or "pointer" in d.message.lower() for d in out.diagnostics)
        finally:
            sandbox.cleanup()

    def test_compiler_warning_vs_error_separation(self) -> None:
        """Verify warnings do not cause failure unless treat_warnings_as_errors is enabled."""
        sandbox = RecompilationSandbox()
        warning_c = """
        #include <stdio.h>
        int main() {
            int unused_var = 123;
            long val = 42;
            printf("val is: %d\\n", (int)val);
            return 0;
        }
        """
        # Normal compilation: warnings present, but compile succeeds
        out_normal = sandbox.compile(source=warning_c, compiler="clang", treat_warnings_as_errors=False)
        try:
            assert out_normal.success is True
            assert out_normal.binary_path is not None
            assert out_normal.binary_path.exists()
            assert "unused" in out_normal.compile_warnings_summary.lower()
            assert out_normal.compile_errors_summary == ""
        finally:
            sandbox.cleanup()

        # Strict mode: treat_warnings_as_errors=True must cause failure
        out_strict = sandbox.compile(source=warning_c, compiler="clang", treat_warnings_as_errors=True)
        try:
            assert out_strict.success is False
            assert out_strict.binary_path is None
            assert out_strict.compile_errors_summary != ""
        finally:
            sandbox.cleanup()

    def test_prelude_injection_when_no_headers_present(self) -> None:
        """C code with no headers automatically receives synthetic prelude and compiles."""
        sandbox = RecompilationSandbox()
        no_headers_c = """
        int main() {
            uint32_t x = 42;
            uint64_t y = 100ULL;
            bool ok = true;
            char* buf = (char*)malloc(64);
            strcpy(buf, "prelude_ok");
            assert(ok && buf != NULL);
            printf("%s: %u, %llu\\n", buf, x, (unsigned long long)y);
            free(buf);
            return 0;
        }
        """
        out = sandbox.compile(source=no_headers_c, compiler="clang", auto_prelude=True)
        try:
            assert out.success is True
            assert out.binary_path is not None
            assert out.binary_path.exists()
        finally:
            sandbox.cleanup()

    def test_prelude_flaw_stdio_stdlib_present_but_missing_stdint_stdbool(self) -> None:
        """
        EMPIRICAL BUG REPRODUCTION:
        RecompilationSandbox line 244 checks:
        has_basic_headers = ('#include <stdio.h>' in source and '#include <stdlib.h>' in source)
        When source has stdio.h and stdlib.h, auto_prelude is suppressed,
        causing code needing stdint.h / stdbool.h / string.h to FAIL compilation!
        """
        sandbox = RecompilationSandbox()
        code = """#include <stdio.h>
#include <stdlib.h>

int main() {
    uint32_t val = 999;
    bool active = true;
    printf("active=%d val=%u\\n", active, val);
    return 0;
}
"""
        out = sandbox.compile(source=code, compiler="clang", auto_prelude=True)
        try:
            assert out.success is True, f"Expected compilation success with prelude injection: {out.compile_errors_summary}"
            assert out.binary_path is not None
            assert out.binary_path.exists()
        finally:
            sandbox.cleanup()

    def test_deep_macro_recursion_limit(self) -> None:
        """Recursive #include __FILE__ without guard hits compiler depth limit gracefully."""
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write("#include __FILE__\nint main() { return 0; }\n")
            src_path = f.name

        try:
            sandbox = RecompilationSandbox(timeout_seconds=5.0)
            with open(src_path) as f:
                code = f.read()
            out = sandbox.compile(source=code, compiler="clang")
            assert out.success is False
            assert out.binary_path is None
            # Compiler catches depth recursion
            assert any("nested too deeply" in d.message or "recursive" in d.message or out.returncode != 0 for d in out.diagnostics)
        finally:
            if os.path.exists(src_path):
                os.remove(src_path)
            sandbox.cleanup()


# ============================================================================
# Dimension 2: Differential Testing & Process Isolation
# ============================================================================

class TestDifferentialTesterProcessIsolation:
    """Stress tests DifferentialTester for process group cleanup, runaway binaries, and timeouts."""

    def test_infinite_loop_timeout_cleanly(self) -> None:
        """Single process in infinite loop is terminated cleanly after timeout."""
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write("int main() { while(1); return 0; }\n")
            c_file = f.name
        bin_file = c_file.replace(".c", "")

        try:
            subprocess.run(["clang", c_file, "-o", bin_file], check=True)
            tester = DifferentialTester(timeout_seconds=1.0)
            t0 = time.time()
            rc, out, err, is_to = tester.run_single_vector([bin_file], {}, timeout_sec=1.0)
            elapsed = time.time() - t0

            assert is_to is True
            assert rc == -124
            assert 0.8 <= elapsed <= 3.0
            assert "timed out" in err.lower()
        finally:
            for p in (c_file, bin_file):
                if os.path.exists(p):
                    os.remove(p)

    def test_child_process_orphan_leak_vulnerability(self) -> None:
        """
        EMPIRICAL BUG REPRODUCTION:
        In DifferentialTester.run_single_vector:
        except subprocess.TimeoutExpired as exc:
            if exc.cmd and hasattr(exc, "pid") and exc.pid:
                os.killpg(...)
        Because subprocess.TimeoutExpired does NOT have a .pid attribute in Python,
        hasattr(exc, "pid") is False!
        Any child processes spawned by target binaries survive as leaked orphans!
        """
        marker = f"orphan_probe_{int(time.time())}"
        pid_file = f"/tmp/child_{marker}.pid"
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(f"""
            #include <unistd.h>
            #include <stdio.h>
            int main() {{
                pid_t pid = fork();
                if (pid == 0) {{
                    while (1) {{ sleep(1); }}
                }}
                FILE* pf = fopen("{pid_file}", "w");
                if (pf) {{
                    fprintf(pf, "%d", (int)pid);
                    fclose(pf);
                }}
                while (1) {{ sleep(1); }}
                return 0;
            }}
            """)
            c_file = f.name
        bin_file = f"/tmp/{marker}"

        try:
            subprocess.run(["clang", c_file, "-o", bin_file], check=True)
            tester = DifferentialTester(timeout_seconds=1.0)

            # Run with 1 second timeout
            rc, out, err, is_to = tester.run_single_vector([bin_file], {}, timeout_sec=1.0)
            assert is_to is True
            assert rc == -124

            # Verify that child process wrote PID and is STILL RUNNING
            assert os.path.exists(pid_file), "Child process failed to write PID"
            with open(pid_file) as pf:
                child_pid = int(pf.read().strip())

            # Allow SIGKILL signal propagation
            time.sleep(0.1)

            child_alive = False
            try:
                os.kill(child_pid, 0)
                child_alive = True
            except ProcessLookupError:
                child_alive = False

            # REMEDIATION VERIFICATION: Child process was killed by os.killpg!
            try:
                assert child_alive is False, "Child process should have been terminated by os.killpg"
            finally:
                # Clean up the orphan process manually if it somehow survived
                with contextlib.suppress(Exception):
                    os.kill(child_pid, signal.SIGKILL)
        finally:
            for p in (c_file, bin_file, pid_file):
                if os.path.exists(p):
                    os.remove(p)

    def test_pipe_flood_timeout_does_not_deadlock(self) -> None:
        """Process that floods stdout with infinite output terminates on timeout without deadlock."""
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write("""
            #include <stdio.h>
            int main() {
                while(1) {
                    printf("FLOOD_DATA_LINE_1234567890_ABCDEFGHIJ\\n");
                }
                return 0;
            }
            """)
            c_file = f.name
        bin_file = c_file.replace(".c", "")

        try:
            subprocess.run(["clang", c_file, "-o", bin_file], check=True)
            tester = DifferentialTester(timeout_seconds=1.0)
            t0 = time.time()
            rc, out, err, is_to = tester.run_single_vector([bin_file], {}, timeout_sec=1.0)
            elapsed = time.time() - t0

            assert is_to is True
            assert rc == -124
            assert elapsed < 3.0
        finally:
            for p in (c_file, bin_file):
                if os.path.exists(p):
                    os.remove(p)


# ============================================================================
# Dimension 3: Stdin Handling, Large Inputs, & EOF Transmission
# ============================================================================

class TestDifferentialTesterStdinHandling:
    """Stress tests DifferentialTester for stdin transmission, EOF behavior, and input types."""

    def test_stdin_eof_transmission(self) -> None:
        """Binary reading until EOF receives EOF properly when stdin_data is sent."""
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write("""
            #include <stdio.h>
            int main() {
                int ch;
                int count = 0;
                while ((ch = getchar()) != EOF) {
                    count++;
                }
                printf("read %d chars\\n", count);
                return 0;
            }
            """)
            c_file = f.name
        bin_file = c_file.replace(".c", "")

        try:
            subprocess.run(["clang", c_file, "-o", bin_file], check=True)
            tester = DifferentialTester()

            # Empty stdin -> EOF immediately
            rc, out, err, is_to = tester.run_single_vector([bin_file], {"stdin_data": ""})
            assert rc == 0
            assert "read 0 chars" in out

            # Populated stdin -> EOF after data
            rc2, out2, err2, is_to2 = tester.run_single_vector([bin_file], {"stdin_data": "Hello World!"})
            assert rc2 == 0
            assert "read 12 chars" in out2
        finally:
            for p in (c_file, bin_file):
                if os.path.exists(p):
                    os.remove(p)

    def test_large_stdin_input_saturation(self) -> None:
        """DifferentialTester successfully transmits large stdin input (>256KB) without pipe deadlock."""
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write("""
            #include <stdio.h>
            int main() {
                char buf[4096];
                size_t total = 0;
                size_t n;
                while ((n = fread(buf, 1, sizeof(buf), stdin)) > 0) {
                    total += n;
                }
                printf("total_bytes: %zu\\n", total);
                return 0;
            }
            """)
            c_file = f.name
        bin_file = c_file.replace(".c", "")

        try:
            subprocess.run(["clang", c_file, "-o", bin_file], check=True)
            tester = DifferentialTester()

            # 512 KB payload
            large_payload = "A" * (512 * 1024)
            rc, out, err, is_to = tester.run_single_vector([bin_file], {"stdin_data": large_payload})
            assert rc == 0
            assert not is_to
            assert "total_bytes: 524288" in out
        finally:
            for p in (c_file, bin_file):
                if os.path.exists(p):
                    os.remove(p)

    def test_non_utf8_binary_stdout_crash_vulnerability(self) -> None:
        """
        EMPIRICAL BUG REPRODUCTION:
        DifferentialTester.run_single_vector uses subprocess.run(..., text=True).
        When a program outputs non-UTF-8 bytes, Python's subprocess throws UnicodeDecodeError,
        which DifferentialTester catches as a generic Exception and returns rc=-1,
        breaking differential testing even when both original and reconstructed binaries match!
        """
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write("""
            #include <stdio.h>
            int main() {
                // Emit raw non-UTF8 bytes: 0x80, 0xFF, 0xFE
                unsigned char raw_bytes[] = {0x80, 0xff, 0xfe, 'o', 'k', '\\n'};
                fwrite(raw_bytes, 1, sizeof(raw_bytes), stdout);
                return 0;
            }
            """)
            c_file = f.name
        bin_file = c_file.replace(".c", "")

        try:
            subprocess.run(["clang", c_file, "-o", bin_file], check=True)
            tester = DifferentialTester()

            rc, out, err, is_to = tester.run_single_vector([bin_file], {})
            # REMEDIATION VERIFICATION:
            # errors="replace" prevents UnicodeDecodeError, returning rc=0 and valid output
            assert rc == 0
            assert is_to is False
            assert "ok" in out
        finally:
            for p in (c_file, bin_file):
                if os.path.exists(p):
                    os.remove(p)


# ============================================================================
# Dimension 4: Non-Deterministic Output Normalization
# ============================================================================

class TestOutputNormalizationAdversarial:
    """Stress tests output normalization against memory addresses, trailing whitespace, CRLF, and timestamps."""

    def test_missing_address_normalization_flaw(self) -> None:
        """
        EMPIRICAL BUG REPRODUCTION:
        Worker handoff claimed: 'masking non-deterministic addresses 0x[0-9a-fA-F]+'
        In reality, DEFAULT_SANITIZERS in differential.py does NOT include any address regex!
        Pointers/addresses across runs cause spurious differential mismatches!
        """
        tester = DifferentialTester()
        out1 = "Allocated buffer pointer at: 0x7ffee1b2c3d0\n"
        out2 = "Allocated buffer pointer at: 0x7ffee1b2c450\n"

        norm1 = tester.normalize_output(out1)
        norm2 = tester.normalize_output(out2)

        # REMEDIATION VERIFICATION:
        # Address sanitizer converts hex pointer addresses to <HEX_ADDR>, making outputs equal
        assert "<HEX_ADDR>" in norm1
        assert "<HEX_ADDR>" in norm2
        assert norm1 == norm2

    def test_missing_trailing_whitespace_normalization_flaw(self) -> None:
        """
        EMPIRICAL BUG REPRODUCTION:
        Worker handoff claimed: 'trimming trailing whitespace'
        In reality, normalize_output does not trim trailing whitespace on lines!
        """
        tester = DifferentialTester()
        out1 = "Result: 42   \n"
        out2 = "Result: 42\n"

        norm1 = tester.normalize_output(out1)
        norm2 = tester.normalize_output(out2)

        # REMEDIATION VERIFICATION:
        # Trailing whitespace on lines is trimmed, making outputs equal
        assert norm1 == norm2

    def test_timestamp_and_pid_normalization(self) -> None:
        """Verify timestamps and PIDs match DEFAULT_SANITIZERS."""
        tester = DifferentialTester()
        s1 = "2026-10-16T12:00:00Z [PID 12345] Server initialized\n"
        s2 = "2026-10-17T08:30:15Z [pid: 67890] Server initialized\n"

        n1 = tester.normalize_output(s1)
        n2 = tester.normalize_output(s2)

        assert "<TIMESTAMP>" in n1 and "<TIMESTAMP>" in n2
        assert "<PID>" in n1 and "<PID>" in n2
        assert n1 == n2

    def test_crlf_to_lf_normalization(self) -> None:
        """Verify Windows CRLF is normalized to Unix LF."""
        tester = DifferentialTester()
        windows_out = "Line 1\r\nLine 2\r\nLine 3\r\n"
        unix_out = "Line 1\nLine 2\nLine 3\n"

        assert tester.normalize_output(windows_out) == tester.normalize_output(unix_out)


# ============================================================================
# Dimension 5: Closed-Loop Recompilation & Equivalence
# ============================================================================

class TestClosedLoopRecompilationAdversarial:
    """Stress tests recompile_and_verify closed-loop behavior."""

    def test_recompile_and_verify_with_divergent_binary(self) -> None:
        """Source compiles, but behavior differs from original binary -> equivalence fails."""
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write("""
            #include <stdio.h>
            int main(int argc, char** argv) {
                if (argc > 1) {
                    printf("ORIGINAL_MODE: %s\\n", argv[1]);
                    return 0;
                }
                return 1;
            }
            """)
            c_file = f.name
        orig_bin = c_file.replace(".c", "")

        try:
            subprocess.run(["clang", c_file, "-o", orig_bin], check=True)

            session = BinarySession(
                session_id="adv_m4_session",
                artifact=TargetArtifact(
                    file_path=orig_bin,
                    architecture=ArchitectureType.ARM64,
                    format=ArtifactFormat.MACHO,
                ),
            )
            global_session_manager._sessions[session.session_id] = session

            # Reconstructed code that outputs different text
            divergent_source = """
            #include <stdio.h>
            int main(int argc, char** argv) {
                if (argc > 1) {
                    printf("WRONG_MODE: %s\\n", argv[1]);
                    return 0;
                }
                return 1;
            }
            """

            test_vectors = [
                {"vector_id": "V1", "cli_args": ["test_arg"]},
            ]

            res = recompile_and_verify(
                session_id="adv_m4_session",
                reconstructed_source=divergent_source,
                compiler="clang",
                test_vectors=test_vectors,
            )

            assert res.success is False
            assert res.equivalence_percentage == 0.0
            assert res.differential_report is not None
            assert res.differential_report["all_passed"] is False
            assert "--- original_stdout" in res.differential_report["vector_results"][0]["diff_details"]
        finally:
            for p in (c_file, orig_bin):
                if os.path.exists(p):
                    os.remove(p)

    def test_recompile_and_verify_with_empty_vectors_reports_100_percent(self) -> None:
        """
        EMPIRICAL BEHAVIOR OBSERVATION:
        When test_vectors is empty, differential testing is bypassed,
        and recompile_and_verify reports success=True and equivalence_percentage=100.0.
        """
        session = BinarySession(
            session_id="adv_m4_empty_vec",
            artifact=TargetArtifact(
                file_path="/bin/echo",
                architecture=ArchitectureType.ARM64,
                format=ArtifactFormat.MACHO,
            ),
        )
        global_session_manager._sessions[session.session_id] = session

        source = "int main() { return 0; }\n"
        res = recompile_and_verify(
            session_id="adv_m4_empty_vec",
            reconstructed_source=source,
            compiler="clang",
            test_vectors=[],
        )

        # Because vectors were empty, equivalence is unverified (0.0%), while compilation succeeded
        assert res.success is True
        assert res.equivalence_percentage == 0.0
        assert res.differential_report is not None
        assert res.differential_report["all_passed"] is False
        assert res.differential_report["total_vectors"] == 0
        assert "unverified" in res.differential_report["warning"].lower()
