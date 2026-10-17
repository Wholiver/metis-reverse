"""
Adversarial Empirical Challenge Suite 2 for Milestone 4 Remediation (M4-R2).
Created by Challenger M4-R2-2.

Rigorous stress verification of:
1. Multi-tier process hierarchy containment under hard timeout (os.killpg).
2. Pointer hex address normalization across varied architectures, formats, and ASLR variations.
3. Trailing whitespace, tabs, CRLF, and empty line normalization.
4. Synthetic prelude resilience under partial header inclusion, type mixing, and idempotence.
5. Non-UTF-8 binary byte streams (0x80-0xFF, full 0-255 byte spectrum) on stdout and stderr.
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from metis_reverse.equivalence.differential import (
    DifferentialTester,
)
from metis_reverse.equivalence.recompilation import (
    METIS_C_PRELUDE,
    RecompilationSandbox,
)

# ============================================================================
# Dimension 1: Multi-Tier Process Tree Containment & SIGKILL Immunity
# ============================================================================

class TestProcessTreeContainmentAdversarial:
    """Stress tests DifferentialTester for process group cleanup with deeply nested trees."""

    def test_multi_tier_process_tree_killed_on_timeout(self) -> None:
        """
        Verify that a multi-tier process hierarchy:
        Parent -> Child -> Grandchild -> Great-Grandchild
        is completely terminated by os.killpg on timeout. No process survives.
        """
        marker = f"adv_tree_{int(time.time() * 1000)}"
        pid_dir = Path(tempfile.mkdtemp(prefix=f"pids_{marker}_"))

        # C code that forks 3 levels deep: parent forks child, child forks grandchild,
        # grandchild forks great-grandchild. All write their PIDs to pid_dir and sleep.
        c_source = f"""
        #include <unistd.h>
        #include <stdio.h>
        #include <stdlib.h>

        void record_pid(const char* name) {{
            char path[256];
            snprintf(path, sizeof(path), "{pid_dir}/%s.pid", name);
            FILE* f = fopen(path, "w");
            if (f) {{
                fprintf(f, "%d\\n", (int)getpid());
                fflush(f);
                fclose(f);
            }}
        }}

        int main() {{
            record_pid("parent");
            pid_t p1 = fork();
            if (p1 == 0) {{
                record_pid("child");
                pid_t p2 = fork();
                if (p2 == 0) {{
                    record_pid("grandchild");
                    pid_t p3 = fork();
                    if (p3 == 0) {{
                        record_pid("great_grandchild");
                        while (1) {{ sleep(1); }}
                    }}
                    while (1) {{ sleep(1); }}
                }}
                while (1) {{ sleep(1); }}
            }}
            while (1) {{ sleep(1); }}
            return 0;
        }}
        """
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(c_source)
            c_file = f.name
        bin_file = c_file.replace(".c", "")

        try:
            subprocess.run(["clang", c_file, "-o", bin_file], check=True)
            tester = DifferentialTester(timeout_seconds=2.0)

            rc, out, err, is_to = tester.run_single_vector([bin_file], {}, timeout_sec=2.0)
            assert is_to is True
            assert rc == -124

            # Read all recorded PIDs
            time.sleep(0.3)
            pids = []
            for name in ["parent", "child", "grandchild", "great_grandchild"]:
                p_file = pid_dir / f"{name}.pid"
                assert p_file.exists(), f"Process {name} failed to write its PID"
                with open(p_file) as pf:
                    pids.append(int(pf.read().strip()))

            assert len(pids) == 4

            # Check that every single process in the tree is DEAD
            alive_pids = []
            for pid in pids:
                try:
                    os.kill(pid, 0)
                    alive_pids.append(pid)
                except ProcessLookupError:
                    pass

            try:
                assert len(alive_pids) == 0, f"Leaked processes detected: {alive_pids}"
            finally:
                for pid in alive_pids:
                    with contextlib.suppress(Exception):
                        os.kill(pid, signal.SIGKILL)
        finally:
            for p in (c_file, bin_file):
                if os.path.exists(p):
                    os.remove(p)
            for pid_f in pid_dir.glob("*.pid"):
                pid_f.unlink()
            pid_dir.rmdir()

    def test_sigterm_ignoring_children_killed_by_sigkill(self) -> None:
        """
        Verify that children attempting to ignore signals (e.g. signal(SIGTERM, SIG_IGN))
        are terminated because os.killpg delivers SIGKILL.
        """
        marker = f"adv_sig_{int(time.time() * 1000)}"
        pid_file = Path(f"/tmp/sig_ign_{marker}.pid")

        c_source = f"""
        #include <unistd.h>
        #include <signal.h>
        #include <stdio.h>

        int main() {{
            signal(SIGTERM, SIG_IGN);
            signal(SIGINT, SIG_IGN);
            signal(SIGHUP, SIG_IGN);

            pid_t p = fork();
            if (p == 0) {{
                signal(SIGTERM, SIG_IGN);
                FILE* f = fopen("{pid_file}", "w");
                if (f) {{
                    fprintf(f, "%d\\n", (int)getpid());
                    fflush(f);
                    fclose(f);
                }}
                while (1) {{ sleep(1); }}
            }}
            while (1) {{ sleep(1); }}
            return 0;
        }}
        """
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(c_source)
            c_file = f.name
        bin_file = c_file.replace(".c", "")

        try:
            subprocess.run(["clang", c_file, "-o", bin_file], check=True)
            tester = DifferentialTester(timeout_seconds=2.0)

            rc, out, err, is_to = tester.run_single_vector([bin_file], {}, timeout_sec=2.0)
            assert is_to is True
            assert rc == -124

            time.sleep(0.3)
            assert pid_file.exists()
            with open(pid_file) as pf:
                child_pid = int(pf.read().strip())

            # Verify child process was killed by SIGKILL
            is_alive = False
            try:
                os.kill(child_pid, 0)
                is_alive = True
            except ProcessLookupError:
                is_alive = False

            try:
                assert is_alive is False, f"Child process {child_pid} survived SIGKILL"
            finally:
                if is_alive:
                    with contextlib.suppress(Exception):
                        os.kill(child_pid, signal.SIGKILL)
        finally:
            for p in (c_file, bin_file, pid_file):
                if os.path.exists(p):
                    os.remove(p)


# ============================================================================
# Dimension 2: Hex Address Normalization & ASLR Differential Equivalence
# ============================================================================

class TestHexAddressNormalizationAdversarial:
    """Stress tests pointer address masking across architectures, representations, and contexts."""

    @pytest.mark.parametrize(
        "addr_str",
        [
            "0x7ffee1b2c3d0",       # Standard 64-bit stack address (12 hex digits)
            "0x1000004b0",          # Standard Mach-O text address (9 hex digits)
            "0x00401000",           # Standard 32-bit ELF text address (8 hex digits)
            "0x00007ffff7a12345",   # 16-hex-digit zero-padded address
            "0x1234",               # 4-hex-digit short offset
            "0xDEADBEEFCAFE",       # Uppercase hex
            "0x7f9a1c002000",       # Heap mmap address
        ],
    )
    def test_hex_address_patterns_normalized_to_token(self, addr_str: str) -> None:
        """Verify varied hex address patterns are replaced with <HEX_ADDR>."""
        tester = DifferentialTester()
        text = f"Pointer returned at: {addr_str}\n"
        norm = tester.normalize_output(text)
        assert "<HEX_ADDR>" in norm
        assert addr_str not in norm
        assert norm == "Pointer returned at: <HEX_ADDR>\n"

    def test_addresses_in_complex_contexts(self) -> None:
        """Verify addresses enclosed in brackets, quotes, or key-value pairs are masked."""
        tester = DifferentialTester()
        text = (
            "Allocated: [0x7ffee1b2c3d0], mapped=(0x1000004b0), "
            "base='0x00401000', next=<0x7f9a1c002000>, end:0xDEADBEEF\n"
        )
        norm = tester.normalize_output(text)
        expected = (
            "Allocated: [<HEX_ADDR>], mapped=(<HEX_ADDR>), "
            "base='<HEX_ADDR>', next=<<HEX_ADDR>>, end:<HEX_ADDR>\n"
        )
        assert norm == expected

    def test_end_to_end_aslr_differential_test_passes(self) -> None:
        """
        Empirical differential test: Two compilations of code printing heap pointer %p.
        Due to ASLR/heap variance, outputs differ in address, but normalized differential test passes!
        """
        c_source = """
        #include <stdio.h>
        #include <stdlib.h>
        int main() {
            void* p = malloc(1024);
            printf("Allocated block at %p, size=1024\\n", p);
            free(p);
            return 0;
        }
        """
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(c_source)
            src_file = f.name
        bin1 = src_file.replace(".c", "_bin1")
        bin2 = src_file.replace(".c", "_bin2")

        try:
            subprocess.run(["clang", "-O2", src_file, "-o", bin1], check=True)
            subprocess.run(["clang", "-O2", src_file, "-o", bin2], check=True)

            tester = DifferentialTester()
            diff_result = tester.run_differential_test(
                session_id="test_aslr_sess",
                original_path=bin1,
                reconstructed_path=bin2,
                test_vectors=[{"vector_id": "V_ASLR"}],
            )
            assert diff_result.all_passed is True
            assert diff_result.passed_vectors == 1
            assert diff_result.total_vectors == 1
            assert diff_result.vector_results[0].passed is True

            # In strict mode (no sanitizers), if addresses differed, strict mode fails
            strict_tester = DifferentialTester(strict_mode=True)
            _rc1, out1, _e1, _ = strict_tester.run_single_vector([bin1], {})
            _rc2, out2, _e2, _ = strict_tester.run_single_vector([bin2], {})
            # Normalized with normal tester should match
            assert tester.normalize_output(out1) == tester.normalize_output(out2)
        finally:
            for p in (src_file, bin1, bin2):
                if os.path.exists(p):
                    os.remove(p)


# ============================================================================
# Dimension 3: Whitespace & Line Ending Normalization
# ============================================================================

class TestWhitespaceNormalizationAdversarial:
    """Stress tests whitespace, tab, and newline normalization."""

    def test_trailing_spaces_and_tabs_matrix(self) -> None:
        """Ensure trailing spaces, tabs, and mixed whitespace on every line are trimmed."""
        tester = DifferentialTester()

        unclean = "Line 1   \nLine 2\t\t\nLine 3 \t \n\n"
        clean = "Line 1\nLine 2\nLine 3\n\n"

        assert tester.normalize_output(unclean) == clean

    def test_empty_lines_with_whitespace_collapse(self) -> None:
        """Lines containing only spaces or tabs become clean empty lines."""
        tester = DifferentialTester()

        unclean = "Header\n   \n\t\t\nFooter\n"
        clean = "Header\n\n\nFooter\n"

        assert tester.normalize_output(unclean) == clean

    def test_crlf_with_trailing_spaces(self) -> None:
        """CRLF line endings combined with trailing spaces normalize to clean LF."""
        tester = DifferentialTester()

        crlf_unclean = "First Line   \r\nSecond Line\t \r\n"
        lf_clean = "First Line\nSecond Line\n"

        assert tester.normalize_output(crlf_unclean) == lf_clean

    def test_differential_whitespace_tolerance(self) -> None:
        """
        Differential test between a binary with trailing spaces and one without
        succeeds due to normalize_output.
        """
        c1 = """#include <stdio.h>\nint main() { printf("Status: OK   \\nCount: 5  \\n"); return 0; }\n"""
        c2 = """#include <stdio.h>\nint main() { printf("Status: OK\\nCount: 5\\n"); return 0; }\n"""

        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f1:
            f1.write(c1)
            s1 = f1.name
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f2:
            f2.write(c2)
            s2 = f2.name

        b1 = s1.replace(".c", "")
        b2 = s2.replace(".c", "")

        try:
            subprocess.run(["clang", s1, "-o", b1], check=True)
            subprocess.run(["clang", s2, "-o", b2], check=True)

            tester = DifferentialTester()
            res = tester.run_differential_test(
                session_id="ws_sess",
                original_path=b1,
                reconstructed_path=b2,
                test_vectors=[{"vector_id": "V_WS"}],
            )
            assert res.all_passed is True
            assert res.passed_vectors == 1
        finally:
            for p in (s1, s2, b1, b2):
                if os.path.exists(p):
                    os.remove(p)


# ============================================================================
# Dimension 4: Synthetic Prelude Resilience & Header Idempotence
# ============================================================================

class TestSyntheticPreludeResilienceAdversarial:
    """Stress tests synthetic prelude injection against partial headers and stdint/stdbool."""

    def test_stdio_stdlib_with_all_prelude_types_compiles(self) -> None:
        """
        CRITICAL DEFECT VERIFICATION:
        Source has ONLY <stdio.h> and <stdlib.h>, but uses:
        uint8_t, uint16_t, uint32_t, uint64_t, bool, size_t, assert, memset, errno, sqrt.
        Must compile cleanly and run.
        """
        source = """
        #include <stdio.h>
        #include <stdlib.h>

        int main() {
            uint8_t u8 = 8;
            uint16_t u16 = 16;
            uint32_t u32 = 32;
            uint64_t u64 = 64;
            bool flag = true;
            size_t sz = sizeof(u64);

            char buf[32];
            memset(buf, 0, sizeof(buf));
            snprintf(buf, sizeof(buf), "ok");

            assert(flag && sz == 8);
            errno = 0;
            double root = sqrt(16.0);

            printf("%s: %u %u %u %llu (root=%.0f)\\n",
                   buf, (unsigned)u8, (unsigned)u16, (unsigned)u32,
                   (unsigned long long)u64, root);
            return 0;
        }
        """
        sandbox = RecompilationSandbox()
        try:
            out = sandbox.compile(source=source, compiler="clang", auto_prelude=True)
            assert out.success is True, f"Compilation failed: {out.compile_errors_summary}"
            assert out.binary_path is not None
            assert out.binary_path.exists()

            # Execute produced binary
            res = subprocess.run([str(out.binary_path)], capture_output=True, text=True, check=True)
            assert "ok: 8 16 32 64 (root=4)" in res.stdout
        finally:
            sandbox.cleanup()

    def test_prelude_idempotence_when_already_included(self) -> None:
        """
        If source already includes METIS_C_PRELUDE, auto_prelude does NOT duplicate it.
        """
        source = METIS_C_PRELUDE + """
        int main() {
            uint32_t a = 10;
            bool b = false;
            printf("val=%u bool=%d\\n", a, (int)b);
            return 0;
        }
        """
        sandbox = RecompilationSandbox()
        try:
            out = sandbox.compile(source=source, compiler="clang", auto_prelude=True)
            assert out.success is True
            assert out.binary_path is not None
        finally:
            sandbox.cleanup()

    def test_auto_prelude_false_omits_prelude(self) -> None:
        """
        When auto_prelude=False, missing headers causes expected compilation failure.
        """
        source = """
        int main() {
            uint32_t a = 10;
            bool b = true;
            return 0;
        }
        """
        sandbox = RecompilationSandbox()
        try:
            out = sandbox.compile(source=source, compiler="clang", auto_prelude=False)
            assert out.success is False
            assert any("uint32_t" in d.message or "bool" in d.message for d in out.diagnostics)
        finally:
            sandbox.cleanup()


# ============================================================================
# Dimension 5: Non-UTF-8 Binary Streams & Raw Bytes
# ============================================================================

class TestNonUtf8BinaryStreamsAdversarial:
    """Stress tests raw non-UTF-8 binary output handling on stdout and stderr."""

    def test_full_byte_spectrum_stdout_no_unicode_decode_error(self) -> None:
        """
        Binary writes all 256 byte values (0x00 to 0xFF) to stdout.
        DifferentialTester must return exit_code 0 without UnicodeDecodeError.
        """
        c_source = """
        #include <stdio.h>
        int main() {
            unsigned char spectrum[256];
            for (int i = 0; i < 256; i++) {
                spectrum[i] = (unsigned char)i;
            }
            fwrite(spectrum, 1, 256, stdout);
            return 0;
        }
        """
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(c_source)
            src_file = f.name
        bin_file = src_file.replace(".c", "")

        try:
            subprocess.run(["clang", src_file, "-o", bin_file], check=True)
            tester = DifferentialTester()

            rc, out, err, is_to = tester.run_single_vector([bin_file], {})
            assert rc == 0
            assert is_to is False
            assert err == ""
            # Output was safely replaced with unicode replacement chars without crashing
            assert len(out) > 0
        finally:
            for p in (src_file, bin_file):
                if os.path.exists(p):
                    os.remove(p)

    def test_raw_bytes_on_stderr_no_crash(self) -> None:
        """
        Binary writes invalid UTF-8 bytes (0x80 - 0xFF) to stderr.
        DifferentialTester must capture stderr without raising UnicodeDecodeError.
        """
        c_source = """
        #include <stdio.h>
        int main() {
            unsigned char bad_bytes[] = {0xC0, 0xAF, 0x80, 0xFF, '\\n'};
            fwrite(bad_bytes, 1, sizeof(bad_bytes), stderr);
            return 42;
        }
        """
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(c_source)
            src_file = f.name
        bin_file = src_file.replace(".c", "")

        try:
            subprocess.run(["clang", src_file, "-o", bin_file], check=True)
            tester = DifferentialTester()

            rc, out, err, is_to = tester.run_single_vector([bin_file], {})
            assert rc == 42
            assert is_to is False
            assert len(err) > 0
        finally:
            for p in (src_file, bin_file):
                if os.path.exists(p):
                    os.remove(p)

    def test_binary_stream_differential_test_passes(self) -> None:
        """
        Differential test comparing two binaries both outputting identical non-UTF-8 bytes
        succeeds with 100% equivalence.
        """
        c_source = """
        #include <stdio.h>
        int main() {
            unsigned char data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x80, 0xFF, 'A', 'B', '\\n'};
            fwrite(data, 1, sizeof(data), stdout);
            return 0;
        }
        """
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
            f.write(c_source)
            src_file = f.name
        bin1 = src_file.replace(".c", "_b1")
        bin2 = src_file.replace(".c", "_b2")

        try:
            subprocess.run(["clang", src_file, "-o", bin1], check=True)
            subprocess.run(["clang", src_file, "-o", bin2], check=True)

            tester = DifferentialTester()
            res = tester.run_differential_test(
                session_id="bin_stream_sess",
                original_path=bin1,
                reconstructed_path=bin2,
                test_vectors=[{"vector_id": "V_BYTES"}],
            )
            assert res.all_passed is True
            assert res.passed_vectors == 1
            assert res.vector_results[0].passed is True
        finally:
            for p in (src_file, bin1, bin2):
                if os.path.exists(p):
                    os.remove(p)
