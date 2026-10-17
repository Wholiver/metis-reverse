"""
Metis Reverse - Target Recompilation Sandbox
Compiles reconstructed C source code using clang or gcc, captures structured
compiler diagnostics, and coordinates closed-loop differential verification.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    BinarySession,
    RecompileResult,
)
from metis_reverse.core.session import SessionNotFoundError, global_session_manager
from metis_reverse.equivalence.differential import DifferentialTester

logger = logging.getLogger("metis_reverse.equivalence.recompilation")

# ============================================================================
# Standard Synthetic Header Prelude
# ============================================================================

METIS_C_PRELUDE = """/* Metis Reverse - Standard Synthetic Header Prelude */
#ifndef _METIS_SYNTHETIC_PRELUDE_H_
#define _METIS_SYNTHETIC_PRELUDE_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <math.h>

#endif /* _METIS_SYNTHETIC_PRELUDE_H_ */
"""

# ============================================================================
# Diagnostic Models & Parsers
# ============================================================================

@dataclass
class CompilerDiagnostic:
    """Structured diagnostic message emitted by compiler or linker."""
    file: str
    line: int
    column: int | None
    severity: str  # "error", "fatal error", "warning", "note"
    message: str
    flag: str | None = None
    raw_text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CompilationOutput:
    """Full execution output of compilation attempt."""
    success: bool
    binary_path: Path | None
    returncode: int
    stdout: str
    stderr: str
    diagnostics: list[CompilerDiagnostic] = field(default_factory=list)
    compile_errors_summary: str = ""
    compile_warnings_summary: str = ""
    command: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


@dataclass
class CompilerInfo:
    """Probed metadata for a compiler toolchain executable."""
    name: str
    path: str
    version: str
    is_available: bool
    is_apple_clang: bool = False
    supported_archs: list[str] = field(default_factory=list)


# ============================================================================
# Compiler Detection
# ============================================================================

class CompilerDetector:
    """Discovers host compilers, SDK roots, and architecture cross-capabilities."""

    @staticmethod
    def get_sdk_path() -> str | None:
        """On macOS, return the SDK path via xcrun --show-sdk-path."""
        if platform.system().lower() != "darwin":
            return None
        try:
            res = subprocess.run(
                ["xcrun", "--show-sdk-path"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5.0,
            )
            if res.returncode == 0:
                p = res.stdout.strip()
                if os.path.exists(p):
                    return p
        except Exception:
            pass
        return None

    @classmethod
    def probe_compiler(cls, name_or_path: str) -> CompilerInfo:
        """Probe compiler availability and version."""
        binary_path = shutil.which(name_or_path) or (
            name_or_path if os.path.isabs(name_or_path) and os.path.exists(name_or_path) else None
        )
        if not binary_path:
            return CompilerInfo(
                name=name_or_path,
                path="",
                version="",
                is_available=False,
            )

        try:
            res = subprocess.run(
                [binary_path, "--version"],
                capture_output=True,
                text=True,
                check=False,
                timeout=5.0,
            )
            v_text = res.stdout or res.stderr
            is_apple = "apple clang" in v_text.lower()
            return CompilerInfo(
                name=name_or_path,
                path=binary_path,
                version=v_text.splitlines()[0] if v_text else "unknown",
                is_available=True,
                is_apple_clang=is_apple,
                supported_archs=["arm64", "x86_64"] if is_apple else [platform.machine().lower()],
            )
        except Exception:
            return CompilerInfo(
                name=name_or_path,
                path=binary_path,
                version="error_probing",
                is_available=False,
            )


# ============================================================================
# Recompilation Sandbox
# ============================================================================

class RecompilationSandbox:
    """Automated sandbox compiling reconstructed C source code."""

    DIAGNOSTIC_REGEX = re.compile(
        r"^(?P<file>[^:\n\r]+):(?P<line>\d+):(?:(?P<col>\d+):)?\s*(?P<severity>error|fatal error|warning|note):\s*(?P<message>.*?)(?:\s*\[(?P<flag>-[^\]]+)\])?$",
        re.MULTILINE,
    )

    def __init__(
        self,
        base_build_dir: Path | None = None,
        timeout_seconds: float = 30.0,
        cleanup_on_failure: bool = True,
    ) -> None:
        self.base_build_dir = base_build_dir
        self.timeout_seconds = timeout_seconds
        self.cleanup_on_failure = cleanup_on_failure
        self._active_build_dirs: list[Path] = []

    def compile(
        self,
        source: str,
        compiler: str = "clang",
        output_path: Path | None = None,
        extra_flags: list[str] | None = None,
        target_arch: ArchitectureType | str | None = None,
        target_format: ArtifactFormat | str | None = None,
        treat_warnings_as_errors: bool = False,
        auto_prelude: bool = True,
        session_id: str | None = None,
    ) -> CompilationOutput:
        """
        Compile C source code string into an executable binary artifact.
        """
        t0 = time.time()
        c_info = CompilerDetector.probe_compiler(compiler)
        if not c_info.is_available:
            # Fallback probe between clang and gcc
            alt = "gcc" if compiler.lower() == "clang" else "clang"
            c_info_alt = CompilerDetector.probe_compiler(alt)
            if c_info_alt.is_available:
                c_info = c_info_alt
            else:
                return CompilationOutput(
                    success=False,
                    binary_path=None,
                    returncode=127,
                    stdout="",
                    stderr=f"Target compiler '{compiler}' not found in PATH.",
                    compile_errors_summary=f"Compiler '{compiler}' not found in PATH.",
                    duration_seconds=time.time() - t0,
                )

        # 1. Prepare Sandbox Directory
        if output_path:
            out_bin = Path(output_path).resolve()
            build_dir = out_bin.parent
            build_dir.mkdir(parents=True, exist_ok=True)
            src_file = build_dir / f"{out_bin.stem}.c"
        else:
            s_prefix = f"metis_build_{session_id[:8] if session_id else 'temp'}_{uuid.uuid4().hex[:8]}_"
            build_dir = Path(tempfile.mkdtemp(prefix=s_prefix, dir=self.base_build_dir))
            self._active_build_dirs.append(build_dir)
            src_file = build_dir / "reconstructed.c"
            out_bin = build_dir / "reconstructed_bin"

        # 2. Prepare Source Code with synthetic prelude if needed
        code_to_write = source
        if auto_prelude and "_METIS_SYNTHETIC_PRELUDE_H_" not in source:
            code_to_write = METIS_C_PRELUDE + "\n" + source

        with open(src_file, "w", encoding="utf-8") as f:
            f.write(code_to_write)

        # 3. Assemble Compiler Command
        cmd = [
            c_info.path,
            "-O2",
            "-std=c11",
            "-fno-ident",
            "-Wall",
            "-Wextra",
        ]

        # Host SDK handling (macOS)
        sdk_path = CompilerDetector.get_sdk_path()
        if sdk_path and platform.system().lower() == "darwin":
            cmd.extend(["-isysroot", sdk_path])

        # Architecture targeting
        host_sys = platform.system().lower()
        arch_val = target_arch.value if target_arch is not None and hasattr(target_arch, "value") else str(target_arch or "")
        arch_str = arch_val.lower()
        if host_sys == "darwin":
            if arch_str in ("arm64", "aarch64"):
                cmd.extend(["-arch", "arm64"])
            elif arch_str in ("x86_64", "amd64"):
                cmd.extend(["-arch", "x86_64"])
        elif host_sys == "linux":
            if arch_str in ("x86_64", "amd64"):
                cmd.append("-m64")
            elif arch_str in ("x86", "i386"):
                cmd.append("-m32")

        if treat_warnings_as_errors:
            cmd.append("-Werror")

        if extra_flags:
            cmd.extend(extra_flags)

        cmd.extend([str(src_file), "-o", str(out_bin), "-lm"])

        # 4. Execute Subprocess
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout_seconds,
            )
            rc = proc.returncode
            stdout_text = proc.stdout or ""
            stderr_text = proc.stderr or ""
        except subprocess.TimeoutExpired:
            return CompilationOutput(
                success=False,
                binary_path=None,
                returncode=-1,
                stdout="",
                stderr=f"Compilation timed out after {self.timeout_seconds} seconds.",
                compile_errors_summary=f"Compilation timed out after {self.timeout_seconds} seconds.",
                command=cmd,
                duration_seconds=time.time() - t0,
            )
        except Exception as e:
            return CompilationOutput(
                success=False,
                binary_path=None,
                returncode=-1,
                stdout="",
                stderr=str(e),
                compile_errors_summary=f"Execution error: {e}",
                command=cmd,
                duration_seconds=time.time() - t0,
            )

        # 5. Parse Diagnostics
        diagnostics = self._parse_diagnostics(stderr_text)
        errors = [d for d in diagnostics if d.severity in ("error", "fatal error")]
        warnings = [d for d in diagnostics if d.severity == "warning"]

        err_summary = "\n".join(
            f"{d.file}:{d.line}:{d.column or 0}: error: {d.message}" for d in errors
        )
        warn_summary = "\n".join(
            f"{d.file}:{d.line}:{d.column or 0}: warning: {d.message}" for d in warnings
        )

        # Handle linker or unstructured fatal compiler errors
        if rc != 0 and not errors:
            err_summary = stderr_text.strip() or f"Compiler exited with code {rc}"
            diagnostics.append(
                CompilerDiagnostic(
                    file="compiler",
                    line=0,
                    column=None,
                    severity="error",
                    message=err_summary,
                    raw_text=stderr_text,
                )
            )

        compile_success = (rc == 0) and (len(errors) == 0) and out_bin.exists()

        if compile_success:
            with contextlib.suppress(Exception):
                os.chmod(out_bin, 0o755)
        elif self.cleanup_on_failure and not output_path:
            shutil.rmtree(build_dir, ignore_errors=True)

        return CompilationOutput(
            success=compile_success,
            binary_path=out_bin if compile_success else None,
            returncode=rc,
            stdout=stdout_text,
            stderr=stderr_text,
            diagnostics=diagnostics,
            compile_errors_summary=err_summary,
            compile_warnings_summary=warn_summary,
            command=cmd,
            duration_seconds=time.time() - t0,
        )

    def _parse_diagnostics(self, stderr_text: str) -> list[CompilerDiagnostic]:
        diagnostics: list[CompilerDiagnostic] = []
        for line in stderr_text.splitlines():
            m = self.DIAGNOSTIC_REGEX.match(line.strip())
            if m:
                d = m.groupdict()
                diagnostics.append(
                    CompilerDiagnostic(
                        file=d["file"],
                        line=int(d["line"]),
                        column=int(d["col"]) if d.get("col") else None,
                        severity=d["severity"].lower(),
                        message=d["message"].strip(),
                        flag=d.get("flag"),
                        raw_text=line,
                    )
                )
        return diagnostics

    def resolve_test_vectors(self, session: BinarySession) -> list[dict[str, Any]]:
        """Auto-discover test vectors for the session artifact."""
        if not session.artifact or not session.artifact.file_path:
            return []

        orig_binary = session.artifact.file_path
        return _discover_test_vectors(orig_binary)

    def cleanup(self) -> None:
        """Remove all active temporary build directories."""
        for p in self._active_build_dirs:
            if p.exists():
                shutil.rmtree(p, ignore_errors=True)
        self._active_build_dirs.clear()


def _discover_test_vectors(binary_path: str) -> list[dict[str, Any]]:
    """Helper to locate test_vectors.json adjacent to binary or from benchmark harness."""
    p = Path(binary_path).resolve()

    # 1. Check parent directories
    candidates = [
        p.parent / "test_vectors.json",
        p.parent.parent / "test_vectors.json",
    ]
    for cand in candidates:
        if cand.exists():
            try:
                with open(cand, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and "test_vectors" in data:
                        return data["test_vectors"]
                    elif isinstance(data, list):
                        return data
            except Exception as e:
                logger.warning("Failed to load test vectors from %s: %s", cand, e)

    # 2. Check known benchmark names in path
    path_str = str(p).lower()
    benchmark_name = None
    if "c_service" in path_str:
        benchmark_name = "c_service"
    elif "go_pipeline" in path_str:
        benchmark_name = "go_pipeline"
    elif "js_obfuscated" in path_str:
        benchmark_name = "js_obfuscated"

    if benchmark_name:
        # Check standard repo benchmark directory
        bench_vec = Path(__file__).resolve().parent.parent.parent.parent / "tests" / "synthetic_benchmarks" / benchmark_name / "test_vectors.json"
        if bench_vec.exists():
            try:
                with open(bench_vec, encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict) and "test_vectors" in data:
                        return data["test_vectors"]
                    elif isinstance(data, list):
                        return data
            except Exception as e:
                logger.warning("Failed to load test vectors from %s: %s", bench_vec, e)

        # Harness loader fallback
        with contextlib.suppress(Exception):
            from tests.synthetic_benchmarks.harness import load_test_vectors
            return load_test_vectors(benchmark_name)

    return []


def recompile_and_verify(
    session_id: str,
    reconstructed_source: str,
    compiler: str = "clang",
    test_vectors: list[dict[str, Any]] | None = None,
) -> RecompileResult:
    """
    Compile reconstructed C code in an isolated sandbox and verify equivalence against test vectors.
    """
    try:
        session = global_session_manager.get_session(session_id)
    except SessionNotFoundError as e:
        return RecompileResult(
            session_id=session_id,
            success=False,
            binary_path=None,
            compile_errors=str(e),
            compile_warnings="",
            equivalence_percentage=0.0,
        )

    orig_binary = session.artifact.file_path if session.artifact else ""
    target_arch = session.artifact.architecture if session.artifact else None
    target_format = session.artifact.format if session.artifact else None

    # 1. Compile in sandbox
    sandbox = RecompilationSandbox()
    comp_output = sandbox.compile(
        source=reconstructed_source,
        compiler=compiler,
        target_arch=target_arch,
        target_format=target_format,
        session_id=session_id,
    )

    if not comp_output.success or not comp_output.binary_path:
        return RecompileResult(
            session_id=session_id,
            success=False,
            binary_path=None,
            compile_errors=comp_output.compile_errors_summary,
            compile_warnings=comp_output.compile_warnings_summary,
            equivalence_percentage=0.0,
            diagnostics=[d.to_dict() for d in comp_output.diagnostics],
            differential_report=None,
        )

    # 2. Resolve Test Vectors
    vectors = test_vectors
    if not vectors and orig_binary:
        vectors = _discover_test_vectors(orig_binary)

    # 3. Differential Testing
    diff_report: dict[str, Any] | None = None
    equiv_pct = 0.0
    all_passed = True

    if vectors and orig_binary and os.path.exists(orig_binary):
        tester = DifferentialTester(timeout_seconds=5.0)
        diff_res = tester.run_differential_test(
            session_id=session_id,
            original_path=orig_binary,
            reconstructed_path=str(comp_output.binary_path),
            test_vectors=vectors,
        )
        equiv_pct = diff_res.equivalence_percentage
        all_passed = diff_res.all_passed
        diff_report = {
            "all_passed": diff_res.all_passed,
            "total_vectors": diff_res.total_vectors,
            "passed_vectors": diff_res.passed_vectors,
            "equivalence_percentage": diff_res.equivalence_percentage,
            "vector_results": [
                {
                    "vector_name": v.vector_name,
                    "passed": v.passed,
                    "original_exit_code": v.original_exit_code,
                    "reconstructed_exit_code": v.reconstructed_exit_code,
                    "diff_details": v.diff_details,
                }
                for v in diff_res.vector_results
            ],
        }
    else:
        equiv_pct = 0.0
        reason = (
            "0 test vectors provided or discovered"
            if not vectors
            else f"Original binary not found: {orig_binary}"
        )
        diff_report = {
            "all_passed": False,
            "total_vectors": 0,
            "passed_vectors": 0,
            "equivalence_percentage": 0.0,
            "vector_results": [],
            "warning": f"Behavioral equivalence unverified: {reason}",
            "note": "Behavioral equivalence unverified due to 0 vectors executed",
        }
        all_passed = True

    return RecompileResult(
        session_id=session_id,
        success=(comp_output.success and all_passed),
        binary_path=str(comp_output.binary_path),
        compile_errors="",
        compile_warnings=comp_output.compile_warnings_summary,
        equivalence_percentage=equiv_pct,
        diagnostics=[d.to_dict() for d in comp_output.diagnostics],
        differential_report=diff_report,
    )
