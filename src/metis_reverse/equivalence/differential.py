"""
Metis Reverse - Black-Box Differential Testing Harness
Executes multi-vector differential testing between original binaries and reconstructed code
comparing exit codes, standard output, and standard error under subprocess isolation.
"""

from __future__ import annotations

import contextlib
import difflib
import logging
import os
import re
import signal
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

from metis_reverse.core.models import (
    DifferentialResult,
    DifferentialVectorResult,
)

logger = logging.getLogger("metis_reverse.equivalence.differential")

# Default regex patterns for sanitizing non-deterministic runtime outputs
DEFAULT_SANITIZERS: list[tuple[str, str]] = [
    (r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b", "<TIMESTAMP>"),
    (r"\b(?:pid|PID|process)\s*[:=]?\s*\d+\b", "<PID>"),
    (r"/tmp/metis_[a-zA-Z0-9_]+", "<TEMP_DIR>"),
    (r"\b0x[0-9a-fA-F]{4,16}\b", "<HEX_ADDR>"),
]


class DifferentialTester:
    """
    Subprocess-isolated differential testing runner comparing exit codes,
    stdout, and stderr across multiple test vectors.
    """

    def __init__(
        self,
        timeout_seconds: float = 5.0,
        strict_mode: bool = False,
        custom_sanitizers: list[tuple[str, str]] | None = None,
    ) -> None:
        self.default_timeout = timeout_seconds
        self.strict_mode = strict_mode
        self.sanitizers = custom_sanitizers if custom_sanitizers is not None else DEFAULT_SANITIZERS

    @staticmethod
    def _resolve_command(target_path: str | Path) -> list[str]:
        """Resolve executable invocation prefix based on target file format."""
        path = Path(target_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Target binary or script not found: {path}")

        path_str = str(path)
        if path_str.endswith(".js"):
            return ["node", path_str]
        elif path_str.endswith(".py"):
            return [sys.executable, path_str]

        # Ensure executable bit is set on native binaries
        try:
            current_mode = os.stat(path_str).st_mode
            if not (current_mode & stat.S_IXUSR):
                os.chmod(path_str, current_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        except Exception as e:
            logger.warning("Could not set executable permissions on %s: %s", path_str, e)

        return [path_str]

    def normalize_output(self, text: str, extra_pattern: str | None = None) -> str:
        """Normalize line endings and mask non-deterministic variance."""
        if not text:
            return ""

        # Normalize CRLF -> LF and strip trailing whitespace per line
        normalized = "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").splitlines())
        if text.endswith(("\r\n", "\n")):
            normalized += "\n"

        if self.strict_mode:
            return normalized

        for pattern, replacement in self.sanitizers:
            normalized = re.sub(pattern, replacement, normalized)

        if extra_pattern:
            normalized = re.sub(extra_pattern, "<MASKED>", normalized)

        return normalized

    def run_single_vector(
        self,
        cmd_prefix: list[str],
        vector: dict[str, Any],
        timeout_sec: float | None = None,
    ) -> tuple[int, str, str, bool]:
        """
        Execute a target command with vector inputs in an isolated subprocess.
        Returns: (exit_code, stdout, stderr, is_timeout)
        """
        cli_args = vector.get("cli_args", [])
        stdin_data = vector.get("stdin_data", "")
        env_vars = vector.get("env_vars", {})
        timeout = timeout_sec or self.default_timeout

        # Isolated environment
        env = os.environ.copy()
        env["LANG"] = "C"
        env["LC_ALL"] = "C"
        env["TERM"] = "dumb"
        env["PYTHONUNBUFFERED"] = "1"
        if env_vars:
            env.update({str(k): str(v) for k, v in env_vars.items()})

        full_cmd = cmd_prefix + [str(a) for a in cli_args]

        proc = None
        try:
            proc = subprocess.Popen(
                full_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                env=env,
                start_new_session=True,
            )
            stdout, stderr = proc.communicate(
                input=stdin_data if stdin_data is not None else "",
                timeout=timeout,
            )
            return proc.returncode, stdout or "", stderr or "", False
        except subprocess.TimeoutExpired:
            logger.warning("Command %s timed out after %s seconds", full_cmd, timeout)
            if proc is not None:
                with contextlib.suppress(Exception):
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                with contextlib.suppress(Exception):
                    proc.kill()
                with contextlib.suppress(Exception):
                    proc.wait()
            return -124, "", f"Execution timed out after {timeout} seconds", True
        except Exception as e:
            logger.error("Failed to execute %s: %s", full_cmd, e)
            if proc is not None:
                with contextlib.suppress(Exception):
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                with contextlib.suppress(Exception):
                    proc.kill()
                with contextlib.suppress(Exception):
                    proc.wait()
            return -1, "", f"Execution error: {e}", False

    def run_differential_test(
        self,
        session_id: str,
        original_path: str,
        reconstructed_path: str,
        test_vectors: list[dict[str, Any]],
        timeout_sec: float | None = None,
        sanitize_pattern: str | None = None,
    ) -> DifferentialResult:
        """
        Run black-box differential comparison between original and reconstructed binaries.
        """
        orig_cmd = self._resolve_command(original_path)
        rec_cmd = self._resolve_command(reconstructed_path)

        vector_results: list[DifferentialVectorResult] = []
        passed_count = 0

        for i, vec in enumerate(test_vectors):
            vname = vec.get("vector_id") or vec.get("vector_name") or f"vector_{i+1}"

            orig_rc, orig_out, orig_err, _orig_to = self.run_single_vector(orig_cmd, vec, timeout_sec)
            rec_rc, rec_out, rec_err, rec_to = self.run_single_vector(rec_cmd, vec, timeout_sec)

            norm_orig_out = self.normalize_output(orig_out, sanitize_pattern)
            norm_rec_out = self.normalize_output(rec_out, sanitize_pattern)
            norm_orig_err = self.normalize_output(orig_err, sanitize_pattern)
            norm_rec_err = self.normalize_output(rec_err, sanitize_pattern)

            rc_match = (orig_rc == rec_rc)
            out_match = (norm_orig_out == norm_rec_out)
            err_match = (norm_orig_err == norm_rec_err)
            passed = rc_match and out_match and err_match and not rec_to

            diff_details: str | None = None
            if not passed:
                diff_parts: list[str] = []
                if rec_to:
                    diff_parts.append(
                        f"Reconstructed execution timed out after {timeout_sec or self.default_timeout}s.\n"
                    )
                if not rc_match:
                    diff_parts.append(f"Exit code mismatch: original={orig_rc}, reconstructed={rec_rc}\n")
                if not out_match:
                    diff_parts.append("--- original_stdout\n+++ reconstructed_stdout\n")
                    diff_parts.extend(
                        difflib.unified_diff(
                            norm_orig_out.splitlines(keepends=True),
                            norm_rec_out.splitlines(keepends=True),
                            fromfile="original_stdout",
                            tofile="reconstructed_stdout",
                        )
                    )
                if not err_match:
                    diff_parts.append("--- original_stderr\n+++ reconstructed_stderr\n")
                    diff_parts.extend(
                        difflib.unified_diff(
                            norm_orig_err.splitlines(keepends=True),
                            norm_rec_err.splitlines(keepends=True),
                            fromfile="original_stderr",
                            tofile="reconstructed_stderr",
                        )
                    )
                diff_details = "".join(diff_parts) if diff_parts else "Unknown mismatch"
            else:
                passed_count += 1

            vector_results.append(
                DifferentialVectorResult(
                    vector_name=vname,
                    passed=passed,
                    original_exit_code=orig_rc,
                    reconstructed_exit_code=rec_rc,
                    original_stdout=orig_out,
                    reconstructed_stdout=rec_out,
                    original_stderr=orig_err,
                    reconstructed_stderr=rec_err,
                    diff_details=diff_details,
                    vector_id=vname,
                )
            )

        total = len(test_vectors)
        pct = (passed_count / total * 100.0) if total > 0 else 0.0

        return DifferentialResult(
            session_id=session_id,
            all_passed=(passed_count == total and total > 0),
            total_vectors=total,
            passed_vectors=passed_count,
            equivalence_percentage=pct,
            vector_results=vector_results,
        )

    def compare(
        self,
        original_path: str,
        reconstructed_path: str,
        vectors: list[dict[str, Any]],
        timeout_sec: float | None = None,
    ) -> dict[str, Any]:
        """Convenience method returning summary dict for compatibility with benchmark harness."""
        res = self.run_differential_test(
            session_id="comparison",
            original_path=original_path,
            reconstructed_path=reconstructed_path,
            test_vectors=vectors,
            timeout_sec=timeout_sec,
        )
        return {
            "all_passed": res.all_passed,
            "total_vectors": res.total_vectors,
            "passed_vectors": res.passed_vectors,
            "equivalence_percentage": res.equivalence_percentage,
            "vector_results": [
                {
                    "vector_name": v.vector_name,
                    "passed": v.passed,
                    "original_exit_code": v.original_exit_code,
                    "reconstructed_exit_code": v.reconstructed_exit_code,
                    "diff_details": v.diff_details,
                }
                for v in res.vector_results
            ],
        }
