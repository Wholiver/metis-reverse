"""HypothesisSandbox: Safe execution sandbox for Agent reverse-engineering hypotheses.

Allows AI agents to test decryption routines, unmask obfuscated strings, and
validate API hash algorithms against actual memory slices extracted from binaries.
"""

import sys
import io
import time
import math
import zlib
import struct
import hashlib
import binascii
import traceback
import threading
import re
import json
import base64
from typing import Dict, Any, Optional, List

try:
    import capstone
except ImportError:
    capstone = None

try:
    import lief
except ImportError:
    lief = None

# Safe helper functions made available in the sandbox namespace
def ror(val: int, r: int, bits: int = 32) -> int:
    mask = (1 << bits) - 1
    val &= mask
    r %= bits
    return ((val >> r) | (val << (bits - r))) & mask

def rol(val: int, r: int, bits: int = 32) -> int:
    mask = (1 << bits) - 1
    val &= mask
    r %= bits
    return ((val << r) | (val >> (bits - r))) & mask

def safe_xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def safe_rc4(data: bytes, key: bytes) -> bytes:
    s = list(range(256))
    j = 0
    out = []
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    for char in data:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(char ^ s[(s[i] + s[j]) % 256])
    return bytes(out)

SAFE_BUILTINS = {
    "abs": abs,
    "all": all,
    "any": any,
    "bin": bin,
    "bool": bool,
    "bytearray": bytearray,
    "bytes": bytes,
    "chr": chr,
    "dict": dict,
    "divmod": divmod,
    "enumerate": enumerate,
    "filter": filter,
    "float": float,
    "format": format,
    "frozenset": frozenset,
    "hex": hex,
    "int": int,
    "isinstance": isinstance,
    "issubclass": issubclass,
    "iter": iter,
    "len": len,
    "list": list,
    "map": map,
    "max": max,
    "min": min,
    "next": next,
    "oct": oct,
    "ord": ord,
    "pow": pow,
    "print": print,
    "range": range,
    "repr": repr,
    "reversed": reversed,
    "round": round,
    "set": set,
    "slice": slice,
    "sorted": sorted,
    "str": str,
    "sum": sum,
    "tuple": tuple,
    "type": type,
    "zip": zip,
    "True": True,
    "False": False,
    "None": None,
    "Exception": Exception,
    "ValueError": ValueError,
    "TypeError": TypeError,
    "KeyError": KeyError,
    "IndexError": IndexError,
}

class HypothesisSandbox:
    """Executes agent-written hypothesis scripts in an isolated, restricted Python environment."""

    def __init__(self, timeout_seconds: float = 5.0):
        self.timeout_seconds = timeout_seconds

    def execute_script(
        self,
        script_code: str,
        memory_slice: bytes = b"",
        expected_output: Optional[str] = None,
        va: str = "N/A",
        custom_vars: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Runs the hypothesis verification script against memory_slice.
        
        The script should define a `verify()` function, or assign result to `result`.
        """
        start_time = time.time()
        stdout_capture = io.StringIO()

        # Build sandboxed globals
        sandbox_globals = {
            "__builtins__": SAFE_BUILTINS,
            "hashlib": hashlib,
            "struct": struct,
            "binascii": binascii,
            "zlib": zlib,
            "math": math,
            "re": re,
            "json": json,
            "base64": base64,
            "capstone": capstone,
            "lief": lief,
            # Injected helpers
            "ror": ror,
            "rol": rol,
            "safe_xor": safe_xor,
            "safe_rc4": safe_rc4,
            # Injected context data
            "memory_slice": memory_slice,
            "data": memory_slice,
            "va": va,
        }

        if custom_vars:
            sandbox_globals.update(custom_vars)

        execution_result = {
            "success": False,
            "returned_value": None,
            "stdout": "",
            "hypothesis_confirmed": False,
            "execution_time_ms": 0.0,
            "error": None,
            "va": va,
        }

        thread_exception = []
        thread_locals = {}

        def _runner():
            old_stdout = sys.stdout
            sys.stdout = stdout_capture
            try:
                exec(script_code, sandbox_globals, thread_locals)
                # If script defines a verify() or decrypt() callable, call it
                if "verify" in thread_locals and callable(thread_locals["verify"]):
                    thread_locals["result"] = thread_locals["verify"](memory_slice)
                elif "decrypt" in thread_locals and callable(thread_locals["decrypt"]):
                    thread_locals["result"] = thread_locals["decrypt"](memory_slice)
            except Exception as e:
                thread_exception.append((e, traceback.format_exc()))
            finally:
                sys.stdout = old_stdout

        worker = threading.Thread(target=_runner)
        worker.daemon = True
        worker.start()
        worker.join(self.timeout_seconds)

        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        execution_result["execution_time_ms"] = elapsed_ms
        execution_result["stdout"] = stdout_capture.getvalue()

        if worker.is_alive():
            execution_result["error"] = f"Execution timed out after {self.timeout_seconds}s (infinite loop guard triggered)"
            return execution_result

        if thread_exception:
            exc, tb = thread_exception[0]
            execution_result["error"] = f"{type(exc).__name__}: {str(exc)}"
            return execution_result

        # Extract returned result
        res = thread_locals.get("result", sandbox_globals.get("result"))
        execution_result["success"] = True
        
        # Format returned value
        if isinstance(res, bytes):
            try:
                decoded_str = res.decode("utf-8")
                execution_result["returned_value"] = decoded_str
                execution_result["returned_hex"] = res.hex()
            except UnicodeDecodeError:
                execution_result["returned_value"] = f"<bytes len={len(res)} hex={res[:64].hex()}...>"
                execution_result["returned_hex"] = res.hex()
        else:
            execution_result["returned_value"] = res

        # Check hypothesis confirmation with strict zero-padding and false-positive guards
        is_all_zeros = len(memory_slice) > 0 and all(b == 0 for b in memory_slice)
        if is_all_zeros:
            execution_result["warning"] = "Memory slice consists entirely of null bytes (0x00). Decryption or transformation result is an artifact of unmapped/zero-padded memory."

        if expected_output is not None:
            if is_all_zeros and expected_output not in ("\x00", "0", "00"):
                execution_result["hypothesis_confirmed"] = False
            else:
                val_str = str(execution_result["returned_value"])
                ret_hex = execution_result.get("returned_hex", "")
                execution_result["hypothesis_confirmed"] = bool(
                    expected_output and (expected_output in val_str or expected_output == ret_hex)
                )
        elif isinstance(res, bool):
            execution_result["hypothesis_confirmed"] = res and not is_all_zeros
        elif isinstance(res, dict) and ("confirmed" in res or "verified" in res):
            execution_result["hypothesis_confirmed"] = bool(res.get("confirmed", res.get("verified"))) and not is_all_zeros
        else:
            # When expected_output is not provided and script returns raw data,
            # do not automatically confirm without explicit assertions or verification criteria
            execution_result["hypothesis_confirmed"] = False
            if is_all_zeros:
                execution_result["hypothesis_note"] = "Target VA returned zero padding (0x00 bytes). Hypothesis cannot be confirmed."
            else:
                execution_result["hypothesis_note"] = "Script executed, but hypothesis confirmation requires either matching 'expected_output' or having verify() return a boolean True."

        return execution_result

    def execute_probe_script(
        self,
        script_code: str,
        read_file_func: Optional[Any] = None,
        read_mem_func: Optional[Any] = None,
        register_child_func: Optional[Any] = None,
        artifact_id: str = "root",
        custom_vars: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Runs custom structure probe script with binary access and child registration (Escape Hatch 1)."""
        start_time = time.time()
        stdout_capture = io.StringIO()
        registered_children: List[Dict[str, Any]] = []

        MAX_ARTIFACT_SIZE_BYTES = 50 * 1024 * 1024 # 50MB per R6

        def _safe_register(offset: int, length: int, data: bytes, name: str = "", description: str = ""):
            eff_len = length or len(data)
            if eff_len > MAX_ARTIFACT_SIZE_BYTES:
                raise ValueError(f"Artifact size ({eff_len} bytes) exceeds safety limit of 50MB (R6 DoS protection)")
            
            # Prevent path traversal in registered child artifact names
            if ".." in name or "/" in name or "\\" in name:
                raise ValueError("Artifact name cannot contain directory traversal characters ('..', '/', '\\')")

            info = {
                "offset": offset,
                "length": eff_len,
                "name": name,
                "description": description,
            }
            if register_child_func:
                node = register_child_func(offset, length, data, name, description)
                info["artifact_id"] = getattr(node, "id", None)
            registered_children.append(info)
            return info

        probe_globals = {
            "__builtins__": SAFE_BUILTINS,
            "hashlib": hashlib,
            "struct": struct,
            "binascii": binascii,
            "zlib": zlib,
            "math": math,
            "re": re,
            "json": json,
            "base64": base64,
            "capstone": capstone,
            "lief": lief,
            "ror": ror,
            "rol": rol,
            "safe_xor": safe_xor,
            "safe_rc4": safe_rc4,
            "artifact_id": artifact_id,
            "read_file_range": read_file_func or (lambda off, sz: b""),
            "read_memory": read_mem_func or (lambda va, sz: b""),
            "register_child": _safe_register,
        }
        if custom_vars:
            probe_globals.update(custom_vars)

        execution_result = {
            "success": False,
            "returned_value": None,
            "stdout": "",
            "registered_children": [],
            "execution_time_ms": 0.0,
            "error": None,
        }

        thread_exception = []
        thread_locals = {}

        def _runner():
            old_stdout = sys.stdout
            sys.stdout = stdout_capture
            try:
                exec(script_code, probe_globals, thread_locals)
                if "probe" in thread_locals and callable(thread_locals["probe"]):
                    thread_locals["result"] = thread_locals["probe"]()
                elif "parse" in thread_locals and callable(thread_locals["parse"]):
                    thread_locals["result"] = thread_locals["parse"]()
            except Exception as e:
                thread_exception.append((e, traceback.format_exc()))
            finally:
                sys.stdout = old_stdout

        worker = threading.Thread(target=_runner)
        worker.daemon = True
        worker.start()
        worker.join(self.timeout_seconds)

        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        execution_result["execution_time_ms"] = elapsed_ms
        execution_result["stdout"] = stdout_capture.getvalue()
        execution_result["registered_children"] = registered_children

        if worker.is_alive():
            execution_result["error"] = f"Probe script execution timed out after {self.timeout_seconds}s"
            return execution_result

        if thread_exception:
            exc, tb = thread_exception[0]
            execution_result["error"] = f"{type(exc).__name__}: {str(exc)}"
            return execution_result

        res = thread_locals.get("result", probe_globals.get("result"))
        execution_result["success"] = True
        execution_result["returned_value"] = str(res) if isinstance(res, bytes) else res
        return execution_result
