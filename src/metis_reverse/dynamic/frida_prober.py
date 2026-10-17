"""
Metis Reverse - Native Frida Dynamic Prober.
Performs process spawning, Interceptor hooking, and runtime memory probing.
"""

from __future__ import annotations

import contextlib
import logging
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from metis_reverse.core.models import (
    ArchitectureCompatibilityError,
    BinarySession,
    FridaNotAvailableError,
    TraceEvent,
    TraceEventType,
    TraceResult,
)
from metis_reverse.dynamic.prober_base import BaseProber, is_host_native_compatible

logger = logging.getLogger("metis_reverse.dynamic.frida")


class FridaProber(BaseProber):
    """Native dynamic prober using Frida dynamic binary instrumentation."""

    def __init__(self, default_timeout: float = 5.0) -> None:
        self.default_timeout = default_timeout

    @property
    def name(self) -> str:
        return "frida"

    def is_available(self, session: BinarySession | None = None) -> bool:
        """Check if Frida package is installed and local device accessible."""
        try:
            import frida
            device = frida.get_local_device()
            if device is None:
                return False
        except Exception as e:
            logger.debug("Frida unavailable: %s", e)
            return False

        if session is not None:
            return is_host_native_compatible(session.artifact)

        return True

    def check_compatibility(self, session: BinarySession) -> tuple[bool, str]:
        """Validate if host system can natively execute the session artifact."""
        if not is_host_native_compatible(session.artifact):
            return False, f"Host cannot natively execute artifact ({session.artifact.format}/{session.artifact.architecture})."
        return True, "Compatible"

    def _prepare_darwin_runner(self, original_path: Path) -> tuple[Path, Path | None]:
        """Create ad-hoc signed temporary binary with get-task-allow on macOS."""
        temp_dir = Path(tempfile.mkdtemp(prefix="metis_frida_"))
        runner_bin = temp_dir / original_path.name
        shutil.copy2(original_path, runner_bin)

        plist_path = temp_dir / "entitlements.plist"
        plist_path.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0">\n'
            '<dict>\n'
            '    <key>com.apple.security.get-task-allow</key>\n'
            '    <true/>\n'
            '</dict>\n'
            '</plist>\n'
        )
        try:
            subprocess.run(
                ["codesign", "-s", "-", "--entitlements", str(plist_path), "-f", str(runner_bin)],
                check=True,
                capture_output=True,
            )
            return runner_bin, temp_dir
        except Exception as e:
            logger.warning("Failed to codesign runner: %s", e)
            shutil.rmtree(temp_dir, ignore_errors=True)
            return original_path, None

    def trace_function(
        self,
        session: BinarySession,
        function_address: int,
        args: list[Any] | None = None,
        *,
        timeout_seconds: float = 5.0,
        max_instructions: int = 100000,
        **kwargs: Any,
    ) -> TraceResult:
        """
        Dynamically trace a function using Frida Interceptor hooks.
        """
        try:
            import frida
        except ImportError as err:
            raise FridaNotAvailableError("frida-python is not installed") from err

        compat, reason = self.check_compatibility(session)
        if not compat:
            raise ArchitectureCompatibilityError(f"Frida cannot trace artifact: {reason}")

        artifact = session.artifact
        original_bin = Path(artifact.file_path)
        if not original_bin.exists():
            raise FileNotFoundError(f"Binary file not found: {original_bin}")

        # Rebase address relative to image base
        base_addr = artifact.base_address or 0
        if base_addr > 0 and function_address >= base_addr:
            offset = function_address - base_addr
        else:
            offset = function_address

        temp_cleanup_dir: Path | None = None
        target_exec = original_bin
        if sys.platform == "darwin":
            target_exec, temp_cleanup_dir = self._prepare_darwin_runner(original_bin)

        cli_args = kwargs.get("cli_args", [])
        stdin_data = kwargs.get("stdin_data")

        events: list[TraceEvent] = []
        captured_strings: list[str] = []
        memory_dumps: dict[str, str] = {}
        ret_val: Any = None
        start_time = time.time()
        timeout_sec = timeout_seconds or self.default_timeout

        try:
            device = frida.get_local_device()
            js_script_src = self._build_interceptor_script(offset)

            if stdin_data is not None:
                proc = subprocess.Popen(
                    [str(target_exec)] + [str(a) for a in cli_args],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                frida_session = device.attach(proc.pid)
                script: Any = frida_session.create_script(js_script_src)

                def on_msg(message: dict[str, Any], data: Any) -> None:
                    self._handle_frida_message(message, events, captured_strings, memory_dumps)

                script.on("message", on_msg)
                script.load()

                if isinstance(stdin_data, str):
                    stdin_bytes = stdin_data.encode("utf-8")
                else:
                    stdin_bytes = bytes(stdin_data)

                if proc.stdin is not None:
                    proc.stdin.write(stdin_bytes)
                    proc.stdin.flush()
                    proc.stdin.close()

                deadline = time.time() + timeout_sec
                while proc.poll() is None and time.time() < deadline:
                    if any(e.event_type in (TraceEventType.LEAVE, "LEAVE") for e in events):
                        break
                    time.sleep(0.05)

                if proc.poll() is None:
                    proc.kill()

                with contextlib.suppress(Exception):
                    frida_session.detach()
            else:
                spawn_args: list[Any] = [str(target_exec)] + [str(a) for a in cli_args]
                pid = device.spawn(spawn_args)
                frida_session = device.attach(pid)
                script_spawn: Any = frida_session.create_script(js_script_src)

                def on_msg_spawn(message: dict[str, Any], data: Any) -> None:
                    self._handle_frida_message(message, events, captured_strings, memory_dumps)

                script_spawn.on("message", on_msg_spawn)
                script_spawn.load()
                device.resume(pid)

                deadline = time.time() + timeout_sec
                while time.time() < deadline:
                    if any(e.event_type in (TraceEventType.LEAVE, "LEAVE") for e in events):
                        break
                    if len(events) > 0:
                        # Event already captured, give brief pause for onLeave
                        time.sleep(0.1)
                        break
                    time.sleep(0.05)

                with contextlib.suppress(Exception):
                    frida_session.detach()
                with contextlib.suppress(Exception):
                    device.kill(pid)

            for e in reversed(events):
                if e.event_type in (TraceEventType.LEAVE, "LEAVE") and e.return_value is not None:
                    ret_val = e.return_value
                    break

            exec_time = (time.time() - start_time) * 1000.0
            return TraceResult(
                success=True,
                session_id=session.session_id,
                function_address=function_address,
                function_name=f"sub_{function_address:x}",
                prober="frida",
                prober_used="frida",
                return_value=ret_val,
                return_type="int" if isinstance(ret_val, int) else None,
                events=events,
                captured_strings=list(set(captured_strings)),
                memory_dumps=memory_dumps,
                instructions_executed=len(events),
                execution_time_ms=exec_time,
            )

        finally:
            if temp_cleanup_dir and temp_cleanup_dir.exists():
                shutil.rmtree(temp_cleanup_dir, ignore_errors=True)

    def _build_interceptor_script(self, offset: int) -> str:
        """Construct robust Frida JavaScript injection script."""
        return f"""
        var mainMod = Process.mainModule;
        var targetAddr = mainMod.base.add({hex(offset)});

        function isReadable(p) {{
            if (!p || p.isNull()) return false;
            try {{
                var range = Process.findRangeByAddress(p);
                return range !== null && range.protection.indexOf('r') !== -1;
            }} catch(e) {{
                return false;
            }}
        }}

        function inspectArg(p) {{
            if (!p) return {{ raw: '0x0', type: 'null' }};
            var hexVal = p.toString();
            var uintVal = p.toUInt32();
            var intVal = p.toInt32();
            var strVal = null;

            if (p.compare(ptr(0x1000)) > 0 && isReadable(p)) {{
                try {{
                    var s = p.readUtf8String(128);
                    if (s && s.length > 0 && /^[\\x20-\\x7E\\r\\n\\t]+$/.test(s)) {{
                        strVal = s;
                    }}
                }} catch(e) {{}}
            }}

            return {{
                raw: hexVal,
                int_val: intVal,
                uint_val: uintVal,
                string_val: strVal
            }};
        }}

        try {{
            Interceptor.attach(targetAddr, {{
                onEnter: function(args) {{
                    var capturedArgs = [];
                    for (var i = 0; i < 6; i++) {{
                        capturedArgs.push(inspectArg(args[i]));
                    }}
                    send({{
                        event_type: 'ENTER',
                        address: targetAddr.toString(),
                        args: capturedArgs
                    }});
                }},
                onLeave: function(retval) {{
                    send({{
                        event_type: 'LEAVE',
                        address: targetAddr.toString(),
                        return_value: retval.toInt32()
                    }});
                }}
            }});
        }} catch(err) {{
            send({{
                event_type: 'EXCEPTION',
                address: targetAddr.toString(),
                error: err.toString()
            }});
        }}
        """

    def _handle_frida_message(
        self,
        message: dict[str, Any],
        events: list[TraceEvent],
        captured_strings: list[str],
        memory_dumps: dict[str, str],
    ) -> None:
        """Process messages received from injected script."""
        if message.get("type") == "send":
            payload = message.get("payload", {})
            event_type = payload.get("event_type", "ENTER")
            addr = payload.get("address", "0x0")
            args_data = payload.get("args", [])
            ret_val = payload.get("return_value")

            for arg in args_data:
                if isinstance(arg, dict) and arg.get("string_val"):
                    captured_strings.append(arg["string_val"])

            event = TraceEvent(
                event_type=event_type,
                address=addr,
                arguments=[a.get("raw") if isinstance(a, dict) else str(a) for a in args_data],
                return_value=ret_val,
                details=payload,
            )
            events.append(event)
