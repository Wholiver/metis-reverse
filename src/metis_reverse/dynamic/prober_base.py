"""
Metis Reverse - Base Dynamic Prober Interface
Defines the standard contract for native (Frida) and emulated (Unicorn) dynamic tracing.
"""

from __future__ import annotations

import logging
import platform
import sys
from abc import ABC, abstractmethod
from typing import Any

from metis_reverse.core.models import (
    ArchitectureCompatibilityError,
    BinarySession,
    DynamicProberError,
    EmulationTimeoutError,
    FridaAttachError,
    FridaNotAvailableError,
    TargetArtifact,
    TraceResult,
    TraceTimeoutError,
)

logger = logging.getLogger("metis_reverse.dynamic.base")

# Re-export exceptions for compatibility with callers
__all__ = [
    "ArchitectureCompatibilityError",
    "BaseProber",
    "EmulationTimeoutError",
    "FridaAttachError",
    "FridaNotAvailableError",
    "ProberError",
    "ProberExecutionError",
    "ProberUnavailableError",
    "TraceTimeoutError",
    "is_host_native_compatible",
]


class ProberError(DynamicProberError):
    """Base exception for dynamic prober errors."""
    pass


class ProberUnavailableError(ProberError):
    """Raised when the requested prober backend is unavailable on the current host."""
    pass


class ProberExecutionError(ProberError):
    """Raised when an error occurs during runtime tracing or emulation."""
    pass


def is_host_native_compatible(artifact: TargetArtifact) -> bool:
    """
    Check if the host operating system and CPU architecture can natively execute
    the given target artifact.
    """
    host_os = sys.platform  # 'darwin', 'linux', 'win32'
    host_machine = platform.machine().lower()

    # Format matching
    art_format = artifact.format
    art_format_str = art_format.upper() if isinstance(art_format, str) else art_format.value.upper()

    os_matches = (
        (host_os == "darwin" and art_format_str == "MACHO")
        or (host_os.startswith("linux") and art_format_str == "ELF")
        or (host_os == "win32" and art_format_str == "PE")
    )
    if not os_matches:
        return False

    # Architecture matching
    art_arch = artifact.architecture
    art_arch_str = art_arch.lower() if isinstance(art_arch, str) else art_arch.value.lower()

    if host_machine in ("arm64", "aarch64"):
        return art_arch_str in ("arm64", "aarch64")
    elif host_machine in ("x86_64", "amd64"):
        return art_arch_str in ("x86_64", "amd64", "x86", "i386")

    return False


class BaseProber(ABC):
    """Abstract base prober defining the contract for dynamic execution engines."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the prober backend (e.g. 'frida', 'unicorn')."""
        ...

    @abstractmethod
    def is_available(self, session: BinarySession | None = None) -> bool:
        """Check if this prober is available and compatible with the target session."""
        ...

    @abstractmethod
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
        Execute or hook target function at `function_address` with provided arguments,
        capturing return value, memory accesses, events, and runtime strings.
        """
        ...
