"""
metis_reverse.backends.base
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Abstract base class definition and error hierarchy for all Metis Reverse analysis engines.
"""

from abc import ABC, abstractmethod
from typing import Any

from metis_reverse.core.models import (
    BinarySession,
    DecompiledCode,
    Instruction,
    TargetArtifact,
)


class BackendError(Exception):
    """Base exception for all backend errors."""
    pass


class UnsupportedArtifactError(BackendError, ValueError):
    """Raised when an artifact format or architecture cannot be handled."""
    pass


class DisassemblyError(BackendError):
    """Raised when instruction decoding fails across a specified range."""
    pass


class DecompilationError(BackendError):
    """Raised when decompilation analysis fails for a target function."""
    pass


class MutationError(BackendError):
    """Raised when a symbol, variable, or type mutation cannot be applied."""
    pass


class BaseBackend(ABC):
    """
    Universal contract for reverse engineering analysis engines.
    Both Tier 1 (native LIEF/Capstone/Angr) and Tier 2 (Ghidra/IDA bridges)
    must implement this interface.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique name and identifier of the backend."""
        pass

    @property
    @abstractmethod
    def tier(self) -> int:
        """Return 1 for built-in lightweight native, 2 for external professional decompiler."""
        pass

    @abstractmethod
    def load_artifact(
        self, artifact_or_path: str | TargetArtifact
    ) -> Any:
        """
        Parse binary headers, sections, symbols, and initialize a new BinarySession.
        May return BinarySession or (TargetArtifact, BinarySession).
        """
        pass

    @abstractmethod
    def disassemble_range(
        self,
        session: BinarySession,
        start_addr: int,
        size: int,
    ) -> list[Instruction]:
        """
        Perform linear sweep disassembly across a designated virtual address range.
        """
        pass

    @abstractmethod
    def get_cfg(
        self,
        session: BinarySession,
        func_addr: int | None = None,
    ) -> dict[str, Any]:
        """
        Retrieve control flow graph (basic blocks and directional edges).
        """
        pass

    @abstractmethod
    def decompile_function(
        self,
        session: BinarySession,
        func_addr: int,
    ) -> DecompiledCode:
        """
        Decompile a function into structured C pseudocode with AST mappings.
        """
        pass

    @abstractmethod
    def mutate_symbol(
        self,
        session: BinarySession,
        addr: int,
        new_name: str,
    ) -> bool:
        """
        Rename a symbol in the backend and session symbol table.
        """
        pass

    @abstractmethod
    def mutate_type(
        self,
        session: BinarySession,
        addr: int,
        new_type: str,
    ) -> bool:
        """
        Update the type signature of a function, variable, or memory slot.
        """
        pass

    def close(self) -> None:
        """
        Release allocated backend resources, caches, and child engines.
        Default implementation is a no-op for backends without resources.
        """
        return None

