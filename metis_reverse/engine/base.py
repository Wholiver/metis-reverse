"""Abstract base class for reverse engineering static backends."""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional

class BaseReEngine(ABC):
    """Abstract interface defining required reverse engineering capabilities."""

    @abstractmethod
    def open_session(self, binary_path: str, session_id: str) -> Dict[str, Any]:
        """Loads a binary into an isolated, read-only analysis session."""
        pass

    @abstractmethod
    def close_session(self, session_id: str) -> None:
        """Closes and unloads an analysis session."""
        pass

    @abstractmethod
    def get_metadata(self, session_id: str) -> Dict[str, Any]:
        """Returns binary architecture, format, entrypoint, and hashes."""
        pass

    @abstractmethod
    def list_functions(self, session_id: str, offset: int = 0, limit: int = 50) -> Dict[str, Any]:
        """Enumerates functions with pagination."""
        pass

    @abstractmethod
    def get_function_context(self, session_id: str, va: str, max_tokens: int = 2048) -> Dict[str, Any]:
        """Extracts decompiled code, callers, callees, strings, and constants for a function."""
        pass

    @abstractmethod
    def get_memory_slice(self, session_id: str, va: str, size: int) -> bytes:
        """Extracts a slice of bytes from a virtual address."""
        pass

    @abstractmethod
    def apply_refinements(self, session_id: str, refinements: Dict[str, Any]) -> Dict[str, Any]:
        """Applies symbol rename, type updates, or comments to the engine."""
        pass

    def read_file_range(self, session_id: str, offset: int, length: int) -> bytes:
        """Direct physical file range read bypassing virtual memory mapping (P0-1)."""
        return b""

    def translate_address(self, session_id: str, value: Any, from_kind: str = "va") -> Dict[str, Any]:
        """Converts between VA, RVA, and file offset coordinates (R8, P0-1)."""
        return {
            "va": str(value) if from_kind == "va" else "0x0",
            "rva": str(value) if from_kind == "rva" else "0x0",
            "file_offset": int(value) if from_kind == "file_offset" else 0,
            "segment": "unknown",
            "section": "unknown",
            "is_zero_fill": False,
        }

    def check_memory_consistency(self, session_id: str) -> Dict[str, Any]:
        """Validates consistency between virtual memory read and physical file offset (P0-1)."""
        return {
            "status": "consistent",
            "memory_view_unreliable": False,
            "discrepancies": [],
        }

    def inspect_binary_structure(
        self,
        session_id: str,
        scope: str = "all",
        query: Optional[str] = None,
        limit: int = 100
    ) -> Dict[str, Any]:
        """Inspects structural binary layout (headers, segments, sections, dependencies, symbols, encryption)."""
        return {
            "status": "error",
            "message": "inspect_binary_structure not implemented for this engine",
        }
