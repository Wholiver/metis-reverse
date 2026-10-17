"""
Metis Reverse - Session Lifecycle Manager
Thread-safe session store, artifact caching, and backend orchestration.
"""

from __future__ import annotations

import contextlib
import hashlib
import inspect
import os
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from metis_reverse.backends.base import UnsupportedArtifactError
from metis_reverse.core.evidence import EvidenceStore
from metis_reverse.core.models import (
    ArchitectureType,
    ArtifactFormat,
    BinarySession,
    SessionInfo,
    TargetArtifact,
)

# ============================================================================
# Exceptions
# ============================================================================

class MetisError(Exception):
    """Base exception for Metis Reverse."""
    pass


class SessionError(MetisError):
    """Session management exception."""
    pass


class SessionNotFoundError(SessionError, KeyError):
    """Raised when the requested session_id is not active."""
    pass


class ArtifactError(MetisError):
    """Target binary ingestion exception."""
    pass


class ArtifactNotFoundError(ArtifactError, FileNotFoundError):
    """Raised when the specified file path does not exist on disk."""
    pass


class BackendError(MetisError):
    """Backend engine exception."""
    pass


# ============================================================================
# Session Manager
# ============================================================================

class SessionManager:
    """
    Central thread-safe coordinator for active reverse engineering sessions,
    artifact caching, and backend bindings.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, BinarySession] = {}
        self._backends: dict[str, Any] = {}
        self._artifact_cache: dict[str, TargetArtifact] = {}
        self._backend_factories: dict[str, Callable[[], Any]] = {}

    def register_backend(self, name: str, factory: Callable[[], Any]) -> None:
        """Register a backend creation factory."""
        with self._lock:
            self._backend_factories[name.lower()] = factory

    def create_session(
        self,
        file_path: str | Path,
        backend_name: str | None = "auto",
        preloaded_backend: Any | None = None,
        validate: bool = False,
    ) -> BinarySession:
        """
        Ingest a target binary, select the backend, and create a BinarySession.
        """
        abs_path = os.path.abspath(os.path.expanduser(str(file_path)))
        if not os.path.exists(abs_path) or not os.path.isfile(abs_path):
            raise ArtifactNotFoundError(f"Target binary file not found: {abs_path}")

        file_size = os.path.getsize(abs_path)
        sha256 = self._compute_sha256(abs_path)

        with self._lock:
            # 1. Retrieve or build TargetArtifact
            artifact = self._artifact_cache.get(sha256)
            cached = artifact is not None
            if artifact is None:
                artifact = self._build_initial_artifact(abs_path, file_size, sha256)

            # 2. Select backend
            backend_key = (backend_name or "auto").lower()
            backend = preloaded_backend

            if backend is None:
                backend = self._resolve_backend(backend_key, artifact)

            backend_type_name = (
                backend.name
                if isinstance(getattr(backend, "name", None), str)
                else (backend.name() if callable(getattr(backend, "name", None)) else backend_key)
            )

            # 3. Create session instance
            session = BinarySession(
                artifact=artifact,
                backend_type=backend_type_name,
                evidence_store=EvidenceStore(),
            )

            # 4. Initialize backend with artifact and session if backend supports it
            if hasattr(backend, "load_artifact"):
                try:
                    sig = inspect.signature(backend.load_artifact)
                    param_count = len(sig.parameters)
                except Exception:
                    param_count = 1

                res = None
                try:
                    if param_count >= 2:
                        res = backend.load_artifact(session, artifact)
                    else:
                        # Single parameter: might expect artifact or path
                        try:
                            res = backend.load_artifact(artifact)
                        except (TypeError, AttributeError):
                            res = backend.load_artifact(abs_path)
                except Exception:
                    if validate:
                        self._artifact_cache.pop(sha256, None)
                        raise
                    res = None

                if isinstance(res, tuple) and len(res) == 2:
                    loaded_art, loaded_sess = res
                    if isinstance(loaded_sess, BinarySession):
                        session = loaded_sess
                    if isinstance(loaded_art, TargetArtifact):
                        artifact = loaded_art
                        session.artifact = artifact
                elif isinstance(res, BinarySession):
                    session = res
                    if not session.artifact:
                        session.artifact = artifact

            # 5. Validation if requested
            if validate:
                is_unknown_arch = (
                    session.artifact.architecture == ArchitectureType.UNKNOWN
                    or str(session.artifact.architecture).lower() in ("unknown", "architecturetype.unknown")
                )
                is_raw_format = (
                    session.artifact.format == ArtifactFormat.RAW
                    or str(session.artifact.format).lower() in ("raw", "artifactformat.raw")
                )
                is_native_format = session.artifact.format in (
                    ArtifactFormat.ELF,
                    ArtifactFormat.MACHO,
                    ArtifactFormat.PE,
                ) or str(session.artifact.format).upper() in ("ELF", "MACHO", "PE")
                is_empty_sections = not bool(session.artifact.sections)

                if is_unknown_arch or is_raw_format or (is_native_format and is_empty_sections):
                    self._artifact_cache.pop(sha256, None)
                    raise UnsupportedArtifactError(
                        f"Unrecognized or malformed binary format for '{abs_path}': "
                        f"format={session.artifact.format}, architecture={session.artifact.architecture}, "
                        f"sections={len(session.artifact.sections)}"
                    )

            if not cached:
                self._artifact_cache[sha256] = session.artifact

            # Populate functions if empty
            if not session.functions and backend and hasattr(backend, "get_functions"):
                with contextlib.suppress(Exception):
                    backend.get_functions(session)

            # Run deterministic grounding engine to extract multi-evidence tags and de-anonymize symbols
            with contextlib.suppress(Exception):
                from metis_reverse.grounding import ground_session
                ground_session(session)

            self._sessions[session.session_id] = session
            self._backends[session.session_id] = backend

            return session

    def get_session(self, session_id: str) -> BinarySession:
        """Retrieve an active session by ID and update last_accessed_at."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise SessionNotFoundError(f"Session not found or expired: {session_id}")
            session.last_accessed_at = datetime.now(UTC)
            return session

    def get_backend(self, session_id: str) -> Any:
        """Retrieve the backend engine associated with a session."""
        with self._lock:
            if session_id not in self._sessions:
                raise SessionNotFoundError(f"Session not found: {session_id}")
            return self._backends.get(session_id)

    def close_session(self, session_id: str) -> bool:
        """Close and purge an active session."""
        with self._lock:
            if session_id not in self._sessions:
                return False
            backend = self._backends.pop(session_id, None)
            if backend and hasattr(backend, "close"):
                with contextlib.suppress(Exception):
                    backend.close()
            self._sessions.pop(session_id, None)
            return True

    def list_sessions(self) -> list[SessionInfo]:
        """Enumerate summaries of all active sessions."""
        with self._lock:
            summaries: list[SessionInfo] = []
            for s in self._sessions.values():
                summaries.append(
                    SessionInfo(
                        session_id=s.session_id,
                        artifact_id=s.artifact.artifact_id,
                        file_path=s.artifact.file_path,
                        file_name=s.artifact.file_name,
                        format=s.artifact.format.value if hasattr(s.artifact.format, "value") else str(s.artifact.format),
                        architecture=s.artifact.architecture.value if hasattr(s.artifact.architecture, "value") else str(s.artifact.architecture),
                        bitness=s.artifact.bitness,
                        entry_point=f"0x{s.artifact.entry_point:x}",
                        backend=s.backend_type,
                        total_functions=len(s.functions),
                        total_symbols=len(s.symbols),
                        is_stripped=s.artifact.is_stripped,
                        created_at=s.created_at.isoformat(),
                    )
                )
            return summaries

    def purge_artifact_cache(self, artifact_id: str) -> None:
        """Purge a cached artifact by artifact_id (SHA-256) if present."""
        with self._lock:
            self._artifact_cache.pop(artifact_id, None)

    def clear_all(self) -> None:
        """Purge all sessions and caches (primarily for unit test isolation)."""
        with self._lock:
            for s_id in list(self._sessions.keys()):
                self.close_session(s_id)
            self._artifact_cache.clear()

    # ------------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------------

    def _compute_sha256(self, file_path: str) -> str:
        """Compute SHA-256 hash using chunked streaming."""
        h = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    def _build_initial_artifact(
        self, file_path: str, file_size: int, sha256: str
    ) -> TargetArtifact:
        """Inspect headers to build an initial TargetArtifact."""
        file_name = os.path.basename(file_path)
        fmt = ArtifactFormat.RAW
        arch = ArchitectureType.UNKNOWN
        bitness = 64

        try:
            with open(file_path, "rb") as f:
                header = f.read(16)
                if header.startswith(b"\x7fELF"):
                    fmt = ArtifactFormat.ELF
                    bitness = 64 if len(header) > 4 and header[4] == 2 else 32
                elif header.startswith(b"MZ"):
                    fmt = ArtifactFormat.PE
                elif len(header) >= 4 and header[:4] in (
                    b"\xfe\xed\xfa\xce",
                    b"\xce\xfa\xed\xfe",
                    b"\xfe\xed\xfa\xcf",
                    b"\xcf\xfa\xed\xfe",
                ):
                    fmt = ArtifactFormat.MACHO
                    bitness = 64 if header[:4] in (b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe") else 32
                elif header.startswith(b"\x00asm"):
                    fmt = ArtifactFormat.WASM
                elif header.startswith(b"dex\n"):
                    fmt = ArtifactFormat.DEX
                    arch = ArchitectureType.DALVIK
                elif file_path.endswith((".js", ".mjs")):
                    fmt = ArtifactFormat.JAVASCRIPT
                    arch = ArchitectureType.JS
        except Exception:
            pass

        # Enrich native formats (ELF, MACHO, PE) using LIEF parser if possible
        if fmt in (ArtifactFormat.ELF, ArtifactFormat.MACHO, ArtifactFormat.PE):
            try:
                from metis_reverse.backends.tier1_native.binary_parser import LiefBinaryParser
                parsed_art, _, _ = LiefBinaryParser.parse(file_path)
                return parsed_art
            except Exception:
                pass

        return TargetArtifact(
            artifact_id=sha256,
            file_path=file_path,
            file_name=file_name,
            file_size=file_size,
            format=fmt,
            architecture=arch,
            bitness=bitness,
        )

    def _resolve_backend(self, backend_key: str, artifact: TargetArtifact) -> Any:
        """Resolve backend from registry, factory, or detector."""
        if backend_key in self._backend_factories:
            return self._backend_factories[backend_key]()

        # Use detector create_backend
        try:
            from metis_reverse.backends.detector import create_backend
            return create_backend(
                backend_name=backend_key,
                artifact_format=artifact.format.value if hasattr(artifact.format, "value") else str(artifact.format),
            )
        except Exception:
            pass

        # Attempt to import tier1 native backend if available
        try:
            from metis_reverse.backends.tier1_native import Tier1NativeBackend
            return Tier1NativeBackend()
        except Exception:
            pass

        # Fallback to mock backend for testing
        try:
            from metis_reverse.backends.tier2_bridge.mock_backend import MockDecompilerBackend
            return MockDecompilerBackend()
        except Exception:
            pass

        return _DefaultDummyBackend()


class _DefaultDummyBackend:
    """Minimal fallback backend used when no other backends are loaded."""
    def name(self) -> str:
        return "fallback_dummy"

    def load_artifact(self, session: BinarySession, artifact: TargetArtifact) -> None:
        pass

    def disassemble_range(self, session: BinarySession, start_addr: int, size: int) -> list[Any]:
        return []

    def decompile_function(self, session: BinarySession, func_addr: int) -> Any:
        return None


# Global singleton instance
global_session_manager = SessionManager()
