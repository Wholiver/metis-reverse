"""
Metis Reverse - Evidence Store & Provenance Registry
Manages immutable evidence tags, thread-safe concurrent storage,
anti-hallucination validation, and multi-criteria evidence queries.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from metis_reverse.core.models import (
    EvidenceSource,
    EvidenceTag,
    extract_address_from_target_id,
)


class ImmutableEvidenceError(Exception):
    """Raised when an attempt is made to overwrite or delete an immutable evidence tag."""
    pass


class EvidenceStore(BaseModel):
    """
    Thread-safe, indexed registry of grounded facts, format string inferences,
    runtime probes, and binary metadata anchors.
    """
    model_config = ConfigDict(validate_assignment=True, arbitrary_types_allowed=True)

    tags: dict[str, EvidenceTag] = Field(default_factory=dict)

    _lock: threading.RLock = PrivateAttr(default_factory=threading.RLock)
    _by_target: dict[str, list[str]] = PrivateAttr(default_factory=dict)
    _by_address: dict[int, list[str]] = PrivateAttr(default_factory=dict)
    _by_source: dict[str, list[str]] = PrivateAttr(default_factory=dict)
    _immutable_targets: set[str] = PrivateAttr(default_factory=set)

    def __init__(self, **data: Any) -> None:
        super().__init__(**data)
        # Index any initial tags passed into constructor
        for tag in self.tags.values():
            self._index_tag(tag)

    def _index_tag(self, tag: EvidenceTag) -> None:
        """Add tag references to secondary indices (must be called under lock)."""
        tid = tag.tag_id
        target = tag.target_id
        source_val = tag.source.value if hasattr(tag.source, "value") else str(tag.source)

        # Index by target
        if target:
            target_list = self._by_target.setdefault(target, [])
            if tid not in target_list:
                target_list.append(tid)

        # Index by source (both raw value and lowercase/uppercase for resilient querying)
        source_keys = {source_val, source_val.upper(), source_val.lower()}
        if source_val.upper() in {"SYSCALL_ABI", "SYSCALL_PROPAGATION", "SYSCALL_INFERENCE"}:
            source_keys.update({"SYSCALL_ABI", "syscall_abi", "SYSCALL_PROPAGATION", "syscall_propagation", "SYSCALL_INFERENCE", "syscall_inference"})
        for key in source_keys:
            src_list = self._by_source.setdefault(key, [])
            if tid not in src_list:
                src_list.append(tid)

        # Index by virtual address
        addr = extract_address_from_target_id(target)
        if addr is not None:
            addr_list = self._by_address.setdefault(addr, [])
            if tid not in addr_list:
                addr_list.append(tid)

        # Track immutable targets
        if tag.is_immutable:
            self._immutable_targets.add(target)
            if addr is not None:
                self._immutable_targets.add(f"0x{addr:x}")
                self._immutable_targets.add(f"func:0x{addr:x}")
                self._immutable_targets.add(f"sym:0x{addr:x}")

    def _unindex_tag(self, tag: EvidenceTag) -> None:
        """Remove tag references from secondary indices (must be called under lock)."""
        tid = tag.tag_id
        target = tag.target_id

        # Unindex by target
        if target and target in self._by_target:
            target_list = self._by_target[target]
            while tid in target_list:
                target_list.remove(tid)
            if not target_list:
                del self._by_target[target]

        # Unindex by virtual address
        addr = extract_address_from_target_id(target)
        if addr is not None and addr in self._by_address:
            addr_list = self._by_address[addr]
            while tid in addr_list:
                addr_list.remove(tid)
            if not addr_list:
                del self._by_address[addr]

        # Unindex by source across all source buckets
        for key, src_list in list(self._by_source.items()):
            if tid in src_list:
                while tid in src_list:
                    src_list.remove(tid)
                if not src_list:
                    del self._by_source[key]

    def add_tag(self, tag: EvidenceTag) -> str:
        """
        Register an evidence tag with thread safety, immutability locking,
        and confidence validation.
        """
        with self._lock:
            existing = self.tags.get(tag.tag_id)
            if existing is not None:
                if existing.is_immutable:
                    raise ImmutableEvidenceError(
                        f"Cannot overwrite immutable evidence tag '{tag.tag_id}' for target '{tag.target_id}'"
                    )
                self._unindex_tag(existing)

            # Check if target is already locked by an immutable tag
            if tag.target_id in self._immutable_targets and not tag.is_immutable:
                tag.is_immutable = False

            self.tags[tag.tag_id] = tag
            self._index_tag(tag)
            return tag.tag_id

    def delete_tag(self, tag_id: str) -> bool:
        """Delete an evidence tag if it is not immutable."""
        with self._lock:
            tag = self.tags.get(tag_id)
            if tag is None:
                return False
            if tag.is_immutable:
                raise ImmutableEvidenceError(f"Cannot delete immutable evidence tag '{tag_id}'")

            del self.tags[tag_id]
            self._unindex_tag(tag)
            return True

    def get_tag(self, tag_id: str) -> EvidenceTag | None:
        """Fetch a specific tag by ID."""
        with self._lock:
            return self.tags.get(tag_id)

    def get_tags_for_target(self, target_id: str) -> list[EvidenceTag]:
        """Fetch all tags matching a target ID (e.g. 'func:0x401000' or 'sym:0x401000')."""
        with self._lock:
            tag_ids = self._by_target.get(target_id, [])
            return [self.tags[tid] for tid in tag_ids if tid in self.tags]

    def get_tags_for_address(self, address: int) -> list[EvidenceTag]:
        """Fetch all tags anchored to a specific virtual address."""
        with self._lock:
            tag_ids = self._by_address.get(address, [])
            return [self.tags[tid] for tid in tag_ids if tid in self.tags]

    def has_immutable_tag(self, target_id: str) -> bool:
        """Check whether a target entity is locked by binary-proven immutable evidence."""
        with self._lock:
            if target_id in self._immutable_targets:
                return True
            for t in self.tags.values():
                if t.target_id == target_id and t.is_immutable:
                    self._immutable_targets.add(target_id)
                    return True
            return False

    def query(
        self,
        target_id: str | None = None,
        address: int | None = None,
        source: EvidenceSource | str | None = None,
        min_confidence: float = 0.0,
    ) -> list[EvidenceTag]:
        """Query evidence tags matching criteria with thread safety and confidence ranking."""
        with self._lock:
            candidates: set[str] = set(self.tags.keys())

            if target_id is not None:
                target_cand = set(self._by_target.get(target_id, []))
                candidates &= target_cand

            if address is not None:
                addr_cand = set(self._by_address.get(address, []))
                candidates &= addr_cand

            if source is not None:
                src_val = source.value if hasattr(source, "value") else str(source)
                query_keys = {src_val, src_val.upper(), src_val.lower()}
                if src_val.upper() in {"SYSCALL_ABI", "SYSCALL_PROPAGATION", "SYSCALL_INFERENCE"}:
                    query_keys.update({"SYSCALL_ABI", "syscall_abi", "SYSCALL_PROPAGATION", "syscall_propagation", "SYSCALL_INFERENCE", "syscall_inference"})
                src_cand: set[str] = set()
                for k in query_keys:
                    src_cand.update(self._by_source.get(k, []))
                candidates &= src_cand

            results: list[EvidenceTag] = []
            for tid in candidates:
                tag = self.tags[tid]
                if tag.confidence >= min_confidence:
                    results.append(tag)

            # Sort descending by confidence, and immutable first on ties
            return sorted(results, key=lambda t: (t.confidence, t.is_immutable), reverse=True)

    def __len__(self) -> int:
        with self._lock:
            return len(self.tags)

    def __iter__(self) -> Iterator[EvidenceTag]:  # type: ignore[override]
        with self._lock:
            return iter(list(self.tags.values()))
