"""
metis_reverse.grounding.syscalls
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
System call and standard C library semantic propagation engine.
Mines deterministic parameter types, file descriptors, local stack buffers,
and return values via bidirectional instruction tracing.
"""

from __future__ import annotations

import contextlib
import logging
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from metis_reverse.backends.tier1_native.disassembler import CapstoneDisassembler
from metis_reverse.core.models import (
    ArchitectureType,
    BinarySession,
    EvidenceSource,
    EvidenceTag,
    Instruction,
    TargetType,
)
from metis_reverse.grounding.format_strings import FormatStringGrounder

logger = logging.getLogger("metis_reverse.grounding.syscalls")


class ParameterDirection(StrEnum):
    IN = "in"
    OUT = "out"
    INOUT = "inout"


@dataclass(frozen=True)
class ParameterDefinition:
    """Specification of a single parameter in a syscall or libc function."""
    name: str
    type: str
    semantic_role: str
    direction: ParameterDirection = ParameterDirection.IN
    is_pointer: bool = False
    size_param_index: int | None = None
    default_name_hint: str | None = None


@dataclass(frozen=True)
class FunctionSignature:
    """Complete typed signature for a standard libc function or syscall."""
    name: str
    return_type: str
    parameters: list[ParameterDefinition]
    category: str
    is_variadic: bool = False
    return_name_hint: str | None = None

    linux_x86_64_nr: int | None = None
    linux_arm64_nr: int | None = None
    darwin_arm64_nr: int | None = None
    darwin_x86_64_nr: int | None = None
    linux_x86_nr: int | None = None


@dataclass
class ResolvedArgument:
    """An argument recovered by backward instruction tracing."""
    param_index: int
    param_def: ParameterDefinition
    target_register: str
    def_instruction: Instruction | None = None
    value_kind: str = "unknown"  # "immediate", "stack_offset", "register", "symbol_address", "unknown"
    immediate_value: int | None = None
    stack_offset: int | None = None
    base_register: str | None = None
    symbol_address: int | None = None
    symbol_string: str | None = None
    suggested_name: str | None = None
    suggested_type: str | None = None


class SyscallDatabase:
    """Systematic catalog of POSIX, Linux, and Darwin libc APIs and system calls."""

    _CATALOG: dict[str, FunctionSignature] = {}
    _NR_LOOKUP: dict[tuple[str, int], FunctionSignature] = {}

    @classmethod
    def initialize(cls) -> None:
        if cls._CATALOG:
            return

        signatures: list[FunctionSignature] = [
            # 1. File & I/O Operations
            FunctionSignature(
                name="read",
                return_type="ssize_t",
                parameters=[
                    ParameterDefinition("fd", "int", "file_descriptor", default_name_hint="fd"),
                    ParameterDefinition("buf", "void*", "buffer_pointer", direction=ParameterDirection.OUT, is_pointer=True, size_param_index=2, default_name_hint="input_buf"),
                    ParameterDefinition("count", "size_t", "buffer_size", default_name_hint="count"),
                ],
                category="io",
                return_name_hint="bytes_read",
                linux_x86_64_nr=0, linux_arm64_nr=63, darwin_arm64_nr=3, darwin_x86_64_nr=0x2000003, linux_x86_nr=3,
            ),
            FunctionSignature(
                name="write",
                return_type="ssize_t",
                parameters=[
                    ParameterDefinition("fd", "int", "file_descriptor", default_name_hint="fd"),
                    ParameterDefinition("buf", "const void*", "buffer_pointer", is_pointer=True, size_param_index=2, default_name_hint="out_buf"),
                    ParameterDefinition("count", "size_t", "buffer_size", default_name_hint="count"),
                ],
                category="io",
                return_name_hint="bytes_written",
                linux_x86_64_nr=1, linux_arm64_nr=64, darwin_arm64_nr=4, darwin_x86_64_nr=0x2000004, linux_x86_nr=4,
            ),
            FunctionSignature(
                name="open",
                return_type="int",
                parameters=[
                    ParameterDefinition("pathname", "const char*", "pathname", is_pointer=True, default_name_hint="file_path"),
                    ParameterDefinition("flags", "int", "open_flags", default_name_hint="flags"),
                    ParameterDefinition("mode", "mode_t", "file_mode", default_name_hint="mode"),
                ],
                category="io",
                return_name_hint="fd",
                linux_x86_64_nr=2, darwin_arm64_nr=5, darwin_x86_64_nr=0x2000005, linux_x86_nr=5,
            ),
            FunctionSignature(
                name="openat",
                return_type="int",
                parameters=[
                    ParameterDefinition("dirfd", "int", "file_descriptor", default_name_hint="dirfd"),
                    ParameterDefinition("pathname", "const char*", "pathname", is_pointer=True, default_name_hint="file_path"),
                    ParameterDefinition("flags", "int", "open_flags", default_name_hint="flags"),
                    ParameterDefinition("mode", "mode_t", "file_mode", default_name_hint="mode"),
                ],
                category="io",
                return_name_hint="fd",
                linux_x86_64_nr=257, linux_arm64_nr=56, darwin_arm64_nr=463,
            ),
            FunctionSignature(
                name="close",
                return_type="int",
                parameters=[
                    ParameterDefinition("fd", "int", "file_descriptor", default_name_hint="fd"),
                ],
                category="io",
                return_name_hint="close_status",
                linux_x86_64_nr=3, linux_arm64_nr=57, darwin_arm64_nr=6, darwin_x86_64_nr=0x2000006, linux_x86_nr=6,
            ),
            FunctionSignature(
                name="lseek",
                return_type="off_t",
                parameters=[
                    ParameterDefinition("fd", "int", "file_descriptor", default_name_hint="fd"),
                    ParameterDefinition("offset", "off_t", "file_offset", default_name_hint="offset"),
                    ParameterDefinition("whence", "int", "seek_whence", default_name_hint="whence"),
                ],
                category="io",
                return_name_hint="new_offset",
                linux_x86_64_nr=8, linux_arm64_nr=62, darwin_arm64_nr=199,
            ),
            FunctionSignature(
                name="pread",
                return_type="ssize_t",
                parameters=[
                    ParameterDefinition("fd", "int", "file_descriptor", default_name_hint="fd"),
                    ParameterDefinition("buf", "void*", "buffer_pointer", direction=ParameterDirection.OUT, is_pointer=True, size_param_index=2, default_name_hint="buf"),
                    ParameterDefinition("count", "size_t", "buffer_size", default_name_hint="count"),
                    ParameterDefinition("offset", "off_t", "file_offset", default_name_hint="offset"),
                ],
                category="io",
                return_name_hint="bytes_read",
                linux_x86_64_nr=17, linux_arm64_nr=67, darwin_arm64_nr=153,
            ),
            FunctionSignature(
                name="pwrite",
                return_type="ssize_t",
                parameters=[
                    ParameterDefinition("fd", "int", "file_descriptor", default_name_hint="fd"),
                    ParameterDefinition("buf", "const void*", "buffer_pointer", is_pointer=True, size_param_index=2, default_name_hint="buf"),
                    ParameterDefinition("count", "size_t", "buffer_size", default_name_hint="count"),
                    ParameterDefinition("offset", "off_t", "file_offset", default_name_hint="offset"),
                ],
                category="io",
                return_name_hint="bytes_written",
                linux_x86_64_nr=18, linux_arm64_nr=68, darwin_arm64_nr=154,
            ),
            FunctionSignature(
                name="ioctl",
                return_type="int",
                parameters=[
                    ParameterDefinition("fd", "int", "file_descriptor", default_name_hint="fd"),
                    ParameterDefinition("request", "unsigned long", "ioctl_request", default_name_hint="request"),
                    ParameterDefinition("argp", "void*", "ioctl_arg", is_pointer=True, default_name_hint="argp"),
                ],
                category="io",
                linux_x86_64_nr=16, linux_arm64_nr=29, darwin_arm64_nr=54,
            ),
            FunctionSignature(
                name="fcntl",
                return_type="int",
                parameters=[
                    ParameterDefinition("fd", "int", "file_descriptor", default_name_hint="fd"),
                    ParameterDefinition("cmd", "int", "fcntl_cmd", default_name_hint="cmd"),
                    ParameterDefinition("arg", "long", "fcntl_arg", default_name_hint="arg"),
                ],
                category="io",
                linux_x86_64_nr=72, linux_arm64_nr=25, darwin_arm64_nr=92,
            ),
            FunctionSignature(
                name="dup",
                return_type="int",
                parameters=[ParameterDefinition("oldfd", "int", "file_descriptor", default_name_hint="oldfd")],
                category="io",
                return_name_hint="newfd",
                linux_x86_64_nr=32, linux_arm64_nr=23, darwin_arm64_nr=90,
            ),
            FunctionSignature(
                name="dup2",
                return_type="int",
                parameters=[
                    ParameterDefinition("oldfd", "int", "file_descriptor", default_name_hint="oldfd"),
                    ParameterDefinition("newfd", "int", "file_descriptor", default_name_hint="newfd"),
                ],
                category="io",
                return_name_hint="newfd",
                linux_x86_64_nr=33, darwin_arm64_nr=90,
            ),
            FunctionSignature(
                name="pipe",
                return_type="int",
                parameters=[ParameterDefinition("pipefd", "int*", "pipe_fds", is_pointer=True, default_name_hint="pipefd")],
                category="io",
                linux_x86_64_nr=22, darwin_arm64_nr=42,
            ),

            # 2. Memory & Allocation
            FunctionSignature(
                name="mmap",
                return_type="void*",
                parameters=[
                    ParameterDefinition("addr", "void*", "memory_address", is_pointer=True, default_name_hint="hint_addr"),
                    ParameterDefinition("length", "size_t", "allocation_size", default_name_hint="length"),
                    ParameterDefinition("prot", "int", "mmap_prot", default_name_hint="prot"),
                    ParameterDefinition("flags", "int", "mmap_flags", default_name_hint="flags"),
                    ParameterDefinition("fd", "int", "file_descriptor", default_name_hint="fd"),
                    ParameterDefinition("offset", "off_t", "file_offset", default_name_hint="offset"),
                ],
                category="memory",
                return_name_hint="mapped_addr",
                linux_x86_64_nr=9, linux_arm64_nr=222, darwin_arm64_nr=197, darwin_x86_64_nr=0x20000C5, linux_x86_nr=90,
            ),
            FunctionSignature(
                name="munmap",
                return_type="int",
                parameters=[
                    ParameterDefinition("addr", "void*", "memory_address", is_pointer=True, default_name_hint="addr"),
                    ParameterDefinition("length", "size_t", "allocation_size", default_name_hint="length"),
                ],
                category="memory",
                linux_x86_64_nr=11, linux_arm64_nr=215, darwin_arm64_nr=198,
            ),
            FunctionSignature(
                name="mprotect",
                return_type="int",
                parameters=[
                    ParameterDefinition("addr", "void*", "memory_address", is_pointer=True, default_name_hint="addr"),
                    ParameterDefinition("len", "size_t", "memory_size", default_name_hint="len"),
                    ParameterDefinition("prot", "int", "protection_flags", default_name_hint="prot"),
                ],
                category="memory",
                linux_x86_64_nr=10, linux_arm64_nr=226, darwin_arm64_nr=199,
            ),
            FunctionSignature(
                name="brk",
                return_type="int",
                parameters=[ParameterDefinition("addr", "void*", "heap_break_addr", is_pointer=True, default_name_hint="addr")],
                category="memory",
                linux_x86_64_nr=12, linux_arm64_nr=214,
            ),
            FunctionSignature(
                name="malloc",
                return_type="void*",
                parameters=[ParameterDefinition("size", "size_t", "allocation_size", default_name_hint="size")],
                category="memory",
                return_name_hint="allocated_ptr",
            ),
            FunctionSignature(
                name="calloc",
                return_type="void*",
                parameters=[
                    ParameterDefinition("nmemb", "size_t", "item_count", default_name_hint="nmemb"),
                    ParameterDefinition("size", "size_t", "item_size", default_name_hint="size"),
                ],
                category="memory",
                return_name_hint="allocated_ptr",
            ),
            FunctionSignature(
                name="realloc",
                return_type="void*",
                parameters=[
                    ParameterDefinition("ptr", "void*", "original_pointer", is_pointer=True, default_name_hint="ptr"),
                    ParameterDefinition("size", "size_t", "new_size", default_name_hint="size"),
                ],
                category="memory",
                return_name_hint="reallocated_ptr",
            ),
            FunctionSignature(
                name="free",
                return_type="void",
                parameters=[ParameterDefinition("ptr", "void*", "freed_pointer", is_pointer=True, default_name_hint="ptr")],
                category="memory",
            ),
            FunctionSignature(
                name="memcpy",
                return_type="void*",
                parameters=[
                    ParameterDefinition("dest", "void*", "dest_buffer", direction=ParameterDirection.OUT, is_pointer=True, default_name_hint="dest"),
                    ParameterDefinition("src", "const void*", "src_buffer", is_pointer=True, default_name_hint="src"),
                    ParameterDefinition("n", "size_t", "byte_count", default_name_hint="n"),
                ],
                category="memory",
                return_name_hint="dest",
            ),
            FunctionSignature(
                name="__memcpy_chk",
                return_type="void*",
                parameters=[
                    ParameterDefinition("dest", "void*", "dest_buffer", direction=ParameterDirection.OUT, is_pointer=True, default_name_hint="dest"),
                    ParameterDefinition("src", "const void*", "src_buffer", is_pointer=True, default_name_hint="src"),
                    ParameterDefinition("n", "size_t", "byte_count", default_name_hint="n"),
                    ParameterDefinition("destlen", "size_t", "dest_capacity", default_name_hint="destlen"),
                ],
                category="memory",
                return_name_hint="dest",
            ),
            FunctionSignature(
                name="memmove",
                return_type="void*",
                parameters=[
                    ParameterDefinition("dest", "void*", "dest_buffer", direction=ParameterDirection.OUT, is_pointer=True, default_name_hint="dest"),
                    ParameterDefinition("src", "const void*", "src_buffer", is_pointer=True, default_name_hint="src"),
                    ParameterDefinition("n", "size_t", "byte_count", default_name_hint="n"),
                ],
                category="memory",
                return_name_hint="dest",
            ),
            FunctionSignature(
                name="memset",
                return_type="void*",
                parameters=[
                    ParameterDefinition("s", "void*", "dest_buffer", direction=ParameterDirection.OUT, is_pointer=True, default_name_hint="s"),
                    ParameterDefinition("c", "int", "fill_byte", default_name_hint="c"),
                    ParameterDefinition("n", "size_t", "byte_count", default_name_hint="n"),
                ],
                category="memory",
                return_name_hint="s",
            ),
            FunctionSignature(
                name="bzero",
                return_type="void",
                parameters=[
                    ParameterDefinition("s", "void*", "dest_buffer", direction=ParameterDirection.OUT, is_pointer=True, default_name_hint="s"),
                    ParameterDefinition("n", "size_t", "byte_count", default_name_hint="n"),
                ],
                category="memory",
            ),
            FunctionSignature(
                name="memcmp",
                return_type="int",
                parameters=[
                    ParameterDefinition("s1", "const void*", "buffer_1", is_pointer=True, default_name_hint="s1"),
                    ParameterDefinition("s2", "const void*", "buffer_2", is_pointer=True, default_name_hint="s2"),
                    ParameterDefinition("n", "size_t", "byte_count", default_name_hint="n"),
                ],
                category="memory",
                return_name_hint="cmp_result",
            ),

            # 3. Networking & Sockets
            FunctionSignature(
                name="socket",
                return_type="int",
                parameters=[
                    ParameterDefinition("domain", "int", "socket_domain", default_name_hint="domain"),
                    ParameterDefinition("type", "int", "socket_type", default_name_hint="type"),
                    ParameterDefinition("protocol", "int", "socket_protocol", default_name_hint="protocol"),
                ],
                category="network",
                return_name_hint="sockfd",
                linux_x86_64_nr=41, linux_arm64_nr=198, darwin_arm64_nr=97, darwin_x86_64_nr=0x2000061, linux_x86_nr=359,
            ),
            FunctionSignature(
                name="bind",
                return_type="int",
                parameters=[
                    ParameterDefinition("sockfd", "int", "file_descriptor", default_name_hint="sockfd"),
                    ParameterDefinition("addr", "const struct sockaddr*", "socket_address", is_pointer=True, default_name_hint="addr"),
                    ParameterDefinition("addrlen", "socklen_t", "address_length", default_name_hint="addrlen"),
                ],
                category="network",
                return_name_hint="bind_status",
                linux_x86_64_nr=49, linux_arm64_nr=200, darwin_arm64_nr=104, linux_x86_nr=361,
            ),
            FunctionSignature(
                name="connect",
                return_type="int",
                parameters=[
                    ParameterDefinition("sockfd", "int", "file_descriptor", default_name_hint="sockfd"),
                    ParameterDefinition("addr", "const struct sockaddr*", "socket_address", is_pointer=True, default_name_hint="addr"),
                    ParameterDefinition("addrlen", "socklen_t", "address_length", default_name_hint="addrlen"),
                ],
                category="network",
                return_name_hint="conn_status",
                linux_x86_64_nr=42, linux_arm64_nr=203, darwin_arm64_nr=98, linux_x86_nr=362,
            ),
            FunctionSignature(
                name="listen",
                return_type="int",
                parameters=[
                    ParameterDefinition("sockfd", "int", "file_descriptor", default_name_hint="sockfd"),
                    ParameterDefinition("backlog", "int", "listen_backlog", default_name_hint="backlog"),
                ],
                category="network",
                return_name_hint="listen_status",
                linux_x86_64_nr=50, linux_arm64_nr=201, darwin_arm64_nr=106, linux_x86_nr=363,
            ),
            FunctionSignature(
                name="accept",
                return_type="int",
                parameters=[
                    ParameterDefinition("sockfd", "int", "file_descriptor", default_name_hint="sockfd"),
                    ParameterDefinition("addr", "struct sockaddr*", "client_address", direction=ParameterDirection.OUT, is_pointer=True, default_name_hint="client_addr"),
                    ParameterDefinition("addrlen", "socklen_t*", "address_length_ptr", direction=ParameterDirection.INOUT, is_pointer=True, default_name_hint="addrlen"),
                ],
                category="network",
                return_name_hint="client_sockfd",
                linux_x86_64_nr=43, linux_arm64_nr=202, darwin_arm64_nr=30, linux_x86_nr=364,
            ),
            FunctionSignature(
                name="send",
                return_type="ssize_t",
                parameters=[
                    ParameterDefinition("sockfd", "int", "file_descriptor", default_name_hint="sockfd"),
                    ParameterDefinition("buf", "const void*", "buffer_pointer", is_pointer=True, size_param_index=2, default_name_hint="buf"),
                    ParameterDefinition("len", "size_t", "buffer_size", default_name_hint="len"),
                    ParameterDefinition("flags", "int", "send_flags", default_name_hint="flags"),
                ],
                category="network",
                return_name_hint="bytes_sent",
            ),
            FunctionSignature(
                name="recv",
                return_type="ssize_t",
                parameters=[
                    ParameterDefinition("sockfd", "int", "file_descriptor", default_name_hint="sockfd"),
                    ParameterDefinition("buf", "void*", "buffer_pointer", direction=ParameterDirection.OUT, is_pointer=True, size_param_index=2, default_name_hint="buf"),
                    ParameterDefinition("len", "size_t", "buffer_size", default_name_hint="len"),
                    ParameterDefinition("flags", "int", "recv_flags", default_name_hint="flags"),
                ],
                category="network",
                return_name_hint="bytes_received",
            ),
            FunctionSignature(
                name="sendto",
                return_type="ssize_t",
                parameters=[
                    ParameterDefinition("sockfd", "int", "file_descriptor", default_name_hint="sockfd"),
                    ParameterDefinition("buf", "const void*", "buffer_pointer", is_pointer=True, size_param_index=2, default_name_hint="buf"),
                    ParameterDefinition("len", "size_t", "buffer_size", default_name_hint="len"),
                    ParameterDefinition("flags", "int", "send_flags", default_name_hint="flags"),
                    ParameterDefinition("dest_addr", "const struct sockaddr*", "dest_address", is_pointer=True, default_name_hint="dest_addr"),
                    ParameterDefinition("addrlen", "socklen_t", "address_length", default_name_hint="addrlen"),
                ],
                category="network",
                return_name_hint="bytes_sent",
                linux_x86_64_nr=44, linux_arm64_nr=206, darwin_arm64_nr=133,
            ),
            FunctionSignature(
                name="recvfrom",
                return_type="ssize_t",
                parameters=[
                    ParameterDefinition("sockfd", "int", "file_descriptor", default_name_hint="sockfd"),
                    ParameterDefinition("buf", "void*", "buffer_pointer", direction=ParameterDirection.OUT, is_pointer=True, size_param_index=2, default_name_hint="buf"),
                    ParameterDefinition("len", "size_t", "buffer_size", default_name_hint="len"),
                    ParameterDefinition("flags", "int", "recv_flags", default_name_hint="flags"),
                    ParameterDefinition("src_addr", "struct sockaddr*", "src_address", direction=ParameterDirection.OUT, is_pointer=True, default_name_hint="src_addr"),
                    ParameterDefinition("addrlen", "socklen_t*", "address_length_ptr", direction=ParameterDirection.INOUT, is_pointer=True, default_name_hint="addrlen"),
                ],
                category="network",
                return_name_hint="bytes_received",
                linux_x86_64_nr=45, linux_arm64_nr=207, darwin_arm64_nr=29,
            ),

            # 4. Strings & Formatted Conversion
            FunctionSignature(
                name="strlen",
                return_type="size_t",
                parameters=[ParameterDefinition("s", "const char*", "string_pointer", is_pointer=True, default_name_hint="s")],
                category="string",
                return_name_hint="str_len",
            ),
            FunctionSignature(
                name="strcpy",
                return_type="char*",
                parameters=[
                    ParameterDefinition("dest", "char*", "dest_string", direction=ParameterDirection.OUT, is_pointer=True, default_name_hint="dest"),
                    ParameterDefinition("src", "const char*", "src_string", is_pointer=True, default_name_hint="src"),
                ],
                category="string",
                return_name_hint="dest",
            ),
            FunctionSignature(
                name="strncpy",
                return_type="char*",
                parameters=[
                    ParameterDefinition("dest", "char*", "dest_string", direction=ParameterDirection.OUT, is_pointer=True, default_name_hint="dest"),
                    ParameterDefinition("src", "const char*", "src_string", is_pointer=True, default_name_hint="src"),
                    ParameterDefinition("n", "size_t", "max_chars", default_name_hint="n"),
                ],
                category="string",
                return_name_hint="dest",
            ),
            FunctionSignature(
                name="strcmp",
                return_type="int",
                parameters=[
                    ParameterDefinition("s1", "const char*", "string_1", is_pointer=True, default_name_hint="s1"),
                    ParameterDefinition("s2", "const char*", "string_2", is_pointer=True, default_name_hint="s2"),
                ],
                category="string",
                return_name_hint="cmp_res",
            ),
            FunctionSignature(
                name="strncmp",
                return_type="int",
                parameters=[
                    ParameterDefinition("s1", "const char*", "string_1", is_pointer=True, default_name_hint="s1"),
                    ParameterDefinition("s2", "const char*", "string_2", is_pointer=True, default_name_hint="s2"),
                    ParameterDefinition("n", "size_t", "max_chars", default_name_hint="n"),
                ],
                category="string",
                return_name_hint="cmp_res",
            ),
            FunctionSignature(
                name="strcasecmp",
                return_type="int",
                parameters=[
                    ParameterDefinition("s1", "const char*", "string_1", is_pointer=True, default_name_hint="s1"),
                    ParameterDefinition("s2", "const char*", "string_2", is_pointer=True, default_name_hint="s2"),
                ],
                category="string",
                return_name_hint="cmp_res",
            ),
            FunctionSignature(
                name="strncasecmp",
                return_type="int",
                parameters=[
                    ParameterDefinition("s1", "const char*", "string_1", is_pointer=True, default_name_hint="s1"),
                    ParameterDefinition("s2", "const char*", "string_2", is_pointer=True, default_name_hint="s2"),
                    ParameterDefinition("n", "size_t", "max_chars", default_name_hint="n"),
                ],
                category="string",
                return_name_hint="cmp_res",
            ),
            FunctionSignature(
                name="snprintf",
                return_type="int",
                parameters=[
                    ParameterDefinition("str", "char*", "dest_buffer", direction=ParameterDirection.OUT, is_pointer=True, size_param_index=1, default_name_hint="str"),
                    ParameterDefinition("size", "size_t", "buffer_capacity", default_name_hint="size"),
                    ParameterDefinition("format", "const char*", "format_string", is_pointer=True, default_name_hint="format"),
                ],
                category="string",
                is_variadic=True,
                return_name_hint="formatted_len",
            ),
            FunctionSignature(
                name="atoi",
                return_type="int",
                parameters=[ParameterDefinition("nptr", "const char*", "number_string", is_pointer=True, default_name_hint="nptr")],
                category="string",
                return_name_hint="parsed_int",
            ),

            # 5. Process & Signals
            FunctionSignature(
                name="exit",
                return_type="void",
                parameters=[ParameterDefinition("status", "int", "exit_status", default_name_hint="status")],
                category="process",
                linux_x86_64_nr=60, linux_arm64_nr=93, darwin_arm64_nr=1, linux_x86_nr=1,
            ),
            FunctionSignature(
                name="getpid",
                return_type="pid_t",
                parameters=[],
                category="process",
                return_name_hint="pid",
                linux_x86_64_nr=39, linux_arm64_nr=172, darwin_arm64_nr=20, linux_x86_nr=20,
            ),
        ]

        for sig in signatures:
            cls._CATALOG[sig.name] = sig
            if sig.linux_x86_64_nr is not None:
                cls._NR_LOOKUP[("linux_x86_64", sig.linux_x86_64_nr)] = sig
            if sig.linux_arm64_nr is not None:
                cls._NR_LOOKUP[("linux_arm64", sig.linux_arm64_nr)] = sig
            if sig.darwin_arm64_nr is not None:
                cls._NR_LOOKUP[("darwin_arm64", sig.darwin_arm64_nr)] = sig
            if sig.linux_x86_nr is not None:
                cls._NR_LOOKUP[("linux_x86", sig.linux_x86_nr)] = sig

    @classmethod
    def get_signature(cls, name: str) -> FunctionSignature | None:
        cls.initialize()
        clean = name.strip()
        # Strip import prefixes, stubs, and PLT decorators
        clean = re.sub(r'[@_].*$', '', clean.lstrip('_'))
        if not clean:
            clean = name.strip().lstrip('_')
        return cls._CATALOG.get(clean) or cls._CATALOG.get(name.strip())

    @classmethod
    def get_syscall_by_nr(cls, nr: int, arch_name: str) -> FunctionSignature | None:
        cls.initialize()
        return cls._NR_LOOKUP.get((arch_name, nr))


class AbiConvention:
    """Hardware and operating system ABI parameter mapping and register normalization."""

    REGISTER_ALIASES: dict[str, set[str]] = {
        "rdi": {"rdi", "edi", "di", "dil"},
        "rsi": {"rsi", "esi", "si", "sil"},
        "rdx": {"rdx", "edx", "dx", "dl", "dh"},
        "rcx": {"rcx", "ecx", "cx", "cl", "ch"},
        "r8":  {"r8", "r8d", "r8w", "r8b"},
        "r9":  {"r9", "r9d", "r9w", "r9b"},
        "r10": {"r10", "r10d", "r10w", "r10b"},
        "rax": {"rax", "eax", "ax", "al", "ah"},
        "rbx": {"rbx", "ebx", "bx", "bl", "bh"},
        "rsp": {"rsp", "esp", "sp", "spl"},
        "rbp": {"rbp", "ebp", "bp", "bpl"},

        "x0": {"x0", "w0"},
        "x1": {"x1", "w1"},
        "x2": {"x2", "w2"},
        "x3": {"x3", "w3"},
        "x4": {"x4", "w4"},
        "x5": {"x5", "w5"},
        "x6": {"x6", "w6"},
        "x7": {"x7", "w7"},
        "x8": {"x8", "w8"},
        "x16": {"x16", "w16"},
        "sp": {"sp", "wsp"},
        "x29": {"x29", "w29", "fp"},
        "x30": {"x30", "w30", "lr"},
    }

    @classmethod
    def get_param_registers(cls, arch: ArchitectureType | str, is_syscall: bool = False) -> list[str]:
        if arch in (ArchitectureType.X86_64, "x86_64"):
            if is_syscall:
                return ["rdi", "rsi", "rdx", "r10", "r8", "r9"]
            return ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        elif arch in (ArchitectureType.ARM64, ArchitectureType.AARCH64, "arm64"):
            return ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
        elif arch in (ArchitectureType.X86, "x86"):
            return []  # Stack-based
        return ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]

    @classmethod
    def get_return_register(cls, arch: ArchitectureType | str) -> str:
        if arch in (ArchitectureType.ARM64, ArchitectureType.AARCH64, "arm64"):
            return "x0"
        return "rax"

    @classmethod
    def match_register(cls, target_reg: str, operand_reg: str) -> bool:
        t = target_reg.lower().strip()
        op = operand_reg.lower().strip()
        if t == op:
            return True
        aliases = cls.REGISTER_ALIASES.get(t, {t})
        return op in aliases


class BackwardInstructionTracer:
    """Traces backwards from call sites to recover argument definitions."""

    @classmethod
    def trace_arguments(
        cls,
        instructions: list[Instruction],
        call_idx: int,
        sig: FunctionSignature,
        arch: ArchitectureType | str,
        is_direct_syscall: bool = False,
    ) -> list[ResolvedArgument]:
        param_regs = AbiConvention.get_param_registers(arch, is_syscall=is_direct_syscall)
        resolved_args: list[ResolvedArgument] = []

        for p_idx, param_def in enumerate(sig.parameters):
            if p_idx >= len(param_regs):
                break

            target_reg = param_regs[p_idx]
            resolved = ResolvedArgument(
                param_index=p_idx,
                param_def=param_def,
                target_register=target_reg,
                suggested_name=param_def.default_name_hint or param_def.name,
                suggested_type=param_def.type,
            )

            # Scan backward from call instruction
            last_adrp: dict[str, int] = {}
            for i in range(call_idx - 1, -1, -1):
                ins = instructions[i]
                ops = [op.strip() for op in ins.op_str.split(',')]
                if not ops:
                    continue

                dest_reg = ops[0].lower()

                # Keep track of adrp for ARM64 ADRP+ADD
                if ins.mnemonic == 'adrp' and len(ops) >= 2:
                    val_str = ops[1].lstrip('#').strip()
                    with contextlib.suppress(ValueError):
                        last_adrp[dest_reg] = int(val_str, 16 if '0x' in val_str else 10)

                if not AbiConvention.match_register(target_reg, dest_reg):
                    continue

                resolved.def_instruction = ins

                # Pattern A: Immediate value
                # e.g., mov w0, #0 or mov edi, 0 or xor edi, edi
                if ins.mnemonic == 'xor' and len(ops) >= 2 and ops[0] == ops[1]:
                    resolved.value_kind = "immediate"
                    resolved.immediate_value = 0
                    break
                elif ins.mnemonic in ('mov', 'movz', 'movn') and len(ops) >= 2:
                    val_str = ops[1].lstrip('#').strip()
                    try:
                        val = int(val_str, 16 if '0x' in val_str else 10)
                        resolved.value_kind = "immediate"
                        resolved.immediate_value = val
                        break
                    except ValueError:
                        pass

                # Pattern B: Stack address calculation (Local stack buffer)
                # ARM64: add x1, sp, #0x28 or sub x0, x29, #0x10
                if ins.mnemonic in ('add', 'sub') and len(ops) >= 3:
                    base = ops[1].lower()
                    if base in ('sp', 'wsp', 'x29', 'w29', 'fp'):
                        off_str = ops[2].lstrip('#').strip()
                        try:
                            off = int(off_str, 16 if '0x' in off_str else 10)
                            resolved.value_kind = "stack_offset"
                            resolved.base_register = base
                            resolved.stack_offset = off if ins.mnemonic == 'add' else -off
                            break
                        except ValueError:
                            pass
                # x86: lea rsi, [rsp + 0x10] or lea rdi, [rbp - 0x20]
                elif ins.mnemonic == 'lea' and len(ops) >= 2:
                    stack_match = re.search(r'\[(rsp|esp|rbp|ebp)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]', ops[1], re.IGNORECASE)
                    if stack_match:
                        base = stack_match.group(1).lower()
                        sign = 1 if stack_match.group(2) == '+' else -1
                        off_val = int(stack_match.group(3), 16 if '0x' in stack_match.group(3) else 10)
                        resolved.value_kind = "stack_offset"
                        resolved.base_register = base
                        resolved.stack_offset = sign * off_val
                        break

                # Pattern C: Global symbol or string reference
                if ins.mnemonic in ('add', 'ldr') and len(ops) >= 3 and ops[1].lower() in last_adrp:
                    base_reg = ops[1].lower()
                    off_str = ops[2].lstrip('#').strip()
                    try:
                        off = int(off_str, 16 if '0x' in off_str else 10)
                        resolved.value_kind = "symbol_address"
                        resolved.symbol_address = last_adrp[base_reg] + off
                        break
                    except ValueError:
                        pass
                elif ins.mnemonic == 'lea' and 'rip' in ins.op_str.lower():
                    disp_match = re.search(r'rip\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)', ins.op_str, re.IGNORECASE)
                    if disp_match:
                        sign = 1 if disp_match.group(1) == '+' else -1
                        disp_val = int(disp_match.group(2), 16 if '0x' in disp_match.group(2) else 10)
                        resolved.value_kind = "symbol_address"
                        resolved.symbol_address = ins.address + ins.size + (sign * disp_val)
                        break

                # Found definition instruction
                break

            # Disambiguate semantic names based on values
            if resolved.value_kind == "immediate":
                imm = resolved.immediate_value
                if param_def.semantic_role == "file_descriptor" and imm is not None:
                    if imm == 0:
                        resolved.suggested_name = "stdin_fd"
                    elif imm == 1:
                        resolved.suggested_name = "stdout_fd"
                    elif imm == 2:
                        resolved.suggested_name = "stderr_fd"
                    else:
                        resolved.suggested_name = "fd"
            elif resolved.value_kind == "stack_offset":
                if param_def.semantic_role == "buffer_pointer":
                    resolved.suggested_name = param_def.default_name_hint or "local_buf"

            resolved_args.append(resolved)

        return resolved_args


class ForwardInstructionTracer:
    """Traces forward from call sites to check where return values are stored or checked."""

    @classmethod
    def trace_return_value(
        cls,
        instructions: list[Instruction],
        call_idx: int,
        sig: FunctionSignature,
        arch: ArchitectureType | str,
    ) -> dict[str, Any] | None:
        if sig.return_type == "void":
            return None

        ret_reg = AbiConvention.get_return_register(arch)
        max_lookahead = min(len(instructions), call_idx + 6)

        for i in range(call_idx + 1, max_lookahead):
            ins = instructions[i]
            ops = [op.strip() for op in ins.op_str.split(',')]
            if not ops:
                continue

            # Check for stack store:
            # ARM64: str x0, [sp, #0x10]
            if ins.mnemonic in ('str', 'strb', 'strh') and len(ops) >= 2:
                src_reg = ops[0].lower()
                if AbiConvention.match_register(ret_reg, src_reg):
                    stack_match = re.search(r'\[(sp|wsp|x29|fp)\s*(?:,\s*#?(0x[0-9a-fA-F]+|\d+))?\]', ins.op_str, re.IGNORECASE)
                    if stack_match:
                        off_str = stack_match.group(2) or "0"
                        off = int(off_str, 16 if '0x' in off_str else 10)
                        return {
                            "kind": "stack_store",
                            "stack_offset": off,
                            "suggested_name": sig.return_name_hint or "status",
                            "suggested_type": sig.return_type,
                            "instruction": ins,
                        }
            # x86: mov [rbp - 0x18], rax
            elif ins.mnemonic == 'mov' and len(ops) >= 2:
                src_reg = ops[1].lower()
                if AbiConvention.match_register(ret_reg, src_reg):
                    stack_match = re.search(r'\[(rsp|esp|rbp|ebp)\s*([+-])\s*(0x[0-9a-fA-F]+|\d+)\]', ops[0], re.IGNORECASE)
                    if stack_match:
                        sign = 1 if stack_match.group(2) == '+' else -1
                        off_val = int(stack_match.group(3), 16 if '0x' in stack_match.group(3) else 10)
                        return {
                            "kind": "stack_store",
                            "stack_offset": sign * off_val,
                            "suggested_name": sig.return_name_hint or "status",
                            "suggested_type": sig.return_type,
                            "instruction": ins,
                        }

        return None


class SyscallPropagator:
    """Coordinates syscall and libc semantic propagation across binary sessions."""

    @classmethod
    def propagate_session(cls, session: BinarySession) -> list[EvidenceTag]:
        tags: list[EvidenceTag] = []
        SyscallDatabase.initialize()

        arch = session.artifact.architecture
        bitness = session.artifact.bitness
        try:
            disasm = CapstoneDisassembler(arch=arch, bitness=bitness)
        except Exception:
            return tags

        # Map symbol stubs and known functions to signatures
        stub_sigs: dict[int, FunctionSignature] = {}
        for sym in session.symbols.values():
            target_sig = SyscallDatabase.get_signature(sym.name)
            if target_sig:
                stub_sigs[sym.address] = target_sig
        for func in session.functions.values():
            if func.name:
                target_sig = SyscallDatabase.get_signature(func.name)
                if target_sig:
                    stub_sigs[func.address] = target_sig

        for func_addr, func in session.functions.items():
            func_size = func.size if func.size > 0 else 1024
            raw_bytes = FormatStringGrounder._read_bytes(session, func_addr, func_size)
            if not raw_bytes:
                continue

            insns = disasm.disassemble_bytes(raw_bytes, func_addr)
            for idx, ins in enumerate(insns):
                sig: FunctionSignature | None = None
                is_direct_syscall = False

                # Case 1: Call to imported stub
                if ins.mnemonic in ('bl', 'call'):
                    clean_op = ins.op_str.lstrip('#').strip()
                    try:
                        target_addr = int(clean_op, 16 if '0x' in clean_op else 10)
                        if target_addr in stub_sigs:
                            sig = stub_sigs[target_addr]
                    except ValueError:
                        pass

                    if not sig:
                        for s_name in SyscallDatabase._CATALOG:
                            if s_name in ins.op_str:
                                sig = SyscallDatabase.get_signature(s_name)
                                break

                # Case 2: Direct syscall instruction (svc #0 or syscall)
                elif ins.mnemonic in ('svc', 'syscall', 'int'):
                    is_direct_syscall = True
                    # Trace syscall number in x8 (Linux ARM64), x16 (Darwin ARM64), or rax (x86_64)
                    nr_reg = "x16" if "darwin" in str(session.artifact.format).lower() else ("x8" if "arm" in str(arch).lower() else "rax")
                    syscall_nr = None
                    for b_i in range(idx - 1, max(-1, idx - 8), -1):
                        b_ins = insns[b_i]
                        b_ops = [op.strip() for op in b_ins.op_str.split(',')]
                        if b_ops and AbiConvention.match_register(nr_reg, b_ops[0]):
                            val_str = b_ops[1].lstrip('#').strip() if len(b_ops) > 1 else ""
                            try:
                                syscall_nr = int(val_str, 16 if '0x' in val_str else 10)
                                break
                            except ValueError:
                                pass
                    if syscall_nr is not None:
                        arch_key = "darwin_arm64" if "darwin" in str(session.artifact.format).lower() else ("linux_arm64" if "arm" in str(arch).lower() else "linux_x86_64")
                        sig = SyscallDatabase.get_syscall_by_nr(syscall_nr, arch_key)

                if not sig:
                    continue

                # Trace arguments backward
                resolved_args = BackwardInstructionTracer.trace_arguments(
                    instructions=insns,
                    call_idx=idx,
                    sig=sig,
                    arch=arch,
                    is_direct_syscall=is_direct_syscall,
                )

                for arg in resolved_args:
                    suggested_name = arg.suggested_name or arg.param_def.name
                    suggested_type = arg.suggested_type or arg.param_def.type

                    tag = EvidenceTag(
                        tag_id=f"ev_syscall_{sig.name}_0x{ins.address:x}_arg{arg.param_index}",
                        target_type=TargetType.VARIABLE if arg.value_kind == "stack_offset" else TargetType.PARAMETER,
                        target_id=f"func:0x{func_addr:x}:var:{suggested_name}",
                        suggested_name=suggested_name,
                        suggested_type=suggested_type,
                        source=EvidenceSource.SYSCALL_ABI,
                        evidence_type="SYSCALL_ABI",
                        confidence=1.0,
                        raw_anchor=f"call:{sig.name}@0x{ins.address:x}:arg{arg.param_index}={arg.target_register}",
                        explanation=(
                            f"Grounded by POSIX call '{sig.name}' at 0x{ins.address:x}: "
                            f"parameter '{arg.param_def.name}' requires type '{arg.param_def.type}' "
                            f"passed via {arg.target_register}"
                        ),
                        context_snippet=f"0x{ins.address:x}: {ins.mnemonic} {ins.op_str}",
                        is_immutable=True,
                    )
                    session.attach_evidence(tag)
                    tags.append(tag)

                # Trace return value forward
                ret_info = ForwardInstructionTracer.trace_return_value(
                    instructions=insns,
                    call_idx=idx,
                    sig=sig,
                    arch=arch,
                )
                if ret_info:
                    ret_tag = EvidenceTag(
                        tag_id=f"ev_syscall_{sig.name}_0x{ins.address:x}_ret",
                        target_type=TargetType.VARIABLE,
                        target_id=f"func:0x{func_addr:x}:var:{ret_info['suggested_name']}",
                        suggested_name=ret_info["suggested_name"],
                        suggested_type=ret_info["suggested_type"],
                        source=EvidenceSource.SYSCALL_ABI,
                        evidence_type="SYSCALL_ABI",
                        confidence=1.0,
                        raw_anchor=f"call:{sig.name}@0x{ins.address:x}:return={AbiConvention.get_return_register(arch)}",
                        explanation=f"Return value of '{sig.name}' stored at stack offset {ret_info['stack_offset']}",
                        is_immutable=True,
                    )
                    session.attach_evidence(ret_tag)
                    tags.append(ret_tag)

        return tags
