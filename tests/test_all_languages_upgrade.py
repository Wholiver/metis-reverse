import os
import plistlib
import sqlite3
import struct
import tempfile
from pathlib import Path
import pytest

from metis_reverse.tools.handlers import MetisToolDispatcher
from metis_reverse.services.family_adapters import FamilyAdapters
from metis_reverse.services.polyglot_detector import PolyglotDetector
from metis_reverse.storage.artifact_tree import ArtifactTree


@pytest.fixture
def dispatcher():
    return MetisToolDispatcher()


def test_120mb_large_file_streaming(dispatcher, tmp_path):
    """1. Large file (>100MB) no-error pass-through and streaming slice read."""
    large_file = tmp_path / "large_sample_120mb.bin"
    # Create 120MB sparse file
    with open(large_file, "wb") as f:
        f.seek(120 * 1024 * 1024 - 1)
        f.write(b"\x00")
        f.seek(0)
        f.write(b"\x7fELF" + b"\x02\x01\x01\x00" * 8)
        # Write marker at 100MB
        f.seek(100 * 1024 * 1024)
        f.write(b"METIS_STREAMING_TEST_PAYLOAD_AT_100MB")

    assert large_file.stat().st_size == 120 * 1024 * 1024

    # 1. re_triage should succeed without 50MB deadlock
    triage_res = dispatcher.handle_re_triage({"file_path": str(large_file)})
    assert triage_res.get("status") != "error"
    assert triage_res["file_size_bytes"] == 120 * 1024 * 1024

    # 2. re_inspect should mount auto session and inspect without crashing
    inspect_res = dispatcher.handle_re_inspect({"target_path_or_artifact": str(large_file)})
    assert inspect_res["status"] == "success"
    assert inspect_res["file_size"] == 120 * 1024 * 1024
    session_id = inspect_res["session_id"]
    assert session_id.startswith("auto_")

    # 3. re_read_file_range at 100MB offset
    read_res = dispatcher.handle_re_read_file_range({
        "session_id": session_id,
        "offset": 100 * 1024 * 1024,
        "length": 37
    })
    assert read_res["status"] == "success"
    assert read_res["ascii_preview"] == "METIS_STREAMING_TEST_PAYLOAD_AT_100MB"

    # 4. Enforce R6 single slice size cap: max 64KB per call
    read_oversized = dispatcher.handle_re_read_file_range({
        "session_id": session_id,
        "offset": 0,
        "length": 128 * 1024  # requests 128KB
    })
    assert read_oversized["status"] == "success"
    assert read_oversized["size_read"] == 64 * 1024
    assert read_oversized["truncated"] is True


def test_app_bundle_bplist_and_sqlite(dispatcher, tmp_path):
    """2. macOS .app bundle with binary Info.plist, SQLite database, and auto artifact tree."""
    app_dir = tmp_path / "Sample.app"
    contents = app_dir / "Contents"
    macos = contents / "MacOS"
    resources = contents / "Resources"
    frameworks = contents / "Frameworks"

    macos.mkdir(parents=True)
    resources.mkdir(parents=True)
    frameworks.mkdir(parents=True)

    # 1. Main executable
    main_exec = macos / "Sample"
    main_exec.write_bytes(b"\xcf\xfa\xed\xfe\x07\x00\x00\x01" + b"\x00" * 128)  # Mach-O 64-bit arm64 header

    # 2. Binary Info.plist (bplist00)
    plist_data = {
        "CFBundleIdentifier": "com.metis.sample",
        "CFBundleName": "SampleApp",
        "CFBundleExecutable": "Sample",
        "CFBundleVersion": "1.0.0",
        "CFBundleShortVersionString": "1.0"
    }
    plist_file = contents / "Info.plist"
    with open(plist_file, "wb") as f:
        plistlib.dump(plist_data, f, fmt=plistlib.FMT_BINARY)

    # 3. Embedded SQLite DB
    db_file = resources / "app.sqlite"
    conn = sqlite3.connect(str(db_file))
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT);")
    cur.execute("CREATE TABLE config (key TEXT PRIMARY KEY, val TEXT);")
    cur.execute("INSERT INTO users VALUES (1, 'admin', 'superuser');")
    cur.execute("INSERT INTO config VALUES ('api_url', 'https://api.example.com');")
    conn.commit()
    conn.close()

    # 4. Native addon .node
    node_file = frameworks / "bridge.node"
    node_file.write_bytes(b"\xcf\xfa\xed\xfe\x07\x00\x00\x01\x00" * 32)

    # Inspect the .app directory directly using re_inspect (Universal Omni Entry)
    res = dispatcher.handle_re_inspect({"target_path_or_artifact": str(app_dir)})
    assert res["status"] == "success"
    assert "macos_app" in res["families"] or "bundle" in res["families"]
    assert res["sub_artifacts_count"] >= 3

    # Check parsed plist info
    deep = res.get("deep_analysis", {})
    assert "macos_bundle_info" in deep
    bundle_info = deep["macos_bundle_info"]
    assert bundle_info["CFBundleIdentifier"] == "com.metis.sample"
    assert bundle_info["CFBundleExecutable"] == "Sample"

    # Check tree status
    tree_status = dispatcher.handle_re_tree_status({"session_id": res["session_id"]})
    assert tree_status["status"] == "success"
    assert tree_status["total_artifacts"] >= 4

    # Check SQLite extraction on the sqlite artifact
    sqlite_node = None
    for sub in res["sub_artifacts"]:
        if "sqlite" in sub["name"].lower():
            sqlite_node = sub
            break
    assert sqlite_node is not None

    db_inspect = dispatcher.handle_re_inspect({
        "session_id": res["session_id"],
        "artifact_id": sqlite_node["id"]
    })
    assert db_inspect["status"] == "success"
    sqlite_analysis = db_inspect["deep_analysis"]["sqlite"]
    assert sqlite_analysis["is_sqlite_db"] is True
    assert "users" in sqlite_analysis["table_names"]
    assert "config" in sqlite_analysis["table_names"]
    assert "CREATE TABLE users" in sqlite_analysis["schemas"]["users"]
    assert sqlite_analysis["row_counts"]["users"] == 1


def test_jvm_class_bytecode_parser():
    """3a. Standard JVM Class 0xCAFEBABE binary parsing & bytecode disassembler."""
    cp_entries = [
        b"\x07\x00\x02",                    # 1: Classref -> #2
        b"\x01\x00\x04Mini",                # 2: Utf8 "Mini"
        b"\x07\x00\x04",                    # 3: Classref -> #4
        b"\x01\x00\x10java/lang/Object",    # 4: Utf8 "java/lang/Object"
        b"\x01\x00\x03add",                 # 5: Utf8 "add"
        b"\x01\x00\x05(II)I",               # 6: Utf8 "(II)I"
        b"\x01\x00\x04Code",                # 7: Utf8 "Code"
    ]
    raw_class = bytearray()
    raw_class.extend(b"\xca\xfe\xba\xbe")   # magic
    raw_class.extend(b"\x00\x00")           # minor 0
    raw_class.extend(b"\x00\x3d")           # major 61 (Java 17)
    raw_class.extend(struct.pack(">H", len(cp_entries) + 1))
    for entry in cp_entries:
        raw_class.extend(entry)

    raw_class.extend(b"\x00\x21")           # access_flags: ACC_PUBLIC | ACC_SUPER
    raw_class.extend(b"\x00\x01")           # this_class: #1
    raw_class.extend(b"\x00\x03")           # super_class: #3
    raw_class.extend(b"\x00\x00")           # interfaces_count: 0
    raw_class.extend(b"\x00\x00")           # fields_count: 0
    raw_class.extend(b"\x00\x01")           # methods_count: 1

    # Method: public static add(II)I
    raw_class.extend(b"\x00\x09")           # access_flags: ACC_PUBLIC | ACC_STATIC
    raw_class.extend(b"\x00\x05")           # name_index: #5 "add"
    raw_class.extend(b"\x00\x06")           # descriptor_index: #6 "(II)I"
    raw_class.extend(b"\x00\x01")           # attributes_count: 1

    # Code attribute
    code_bytes = b"\x1a\x1b\x60\xac"        # iload_0, iload_1, iadd, ireturn
    code_attr = bytearray()
    code_attr.extend(b"\x00\x02")           # max_stack: 2
    code_attr.extend(b"\x00\x02")           # max_locals: 2
    code_attr.extend(struct.pack(">I", len(code_bytes)))
    code_attr.extend(code_bytes)
    code_attr.extend(b"\x00\x00")           # exception_table_length: 0
    code_attr.extend(b"\x00\x00")           # attributes_count: 0

    raw_class.extend(b"\x00\x07")           # attribute_name_index: #7 "Code"
    raw_class.extend(struct.pack(">I", len(code_attr)))
    raw_class.extend(code_attr)
    raw_class.extend(b"\x00\x00")           # class attributes_count: 0

    res = FamilyAdapters.analyze_jvm_android(bytes(raw_class))
    assert res["is_jvm_class"] is True
    assert res["class_name"] == "Mini"
    assert res["super_class"] == "java/lang/Object"
    assert len(res["methods"]) == 1
    m = res["methods"][0]
    assert m["name"] == "add"
    assert m["descriptor"] == "(II)I"
    assert "ACC_PUBLIC" in m["flags"]
    assert "ACC_STATIC" in m["flags"]
    assert m["code_length"] == 4
    # Bytecode instructions
    assert m["instructions"] == ["0: iload_0", "1: iload_1", "2: iadd", "3: ireturn"]


def test_wasm_parser():
    """3b. WebAssembly binary parser: sections, imports, and exports."""
    wasm = bytearray(b"\x00asm\x01\x00\x00\x00")
    
    # Section 1 (Type Section): 1 type, func () -> ()
    type_sec = b"\x01\x60\x00\x00"
    wasm.append(1)
    wasm.extend(struct.pack("B", len(type_sec)))
    wasm.extend(type_sec)

    # Section 3 (Function Section): 1 func of type 0
    func_sec = b"\x01\x00"
    wasm.append(3)
    wasm.extend(struct.pack("B", len(func_sec)))
    wasm.extend(func_sec)

    # Section 7 (Export Section): 1 export "calculateSum" func 0
    export_name = b"calculateSum"
    export_sec = bytearray()
    export_sec.append(1)
    export_sec.append(len(export_name))
    export_sec.extend(export_name)
    export_sec.append(0)
    export_sec.append(0)

    wasm.append(7)
    wasm.extend(struct.pack("B", len(export_sec)))
    wasm.extend(export_sec)

    res = FamilyAdapters.analyze_wasm(bytes(wasm))
    assert res["is_wasm"] is True
    assert res["wasm_version"] == 1
    assert "calculateSum" in [exp["name"] for exp in res["exports"]]
    assert len(res["sections"]) == 3


def test_il2cpp_metadata_parser():
    """3c. Unity IL2CPP global-metadata.dat string literals & type definitions."""
    hdr = bytearray(b"\xaf\x1b\xb1\xfa")
    hdr.extend(struct.pack("<I", 29))  # version 29
    hdr.extend(b"\x00" * 256)

    lit_meta_off = 0x120
    lit_data_off = 0x140
    str_off = 0x160
    type_def_off = 0x180

    struct.pack_into("<II", hdr, 0x08, lit_meta_off, 1 * 8)
    struct.pack_into("<II", hdr, 0x10, lit_data_off, 64)
    struct.pack_into("<II", hdr, 0x18, str_off, 64)
    struct.pack_into("<II", hdr, 160, type_def_off, 48)

    payload = bytearray(hdr)
    if len(payload) < 0x300:
        payload.extend(b"\x00" * (0x300 - len(payload)))

    # String literal metadata: length=11, offset=0
    struct.pack_into("<II", payload, lit_meta_off, 11, 0)
    payload[lit_data_off:lit_data_off + 11] = b"UnitySecret"

    payload[str_off:str_off + 15] = b"GameManager\x00Player\x00"
    struct.pack_into("<II", payload, type_def_off, 0, 0)

    res = FamilyAdapters.analyze_il2cpp(bytes(payload))
    assert res["is_il2cpp_metadata"] is True
    assert res["metadata_version"] == 29
    assert "UnitySecret" in res["string_literals_sample"]
    assert any("GameManager" in t for t in res["types_recovered"])


def test_erlang_beam_parser():
    """3d. Erlang/Elixir BEAM parser (FOR1 container, AtU8, ExpT)."""
    beam_header = b"FOR1\x00\x00\x00\x80BEAM"
    atoms_data = bytearray()
    atoms_data.extend(struct.pack(">I", 3))  # 3 atoms
    atoms_data.extend(b"\x07my_atom")
    atoms_data.extend(b"\x05login")
    atoms_data.extend(b"\x08password")
    while len(atoms_data) % 4 != 0:
        atoms_data.append(0)

    atu8_chunk = b"AtU8" + struct.pack(">I", len(atoms_data)) + bytes(atoms_data)

    expt_data = bytearray()
    expt_data.extend(struct.pack(">I", 1))  # 1 export
    expt_data.extend(struct.pack(">III", 2, 2, 1))  # atom 2 ("login"), arity 2, label 1
    while len(expt_data) % 4 != 0:
        expt_data.append(0)

    expt_chunk = b"ExpT" + struct.pack(">I", len(expt_data)) + bytes(expt_data)
    raw_beam = beam_header + atu8_chunk + expt_chunk

    res = FamilyAdapters.analyze_erlang_beam(raw_beam)
    assert res["is_beam_bytecode"] is True
    assert "my_atom" in res["atoms_sample"]
    assert "login" in res["atoms_sample"]
    assert "login/2" in res["exported_functions"]


def test_delphi_dfm_parser():
    """3e. Delphi / Object Pascal DFM binary form (TPF0) parser."""
    dfm = bytearray(b"TPF0")
    dfm.append(0)  # flag
    dfm.append(9)
    dfm.extend(b"TMainForm")
    dfm.append(8)
    dfm.extend(b"MainForm")
    dfm.append(7)
    dfm.extend(b"Caption")
    dfm.append(6)
    dfm.append(12)
    dfm.extend(b"Login Window")
    dfm.append(0)

    res = FamilyAdapters.analyze_delphi_dfm(bytes(dfm))
    assert res["is_delphi_binary"] is True
    assert res["has_dfm_binary_form"] is True
    text = res["dfm_text_representation"]
    assert "TMainForm" in text
    assert "Caption" in text
    assert "Login Window" in text
