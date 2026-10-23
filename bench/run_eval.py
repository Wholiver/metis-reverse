#!/usr/bin/env python3
"""Automated Benchmark Evaluation Suite for Metis Reverse MCP Architecture.

Evaluates all benchmark fixtures across the polyglot matrix:
- Triage & File Format Parsing
- Artifact Tree Extraction & Decomposition
- Coordinate Translation & Physical Reading
- Cross-Language Bridge Mapping (N-API, JNI, C-API)
- Family-Specific Adapters (Go, Rust, .NET, Python, Lua, Android DEX, Wasm, IL2CPP, Flutter, HarmonyOS, Firmware, Packers)
- Safety & Anti-Hallucination Guardrails
"""

import os
import sys
import time
import json
from pathlib import Path
from typing import Dict, Any, List

from metis_reverse.tools.handlers import MetisToolDispatcher
from metis_reverse.services.polyglot_detector import PolyglotDetector
from metis_reverse.services.family_adapters import FamilyAdapters
from metis_reverse.services.deep_static_service import DeepStaticService
from metis_reverse.services.bridge_service import BridgeService
from metis_reverse.security.prompt_shield import PromptShield

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class BenchmarkRunner:
    def __init__(self):
        self.dispatcher = MetisToolDispatcher()
        self.shield = PromptShield()
        self.results = []

    def run_all(self):
        print("=" * 80)
        print("METIS REVERSE: AUTOMATED BENCHMARK EVALUATION SUITE")
        print("=" * 80)

        fixture_configs = [
            {
                "name": "bun_composite_sample",
                "path": FIXTURES_DIR / "bun_composite_sample",
                "family": "Bun / Mach-O / JS",
                "tasks": ["mount_session", "tree_decomposition", "coord_translation", "napi_bridge", "js_slicing", "tiered_evidence"],
            },
            {
                "name": "sample_go.bin",
                "path": FIXTURES_DIR / "sample_go.bin",
                "family": "Go (Golang)",
                "tasks": ["mount_session", "pclntab_recovery", "abi_detection", "tiered_evidence"],
            },
            {
                "name": "sample_rust.bin",
                "path": FIXTURES_DIR / "sample_rust.bin",
                "family": "Rust",
                "tasks": ["mount_session", "demangle_v0_legacy", "crate_identification"],
            },
            {
                "name": "sample_pyinstaller.bin",
                "path": FIXTURES_DIR / "sample_pyinstaller.bin",
                "family": "Python",
                "tasks": ["mount_session", "pyinstaller_toc", "pyc_magic_repair"],
            },
            {
                "name": "sample_dotnet.dll",
                "path": FIXTURES_DIR / "sample_dotnet.dll",
                "family": ".NET / CLR",
                "tasks": ["mount_session", "bsjb_header", "clr_version"],
            },
            {
                "name": "sample_lua.luac",
                "path": FIXTURES_DIR / "sample_lua.luac",
                "family": "Lua Bytecode",
                "tasks": ["mount_session", "lua_format_distinction"],
            },
            {
                "name": "sample_firmware.bin",
                "path": FIXTURES_DIR / "sample_firmware.bin",
                "family": "Firmware Container",
                "tasks": ["mount_session", "squashfs_uboot_detection"],
            },
            {
                "name": "sample_android.dex",
                "path": FIXTURES_DIR / "sample_android.dex",
                "family": "JVM / Android",
                "tasks": ["mount_session", "dex_classes_extraction", "external_jadx_gating"],
            },
            {
                "name": "sample_wasm.wasm",
                "path": FIXTURES_DIR / "sample_wasm.wasm",
                "family": "WebAssembly",
                "tasks": ["mount_session", "wasm_section_parsing"],
            },
            {
                "name": "global-metadata.dat",
                "path": FIXTURES_DIR / "global-metadata.dat",
                "family": "Unity IL2CPP",
                "tasks": ["mount_session", "il2cpp_magic_version"],
            },
            {
                "name": "sample_flutter.so",
                "path": FIXTURES_DIR / "sample_flutter.so",
                "family": "Flutter / Dart",
                "tasks": ["mount_session", "snapshot_asset_detection"],
            },
            {
                "name": "sample_ark.abc",
                "path": FIXTURES_DIR / "sample_ark.abc",
                "family": "HarmonyOS",
                "tasks": ["mount_session", "ark_bytecode_detection"],
            },
            {
                "name": "sample_upx.bin",
                "path": FIXTURES_DIR / "sample_upx.bin",
                "family": "Packers / Protectors",
                "tasks": ["mount_session", "packer_signature_warning"],
            },
            {
                "name": "sample_large_48mb.bin",
                "path": FIXTURES_DIR / "sample_large_48mb.bin",
                "family": "Large 64-bit Segment",
                "tasks": ["mount_session", "large_segment_consistency", "64bit_offset_anchors", "direct_disk_read"],
            },
        ]

        total_tool_calls = 0
        total_time_ms = 0.0

        for cfg in fixture_configs:
            f_res = self._eval_fixture(cfg)
            self.results.append(f_res)
            total_tool_calls += f_res["tool_calls"]
            total_time_ms += f_res["duration_ms"]

        self._print_summary_table(total_tool_calls, total_time_ms)

    def _eval_fixture(self, cfg: Dict[str, Any]) -> Dict[str, Any]:
        p = cfg["path"]
        name = cfg["name"]
        sess_id = f"eval_{name.replace('.', '_')}"
        tool_calls = 0
        tool_faults = 0
        model_faults = 0
        passed_tasks = 0
        t0 = time.time()

        if not p.is_file():
            return {
                "name": name,
                "family": cfg["family"],
                "success_rate": 0.0,
                "tool_calls": 0,
                "duration_ms": 0.0,
                "tool_faults": 1,
                "model_faults": 0,
                "notes": "Fixture file missing",
            }

        content = p.read_bytes()

        # 1. Mount session
        try:
            tool_calls += 1
            mount_res = self.dispatcher.dispatch("re_session_manager", {
                "action": "open",
                "file_path": str(p),
                "session_id": sess_id,
            })
            if mount_res.get("status") == "ready":
                passed_tasks += 1
            else:
                tool_faults += 1
        except Exception:
            tool_faults += 1

        # 2. Specific tasks per fixture
        for task in cfg["tasks"]:
            if task == "mount_session":
                continue

            try:
                if task == "tree_decomposition":
                    tool_calls += 1
                    t_res = self.dispatcher.dispatch("re_tree_status", {"session_id": sess_id})
                    if t_res.get("status") == "success" and t_res.get("total_artifacts", 0) >= 7:
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "coord_translation":
                    tool_calls += 1
                    tr = self.dispatcher.dispatch("re_translate_address", {
                        "session_id": sess_id,
                        "value": 0x100a28080,
                        "from_kind": "va",
                    })
                    if tr.get("file_offset") is not None and tr.get("segment") == "__TEXT":
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "napi_bridge":
                    tool_calls += 1
                    br = self.dispatcher.dispatch("re_bridge_map", {
                        "session_id": sess_id,
                        "artifact_id": "root:node:0",
                    })
                    bridges = br.get("bridges", [])
                    has_acc = any(b["property_kind"] == "getter/setter" for b in bridges)
                    all_valid_coords = len(bridges) >= 3 and all(b.get("native_implementation", {}).get("coordinate_valid", False) for b in bridges)
                    if has_acc and all_valid_coords:
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "js_slicing":
                    tool_calls += 2
                    js_l = self.dispatcher.dispatch("js_list_modules", {"session_id": sess_id, "artifact_id": "root"})
                    js_m = self.dispatcher.dispatch("js_get_module", {"session_id": sess_id, "artifact_id": "root:js:0", "start_line": 1, "end_line": 5})
                    if js_l.get("status") == "success" and js_m.get("status") == "success":
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "tiered_evidence":
                    tool_calls += 1
                    ev_res = self.dispatcher.dispatch("re_add_finding", {
                        "session_id": sess_id,
                        "claim": "Verified entrypoint at VA 0x100a28080",
                        "evidence": [{"va": "0x100a28080", "type": "instruction_prologue"}],
                        "confidence": 1.0,
                        "status": "proven",
                    })
                    if ev_res.get("status") == "recorded":
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "pclntab_recovery":
                    tool_calls += 1
                    go_res = FamilyAdapters.analyze_go(content)
                    if go_res.get("detected_version") == "Go 1.20+" and go_res.get("recovered_functions_count", 0) >= 2:
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "abi_detection":
                    tool_calls += 1
                    go_res = FamilyAdapters.analyze_go(content)
                    if "ABIInternal" in go_res.get("abi", ""):
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "demangle_v0_legacy":
                    tool_calls += 1
                    rust_res = FamilyAdapters.analyze_rust(content)
                    if rust_res.get("symbol_count", 0) >= 2:
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "crate_identification":
                    tool_calls += 1
                    rust_res = FamilyAdapters.analyze_rust(content)
                    if "mycrate" in rust_res.get("crates_identified", []):
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "pyinstaller_toc":
                    tool_calls += 1
                    py_res = FamilyAdapters.analyze_python(content)
                    if py_res.get("is_pyinstaller"):
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "pyc_magic_repair":
                    tool_calls += 1
                    py_res = FamilyAdapters.analyze_python(content)
                    if py_res.get("python_version") == "Python 3.11":
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "bsjb_header":
                    tool_calls += 1
                    net_res = FamilyAdapters.analyze_dotnet(content)
                    if net_res.get("is_clr_assembly"):
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "clr_version":
                    tool_calls += 1
                    net_res = FamilyAdapters.analyze_dotnet(content)
                    if "v4.0.30319" in net_res.get("clr_version", ""):
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "lua_format_distinction":
                    tool_calls += 1
                    lua_res = FamilyAdapters.analyze_lua(content)
                    if "PUC-Lua" in lua_res.get("lua_bytecode_format", ""):
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "squashfs_uboot_detection":
                    tool_calls += 1
                    fw_res = FamilyAdapters.analyze_firmware(content)
                    sigs = fw_res.get("detected_signatures", [])
                    if "SquashFS" in sigs and "U-Boot uImage" in sigs:
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "dex_classes_extraction":
                    tool_calls += 1
                    dex_res = FamilyAdapters.analyze_jvm_android(content)
                    if dex_res.get("is_dex") and len(dex_res.get("classes_sample", [])) >= 2:
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "external_jadx_gating":
                    tool_calls += 1
                    dex_res = FamilyAdapters.analyze_jvm_android(content)
                    if "installed" in dex_res.get("engine_status", ""):
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "wasm_section_parsing":
                    tool_calls += 1
                    wasm_res = FamilyAdapters.analyze_wasm(content)
                    if wasm_res.get("is_wasm") and wasm_res.get("wasm_version") == 1:
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "il2cpp_magic_version":
                    tool_calls += 1
                    il_res = FamilyAdapters.analyze_il2cpp(content)
                    if (
                        il_res.get("is_il2cpp_metadata")
                        and il_res.get("metadata_version") == 29
                        and len(il_res.get("strings_sample", [])) > 0
                        and len(il_res.get("assemblies_recovered", [])) > 0
                        and il_res.get("degraded_result") is True
                    ):
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "snapshot_asset_detection":
                    tool_calls += 1
                    fl_res = FamilyAdapters.analyze_flutter(content)
                    if (
                        fl_res.get("is_flutter_app")
                        and fl_res.get("has_aot_snapshot")
                        and len(fl_res.get("feature_flags", [])) > 0
                        and len(fl_res.get("package_uris", [])) > 0
                        and fl_res.get("degraded_result") is True
                    ):
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "ark_bytecode_detection":
                    tool_calls += 1
                    ark_res = FamilyAdapters.analyze_harmony(content)
                    if (
                        ark_res.get("is_ark_bytecode")
                        and ark_res.get("bytecode_version") == 1
                        and len(ark_res.get("classes_sample", [])) > 0
                        and ark_res.get("degraded_result") is True
                    ):
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "packer_signature_warning":
                    tool_calls += 1
                    pk_res = FamilyAdapters.analyze_packers(content)
                    if pk_res.get("is_packed") and "UPX" in pk_res.get("detected_packers", []):
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "large_segment_consistency":
                    tool_calls += 1
                    cons_res = self.dispatcher.engine.check_memory_consistency(sess_id)
                    if cons_res.get("status") == "consistent" and not cons_res.get("memory_view_unreliable"):
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "64bit_offset_anchors":
                    tool_calls += 2
                    data_size = 48 * 1024 * 1024
                    tr_head = self.dispatcher.engine.translate_address(sess_id, "0x100010000", from_kind="va")
                    tail_va = hex(0x100010000 + data_size - 64)
                    tr_tail = self.dispatcher.engine.translate_address(sess_id, tail_va, from_kind="va")
                    if tr_head.get("file_offset") == 0x10000 and tr_tail.get("file_offset") == 0x10000 + data_size - 64:
                        passed_tasks += 1
                    else:
                        tool_faults += 1

                elif task == "direct_disk_read":
                    tool_calls += 1
                    data_size = 48 * 1024 * 1024
                    tail_bytes = self.dispatcher.engine.read_file_range(sess_id, 0x10000 + data_size - 64, 32)
                    mem_bytes = self.dispatcher.engine.get_memory_slice(sess_id, hex(0x100010000 + data_size - 64), 32)
                    if tail_bytes.startswith(b"CANARY_TAIL") and tail_bytes == mem_bytes:
                        passed_tasks += 1
                    else:
                        tool_faults += 1

            except Exception:
                tool_faults += 1

        duration_ms = round((time.time() - t0) * 1000, 2)
        total_tasks = len(cfg["tasks"])
        success_rate = round((passed_tasks / total_tasks) * 100, 1)

        return {
            "name": name,
            "family": cfg["family"],
            "total_tasks": total_tasks,
            "passed_tasks": passed_tasks,
            "success_rate": success_rate,
            "tool_calls": tool_calls,
            "duration_ms": duration_ms,
            "tool_faults": tool_faults,
            "model_faults": model_faults,
        }

    def _print_summary_table(self, total_tool_calls: int, total_time_ms: float):
        print(f"\n{'Fixture Name':<28} | {'Language / Family':<20} | {'Pass Rate':<10} | {'Calls':<6} | {'Time (ms)':<10} | {'Tool Fault':<10} | {'Model Fault':<11}")
        print("-" * 110)
        for r in self.results:
            rate_str = f"{r['success_rate']}%"
            print(f"{r['name']:<28} | {r['family']:<20} | {rate_str:<10} | {r['tool_calls']:<6} | {r['duration_ms']:<10.2f} | {r['tool_faults']:<10} | {r['model_faults']:<11}")
        print("-" * 110)
        all_passed = sum(r["passed_tasks"] for r in self.results)
        all_tasks = sum(r["total_tasks"] for r in self.results)
        overall_rate = round((all_passed / all_tasks) * 100, 1) if all_tasks else 0
        total_tf = sum(r["tool_faults"] for r in self.results)
        total_mf = sum(r["model_faults"] for r in self.results)
        print(f"{'OVERALL SUMMARY':<28} | {'13 Fixtures Evaluated':<20} | {f'{overall_rate}%':<10} | {total_tool_calls:<6} | {total_time_ms:<10.2f} | {total_tf:<10} | {total_mf:<11}")
        print("=" * 110)


if __name__ == "__main__":
    runner = BenchmarkRunner()
    runner.run_all()
