"""
Metis Reverse - Ghidra Headless Integration Runner
Invokes analyzeHeadless with embedded script execution, temporary project management,
and structured JSON session population.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any

from metis_reverse.backends.base import BaseBackend
from metis_reverse.core.evidence import EvidenceStore
from metis_reverse.core.models import (
    BasicBlock,
    BinarySession,
    DecompiledCode,
    Function,
    Instruction,
    Symbol,
    SymbolType,
    TargetArtifact,
    Variable,
)

logger = logging.getLogger("metis_reverse.backends.ghidra_headless")

_JAVA_EXPORTER_SCRIPT = """import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import java.io.FileWriter;
import java.io.PrintWriter;

public class MetisGhidraExport extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputPath = args.length > 0 ? args[0] : "export.json";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        PrintWriter writer = new PrintWriter(new FileWriter(outputPath));
        writer.println("{");
        writer.println("  \\"functions\\": [");

        FunctionIterator funcIter = currentProgram.getListing().getFunctions(true);
        boolean firstFunc = true;
        while (funcIter.hasNext() && !monitor.isCancelled()) {
            Function fn = funcIter.next();
            if (!firstFunc) writer.println(",");
            firstFunc = false;

            DecompileResults results = decomp.decompileFunction(fn, 60, monitor);
            String decompCode = (results != null && results.getDecompiledFunction() != null)
                ? results.getDecompiledFunction().getC()
                : "/* Decompilation unavailable */";

            decompCode = decompCode.replace("\\\\", "\\\\\\\\")
                                   .replace("\\"", "\\\\\\"")
                                   .replace("\\r", "")
                                   .replace("\\n", "\\\\n");

            writer.println("    {");
            writer.println("      \\"address\\": \\"0x" + Long.toHexString(fn.getEntryPoint().getOffset()) + "\\",");
            writer.println("      \\"name\\": \\"" + fn.getName() + "\\",");
            writer.println("      \\"return_type\\": \\"" + fn.getReturnType().getName() + "\\",");
            writer.println("      \\"decompiled_code\\": \\"" + decompCode + "\\",");
            writer.println("      \\"size\\": " + fn.getBody().getNumAddresses() + ",");
            writer.println("      \\"parameters\\": [");
            Parameter[] params = fn.getParameters();
            for (int i = 0; i < params.length; i++) {
                writer.print("        {\\"name\\": \\"" + params[i].getName() + "\\", \\"type\\": \\"" + params[i].getDataType().getName() + "\\"}");
                if (i + 1 < params.length) writer.print(",");
                writer.println();
            }
            writer.println("      ]");
            writer.print("    }");
        }
        writer.println("\\n  ]");
        writer.println("}");
        writer.close();
    }
}
"""


class GhidraHeadlessBackend(BaseBackend):
    """
    Subprocess runner for Ghidra analyzeHeadless.
    """

    def __init__(
        self,
        headless_path: str,
        timeout_seconds: int = 120,
        max_cpu: int = 4,
    ) -> None:
        self.headless_path = headless_path
        self.timeout_seconds = timeout_seconds
        self.max_cpu = max_cpu

    @property
    def name(self) -> str:
        return "ghidra"

    @property
    def tier(self) -> int:
        return 2

    def load_artifact(
        self, artifact_or_path: str | TargetArtifact
    ) -> BinarySession:
        if isinstance(artifact_or_path, TargetArtifact):
            artifact = artifact_or_path
        else:
            from metis_reverse.backends.tier1_native.binary_parser import LiefBinaryParser
            try:
                artifact, _, _ = LiefBinaryParser.parse(str(artifact_or_path))
            except Exception:
                artifact = TargetArtifact(path=str(artifact_or_path), format="ELF", architecture="x86_64")

        target_file_path = artifact.file_path or artifact.path
        logger.info("Starting Ghidra Headless analysis for %s", target_file_path)

        with tempfile.TemporaryDirectory(prefix="metis_ghidra_") as temp_dir:
            script_dir = Path(temp_dir) / "scripts"
            script_dir.mkdir(parents=True, exist_ok=True)
            script_file = script_dir / "MetisGhidraExport.java"
            script_file.write_text(_JAVA_EXPORTER_SCRIPT, encoding="utf-8")

            output_json = Path(temp_dir) / "output.json"
            proj_dir = Path(temp_dir) / "proj"
            proj_dir.mkdir(parents=True, exist_ok=True)

            cmd = [
                self.headless_path,
                str(proj_dir),
                "MetisTempProj",
                "-import",
                str(target_file_path),
                "-scriptPath",
                str(script_dir),
                "-postScript",
                "MetisGhidraExport.java",
                str(output_json),
                "-deleteProject",
                "-max-cpu",
                str(self.max_cpu),
            ]

            logger.debug("Executing Ghidra command: %s", " ".join(cmd))
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired as e:
                raise TimeoutError(f"Ghidra analyzeHeadless timed out after {self.timeout_seconds}s") from e

            if not output_json.exists():
                logger.error("Ghidra headless output json missing. Stderr: %s", proc.stderr)
                raise RuntimeError(f"Ghidra Headless failed to generate export: {proc.stderr[:400]}")

            export_data = json.loads(output_json.read_text(encoding="utf-8"))

        functions: dict[int, Function] = {}
        symbols: dict[Any, Symbol] = {}

        for item in export_data.get("functions", []):
            addr_int = int(item["address"], 16)
            name = item["name"]
            size = item.get("size", 32)
            ret_type = item.get("return_type", "void")
            code = item.get("decompiled_code", "")

            params = [
                Variable(name=p["name"], type=p["type"])
                for p in item.get("parameters", [])
            ]

            fn = Function(
                address=addr_int,
                name=name,
                size=size,
                is_stripped=False,
                basic_blocks=[
                    BasicBlock(start_address=addr_int, end_address=addr_int + size, size=size)
                ],
                parameters=params,
                return_type=ret_type,
                decompiled_code=code,
                evidence_tag_ids=[],
            )
            functions[addr_int] = fn
            sym = Symbol(
                address=addr_int,
                name=name,
                type=SymbolType.FUNCTION,
                size=size,
                confidence=1.0,
            )
            symbols[name] = sym
            symbols[addr_int] = sym

        session_id = f"ghidra-{uuid.uuid4().hex[:8]}"
        return BinarySession(
            session_id=session_id,
            artifact=artifact,
            backend_type="ghidra",
            functions=functions,
            symbols=symbols,
            evidence_store=EvidenceStore(),
        )

    def disassemble_range(
        self, session: BinarySession, start_addr: int, size: int
    ) -> list[Instruction]:
        from metis_reverse.backends.tier1_native.disassembler import CapstoneDisassembler
        disasm = CapstoneDisassembler(architecture=session.artifact.architecture)
        return disasm.disassemble(session.artifact.file_path, start_addr, size)

    def get_cfg(
        self, session: BinarySession, func_addr: int | None = None
    ) -> dict[str, Any]:
        nodes = []
        for fn in session.functions.values():
            if func_addr is not None and fn.address != func_addr:
                continue
            for bb in fn.basic_blocks:
                nodes.append({
                    "start": bb.start_address,
                    "end": bb.end_address,
                    "function": fn.name,
                })
        return {"nodes": nodes, "count": len(nodes)}

    def decompile_function(
        self, session: BinarySession, func_addr: int
    ) -> DecompiledCode:
        fn = session.functions.get(func_addr)
        if not fn or not fn.decompiled_code:
            raise KeyError(f"No decompiled code cached for function at 0x{func_addr:x}")

        code = (
            fn.decompiled_code.source_code
            if isinstance(fn.decompiled_code, DecompiledCode)
            else str(fn.decompiled_code)
        )
        return DecompiledCode(
            function_address=func_addr,
            function_name=fn.name,
            source_code=code,
            code=code,
            language="c",
        )

    def mutate_symbol(
        self, session: BinarySession, addr: int, new_name: str
    ) -> bool:
        fn = session.functions.get(addr)
        if not fn:
            return False
        old_name = fn.name
        fn.name = new_name
        if old_name in session.symbols:
            sym = session.symbols.pop(old_name)
            sym.name = new_name
            session.symbols[new_name] = sym
            session.symbols[addr] = sym
        return True

    def mutate_type(
        self, session: BinarySession, addr: int, new_type: str
    ) -> bool:
        fn = session.functions.get(addr)
        if not fn:
            return False
        fn.return_type = new_type
        return True
