import os
import subprocess
import tempfile
from pathlib import Path

from .base import Decompiler

class GhidraDecompiler(Decompiler):
    """
    Decompiler implementation for Ghidra.
    """

    def __init__(self, ghidra_path: str):
        self.ghidra_path = ghidra_path

    @property
    def name(self) -> str:
        return "ghidra"

    def decompile(self, binary_path: str, output_dir: str, analysis_results: dict = None) -> str:
        """
        Decompiles the binary at the given path and returns the path to the decompiled C code.
        """
        output_c_filename = f"decompiled_{self.name}.c"
        decompiled_path = os.path.join(output_dir, output_c_filename)

        functions_to_decompile = []
        if analysis_results and "functions_to_decompile" in analysis_results:
            functions_to_decompile = analysis_results["functions_to_decompile"]

        with tempfile.TemporaryDirectory() as temp_dir:
            project_name = "ghidra_project"
            script_path = os.path.join(temp_dir, "DecompileScript.java")

            with open(script_path, "w") as f:
                f.write(self._get_ghidra_script(output_dir, output_c_filename, functions_to_decompile))

            ghidra_headless = os.path.join(self.ghidra_path, "support", "analyzeHeadless")
            cmd = [
                ghidra_headless,
                temp_dir,
                project_name,
                "-import",
                binary_path,
                "-postScript",
                os.path.basename(script_path),
                "-scriptPath",
                temp_dir,
                "-deleteProject",
            ]

            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"Error running Ghidra: {result.stderr}")

        if not os.path.exists(decompiled_path):
            raise FileNotFoundError(f"Ghidra output not found at {decompiled_path}")

        return decompiled_path

    def _get_ghidra_script(self, output_dir: str, output_c_filename: str, functions_to_decompile: list = None) -> str:
        function_logic = ""
        if functions_to_decompile:
            function_logic = f"""
            AddressSetView restrictedSet = new AddressSet();
            """
            for func_addr in functions_to_decompile:
                function_logic += f'restrictedSet.add(toAddr("{func_addr}"));\n'
            function_logic += """
            for (Function func : currentProgram.getFunctionManager().getFunctions(restrictedSet, true)) {
                DecompileResults res = iface.decompileFunction(func, 0, new ConsoleTaskMonitor());
                if (res.decompileCompleted()) {
                    out.println(res.getDecompiledFunction().getC());
                }
            }
            """
        else:
            function_logic = """
            for (Function func : currentProgram.getFunctionManager().getFunctions(true)) {
                DecompileResults res = iface.decompileFunction(func, 0, new ConsoleTaskMonitor());
                if (res.decompileCompleted()) {
                    out.println(res.getDecompiledFunction().getC());
                }
            }
            """

        return f"""
import ghidra.app.decompiler.DecompInterface;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;


public class DecompileScript extends GhidraScript {{
    @Override
    protected void run() throws Exception {{
        DecompInterface iface = new DecompInterface();
        iface.openProgram(currentProgram);

        try (PrintWriter out = new PrintWriter(new File("{os.path.join(output_dir, output_c_filename)}"))) {{
            {function_logic}
        }}
    }}
}}
"""