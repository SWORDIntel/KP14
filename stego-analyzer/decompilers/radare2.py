import os
import subprocess

from .base import Decompiler

class Radare2Decompiler(Decompiler):
    """
    Decompiler implementation for Radare2.
    """

    def __init__(self, radare2_path: str):
        self.radare2_path = radare2_path

    @property
    def name(self) -> str:
        return "radare2"

    def decompile(self, binary_path: str, output_dir: str, analysis_results: dict = None) -> str:
        """
        Decompiles the binary at the given path and returns the path to the decompiled C code.
        """
        output_c_filename = f"decompiled_{self.name}.c"
        decompiled_path = os.path.join(output_dir, output_c_filename)

        functions_to_decompile = []
        if analysis_results and "functions_to_decompile" in analysis_results:
            functions_to_decompile = analysis_results["functions_to_decompile"]

        if functions_to_decompile:
            # Decompile specific functions
            with open(decompiled_path, "w") as f:
                for func in functions_to_decompile:
                    cmd = f"{self.radare2_path} -A -q -c 's {func}; pdg' {binary_path}"
                    result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if result.returncode == 0:
                        f.write(f"// Decompilation for function: {func}\n")
                        f.write(result.stdout)
                        f.write("\n\n")
                    else:
                        f.write(f"// Failed to decompile function: {func}\n")
                        f.write(f"// {result.stderr}\n\n")
        else:
            # Decompile the entire binary
            cmd = f"{self.radare2_path} -A -q -c 'pdg' {binary_path} > {decompiled_path}"
            result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"Error running Radare2: {result.stderr}")

        if not os.path.exists(decompiled_path):
            raise FileNotFoundError(f"Radare2 output not found at {decompiled_path}")

        return decompiled_path