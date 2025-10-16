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

    def decompile(self, binary_path: str, output_dir: str) -> str:
        """
        Decompiles the binary at the given path and returns the path to the decompiled C code.
        """
        output_c_filename = f"decompiled_{self.name}.c"
        decompiled_path = os.path.join(output_dir, output_c_filename)

        cmd = [
            self.radare2_path,
            "-A",
            "-q",
            "-c",
            "pdg > " + decompiled_path,
            binary_path,
        ]

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            raise RuntimeError(f"Error running Radare2: {result.stderr}")

        if not os.path.exists(decompiled_path):
            raise FileNotFoundError(f"Radare2 output not found at {decompiled_path}")

        return decompiled_path