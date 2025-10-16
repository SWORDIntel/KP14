from configparser import ConfigParser

from .base import Decompiler
from .ghidra import GhidraDecompiler
from .radare2 import Radare2Decompiler

class DecompilerFactory:
    """
    Factory for creating decompiler instances.
    """

    @staticmethod
    def create(config: ConfigParser) -> Decompiler:
        """
        Creates a decompiler instance based on the given configuration.
        """
        decompiler_name = config.get("decompiler", "backend")
        decompiler_path = config.get("decompiler", "path")

        if decompiler_name == "ghidra":
            return GhidraDecompiler(decompiler_path)
        elif decompiler_name == "radare2":
            return Radare2Decompiler(decompiler_path)
        else:
            raise ValueError(f"Unknown decompiler: {decompiler_name}")