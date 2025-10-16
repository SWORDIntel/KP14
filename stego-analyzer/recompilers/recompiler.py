import os
import subprocess
import logging
from configparser import ConfigParser

logger = logging.getLogger(__name__)

class Recompiler:
    """
    Handles the recompilation of C code.
    """

    def __init__(self, config: ConfigParser):
        self.compiler = config.get("recompiler", "compiler", fallback="gcc")
        self.flags = config.get("recompiler", "flags", fallback="-O2 -w").split()

    def recompile(self, c_file_path: str, output_dir: str, patch_file_path: str = None) -> str:
        """
        Recompiles the given C file, optionally applying a patch first.
        """
        if not os.path.exists(c_file_path):
            raise FileNotFoundError(f"C file not found at: {c_file_path}")

        patched_c_file = c_file_path
        if patch_file_path:
            if not os.path.exists(patch_file_path):
                raise FileNotFoundError(f"Patch file not found at: {patch_file_path}")

            patched_c_file = os.path.join(output_dir, "patched_decompiled.c")
            cmd_patch = ["patch", "-o", patched_c_file, c_file_path, patch_file_path]

            try:
                subprocess.run(cmd_patch, check=True, capture_output=True, text=True)
                logger.info(f"Successfully patched C file to: {patched_c_file}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to apply patch: {e.stderr}")
                raise

        output_executable_path = os.path.join(output_dir, "recompiled_executable")
        cmd_compile = [self.compiler, *self.flags, "-o", output_executable_path, patched_c_file]

        try:
            subprocess.run(cmd_compile, check=True, capture_output=True, text=True)
            logger.info(f"Successfully recompiled to: {output_executable_path}")
            return output_executable_path
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to recompile: {e.stderr}")
            raise