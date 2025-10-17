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
        self.archive_password = config.get("recompiler", "archive_password", fallback="infected")

    def recompile_and_secure(self, c_file_path: str, output_dir: str, patch_file_path: str = None) -> (str, str):
        """
        Recompiles the given C file, performs a safe analysis, and archives the result.
        """
        executable_path = self.recompile(c_file_path, output_dir, patch_file_path)

        analysis_results = self._safe_analyze(executable_path)

        archive_path = self._archive_executable(executable_path)

        return archive_path, analysis_results

    def _safe_analyze(self, executable_path: str) -> str:
        """
        Performs a safe, static analysis of the executable.
        """
        analysis_output = ""
        try:
            analysis_output += f"--- Analysis for {os.path.basename(executable_path)} ---\n"

            # file command
            file_cmd = ["file", executable_path]
            file_res = subprocess.run(file_cmd, check=True, capture_output=True, text=True)
            analysis_output += f"\n[File Type]\n{file_res.stdout}\n"

            # strings command
            strings_cmd = ["strings", executable_path]
            strings_res = subprocess.run(strings_cmd, check=True, capture_output=True, text=True)
            analysis_output += f"\n[Strings]\n{strings_res.stdout}\n"

            # ldd command
            ldd_cmd = ["ldd", executable_path]
            ldd_res = subprocess.run(ldd_cmd, check=True, capture_output=True, text=True)
            analysis_output += f"\n[Dependencies]\n{ldd_res.stdout}\n"

        except subprocess.CalledProcessError as e:
            analysis_output += f"\nError during analysis: {e.stderr}\n"
        except FileNotFoundError as e:
            analysis_output += f"\nAnalysis tool not found: {e.filename}\n"

        return analysis_output

    def _archive_executable(self, executable_path: str) -> str:
        """
        Archives the executable into a password-protected zip file.
        """
        archive_path = f"{executable_path}.zip"
        cmd_zip = [
            "zip",
            f"--password={self.archive_password}",
            archive_path,
            executable_path
        ]
        try:
            subprocess.run(cmd_zip, check=True, capture_output=True, text=True)
            logger.info(f"Successfully archived executable to: {archive_path}")
            return archive_path
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to archive executable: {e.stderr}")
            raise

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