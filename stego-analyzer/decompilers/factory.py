import os
import subprocess
import shutil
import logging
from configparser import ConfigParser
from typing import List

from .base import Decompiler
from .ghidra import GhidraDecompiler
from .radare2 import Radare2Decompiler

logger = logging.getLogger(__name__)

class DecompilerFactory:
    """
    Factory for creating decompiler instances.
    """

    @staticmethod
    def create_all(config: ConfigParser) -> List[Decompiler]:
        """
        Creates all decompiler instances specified in the configuration.
        """
        decompilers = []
        backend_names = [b.strip() for b in config.get("decompiler", "backends", fallback="").split(",") if b.strip()]

        if not backend_names:
            logger.warning("No decompiler backends specified in the configuration.")
            return []

        for name in backend_names:
            try:
                if name == "ghidra":
                    ghidra_path = config.get("ghidra", "path")
                    if not ghidra_path or not os.path.exists(ghidra_path):
                        logger.error(f"Ghidra path '{ghidra_path}' is not valid. Please configure it in settings.ini.")
                        logger.error("Ghidra requires manual installation. Please download it from the official website.")
                        continue
                    decompilers.append(GhidraDecompiler(ghidra_path))
                elif name == "radare2":
                    radare2_path = config.get("radare2", "path", fallback="auto")
                    if radare2_path == "auto":
                        radare2_path = DecompilerFactory._find_or_install_radare2()

                    if not radare2_path:
                        logger.error("Radare2 is not available and could not be installed automatically.")
                        continue
                    decompilers.append(Radare2Decompiler(radare2_path))
                else:
                    logger.warning(f"Unknown decompiler backend specified: {name}")
            except Exception as e:
                logger.error(f"Failed to initialize decompiler backend '{name}': {e}")

        return decompilers

    @staticmethod
    def _find_or_install_radare2() -> str:
        """
        Finds the path to the radare2 executable or attempts to install it.
        Returns the path if successful, otherwise None.
        """
        # 1. Check if r2 is in PATH
        r2_path = shutil.which("r2")
        if r2_path:
            logger.info(f"Found radare2 executable at: {r2_path}")
            return r2_path

        logger.warning("radare2 not found in PATH. Attempting to install...")

        # 2. Attempt to install using package manager (apt for Debian-based systems)
        try:
            # Check if we are on a Debian-based system
            if shutil.which("apt-get"):
                logger.info("Attempting to install radare2 using apt-get...")
                subprocess.run(["sudo", "apt-get", "update"], check=True)
                subprocess.run(["sudo", "apt-get", "install", "-y", "radare2"], check=True)

                r2_path = shutil.which("r2")
                if r2_path:
                    logger.info(f"Successfully installed radare2 at: {r2_path}")
                    return r2_path
                else:
                    logger.error("Installation appeared to succeed, but radare2 is still not in PATH.")
                    return None
            else:
                logger.error("Unsupported package manager. Please install radare2 manually.")
                return None
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.error(f"Failed to install radare2 automatically: {e}")
            logger.error("Please try installing it manually.")
            return None