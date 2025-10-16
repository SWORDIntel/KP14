#!/usr/bin/env python3
"""
KEYPLUG Decompiler Integration
------------------------------
Integration with various decompilers for KEYPLUG malware analysis.
"""

import os
import json
import shutil
import logging
from configparser import ConfigParser

from stego_analyzer.decompilers.factory import DecompilerFactory


class DecompilerIntegration:
    """
    Integration with various decompilers.
    """

    def __init__(self, config: ConfigParser):
        """
        Initialize the decompiler integration.

        Args:
            config: The configuration parser.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.decompiler = DecompilerFactory.create(config)

    def decompile(self, binary_path: str, output_dir: str) -> str:
        """
        Decompiles the binary at the given path and returns the path to the decompiled C code.
        """
        if not os.path.exists(binary_path):
            self.logger.error(f"File {binary_path} not found")
            return ""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        return self.decompiler.decompile(binary_path, output_dir)

    def produce_consensus_output(self, decompiler_outputs: dict, output_dir: str, consensus_filename: str = "consensus_decompiled.c"):
        # This method is no longer needed as we are using a single decompiler
        pass

    def refine_cfg(self, binary_path: str, decompiler_outputs: dict | None = None, output_dir: str | None = None) -> str | None:
        # This method is no longer needed as we are using a single decompiler
        pass

    def normalize_signatures(self, signature_data_list: list) -> list:
        # This method is no longer needed as we are using a single decompiler
        pass