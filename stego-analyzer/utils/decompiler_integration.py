#!/usr/bin/env python3
"""
KEYPLUG Decompiler Integration
------------------------------
Integration with various decompilers for KEYPLUG malware analysis.
"""

import os
import difflib
import logging
from configparser import ConfigParser
from typing import List, Dict, Any
from collections import Counter

from stego_analyzer.decompilers.factory import DecompilerFactory
from stego_analyzer.decompilers.base import Decompiler


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
        self.decompilers: List[Decompiler] = DecompilerFactory.create_all(config)

    def decompile(self, binary_path: str, output_dir: str, analysis_results: Dict[str, Any] = None) -> Dict[str, str]:
        """
        Decompiles the binary at the given path using all configured decompilers
        and returns a dictionary of decompiler names to their output paths.
        """
        if not os.path.exists(binary_path):
            self.logger.error(f"File {binary_path} not found")
            return {}
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        decompiler_outputs = {}
        for decompiler in self.decompilers:
            try:
                self.logger.info(f"Decompiling with {decompiler.name}...")
                # Pass analysis_results to decompiler if it accepts it
                if "analysis_results" in decompiler.decompile.__code__.co_varnames:
                    output_path = decompiler.decompile(binary_path, output_dir, analysis_results=analysis_results)
                else:
                    output_path = decompiler.decompile(binary_path, output_dir)
                decompiler_outputs[decompiler.name] = output_path
            except Exception as e:
                self.logger.error(f"Failed to decompile with {decompiler.name}: {e}")

        return decompiler_outputs

    def produce_consensus_output(self, decompiler_outputs: Dict[str, str], output_dir: str, consensus_filename: str = "consensus_decompiled.c"):
        """
        Generates a consensus C code output from multiple decompiler outputs.
        """
        if not decompiler_outputs:
            self.logger.warning("No decompiler outputs to produce consensus from.")
            return None

        lines_by_decompiler = {}
        for name, path in decompiler_outputs.items():
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    lines_by_decompiler[name] = [line.strip() for line in f.readlines()]
            except Exception as e:
                self.logger.error(f"Failed to read output from {name}: {e}")

        if not lines_by_decompiler:
            self.logger.error("Could not read any decompiler output files.")
            return None

        # Simple consensus by line voting
        all_lines = [line for lines in lines_by_decompiler.values() for line in lines]
        line_counts = Counter(all_lines)

        # Keep lines that appear in more than half of the decompilers
        num_decompilers = len(lines_by_decompiler)
        consensus_lines = [line for line, count in line_counts.items() if count > num_decompilers / 2]

        consensus_path = os.path.join(output_dir, consensus_filename)
        try:
            with open(consensus_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(consensus_lines))
            self.logger.info(f"Consensus output written to: {consensus_path}")
            return consensus_path
        except Exception as e:
            self.logger.error(f"Failed to write consensus output: {e}")
            return None

    def produce_diff_report(self, decompiler_outputs: Dict[str, str], output_dir: str, diff_filename: str = "decompiler_diff.txt"):
        """
        Generates a diff report comparing the outputs of multiple decompilers.
        """
        if len(decompiler_outputs) < 2:
            self.logger.info("Need at least two decompiler outputs to produce a diff report.")
            return None

        diff_path = os.path.join(output_dir, diff_filename)

        try:
            with open(diff_path, 'w', encoding='utf-8') as f:
                decompiler_names = sorted(decompiler_outputs.keys())

                # Compare each pair of decompilers
                for i in range(len(decompiler_names)):
                    for j in range(i + 1, len(decompiler_names)):
                        name1 = decompiler_names[i]
                        name2 = decompiler_names[j]
                        path1 = decompiler_outputs[name1]
                        path2 = decompiler_outputs[name2]

                        f.write(f"--- Diff between {name1} and {name2} ---\n\n")

                        try:
                            with open(path1, 'r', encoding='utf-8') as f1, open(path2, 'r', encoding='utf-8') as f2:
                                lines1 = f1.readlines()
                                lines2 = f2.readlines()
                                diff = difflib.unified_diff(lines1, lines2, fromfile=name1, tofile=name2)
                                f.writelines(diff)
                        except Exception as e:
                            f.write(f"Failed to generate diff: {e}\n")

                        f.write("\n\n")

            self.logger.info(f"Diff report written to: {diff_path}")
            return diff_path
        except Exception as e:
            self.logger.error(f"Failed to write diff report: {e}")
            return None