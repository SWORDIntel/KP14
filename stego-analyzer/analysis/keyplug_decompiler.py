#!/usr/bin/env python3
"""
KEYPLUG Decompiler
A tool for decrypting and analyzing APT-41's KEYPLUG malware payloads
"""

import os
import sys
import argparse
from pathlib import Path
from configparser import ConfigParser

from stego_analyzer.utils.decompiler_integration import DecompilerIntegration


from stego_analyzer.recompilers.recompiler import Recompiler

def analyze_payload(payload_path: str, output_dir: str | None, config: ConfigParser, patch_file: str | None):
    """
    Analyze a KEYPLUG payload and attempt to extract source code.
    """
    payload_path = Path(payload_path)

    if output_dir:
        output_dir = Path(output_dir)
    else:
        output_dir = payload_path.parent / f"{payload_path.stem}_code"

    output_dir.mkdir(exist_ok=True, parents=True)

    decompiler_integration = DecompilerIntegration(config)
    decompiler_outputs = decompiler_integration.decompile(str(payload_path), str(output_dir))

    if not decompiler_outputs:
        print("Decompilation failed.")
        return

    print("Decompilation outputs:")
    for name, path in decompiler_outputs.items():
        print(f"  {name}: {path}")

    consensus_path = decompiler_integration.produce_consensus_output(decompiler_outputs, str(output_dir))
    if consensus_path:
        print(f"Consensus decompiled code saved to: {consensus_path}")

        if patch_file:
            print(f"Performing secure recompilation with patch file: {patch_file}")
            recompiler = Recompiler(config)
            try:
                archive_path, analysis_results = recompiler.recompile_and_secure(consensus_path, str(output_dir), patch_file)
                print("\n--- Safe Analysis Report ---")
                print(analysis_results)
                print(f"--- End of Report ---\n")
                print(f"Secure archive created at: {archive_path}")
                print(f"Archive password: {recompiler.archive_password}")
            except Exception as e:
                print(f"Secure recompilation failed: {e}")

    diff_path = decompiler_integration.produce_diff_report(decompiler_outputs, str(output_dir))
    if diff_path:
        print(f"Decompiler diff report saved to: {diff_path}")


def main():
    parser = argparse.ArgumentParser(description='KEYPLUG Decompiler - Extract source code from KEYPLUG payloads')
    parser.add_argument('file', help='Path to the payload file to analyze')
    parser.add_argument('-o', '--output', help='Output directory for extracted content')
    parser.add_argument('-c', '--config', help='Path to the configuration file', default='settings.ini')
    parser.add_argument('--secure-recompile', help='Path to a patch file to apply before secure recompilation')
    args = parser.parse_args()

    config = ConfigParser()
    if not os.path.exists(args.config):
        print(f"Error: Configuration file not found at {args.config}")
        return 1
    config.read(args.config)

    try:
        analyze_payload(args.file, args.output, config, args.secure_recompile)
        print("Analysis complete!")
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())