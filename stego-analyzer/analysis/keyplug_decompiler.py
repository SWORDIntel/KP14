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


def analyze_payload(payload_path: str, output_dir: str | None, config: ConfigParser):
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
    decompiled_path = decompiler_integration.decompile(str(payload_path), str(output_dir))

    print(f"Decompiled code saved to: {decompiled_path}")


def main():
    parser = argparse.ArgumentParser(description='KEYPLUG Decompiler - Extract source code from KEYPLUG payloads')
    parser.add_argument('file', help='Path to the payload file to analyze')
    parser.add_argument('-o', '--output', help='Output directory for extracted content')
    parser.add_argument('-c', '--config', help='Path to the configuration file', default='settings.ini')
    args = parser.parse_args()

    config = ConfigParser()
    config.read(args.config)

    try:
        analyze_payload(args.file, args.output, config)
        print("Analysis complete!")
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())