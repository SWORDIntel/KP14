# KeyPlug Analyzer Usage Examples
**(Note: The main script has been updated to `run_pipeline.py` located in the `stego-analyzer` directory. Examples below may need to be adjusted accordingly. New examples for `run_pipeline.py` are being added.)**

This document provides examples of how to use the KeyPlug analyzer command-line tool.
(Note: These examples refer to a previous version of the tool, `keyplug_analyzer.py`,
and may need adaptation for the current `stego-analyzer` pipeline.)

## Analyze a Single File

To analyze a single payload file:
```bash
./keyplug_analyzer.py analyze /path/to/keyplug/payloads/10000000000002EE000003C0C4539E29A848DE5F_forced_8ca7ab3b.bin
```

## Batch Analyze Files in a Directory

To analyze all payload files within a specified directory:
```bash
./keyplug_analyzer.py batch /home/john/Documents/keyplug/payloads
```

## Generate Entropy Graph

To generate an entropy graph for a specific payload file:
```bash
./keyplug_analyzer.py entropy /path/to/keyplug/payloads/10000000000002EE000003C0C4539E29A848DE5F_forced_8ca7ab3b.bin
```

## Extract Embedded Files

To extract any embedded files or data from a payload:
```bash
./keyplug_analyzer.py extract /path/to/keyplug/payloads/10000000000002EE000003C0C4539E29A848DE5F_forced_8ca7ab3b.bin
```

## `stego-analyzer/run_pipeline.py` Examples

These examples pertain to the current `run_pipeline.py` script.

### Basic Analysis of an Image

To run the default analysis pipeline on an image:
```bash
# Ensure you are in the stego-analyzer directory and the virtual environment is active
./run_pipeline.py /path/to/your/image.png
```

### Static Analysis of a File (e.g., a PE file)

If you have a file that you suspect is an executable (e.g., .exe, .dll) and want to perform static analysis:
```bash
./run_pipeline.py /path/to/your/executable.exe --enable-static-analysis
```
This will output:
-   Basic PE information (sections, imports, exports).
-   Extracted strings.
-   Disassembly of the entry point.

*(More examples will be added as features are developed.)*
