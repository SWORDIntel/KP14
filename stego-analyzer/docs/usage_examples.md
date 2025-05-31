# KeyPlug Analyzer Usage Examples

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
