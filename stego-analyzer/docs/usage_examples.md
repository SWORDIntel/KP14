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

## Python Import Resolver (`tools/import_resolver.py`)

The `import_resolver.py` script is a utility for analyzing and refactoring Python import statements within the `stego-analyzer` project (or any Python project). It helps maintain consistency and aids in larger architectural changes.

**Key Features (as of current version):**
*   Scans directories for Python files.
*   Parses Abstract Syntax Trees (AST) to identify import statements.
*   Applies rules from a JSON configuration file to refactor imports. Currently, it primarily supports aliasing import paths (changing `import old.path` to `import new.path`).
*   Offers a `--dry-run` mode to preview changes.
*   Offers an `--apply` mode to write changes to files.

### Command-Line Arguments

*   `target_directory`: (Required) The directory to recursively scan for Python files.
*   `--project-root PATH`: Path to the project's root directory. Crucial for rules that might involve converting relative to absolute paths (though this specific rule is not fully implemented yet). If omitted, it's inferred (e.g., as parent of `target_directory`).
*   `--rules-config PATH`: Path to a JSON file containing refactoring rules. See `stego-analyzer/tools/sample_import_rules.json` for structure and examples.
*   `--dry-run`: Show proposed changes without modifying files.
*   `--apply`: Apply refactoring changes to files. (Cannot be used with `--dry-run`)

### Example Usage

1.  **Dry Run to see proposed changes:**
    Suppose you want to refactor imports in the `stego-analyzer/analysis/` directory, using rules defined in `stego-analyzer/tools/sample_import_rules.json`, and your project root is the main `stego-analyzer` directory.

    ```bash
    # Ensure your virtual environment is active if the tool has dependencies (currently it uses only standard library ast)
    # Navigate to the stego-analyzer directory
    python tools/import_resolver.py analysis/ --project-root . --rules-config tools/sample_import_rules.json --dry-run
    ```
    This will print out any import statements in `*.py` files under `analysis/` that would be changed by the rules in `sample_import_rules.json`.

2.  **Apply the changes:**
    After reviewing the dry run, if you want to apply the changes:
    ```bash
    python tools/import_resolver.py analysis/ --project-root . --rules-config tools/sample_import_rules.json --apply
    ```
    This will modify the files in place. **It's highly recommended to have your code under version control (e.g., Git) before applying changes.**

### Sample Rules Configuration (`sample_import_rules.json`)

The `stego-analyzer/tools/sample_import_rules.json` file provides a template for defining rules. Currently, the most active rule type is `alias_paths`:

```json
{
    "alias_paths": {
        "comment": "Replaces import paths. Key is old path, value is new path.",
        "utils.old_utility_module": "core.new_utility_module",
        "common.data_structures": "stego_analyzer.core.data_structures"
        // ... more rules
    },
    // ... other rule types (mostly placeholders for future development)
}
```
Refer to the sample file for more details on other planned rule types like `force_absolute_imports_from_root`, `banned_relative_imports_depth`, etc., though their implementation in `import_resolver.py` is still pending.
