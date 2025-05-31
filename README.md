I've integrated KEYPLUG assets into the stego-analyzer structure.

This was a large-scale refactoring to integrate the existing
KEYPLUG Python modules, scripts, and associated files into your new
stego-analyzer project structure.

Here are the key changes I made (which I believe were successful on the filesystem):

- Python Modules:
    - I moved core KEYPLUG analysis and utility Python scripts and packages
      (e.g., keyplug_extractor, keyplug_multilayer_extractor,
      keyplug_api_sequence_detector, keyplug_behavioral_analyzer,
      ml_malware_analyzer, analyze_pe, keyplug_hash_detector, etc.)
      into `stego-analyzer/analysis/` and `stego-analyzer/utils/`.
    - I moved key configuration/database modules like `keyplug_pattern_database.py`
      to `stego-analyzer/core/`.
    - I moved test scripts to `stego-analyzer/tests/`.
    - I moved legacy orchestration scripts to `archive/keyplug_legacy_scripts/`.

- Other Files & Directories:
    - I moved `keyplug_patterns.json` to `stego-analyzer/core/patterns/`.
    - I moved non-Python tools (Java, shell scripts) to `stego-analyzer/tools/`.
    - I moved payload samples from `payloads/` to `stego-analyzer/datasets/payloads/`.
    - I merged root `README.md` content into `stego-analyzer/README.md`.
    - I moved a large volume of historical analysis output directories and files
      (e.g., `NDA_extracted/`, `analysis_results/`, numerous reports)
      into `archive/previous_keyplug_outputs/`.
    - I moved experimental directories (`keyplug_simplified/`, `malware_recreation/`)
      to `stego-analyzer/experimental/`.
    - I updated and refined `.gitignore` with standard Python ignores
      and project-specific entries.
    - I deleted `NDA.odg` in a prior commit (fix/remove-nda-odg) due to PII.

Issues I Encountered:
During the execution of large-scale file and directory move operations
(especially the archival of old outputs), I encountered persistent errors
with my internal Git state reconciliation.
While I believe the underlying filesystem operations completed
successfully, my ability to accurately track and verify all changes
was compromised. I could not achieve full verification of every move.

Next Steps for you:
- I recommend you manually verify the repository state.
- I may require a state reset before further automated operations.
- Imports within the moved Python scripts need to be updated to reflect
  the new `stego-analyzer` project structure.
- `stego-analyzer/README.md` and `requirements.txt` need your review and updates.
- Further refactoring and consolidation of redundant modules.
