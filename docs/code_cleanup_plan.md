# Code and Directory Cleanup Plan

This document outlines the steps to tidy up the repository, consolidate modules, organize documentation, and remove output files, in preparation for a public release.

## Phase 1: Consolidate Core Analysis Scripts into `stego-analyzer`

**Goal:** Move core Python analysis scripts from the root directory into the `stego-analyzer/analysis/` subdirectory and update the pipeline configuration to reflect these new locations.

**Files to Move from Root to `stego-analyzer/analysis/`:**
*   `analyze_api_hashing.py`
*   `analyze_encoded_strings.py`
*   `code_intent_classifier.py`
*   `keyplug_accelerated_multilayer.py`
*   `keyplug_advanced_analysis.py`
*   `keyplug_combination_decrypt.py`
*   `keyplug_cross_sample_correlator.py`
*   `keyplug_decompiler.py`
*   `keyplug_memory_forensics.py`
*   `keyplug_peb_detector.py`

**Action:**
1.  For each file listed above, perform: `mv {filename} stego-analyzer/analysis/{filename}`
2.  Verify all 10 files are moved into `stego-analyzer/analysis/`.
3.  Modify `keyplug_pipeline_config.py`:
    *   In the `get_module_import_map()` function, update the paths for the following class names to point to `stego_analyzer.analysis.` followed by the module name and class name (e.g., `"KeyplugDecompiler": "stego_analyzer.analysis.keyplug_decompiler.KeyplugDecompiler"`).
        *   `KeyplugDecompiler`
        *   `KeyplugCombinationDecrypt`
        *   `KeyplugAdvancedAnalysis`
        *   `KeyplugAcceleratedMultilayer`
        *   `CodeIntentClassifier`
        *   `KeyplugMemoryAnalyzer`
        *   `KeyplugCrossSampleCorrelator`
    *   Ensure other paths in this map correctly point to `stego_analyzer.utils.*`, `stego_analyzer.analysis.*`, or `stego_analyzer.core.*` as previously determined to be correct. (This part was likely completed and persisted before the rollbacks affecting file moves).

## Phase 2: Organize Utility, Test, and Legacy Scripts

**Goal:** Move miscellaneous scripts to appropriate `tools/`, `tests/`, or `archive/` directories.

**Actions:**
1.  Create directories if they don't exist:
    *   `mkdir -p tools`
    *   `mkdir -p archive/jpeg_parser_stages`
    *   `mkdir -p archive/legacy_orchestrators`
    *   `mkdir -p archive/legacy_modules`
    *   `mkdir -p archive/legacy_scripts`
2.  Move utility scripts:
    *   `mv create_test_jpegs.py tools/`
    *   `mv create_test_pngs.py tools/`
3.  Move external tool integration scripts:
    *   `mv ida_decompile_script.py stego-analyzer/tools/`
4.  Archive experimental JPEG parsers (ELF executables):
    *   `mv jpeg_parser_phase1 archive/jpeg_parser_stages/`
    *   `mv jpeg_parser_phase2 archive/jpeg_parser_stages/`
    *   `mv jpeg_parser_phase3 archive/jpeg_parser_stages/`
    *   `mv jpeg_parser_phase4 archive/jpeg_parser_stages/`
    *   `mv jpeg_parser_unified archive/jpeg_parser_stages/`
5.  Move test scripts:
    *   `mv minimal_jpegio_test.py stego-analyzer/tests/`
    *   `mv test_f5.py stego-analyzer/tests/`
    *   `mv test_jsteg.py stego-analyzer/tests/`
6.  Archive legacy orchestrator scripts:
    *   `mv run_analyzer.py archive/legacy_orchestrators/`
    *   `mv run_deep_analysis.py archive/legacy_orchestrators/`
    *   `mv run_full_analysis_suite.py archive/legacy_orchestrators/`
    *   If `keyplug_unified_orchestrator.py.bak` exists, rename it to `keyplug_unified_orchestrator.py` then `mv keyplug_unified_orchestrator.py archive/legacy_orchestrators/`. If `keyplug_unified_orchestrator.py` (not .bak) exists at root, move it.
7.  Archive legacy `type_inference.py`:
    *   `mv type_inference.py archive/legacy_scripts/` (Verify this is not the one from `stego-analyzer/utils/` if namespacing is an issue).
8.  Archive legacy `modules/` directory:
    *   `mv modules archive/legacy_modules/old_modules` (or similar name to avoid conflict if `archive/legacy_modules` was created by `mkdir`).
9.  Consolidate `tests/` directory:
    *   `rsync -av tests/ stego-analyzer/tests/` (or `mv tests/* stego-analyzer/tests/` carefully if subdirectories `extraction_analyzer` and `static_analyzer` don't exist in target)
    *   `rm -rf tests/` (after verifying contents are moved)

## Phase 3: Documentation and `.gitignore` (Re-verification/Application)

**Goal:** Ensure documentation is organized and `.gitignore` is correct. These steps were likely successful before but should be verified or re-applied if rollbacks reverted them.

1.  **README.md:** Ensure it contains the "KP14: UNPLUGGED" content and the added section for `stego_test.py`.
2.  **requirements.txt:** Ensure it's the consolidated version at the root, and `stego-analyzer/requirements.txt` is deleted.
3.  **`docs/` directory:**
    *   Ensure `docs/` directory exists.
    *   Ensure the following files are present in `docs/` (renamed from their root locations):
        *   `project_overview_and_keyplug_analysis.md` (from `total_report.md`)
        *   `system_architecture_evolution.md` (from `keypluganalysisv2.md`)
        *   `malware_sample_refactoring_plan.md` (from `sourcerefactor.md`)
        *   `future_development_roadmap.md` (from `nextsteps.md`)
        *   `memory_forensics_integration_plan.md` (from `memory.md`)
        *   `issue_tracker.md` (from `issue-tracker.md`)
        *   `detailed_keyplug_payload_analysis_report.md` (from `enhanced_keyplug_report.md`)
    *   Ensure `docs/features_overview.md` and `docs/components_and_pipeline.md` exist and contain the consolidated content from the various `.txt` files.
    *   Ensure original `.txt` files (`malware_analysis_features.txt`, etc.) and `final_report.md` are deleted from the root.
4.  **`.gitignore`:** Ensure it matches the refined version (without broad `*.bin`, `*.c` etc. rules, and with standard Python/OS ignores).

## Phase 4: Delete Output Directories and Files

**Goal:** Remove specific output directories and files to prepare for public release.

**Actions:**
1.  Verify `analysis_results/patterns.json` has been moved to `stego-analyzer/core/patterns/patterns.json`. If not, move it: `mv analysis_results/patterns.json stego-analyzer/core/patterns/`.
2.  Delete the following directories and their contents:
    *   `rm -rf NDA_extracted/`
    *   `rm -rf NDA_keyplug_extracted/`
    *   `rm -rf advanced_decryption_results/`
    *   `rm -rf analysis_results/` (should be empty or contain only sample-specific subdirs after patterns.json is moved)
    *   `rm -rf decrypted/`
    *   `rm -rf detailed_analysis/`
    *   `rm -rf extracted_pe/`
    *   `rm -rf keyplug_analysis_results/`
    *   `rm -rf keyplug_deep_analysis/`
    *   `rm -rf keyplug_full_analysis/`
    *   `rm -rf keyplug_full_deep_analysis/`
    *   `rm -rf odg_extract/`
    *   `rm -rf polyglot_analysis/`
    *   `rm -rf odg_contents/`
    *   `rm -rf __pycache__/` (at the root)
    *   `rm -rf stego-analyzer/__pycache__/` (and any other `__pycache__` directories)

## Phase 5: Final Verification
1.  Run `ls -R` or equivalent to check the final directory structure.
2.  Review `.gitignore` again.
3.  Ensure `stego-analyzer/run_pipeline.py` can (at least conceptually) operate with the new structure if its dependencies are met.
