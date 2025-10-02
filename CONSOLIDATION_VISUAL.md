# Visual Consolidation Plan
## KP14 Stego-Analyzer Module Consolidation

---

## Current Architecture (BEFORE)

```
analysis/ (23 modules, 9,890 lines)
│
├─ KeyPlug Modules (8 modules, 5,368 lines)
│  ├─ keyplug_memory_forensics.py       [1,089 lines] ═╗
│  ├─ keyplug_peb_detector.py           [642 lines]    ║
│  ├─ keyplug_accelerated_multilayer.py [613 lines]    ║
│  ├─ keyplug_extractor.py              [524 lines]    ║
│  ├─ keyplug_cross_sample_correlator.py[517 lines]    ║─► Contains duplicate:
│  ├─ keyplug_advanced_analysis.py      [516 lines]    ║   - calculate_entropy() [5×]
│  ├─ keyplug_decompiler.py             [491 lines]    ║   - xor_decrypt() [2×]
│  └─ keyplug_combination_decrypt.py    [465 lines]   ═╝   - XOR keys [8×]
│
├─ ML Modules (4 modules, 1,813 lines)
│  ├─ ml_malware_analyzer_fixed.py      [600 lines]   ═╗
│  ├─ ml_malware_analyzer.py            [587 lines]    ║─► Contains duplicate:
│  ├─ ml_malware_analyzer_hw.py         [540 lines]    ║   - calculate_entropy() [3×]
│  └─ ml_classifier.py                  [86 lines]    ═╝   - find_strings() [3×]
│
├─ Code Analysis Modules (5 modules, 2,179 lines)
│  ├─ code_intent_classifier.py         [799 lines]   ═╗
│  ├─ behavioral_analyzer.py            [684 lines]    ║
│  ├─ api_sequence_detector.py          [471 lines]    ║─► Related functionality
│  ├─ analyze_encoded_strings.py        [217 lines]    ║   but scattered across
│  └─ analyze_api_hashing.py            [122 lines]   ═╝   5 different files
│
├─ Steganography Modules (3 modules, 654 lines)
│  ├─ multilayer_extractor.py           [537 lines]   ═╗
│  ├─ stegdetect.py                     [60 lines]     ║─► Related stego logic
│  └─ payload_extract.py                [57 lines]    ═╝   in 3 separate files
│
├─ Network Module (1 module, 69 lines)
│  └─ ip_log_tracer.py                  [69 lines]    ─► Keep as separate
│
└─ General Module (1 module, 204 lines)
   └─ static_analyzer.py                [204 lines]   ─► Keep as is
```

### Problems Identified

```
┌─────────────────────────────────────────────────────────────┐
│ DUPLICATIONS                                                 │
├─────────────────────────────────────────────────────────────┤
│ • calculate_entropy() duplicated in 7 files                 │
│ • xor_decrypt() duplicated in 2 files                       │
│ • find_strings() duplicated in 3 files                      │
│ • PE parsing logic duplicated across multiple files         │
│ • File signatures duplicated in 2 files                     │
│ • XOR key constants duplicated in 8 files                   │
│ • Network indicator extraction duplicated in 3 files        │
├─────────────────────────────────────────────────────────────┤
│ ORGANIZATIONAL ISSUES                                        │
├─────────────────────────────────────────────────────────────┤
│ • 3 versions of same ML analyzer (base, fixed, hw)          │
│ • Related KeyPlug functionality scattered across 8 files    │
│ • Code analysis split across 5 files                        │
│ • No clear plugin architecture                              │
│ • Circular import dependencies                              │
│ • No shared base class for analyzers                        │
└─────────────────────────────────────────────────────────────┘
```

---

## Proposed Architecture (AFTER)

```
stego-analyzer/
│
├─ analyzers/ (NEW - 5 modules, ~2,050 lines)
│  │
│  ├─ keyplug_analyzer.py               [~800 lines]  ◄═══ 8 modules consolidated
│  │  │                                                     85% reduction (5,368→800)
│  │  ├─ class KeyPlugAnalyzer(BaseAnalyzer)
│  │  │  ├─ analyze_odg()          ← from keyplug_extractor.py
│  │  │  ├─ analyze_payload()      ← from keyplug_advanced_analysis.py
│  │  │  ├─ decompile()            ← from keyplug_decompiler.py
│  │  │  ├─ multilayer_decrypt()   ← from keyplug_accelerated_multilayer.py
│  │  │  ├─ correlate_samples()    ← from keyplug_cross_sample_correlator.py
│  │  │  ├─ combination_decrypt()  ← from keyplug_combination_decrypt.py
│  │  │  ├─ detect_peb()           ← from keyplug_peb_detector.py
│  │  │  └─ memory_forensics()     ← from keyplug_memory_forensics.py
│  │
│  ├─ ml_analyzer.py                    [~400 lines]  ◄═══ 4 modules consolidated
│  │  │                                                     78% reduction (1,813→400)
│  │  ├─ class MLMalwareAnalyzer(BaseAnalyzer)
│  │  │  ├─ extract_features()     ← from all 3 ml_malware_analyzer_*.py
│  │  │  ├─ classify_malware()     ← merged from _fixed.py (keeps fixes)
│  │  │  ├─ detect_malicious()     ← merged from _hw.py (keeps HW accel)
│  │  │  └─ classify_payload()     ← from ml_classifier.py
│  │
│  ├─ code_analyzer.py                  [~500 lines]  ◄═══ 5 modules consolidated
│  │  │                                                     77% reduction (2,179→500)
│  │  ├─ class CodeAnalyzer(BaseAnalyzer)
│  │  │  ├─ analyze_behavior()     ← from behavioral_analyzer.py
│  │  │  ├─ classify_intent()      ← from code_intent_classifier.py
│  │  │  ├─ detect_api_sequences() ← from api_sequence_detector.py
│  │  │  ├─ detect_api_hashing()   ← from analyze_api_hashing.py
│  │  │  └─ analyze_encoded_strings() ← from analyze_encoded_strings.py
│  │
│  ├─ stego_analyzer.py                 [~250 lines]  ◄═══ 3 modules consolidated
│  │  │                                                     62% reduction (654→250)
│  │  ├─ class SteganographyAnalyzer(BaseAnalyzer)
│  │  │  ├─ extract_multilayer()   ← from multilayer_extractor.py
│  │  │  ├─ detect_stego()         ← from stegdetect.py
│  │  │  └─ extract_payload()      ← from payload_extract.py
│  │
│  └─ network_analyzer.py               [~100 lines]  ◄═══ 1 module enhanced
│     │
│     ├─ class NetworkAnalyzer(BaseAnalyzer)
│     │  ├─ trace_ip_logs()        ← from ip_log_tracer.py
│     │  └─ extract_indicators()   ← network logic from other modules
│
├─ core/ (Enhanced)
│  │
│  ├─ base_analyzer.py                  [~150 lines]  ◄═══ NEW
│  │  │
│  │  └─ class BaseAnalyzer
│  │     ├─ __init__()              # Standard initialization
│  │     ├─ _setup_logging()        # Common logging
│  │     ├─ _load_config()          # Configuration loading
│  │     ├─ _init_openvino()        # OpenVINO setup
│  │     └─ generate_report()       # Standard reporting
│  │
│  ├─ logger.py                         [existing]
│  ├─ pattern_database.py               [existing]
│  └─ reporting.py                      [existing]
│
├─ utils/ (Enhanced)
│  │
│  ├─ crypto_utils.py                   [~200 lines]  ◄═══ NEW
│  │  ├─ xor_decrypt()              # Single implementation
│  │  ├─ rc4_decrypt()              # RC4 decryption
│  │  ├─ multi_stage_decrypt()      # Multi-stage logic
│  │  └─ KNOWN_XOR_KEYS             # Centralized constants
│  │
│  ├─ string_extractor.py               [~150 lines]  ◄═══ NEW
│  │  ├─ find_strings()             # Single implementation
│  │  ├─ extract_api_references()   # API extraction
│  │  └─ extract_network_indicators() # Network indicators
│  │
│  ├─ file_signatures.py                [~100 lines]  ◄═══ NEW
│  │  ├─ FILE_SIGNATURES            # Centralized database
│  │  ├─ detect_file_type()         # File type detection
│  │  └─ scan_for_signatures()      # Signature scanning
│  │
│  ├─ pe_utils.py                       [~300 lines]  ◄═══ Enhanced
│  │  ├─ extract_pe_info()          # PE header parsing
│  │  ├─ extract_pe_sections()      # Section extraction
│  │  ├─ find_embedded_pe()         # Find embedded PEs
│  │  └─ calculate_section_entropy() # Section entropy
│  │
│  └─ entropy.py                        [existing]    ◄═══ Use existing
│     └─ calculate_entropy()        # Single implementation
│
└─ analysis/ (Legacy - deprecated)
   │
   ├─ __init__.py                       [enhanced with warnings]
   │  └─ Emits DeprecationWarning when old modules imported
   │
   ├─ static_analyzer.py                [keep as is]
   │
   └─ [All other modules]               [deprecated, emit warnings]
      └─ Compatibility shims redirect to new analyzers
```

---

## Consolidation Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        CONSOLIDATION PROCESS                             │
└─────────────────────────────────────────────────────────────────────────┘

Step 1: Extract Common Utilities
════════════════════════════════════

keyplug_extractor.py                        utils/
keyplug_advanced_analysis.py               ├─ crypto_utils.py
keyplug_decompiler.py            ═════►    │  └─ xor_decrypt()
keyplug_combination_decrypt.py             │
ml_malware_analyzer*.py                    ├─ string_extractor.py
                                           │  └─ find_strings()
                                           │
                                           ├─ file_signatures.py
                                           │  └─ FILE_SIGNATURES
                                           │
                                           └─ entropy.py (existing)
                                              └─ calculate_entropy()


Step 2: Create Base Class
═════════════════════════

All analyzers need:                         core/base_analyzer.py
- OpenVINO setup              ═════►       ┌─────────────────────┐
- Logging                                  │ class BaseAnalyzer  │
- Config loading                           │  ├─ __init__()      │
- Report generation                        │  ├─ _setup_logging()│
                                           │  ├─ _load_config()  │
                                           │  └─ generate_report()│
                                           └─────────────────────┘


Step 3: Consolidate KeyPlug (8 → 1)
═══════════════════════════════════

keyplug_memory_forensics.py  ┐
keyplug_peb_detector.py      │
keyplug_accelerated_multilayer.py  │
keyplug_extractor.py         │              analyzers/keyplug_analyzer.py
keyplug_cross_sample_correlator.py │  ═►    ┌─────────────────────────────┐
keyplug_advanced_analysis.py │              │ class KeyPlugAnalyzer       │
keyplug_decompiler.py        │              │   extends BaseAnalyzer      │
keyplug_combination_decrypt.py ┘            │                             │
                                            │ All functionality merged    │
                                            │ Duplicates eliminated       │
                                            │ Clean interface             │
                                            └─────────────────────────────┘


Step 4: Consolidate ML (4 → 1)
═════════════════════════════

ml_malware_analyzer.py       ┐              analyzers/ml_analyzer.py
ml_malware_analyzer_fixed.py │    ═════►    ┌─────────────────────────────┐
ml_malware_analyzer_hw.py    │              │ class MLMalwareAnalyzer     │
ml_classifier.py             ┘              │   extends BaseAnalyzer      │
                                            │                             │
                                            │ Keeps fixes from _fixed.py  │
                                            │ Keeps HW accel from _hw.py  │
                                            │ Merges classification       │
                                            └─────────────────────────────┘


Step 5: Consolidate Code Analysis (5 → 1)
═════════════════════════════════════════

code_intent_classifier.py    ┐
behavioral_analyzer.py       │              analyzers/code_analyzer.py
api_sequence_detector.py     │    ═════►    ┌─────────────────────────────┐
analyze_encoded_strings.py   │              │ class CodeAnalyzer          │
analyze_api_hashing.py       ┘              │   extends BaseAnalyzer      │
                                            │                             │
                                            │ Unified code analysis       │
                                            │ Behavior + Intent + APIs    │
                                            └─────────────────────────────┘


Step 6: Consolidate Steganography (3 → 1)
═════════════════════════════════════════

multilayer_extractor.py      ┐              analyzers/stego_analyzer.py
stegdetect.py                │    ═════►    ┌─────────────────────────────┐
payload_extract.py           ┘              │ class SteganographyAnalyzer │
                                            │   extends BaseAnalyzer      │
                                            │                             │
                                            │ Unified stego analysis      │
                                            └─────────────────────────────┘
```

---

## Code Size Reduction Visualization

```
BEFORE: 23 modules, 9,890 lines
════════════════════════════════════════════════════════════════

KeyPlug (8 modules)         ████████████████████████████████████ 5,368 lines (54%)
ML (4 modules)              ████████ 1,813 lines (18%)
Code Analysis (5 modules)   ██████████ 2,179 lines (22%)
Steganography (3 modules)   ██ 654 lines (7%)
Network (1 module)          ▌69 lines (1%)
General (1 module)          ▌204 lines (2%)
__init__ (1 module)         ▌0 lines (0%)


AFTER: 8-10 modules, ~5,934 lines (40% reduction)
════════════════════════════════════════════════════════════════

KeyPlug (1 module)          ████ 800 lines (13%)  [85% reduction]
ML (1 module)               ██ 400 lines (7%)     [78% reduction]
Code Analysis (1 module)    ██ 500 lines (8%)     [77% reduction]
Steganography (1 module)    ▌250 lines (4%)       [62% reduction]
Network (1 module)          ▌100 lines (2%)       [+45% enhanced]
General (1 module)          ▌204 lines (3%)       [kept as is]

New Infrastructure:
  base_analyzer.py          ▌150 lines (3%)       [NEW]
  crypto_utils.py           ▌200 lines (3%)       [NEW]
  string_extractor.py       ▌150 lines (3%)       [NEW]
  file_signatures.py        ▌100 lines (2%)       [NEW]
  pe_utils.py (enhanced)    ███ 300 lines (5%)    [NEW/Enhanced]

Total Utilities: ~900 lines (15%)
Total Analyzers: ~2,254 lines (38%)
Other: ~204 lines (3%)

ELIMINATED: ~3,956 lines (40% of original)
```

---

## Dependency Graph Transformation

### BEFORE (Complex, Circular)

```
┌──────────────────────────────────────────────────────────┐
│                   Circular Dependencies                   │
│                                                           │
│  keyplug_extractor ──────► keyplug_advanced_analysis     │
│        ▲                            │                     │
│        │                            ▼                     │
│        │                     ml_malware_analyzer          │
│        │                            │                     │
│        └────────────────────────────┘                     │
│                                                           │
│  behavioral_analyzer ───────► api_sequence_detector       │
│        ▲                            │                     │
│        │                            ▼                     │
│        │                     code_intent_classifier       │
│        │                            │                     │
│        └────────────────────────────┘                     │
└──────────────────────────────────────────────────────────┘

Problems:
  ✗ Circular imports
  ✗ Complex dependencies
  ✗ Hard to test in isolation
  ✗ Unpredictable import order
```

### AFTER (Clean, Hierarchical)

```
┌──────────────────────────────────────────────────────────┐
│                   Clean Hierarchy                         │
│                                                           │
│  analyzers/                                              │
│  ├─ keyplug_analyzer ──────┐                            │
│  ├─ ml_analyzer ───────────┤                            │
│  ├─ code_analyzer ─────────┼──► core/base_analyzer      │
│  ├─ stego_analyzer ────────┤                            │
│  └─ network_analyzer ──────┘                            │
│                             │                            │
│                             ▼                            │
│                          utils/                          │
│                          ├─ crypto_utils                 │
│                          ├─ string_extractor             │
│                          ├─ file_signatures              │
│                          ├─ pe_utils                     │
│                          └─ entropy                      │
│                                                           │
└──────────────────────────────────────────────────────────┘

Benefits:
  ✓ No circular imports
  ✓ Clear dependency flow
  ✓ Easy to test
  ✓ Predictable behavior
```

---

## Migration Path Visualization

```
Timeline: 3 Release Cycles
═══════════════════════════════════════════════════════════

Release 1.0 (Consolidation Release)
────────────────────────────────────
┌──────────────────────────────────────────────────────────┐
│ New Modules        │ Legacy Modules                      │
├────────────────────┼─────────────────────────────────────┤
│ analyzers/         │ analysis/ (DEPRECATED)              │
│ ✓ keyplug_analyzer │ ⚠ keyplug_extractor (→ redirect)   │
│ ✓ ml_analyzer      │ ⚠ ml_malware_analyzer (→ redirect) │
│ ✓ code_analyzer    │ ⚠ behavioral_analyzer (→ redirect) │
│ ✓ stego_analyzer   │ ... all emit warnings ...           │
│ ✓ network_analyzer │                                     │
│                    │ Both work, warnings shown           │
└────────────────────┴─────────────────────────────────────┘


Release 1.1-1.3 (Migration Period)
──────────────────────────────────
┌──────────────────────────────────────────────────────────┐
│ Users migrate their code                                 │
│ from analysis.* imports → analyzers.* imports            │
│                                                           │
│ Old code: Still works with deprecation warnings          │
│ New code: Uses new analyzers, no warnings                │
│                                                           │
│ Documentation updated, migration guide available         │
└──────────────────────────────────────────────────────────┘


Release 2.0 (Cleanup Release)
─────────────────────────────
┌──────────────────────────────────────────────────────────┐
│ New Modules        │ Legacy Modules                      │
├────────────────────┼─────────────────────────────────────┤
│ analyzers/         │ analysis/                           │
│ ✓ keyplug_analyzer │ ✓ static_analyzer (kept)           │
│ ✓ ml_analyzer      │ ✗ ALL OTHERS REMOVED                │
│ ✓ code_analyzer    │                                     │
│ ✓ stego_analyzer   │ Clean architecture achieved         │
│ ✓ network_analyzer │                                     │
└────────────────────┴─────────────────────────────────────┘
```

---

## Success Metrics Dashboard

```
╔═══════════════════════════════════════════════════════════╗
║                    CONSOLIDATION METRICS                   ║
╠═══════════════════════════════════════════════════════════╣
║                                                            ║
║  Module Count                                             ║
║  ┌──────────────────────────────────────────────┐        ║
║  │ Before: ████████████████████████ 23 modules │        ║
║  │ After:  ████████ 8-10 modules               │        ║
║  │ Reduction: 65%                                │        ║
║  └──────────────────────────────────────────────┘        ║
║                                                            ║
║  Lines of Code                                            ║
║  ┌──────────────────────────────────────────────┐        ║
║  │ Before: ████████████████████████ 9,890 lines│        ║
║  │ After:  ████████████ 5,934 lines            │        ║
║  │ Reduction: 40%                                │        ║
║  └──────────────────────────────────────────────┘        ║
║                                                            ║
║  Code Duplication                                         ║
║  ┌──────────────────────────────────────────────┐        ║
║  │ Before: ████████████ 12+ duplicates         │        ║
║  │ After:  0 duplicates                         │        ║
║  │ Reduction: 100%                               │        ║
║  └──────────────────────────────────────────────┘        ║
║                                                            ║
║  Test Coverage                                            ║
║  ┌──────────────────────────────────────────────┐        ║
║  │ Before: Unknown / Low                        │        ║
║  │ After:  ████████████████████ >90%           │        ║
║  │ Improvement: Significant                      │        ║
║  └──────────────────────────────────────────────┘        ║
║                                                            ║
║  Circular Imports                                         ║
║  ┌──────────────────────────────────────────────┐        ║
║  │ Before: ████ Present                         │        ║
║  │ After:  0                                    │        ║
║  │ Reduction: 100%                               │        ║
║  └──────────────────────────────────────────────┘        ║
║                                                            ║
╚═══════════════════════════════════════════════════════════╝
```

---

## Files Generated

1. **MODULE_CONSOLIDATION_REPORT.md** (658 lines)
   - Detailed consolidation plan
   - Phase-by-phase implementation guide
   - Risk assessment and mitigation
   - Testing strategy

2. **CONSOLIDATION_SUMMARY.md**
   - Quick reference guide
   - Key statistics and metrics
   - Implementation timeline
   - Expected benefits

3. **CONSOLIDATION_VISUAL.md** (this file)
   - Visual representation of consolidation
   - Architecture diagrams
   - Flow charts and metrics
   - Easy-to-understand overview

---

## Recommendation

**Proceed with consolidation** starting with:

1. **Phase 1:** Create infrastructure (base classes and utilities)
2. **Phase 2:** Consolidate KeyPlug modules (highest impact)
3. **Phase 3-5:** Consolidate remaining modules
4. **Phase 6:** Add migration support and documentation

**Expected timeline:** 13-20 days for complete consolidation
**Expected benefit:** 40% code reduction, 65% fewer modules, 0 duplications
