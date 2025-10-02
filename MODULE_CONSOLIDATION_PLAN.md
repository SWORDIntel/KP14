# KP14 Module Consolidation Plan

## Executive Summary

This document outlines the consolidation strategy for 85+ analyzer modules in the KP14 platform. The goal is to reduce code duplication, eliminate circular dependencies, and create cohesive analyzer plugins organized by functionality.

**Current State:**
- 85+ scattered analyzer modules
- Circular import dependencies
- Code duplication across similar modules
- Unclear module boundaries

**Target State:**
- ~20-25 consolidated analyzer plugins
- Zero circular dependencies
- Clear separation of concerns
- Standardized plugin interface

---

## Table of Contents

1. [Module Inventory](#module-inventory)
2. [Consolidation Strategy](#consolidation-strategy)
3. [Category-by-Category Plan](#category-by-category-plan)
4. [Dependency Resolution](#dependency-resolution)
5. [Implementation Timeline](#implementation-timeline)
6. [Testing Strategy](#testing-strategy)
7. [Risk Mitigation](#risk-mitigation)

---

## Module Inventory

### Current Modules (by location)

#### /stego-analyzer/analysis/ (23 modules)

**KeyPlug-specific (7 modules) → Consolidate to `KeyPlugAnalyzer`:**
- `keyplug_extractor.py` - ODG/JPEG payload extraction
- `keyplug_decompiler.py` - Payload decompilation
- `keyplug_peb_detector.py` - PEB traversal detection
- `keyplug_memory_forensics.py` - Memory dump analysis
- `keyplug_combination_decrypt.py` - Decryption combinations
- `keyplug_accelerated_multilayer.py` - Multi-layer decryption
- `keyplug_cross_sample_correlator.py` - Cross-sample correlation

**ML Analyzers (3 modules) → Consolidate to `MLMalwareAnalyzer`:**
- `ml_malware_analyzer.py` - Base ML analyzer
- `ml_malware_analyzer_fixed.py` - Fixed version
- `ml_malware_analyzer_hw.py` - Hardware-accelerated version

**Static Analysis (4 modules) → Consolidate to `StaticAnalyzer`:**
- `static_analyzer.py` - Basic PE analysis
- `code_intent_classifier.py` - Intent classification
- `analyze_api_hashing.py` - API hashing detection
- `analyze_encoded_strings.py` - String encoding analysis

**Behavioral (2 modules) → Keep as separate analyzers:**
- `behavioral_analyzer.py` - Behavioral pattern detection ✓
- `api_sequence_detector.py` - API sequence analysis ✓

**Extraction (3 modules) → Consolidate to `MultiLayerExtractor`:**
- `multilayer_extractor.py` - Multi-layer extraction
- `payload_extract.py` - Basic payload extraction
- `stegdetect.py` - Steganography detection

**Specialized (2 modules) → Keep as separate analyzers:**
- `ml_classifier.py` - ML classification ✓
- `ip_log_tracer.py` - IP logging tracer ✓

**Other (2 modules):**
- `keyplug_advanced_analysis.py` - Consolidate to KeyPlugAnalyzer

#### /stego-analyzer/utils/ (10+ modules)

**Analysis Tools:**
- `polyglot_analyzer.py` - Polyglot detection
- `hybrid_analyzer.py` - Hybrid analysis
- `ml_pattern_analyzer.py` - Pattern detection
- `string_decoder/entropy_analyzer.py` - Entropy analysis

#### /archive/legacy_modules/ (15+ modules)

**Old Analyzers (deprecated):**
- `extraction_analyzer/crypto_analyzer.py`
- `extraction_analyzer/polyglot_analyzer.py`
- `extraction_analyzer/steganography_analyzer.py`
- `static_analyzer/code_analyzer.py`
- `static_analyzer/obfuscation_analyzer.py`
- `static_analyzer/pe_analyzer.py`

**Status:** Archive only, do not migrate

#### Root Level (5 modules)

**Orchestrators:**
- `batch_analyzer.py` - Batch processing ✓ (keep)
- `keyplug_module_loader.py` - Module loading
- `keyplug_pipeline_config.py` - Pipeline config
- `keyplug_results_processor.py` - Results processing

### Total Module Count

| Category | Count | Target |
|----------|-------|--------|
| KeyPlug modules | 7 | 1 |
| ML analyzers | 3 | 1 |
| Static analysis | 4 | 1 |
| Behavioral | 2 | 2 |
| Extraction | 3 | 1 |
| Specialized | 2 | 2 |
| Utils | 10+ | 3 |
| Legacy (archive) | 15+ | 0 |
| Orchestrators | 5 | 2 |
| **Total** | **85+** | **~25** |

---

## Consolidation Strategy

### Principles

1. **Functional Cohesion**: Group by related functionality
2. **Minimize Breaking Changes**: Maintain external interfaces
3. **Eliminate Duplication**: Merge similar code
4. **Clear Boundaries**: One responsibility per plugin
5. **Preserve History**: Keep old modules temporarily deprecated

### Consolidation Patterns

#### Pattern 1: Family Consolidation

Merge multiple modules for same malware family.

**Example: KeyPlug Modules**
```
Before (7 modules):
- keyplug_extractor.py
- keyplug_decompiler.py
- keyplug_peb_detector.py
- keyplug_memory_forensics.py
- keyplug_combination_decrypt.py
- keyplug_accelerated_multilayer.py
- keyplug_cross_sample_correlator.py

After (1 module):
- analyzers/keyplug_analyzer.py
  - Extraction class
  - Decompilation class
  - PEB detection class
  - Memory forensics class
  - Decryption class
  - Correlation class
```

#### Pattern 2: Version Consolidation

Merge multiple versions into single module with feature flags.

**Example: ML Analyzers**
```
Before (3 modules):
- ml_malware_analyzer.py (base)
- ml_malware_analyzer_fixed.py (fixes)
- ml_malware_analyzer_hw.py (hardware)

After (1 module):
- analyzers/ml_malware_analyzer.py
  - Base implementation (from _fixed)
  - Hardware acceleration (from _hw)
  - Automatic fallback
```

#### Pattern 3: Layer Consolidation

Merge analysis layers into single module.

**Example: Static Analysis**
```
Before (4 modules):
- static_analyzer.py
- code_intent_classifier.py
- analyze_api_hashing.py
- analyze_encoded_strings.py

After (1 module):
- analyzers/static_analyzer.py
  - PE parsing
  - Code analysis
  - String analysis
  - API hashing
```

---

## Category-by-Category Plan

### 1. FORMAT Analyzers

#### PEAnalyzer
**Consolidates:** static_analyzer.py + PE analysis parts

**Responsibilities:**
- PE header parsing
- Section enumeration
- Import/Export tables
- Resource extraction
- Overlay detection

**Priority:** 100

**Implementation:**
```python
# analyzers/pe_analyzer.py
class PEAnalyzer(BaseAnalyzer):
    def get_capabilities(self):
        return AnalyzerCapabilities(
            name="pe_analyzer",
            version="2.0.0",
            category=AnalyzerCategory.FORMAT,
            supported_file_types={FileType.PE},
            supported_phases={AnalysisPhase.STATIC}
        )
```

#### ImageAnalyzer
**Consolidates:** JPEG/PNG/BMP analysis

**Responsibilities:**
- Image format validation
- Metadata extraction (EXIF)
- Basic structure analysis

**Priority:** 110

#### ArchiveAnalyzer
**Consolidates:** ZIP/ODG analysis

**Responsibilities:**
- Archive extraction
- File enumeration
- Nested archive detection

**Priority:** 120

### 2. CONTENT Analyzers

#### SteganographyAnalyzer
**Consolidates:**
- stegdetect.py
- payload_extract.py
- LSB analysis code

**Responsibilities:**
- LSB extraction
- DCT analysis (JPEG)
- Appended data detection
- Palette analysis

**Priority:** 200

**Dependencies:** ImageAnalyzer

#### PolyglotAnalyzer
**Consolidates:**
- polyglot_analyzer.py
- Hybrid format detection

**Responsibilities:**
- Multi-format detection
- Format boundary identification
- Hidden content extraction

**Priority:** 210

**Dependencies:** FORMAT analyzers

#### CodeAnalyzer
**Consolidates:**
- Code intent classifier
- API hashing
- String analysis

**Responsibilities:**
- Disassembly
- Control flow analysis
- API call detection
- Pattern matching

**Priority:** 220

**Dependencies:** PEAnalyzer

### 3. CRYPTOGRAPHIC Analyzers

#### CryptoAnalyzer
**Consolidates:**
- XOR decryption
- AES decryption
- RC4 decryption
- Crypto detection

**Responsibilities:**
- Algorithm detection
- Key bruteforcing
- Decryption attempts
- Entropy analysis

**Priority:** 300

#### MultiLayerExtractor
**Consolidates:**
- multilayer_extractor.py
- keyplug_combination_decrypt.py
- keyplug_accelerated_multilayer.py

**Responsibilities:**
- Multi-stage decryption
- Layer detection
- Recursive unpacking
- Hardware acceleration

**Priority:** 310

**Dependencies:** CryptoAnalyzer

### 4. BEHAVIORAL Analyzers

#### APISequenceAnalyzer
**Source:** api_sequence_detector.py

**Action:** Refactor to plugin interface (minimal changes)

**Priority:** 400

#### BehavioralAnalyzer
**Source:** behavioral_analyzer.py

**Action:** Refactor to plugin interface (minimal changes)

**Priority:** 410

**Dependencies:** APISequenceAnalyzer

### 5. INTELLIGENCE Analyzers

#### KeyPlugAnalyzer
**Consolidates:**
- keyplug_extractor.py
- keyplug_decompiler.py
- keyplug_peb_detector.py
- keyplug_memory_forensics.py
- keyplug_cross_sample_correlator.py
- keyplug_advanced_analysis.py

**Responsibilities:**
- APT41-specific detection
- KeyPlug payload extraction
- PEB traversal detection
- Memory forensics
- Cross-sample correlation

**Priority:** 500

**Dependencies:**
- PEAnalyzer
- SteganographyAnalyzer
- CryptoAnalyzer

**Implementation:**
```python
# analyzers/keyplug_analyzer.py
class KeyPlugAnalyzer(BaseAnalyzer):
    def __init__(self, config):
        super().__init__(config)
        # Sub-components
        self.extractor = KeyPlugExtractor()
        self.decompiler = KeyPlugDecompiler()
        self.peb_detector = PEBDetector()
        self.memory_forensics = MemoryForensics()
        self.correlator = CrossSampleCorrelator()
```

#### MLMalwareAnalyzer
**Consolidates:**
- ml_malware_analyzer.py
- ml_malware_analyzer_fixed.py
- ml_malware_analyzer_hw.py

**Responsibilities:**
- ML-based classification
- Feature extraction
- Hardware acceleration
- Prediction

**Priority:** 510

**Dependencies:** StaticAnalyzer

#### ThreatScoringAnalyzer
**New module**

**Responsibilities:**
- Aggregate findings
- Calculate threat score
- Confidence calculation

**Priority:** 520

**Dependencies:** All previous analyzers

### 6. EXPORT Analyzers

#### STIXGeneratorAnalyzer
**New module**

**Responsibilities:**
- STIX bundle creation
- Indicator generation
- Relationship mapping

**Priority:** 600

#### YARARuleGeneratorAnalyzer
**New module**

**Responsibilities:**
- YARA rule generation
- Signature extraction
- Optimization

**Priority:** 610

#### MISPEventGeneratorAnalyzer
**New module**

**Responsibilities:**
- MISP event creation
- Attribute mapping
- Tagging

**Priority:** 620

---

## Dependency Resolution

### Dependency Graph

```
┌─────────────┐
│   FORMAT    │
│  Analyzers  │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   CONTENT   │
│  Analyzers  │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│CRYPTOGRAPHIC│
│  Analyzers  │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ BEHAVIORAL  │
│  Analyzers  │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│INTELLIGENCE │
│  Analyzers  │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   EXPORT    │
│  Analyzers  │
└─────────────┘
```

### Breaking Circular Dependencies

**Problem:** Old modules had circular imports
```python
# Old: Circular dependency
# module_a.py
from module_b import function_b

def function_a():
    return function_b()

# module_b.py
from module_a import function_a  # Circular!

def function_b():
    return function_a()
```

**Solution:** Use service locator pattern
```python
# New: Dependency injection
# analyzers/analyzer_a.py
class AnalyzerA(BaseAnalyzer):
    def __init__(self, config):
        super().__init__(config)
        self.service_locator = None  # Injected by pipeline

    def analyze(self, file_data, metadata):
        # Get dependency dynamically
        analyzer_b = self.service_locator.get_analyzer("analyzer_b")
        if analyzer_b:
            result_b = analyzer_b.analyze(file_data, metadata)
```

---

## Implementation Timeline

### Phase 1: Foundation (Week 1) ✅ COMPLETE

**Tasks:**
- [x] Create BaseAnalyzer
- [x] Create AnalyzerRegistry
- [x] Create data classes
- [x] Write documentation

### Phase 2: FORMAT Analyzers (Week 2-3)

**Week 2:**
- [ ] Implement PEAnalyzer
  - Consolidate static_analyzer.py
  - Add comprehensive PE parsing
  - Unit tests
- [ ] Implement ImageAnalyzer
  - JPEG/PNG/BMP support
  - Metadata extraction
  - Unit tests

**Week 3:**
- [ ] Implement ArchiveAnalyzer
  - ZIP/ODG support
  - Nested detection
  - Unit tests
- [ ] Integration testing
- [ ] Performance benchmarking

**Deliverables:**
- 3 FORMAT analyzer plugins
- 90%+ code coverage
- Performance baseline

### Phase 3: CONTENT Analyzers (Week 4-5)

**Week 4:**
- [ ] Implement SteganographyAnalyzer
  - LSB extraction
  - DCT analysis
  - Appended data
  - Unit tests
- [ ] Implement PolyglotAnalyzer
  - Multi-format detection
  - Unit tests

**Week 5:**
- [ ] Implement CodeAnalyzer
  - Disassembly integration
  - API detection
  - Unit tests
- [ ] Integration testing

**Deliverables:**
- 3 CONTENT analyzer plugins
- Integration tests passing

### Phase 4: CRYPTOGRAPHIC Analyzers (Week 6)

**Tasks:**
- [ ] Implement CryptoAnalyzer
  - XOR, AES, RC4 support
  - Algorithm detection
  - Unit tests
- [ ] Implement MultiLayerExtractor
  - Recursive decryption
  - Hardware acceleration
  - Unit tests
- [ ] Integration testing

**Deliverables:**
- 2 CRYPTOGRAPHIC analyzer plugins
- Decryption success rate metrics

### Phase 5: BEHAVIORAL & INTELLIGENCE (Week 7-9)

**Week 7:**
- [ ] Refactor APISequenceAnalyzer
  - Plugin interface
  - Unit tests
- [ ] Refactor BehavioralAnalyzer
  - Plugin interface
  - Unit tests

**Week 8:**
- [ ] Implement KeyPlugAnalyzer
  - Consolidate 7 modules
  - Sub-component classes
  - Unit tests
- [ ] Implement MLMalwareAnalyzer
  - Consolidate 3 versions
  - Hardware support
  - Unit tests

**Week 9:**
- [ ] Implement ThreatScoringAnalyzer
  - Aggregation logic
  - Scoring algorithm
  - Unit tests
- [ ] Integration testing
- [ ] Performance tuning

**Deliverables:**
- 5 BEHAVIORAL/INTELLIGENCE plugins
- End-to-end tests

### Phase 6: EXPORT Analyzers (Week 10)

**Tasks:**
- [ ] Implement STIXGeneratorAnalyzer
- [ ] Implement YARARuleGeneratorAnalyzer
- [ ] Implement MISPEventGeneratorAnalyzer
- [ ] Integration testing
- [ ] Export format validation

**Deliverables:**
- 3 EXPORT analyzer plugins
- Format compliance tests

### Phase 7: Integration & Migration (Week 11-12)

**Week 11:**
- [ ] Update PipelineManager
  - Use AnalyzerRegistry
  - Load order calculation
  - Service locator integration
- [ ] Update ConfigurationManager
  - Per-analyzer config
  - Validation
- [ ] Update all imports
- [ ] Deprecation warnings

**Week 12:**
- [ ] Full system testing
- [ ] Performance benchmarking
- [ ] Documentation updates
- [ ] Migration guide finalization
- [ ] Code review

**Deliverables:**
- Fully integrated system
- Migration complete
- Documentation updated

### Phase 8: Cleanup (Week 13)

**Tasks:**
- [ ] Remove deprecated modules
- [ ] Archive old code
- [ ] Final testing
- [ ] Release notes

**Deliverables:**
- Production-ready system
- v2.0.0 release

---

## Testing Strategy

### Unit Testing

**Per Analyzer:**
```python
# tests/analyzers/test_pe_analyzer.py
import pytest
from analyzers.pe_analyzer import PEAnalyzer

def test_pe_analyzer_capabilities():
    analyzer = PEAnalyzer({})
    caps = analyzer.get_capabilities()
    assert caps.name == "pe_analyzer"
    assert FileType.PE in caps.supported_file_types

def test_pe_analyzer_parse_valid():
    analyzer = PEAnalyzer({})
    with open("samples/valid.exe", "rb") as f:
        data = f.read()
    result = analyzer.analyze(data, {"file_type": FileType.PE})
    assert result.success
    assert "sections" in result.data

def test_pe_analyzer_invalid_file():
    analyzer = PEAnalyzer({})
    result = analyzer.analyze(b"not a PE file", {"file_type": FileType.PE})
    assert not result.success
    assert result.error_message is not None
```

**Coverage Goal:** 90%+ per module

### Integration Testing

**Analyzer Chain:**
```python
# tests/integration/test_analyzer_chain.py
def test_pe_to_threat_scoring():
    registry = AnalyzerRegistry()
    registry.discover_analyzers([Path("analyzers")])

    # Load in order
    analyzers = [
        registry.get_analyzer("pe_analyzer"),
        registry.get_analyzer("code_analyzer"),
        registry.get_analyzer("behavioral_analyzer"),
        registry.get_analyzer("threat_scorer")
    ]

    # Run chain
    with open("samples/malware.exe", "rb") as f:
        data = f.read()

    metadata = {"file_type": FileType.PE}
    for analyzer in analyzers:
        result = analyzer.analyze(data, metadata)
        metadata["previous_results"] = metadata.get("previous_results", [])
        metadata["previous_results"].append(result)

    # Validate final result
    final_result = metadata["previous_results"][-1]
    assert "threat_score" in final_result.data
```

### Performance Testing

**Benchmarks:**
```python
# tests/performance/test_analyzer_performance.py
import time

def test_pe_analyzer_performance():
    analyzer = PEAnalyzer({})
    sample_sizes = [1, 5, 10, 50]  # MB

    for size_mb in sample_sizes:
        data = generate_pe_file(size_mb * 1024 * 1024)
        start = time.time()
        result = analyzer.analyze(data, {})
        duration = time.time() - start

        # Should process at least 10 MB/s
        assert duration < (size_mb / 10)
```

### Regression Testing

**Ensure no functionality lost:**
```python
# tests/regression/test_keyplug_consolidation.py
def test_keyplug_extractor_same_results():
    # Old module
    from old_modules.keyplug_extractor import analyze_odg_file as old_analyze

    # New module
    from analyzers.keyplug_analyzer import KeyPlugAnalyzer
    new_analyzer = KeyPlugAnalyzer({})

    # Compare results
    sample = "samples/apt41_sample.odg"

    old_result, _ = old_analyze(sample)
    with open(sample, "rb") as f:
        new_result = new_analyzer.analyze(f.read(), {"file_type": FileType.ODG})

    # Verify same payloads found
    assert len(old_result["payloads"]) == len(new_result.extracted_files)
```

---

## Risk Mitigation

### Risk 1: Breaking Existing Functionality

**Likelihood:** High
**Impact:** High

**Mitigation:**
- Comprehensive regression tests
- Parallel running (old + new) during transition
- Feature flag for new plugin system
- Gradual rollout

### Risk 2: Performance Degradation

**Likelihood:** Medium
**Impact:** Medium

**Mitigation:**
- Performance benchmarks before/after
- Hardware acceleration preserved
- Load order optimization
- Profiling and optimization

### Risk 3: Circular Dependencies Reintroduced

**Likelihood:** Low
**Impact:** High

**Mitigation:**
- Automated dependency graph analysis
- CI/CD checks for circular imports
- Code review checklist
- Service locator pattern enforcement

### Risk 4: Incomplete Migration

**Likelihood:** Medium
**Impact:** High

**Mitigation:**
- Clear checklist for each module
- Automated migration scripts
- Tracking spreadsheet
- Regular progress reviews

### Risk 5: Developer Resistance

**Likelihood:** Low
**Impact:** Medium

**Mitigation:**
- Clear documentation
- Migration guide with examples
- Training sessions
- Champion early adopters

---

## Success Metrics

### Code Quality Metrics

- **Lines of Code:** Reduce by 40% (from ~15K to ~9K)
- **Modules:** Reduce from 85+ to ~25
- **Cyclomatic Complexity:** Average < 10
- **Code Coverage:** > 90%
- **Circular Imports:** 0

### Performance Metrics

- **Analysis Time:** No degradation (< 5% slowdown acceptable)
- **Memory Usage:** Reduce by 20%
- **Hardware Utilization:** Improve NPU usage by 30%

### Reliability Metrics

- **Error Rate:** < 1% on test corpus
- **False Positives:** < 5%
- **Crash Rate:** < 0.1%

---

## Appendix: Module Mapping Table

| Old Module | New Module | Status | Priority |
|------------|------------|--------|----------|
| keyplug_extractor.py | KeyPlugAnalyzer | Pending | High |
| keyplug_decompiler.py | KeyPlugAnalyzer | Pending | High |
| keyplug_peb_detector.py | KeyPlugAnalyzer | Pending | High |
| keyplug_memory_forensics.py | KeyPlugAnalyzer | Pending | Medium |
| keyplug_combination_decrypt.py | KeyPlugAnalyzer | Pending | High |
| keyplug_accelerated_multilayer.py | MultiLayerExtractor | Pending | Medium |
| keyplug_cross_sample_correlator.py | KeyPlugAnalyzer | Pending | Low |
| ml_malware_analyzer.py | MLMalwareAnalyzer | Pending | High |
| ml_malware_analyzer_fixed.py | MLMalwareAnalyzer | Pending | High |
| ml_malware_analyzer_hw.py | MLMalwareAnalyzer | Pending | High |
| static_analyzer.py | PEAnalyzer | Pending | High |
| code_intent_classifier.py | CodeAnalyzer | Pending | Medium |
| analyze_api_hashing.py | CodeAnalyzer | Pending | Medium |
| analyze_encoded_strings.py | CodeAnalyzer | Pending | Medium |
| behavioral_analyzer.py | BehavioralAnalyzer | Pending | High |
| api_sequence_detector.py | APISequenceAnalyzer | Pending | High |
| multilayer_extractor.py | MultiLayerExtractor | Pending | High |
| payload_extract.py | SteganographyAnalyzer | Pending | Medium |
| stegdetect.py | SteganographyAnalyzer | Pending | Medium |
| polyglot_analyzer.py | PolyglotAnalyzer | Pending | High |

---

## Conclusion

This consolidation plan provides a structured approach to reducing complexity while maintaining functionality. By following the phased timeline and mitigation strategies, we can successfully modernize the KP14 analyzer architecture.

**Key Takeaways:**
- Reduce 85+ modules to ~25 plugins
- Eliminate all circular dependencies
- Standardize plugin interface
- Maintain backward compatibility during transition
- Improve performance through better organization

For implementation details, see:
- [PLUGIN_ARCHITECTURE.md](PLUGIN_ARCHITECTURE.md)
- [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md)
