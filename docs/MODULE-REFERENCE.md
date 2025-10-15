# KP14 Plugin Architecture Design

## Executive Summary

This document describes the plugin architecture for consolidating 85+ analyzer modules in the KP14 platform. The design eliminates circular imports, provides clear module boundaries, and enables clean extensibility through a standardized plugin interface.

**Key Goals:**
- Consolidate 85+ scattered analyzer modules into cohesive plugins
- Eliminate circular dependencies through dependency injection
- Enable runtime plugin discovery and loading
- Provide consistent API across all analyzers
- Support hardware acceleration transparently

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Components](#core-components)
3. [Plugin Interface](#plugin-interface)
4. [Analyzer Categories](#analyzer-categories)
5. [Dependency Resolution](#dependency-resolution)
6. [Lifecycle Management](#lifecycle-management)
7. [Configuration System](#configuration-system)
8. [UML Diagrams](#uml-diagrams)
9. [Implementation Examples](#implementation-examples)
10. [Migration Strategy](#migration-strategy)

---

## Architecture Overview

### High-Level Design

```
┌─────────────────────────────────────────────────────────────────────┐
│                        KP14 Application Layer                        │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌────────────────┐       ┌─────────────────┐                       │
│  │ Pipeline       │       │ Configuration   │                       │
│  │ Manager        │◄──────┤ Manager         │                       │
│  └───────┬────────┘       └─────────────────┘                       │
│          │                                                            │
│          │ Uses                                                       │
│          ▼                                                            │
│  ┌──────────────────────────────────────────────────────────┐       │
│  │           Analyzer Registry (Plugin System)              │       │
│  ├──────────────────────────────────────────────────────────┤       │
│  │                                                            │       │
│  │  • Plugin Discovery (automatic)                           │       │
│  │  • Plugin Registration                                    │       │
│  │  • Dependency Resolution                                  │       │
│  │  • Load Order Calculation                                 │       │
│  │  • Lifecycle Management                                   │       │
│  │                                                            │       │
│  └──────────────────────────────────────────────────────────┘       │
│          │                                                            │
│          │ Manages                                                    │
│          ▼                                                            │
│  ┌──────────────────────────────────────────────────────────┐       │
│  │              BaseAnalyzer (Abstract Interface)           │       │
│  ├──────────────────────────────────────────────────────────┤       │
│  │                                                            │       │
│  │  + get_capabilities() → AnalyzerCapabilities             │       │
│  │  + analyze(data, metadata) → AnalysisResult              │       │
│  │  + get_priority() → int                                   │       │
│  │  + validate_input(data, metadata) → bool                 │       │
│  │  + cleanup()                                              │       │
│  │                                                            │       │
│  └──────────────────────────────────────────────────────────┘       │
│          │                                                            │
│          │ Implemented by                                            │
│          ▼                                                            │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Plugin Categories                         │   │
│  ├─────────────────────────────────────────────────────────────┤   │
│  │                                                               │   │
│  │  FORMAT         │  CONTENT       │  INTELLIGENCE  │  EXPORT  │   │
│  │  ─────────      │  ────────      │  ────────────  │  ──────  │   │
│  │  • PEAnalyzer   │  • Stego       │  • C2Extract   │  • STIX  │   │
│  │  • JPEGAnalyzer │  • Polyglot    │  • ThreatScore │  • YARA  │   │
│  │  • ZIPAnalyzer  │  • CodeAnalyze │  • MITREMap    │  • MISP  │   │
│  │                                                               │   │
│  │  CRYPTOGRAPHIC  │  BEHAVIORAL                                │   │
│  │  ─────────────  │  ──────────                                │   │
│  │  • XORDecrypt   │  • APISequence                             │   │
│  │  • AESDecrypt   │  • PatternMatch                            │   │
│  │  • MultiLayer   │                                            │   │
│  │                                                               │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Single Responsibility**: Each analyzer has one focused purpose
2. **Open/Closed**: Open for extension (new plugins), closed for modification
3. **Dependency Inversion**: Depend on abstractions (BaseAnalyzer), not implementations
4. **Interface Segregation**: Minimal required interface, optional enhancements
5. **Liskov Substitution**: All analyzers are interchangeable through base interface

---

## Core Components

### 1. BaseAnalyzer (Abstract Base Class)

**File:** `base_analyzer.py`

**Purpose:** Defines the contract all analyzers must implement.

**Key Methods:**
```python
class BaseAnalyzer(ABC):
    @abstractmethod
    def get_capabilities(self) -> AnalyzerCapabilities:
        """Return analyzer metadata and capabilities"""

    @abstractmethod
    def analyze(self, file_data: bytes, metadata: Dict) -> AnalysisResult:
        """Perform analysis"""

    @abstractmethod
    def get_priority(self) -> int:
        """Return execution priority (0-999)"""

    def validate_input(self, file_data: bytes, metadata: Dict) -> bool:
        """Validate input (optional override)"""

    def cleanup(self):
        """Cleanup resources (optional override)"""
```

**Key Classes:**
- `AnalyzerCapabilities`: Metadata about what analyzer can do
- `AnalysisResult`: Standardized result format
- `AnalyzerCategory`: Enum for categorization
- `AnalysisPhase`: Enum for pipeline phases
- `FileType`: Enum for file type support

### 2. AnalyzerRegistry

**File:** `analyzer_registry.py`

**Purpose:** Central plugin management system.

**Key Features:**
- **Automatic Discovery**: Scans directories for analyzer classes
- **Registration**: Manages analyzer lifecycle
- **Dependency Resolution**: Topological sort with priority
- **Thread-Safe**: Concurrent access protection
- **Singleton Pattern**: Global registry instance

**Key Methods:**
```python
class AnalyzerRegistry:
    def discover_analyzers(self, search_paths: List[Path]) -> int:
        """Auto-discover plugins"""

    def register_analyzer(self, analyzer_class: Type[BaseAnalyzer]) -> bool:
        """Register a plugin"""

    def get_analyzer(self, name: str, config: Dict = None) -> BaseAnalyzer:
        """Get analyzer instance"""

    def get_load_order(self) -> List[str]:
        """Get execution order"""

    def validate_dependencies(self) -> Dict[str, List[str]]:
        """Check for missing dependencies"""
```

### 3. Data Classes

**AnalyzerCapabilities**
```python
@dataclass
class AnalyzerCapabilities:
    name: str                                    # Unique identifier
    version: str                                 # Semantic version
    category: AnalyzerCategory                   # Category
    supported_file_types: Set[FileType]         # What files to process
    supported_phases: Set[AnalysisPhase]        # Which pipeline phases
    requires_pe_format: bool                     # PE file required
    can_extract_payloads: bool                   # Can extract files
    can_decrypt: bool                            # Decryption capability
    supports_recursive: bool                     # Recursive analysis
    hardware_accelerated: bool                   # Uses OpenVINO
    dependencies: Set[str]                       # Required analyzers
    optional_dependencies: Set[str]              # Optional analyzers
    description: str                             # Human description
    author: str                                  # Author name
    license: str                                 # License type
```

**AnalysisResult**
```python
@dataclass
class AnalysisResult:
    analyzer_name: str                          # Which analyzer
    analyzer_version: str                       # Version
    success: bool                               # Success/failure
    error_message: Optional[str]                # Error details
    data: Dict[str, Any]                        # Analysis data
    execution_time_ms: float                    # Timing info
    warnings: List[str]                         # Warnings
    threat_indicators: List[Dict]               # Threats found
    confidence_score: float                     # 0.0 to 1.0
    extracted_files: List[Path]                 # Files extracted
```

---

## Plugin Interface

### Minimal Plugin Implementation

```python
from base_analyzer import (
    BaseAnalyzer,
    AnalyzerCapabilities,
    AnalyzerCategory,
    AnalysisPhase,
    FileType,
    AnalysisResult
)

class MyAnalyzer(BaseAnalyzer):
    """Example minimal analyzer implementation"""

    def get_capabilities(self) -> AnalyzerCapabilities:
        return AnalyzerCapabilities(
            name="my_analyzer",
            version="1.0.0",
            category=AnalyzerCategory.CONTENT,
            supported_file_types={FileType.PE, FileType.BINARY},
            supported_phases={AnalysisPhase.STATIC},
            description="Example analyzer",
            author="Security Team",
            dependencies=set()  # No dependencies
        )

    def analyze(self, file_data: bytes, metadata: Dict) -> AnalysisResult:
        result = AnalysisResult(
            analyzer_name="my_analyzer",
            analyzer_version="1.0.0",
            success=True
        )

        # Perform analysis
        result.data["finding"] = "example"
        result.confidence_score = 0.85

        return result

    def get_priority(self) -> int:
        return 400  # Static analysis phase
```

### Hardware-Accelerated Plugin

```python
from base_analyzer import HardwareAcceleratedAnalyzer

class GPUAnalyzer(HardwareAcceleratedAnalyzer):
    """Analyzer with GPU/NPU acceleration"""

    def __init__(self, config: Dict = None):
        super().__init__(config)
        if self.is_hardware_available():
            self._load_openvino_model()

    def _load_openvino_model(self):
        """Load OpenVINO model"""
        # Model loading logic
        pass

    def analyze(self, file_data: bytes, metadata: Dict) -> AnalysisResult:
        if self.is_hardware_available():
            return self._analyze_with_hw(file_data, metadata)
        else:
            return self._analyze_cpu_fallback(file_data, metadata)
```

---

## Analyzer Categories

### 1. FORMAT Analyzers (Priority: 100-199)

**Purpose:** Parse and extract information from file formats.

**Examples:**
- `PEAnalyzer`: PE executable analysis
- `JPEGAnalyzer`: JPEG file structure
- `PNGAnalyzer`: PNG file structure
- `ZIPAnalyzer`: ZIP archive parsing

**Characteristics:**
- No dependencies on other analyzers
- Execute early in pipeline
- Provide foundation for other analyzers

### 2. CONTENT Analyzers (Priority: 200-299)

**Purpose:** Analyze file content for hidden data, code, patterns.

**Examples:**
- `SteganographyAnalyzer`: Hidden data detection
- `PolyglotAnalyzer`: Multi-format file detection
- `CodeAnalyzer`: Code structure analysis
- `ObfuscationAnalyzer`: Obfuscation detection

**Characteristics:**
- May depend on FORMAT analyzers
- Focus on content, not format
- Detect anomalies and hidden content

### 3. CRYPTOGRAPHIC Analyzers (Priority: 300-399)

**Purpose:** Decrypt encrypted content, detect encryption.

**Examples:**
- `XORDecryptAnalyzer`: XOR decryption
- `AESDecryptAnalyzer`: AES decryption
- `MultiLayerDecryptAnalyzer`: Multi-stage decryption
- `CryptoDetectAnalyzer`: Encryption detection

**Characteristics:**
- May depend on CONTENT analyzers
- Can extract payloads
- Support recursive analysis

### 4. BEHAVIORAL Analyzers (Priority: 400-499)

**Purpose:** Detect behavioral patterns and API usage.

**Examples:**
- `APISequenceAnalyzer`: API call patterns
- `BehavioralPatternAnalyzer`: Behavior detection
- `AntiAnalysisDetector`: Anti-debug/VM detection

**Characteristics:**
- Depend on static analysis
- Pattern matching
- Often hardware accelerated

### 5. INTELLIGENCE Analyzers (Priority: 500-599)

**Purpose:** Extract threat intelligence from analyzed files.

**Examples:**
- `C2ExtractorAnalyzer`: C2 infrastructure extraction
- `ThreatScoringAnalyzer`: Threat level calculation
- `MITREMappingAnalyzer`: ATT&CK framework mapping
- `MalwareFamilyAnalyzer`: Family classification

**Characteristics:**
- Depend on all previous analyzers
- Aggregate findings
- Generate high-level intelligence

### 6. EXPORT Analyzers (Priority: 600-699)

**Purpose:** Generate export formats and reports.

**Examples:**
- `STIXGeneratorAnalyzer`: STIX bundle creation
- `YARARuleGeneratorAnalyzer`: YARA rule creation
- `MISPEventGeneratorAnalyzer`: MISP event creation
- `SuricataRuleGeneratorAnalyzer`: Suricata rules

**Characteristics:**
- Execute last in pipeline
- Read-only (don't modify data)
- Generate external artifacts

---

## Dependency Resolution

### Dependency Declaration

```python
def get_capabilities(self) -> AnalyzerCapabilities:
    return AnalyzerCapabilities(
        name="threat_scorer",
        version="1.0.0",
        category=AnalyzerCategory.INTELLIGENCE,

        # Required dependencies
        dependencies={
            "pe_analyzer",
            "c2_extractor"
        },

        # Optional dependencies (graceful degradation)
        optional_dependencies={
            "mitre_mapper"
        }
    )
```

### Load Order Calculation

The registry uses **topological sort with priority** to determine execution order:

1. Build dependency graph
2. Identify nodes with no dependencies
3. Sort by priority (lower = earlier)
4. Process nodes, updating neighbor dependencies
5. Detect circular dependencies

**Algorithm Pseudocode:**
```
function calculate_load_order():
    graph = build_dependency_graph()
    in_degree = calculate_in_degrees()
    available = nodes_with_zero_in_degree()
    result = []

    while available not empty:
        available.sort_by_priority()
        current = available.pop_first()
        result.append(current)

        for neighbor in graph[current]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                available.append(neighbor)

    if len(result) != len(all_nodes):
        # Circular dependency detected
        warn_circular_dependency()

    return result
```

### Circular Dependency Detection

If circular dependencies exist, the registry:
1. Logs an error with affected analyzers
2. Adds remaining analyzers sorted by priority
3. Allows pipeline to continue (graceful degradation)

---

## Lifecycle Management

### Analyzer Lifecycle States

```
┌──────────┐
│ Unloaded │
└────┬─────┘
     │ discover/register
     ▼
┌────────────┐
│ Registered │
└────┬───────┘
     │ get_analyzer()
     ▼
┌──────────────┐
│ Instantiated │
└────┬─────────┘
     │ analyze()
     ▼
┌──────────┐
│ Executing│
└────┬─────┘
     │ complete/error
     ▼
┌──────────┐
│ Idle     │
└────┬─────┘
     │ cleanup()
     ▼
┌──────────┐
│ Destroyed│
└──────────┘
```

### Instance Management

**Singleton Mode** (default):
```python
# Same instance reused
analyzer1 = registry.get_analyzer("pe_analyzer")
analyzer2 = registry.get_analyzer("pe_analyzer")
# analyzer1 is analyzer2 → True
```

**Custom Config Mode**:
```python
# New instance per call
config = {"custom_setting": True}
analyzer1 = registry.get_analyzer("pe_analyzer", config)
analyzer2 = registry.get_analyzer("pe_analyzer", config)
# analyzer1 is analyzer2 → False
```

### Resource Cleanup

```python
# Cleanup single analyzer
analyzer.cleanup()

# Cleanup all analyzers
registry.cleanup_all()
```

---

## Configuration System

### Configuration Hierarchy

```
1. System Defaults (in analyzer code)
   ↓ overridden by
2. Global Config File (settings.ini)
   ↓ overridden by
3. Analyzer-Specific Config
   ↓ overridden by
4. Runtime Config (passed to get_analyzer())
```

### Configuration Format

**settings.ini**
```ini
[analyzers]
# Global settings for all analyzers
enabled = true
log_level = INFO

[analyzer.pe_analyzer]
enabled = true
max_file_size_mb = 100
analyze_sections = true

[analyzer.stego_analyzer]
enabled = true
check_lsb = true
check_appended_data = true
max_scan_size_mb = 10

[analyzer.threat_scorer]
enabled = true
scoring_model = ml  # or heuristic
confidence_threshold = 0.7
```

### Accessing Configuration

```python
class MyAnalyzer(BaseAnalyzer):
    def __init__(self, config: Dict = None):
        super().__init__(config)

        # Get config with default
        self.max_size = self.get_config("max_size", 100)
        self.enabled = self.get_config("enabled", True)
```

---

## UML Diagrams

### Class Diagram

```
┌──────────────────────────────┐
│     BaseAnalyzer (ABC)       │
├──────────────────────────────┤
│ # config: Dict               │
│ # logger: Logger             │
├──────────────────────────────┤
│ + get_capabilities()         │ ◄──────── Interface
│ + analyze(data, meta)        │            (must implement)
│ + get_priority()             │
│ + validate_input()           │ ◄──────── Optional
│ + cleanup()                  │            (can override)
└──────────────┬───────────────┘
               │
               │ Inherits
               │
      ┌────────┴───────┬──────────────────┬──────────────┐
      │                │                  │              │
      ▼                ▼                  ▼              ▼
┌───────────┐  ┌──────────────┐  ┌─────────────┐  ┌──────────┐
│PEAnalyzer │  │StegoAnalyzer │  │C2Extractor  │  │STIX      │
│           │  │              │  │             │  │Generator │
│(FORMAT)   │  │(CONTENT)     │  │(INTELLIGENCE)│ │(EXPORT)  │
└───────────┘  └──────────────┘  └─────────────┘  └──────────┘

┌─────────────────────────────────────┐
│  HardwareAcceleratedAnalyzer (ABC)  │
├─────────────────────────────────────┤
│ + ov_core: Core                     │
│ + _hardware_available: bool         │
├─────────────────────────────────────┤
│ + is_hardware_available()           │
│ # _init_hardware()                  │
└──────────────┬──────────────────────┘
               │
               │ Inherits
               ▼
      ┌────────────────┐
      │ MLAnalyzer     │
      │ (Behavioral)   │
      └────────────────┘
```

### Sequence Diagram: Analyzer Discovery and Execution

```
Pipeline    Registry     FileSystem   AnalyzerClass   AnalyzerInstance
Manager
   │            │            │              │               │
   ├─discover──►│            │              │               │
   │            ├─scan_dir──►│              │               │
   │            │◄─py_files──┤              │               │
   │            │            │              │               │
   │            ├─import_module──────────►  │               │
   │            ├─create_temp_instance──────┼──►new()       │
   │            │                           │   ◄───────────┤
   │            ├─get_capabilities()────────┼──────────────►│
   │            │                           │◄──caps────────┤
   │            ├─register(class, caps)     │               │
   │            │                           │               │
   │◄─count─────┤                           │               │
   │            │                           │               │
   ├─get_load_order()                       │               │
   │            ├─calculate_dependencies()  │               │
   │            ├─topological_sort()        │               │
   │◄─order─────┤                           │               │
   │            │                           │               │
   ├─run_pipeline()                         │               │
   │            │                           │               │
   ├─get_analyzer("pe_analyzer")            │               │
   │            ├─create_instance()─────────┼──►new(config) │
   │            │                           │   ◄───────────┤
   │◄─instance──┤                           │               │
   │            │                           │               │
   ├─analyze(data, meta)─────────────────────────────────►  │
   │                                                  [processing]
   │◄─result─────────────────────────────────────────────────┤
   │            │                           │               │
   ├─cleanup() ─────────────────────────────────────────────►│
   │            │                           │               │
```

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        KP14 Application                          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │ uses
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Plugin Architecture                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  ┌───────────────────────┐        ┌──────────────────────┐     │
│  │  AnalyzerRegistry     │        │  BaseAnalyzer        │     │
│  │                       │manages │                      │     │
│  │  - _analyzers: Dict   │◄───────┤  «interface»         │     │
│  │  - _capabilities      │        │                      │     │
│  │  - _load_order        │        └──────────┬───────────┘     │
│  │                       │                   │                  │
│  │  + discover()         │                   │ implements       │
│  │  + register()         │                   │                  │
│  │  + get_analyzer()     │                   ▼                  │
│  └───────────────────────┘         ┌────────────────────┐      │
│                                     │  Concrete Analyzers│      │
│                                     └────────────────────┘      │
│                                                                   │
│  ┌──────────────────────┐          ┌──────────────────────┐    │
│  │  AnalyzerCapabilities│          │  AnalysisResult      │    │
│  │  «dataclass»         │          │  «dataclass»         │    │
│  └──────────────────────┘          └──────────────────────┘    │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation Examples

### Example 1: PE Analyzer

```python
# analyzers/pe_analyzer.py

from base_analyzer import (
    BaseAnalyzer,
    AnalyzerCapabilities,
    AnalyzerCategory,
    AnalysisPhase,
    FileType,
    AnalysisResult
)
import pefile
import time

class PEAnalyzer(BaseAnalyzer):
    """Analyzes PE executable files"""

    def get_capabilities(self) -> AnalyzerCapabilities:
        return AnalyzerCapabilities(
            name="pe_analyzer",
            version="2.0.0",
            category=AnalyzerCategory.FORMAT,
            supported_file_types={FileType.PE},
            supported_phases={AnalysisPhase.STATIC},
            requires_pe_format=True,
            description="PE file format analyzer",
            author="KP14 Team"
        )

    def analyze(self, file_data: bytes, metadata: Dict) -> AnalysisResult:
        start_time = time.time()

        result = AnalysisResult(
            analyzer_name="pe_analyzer",
            analyzer_version="2.0.0",
            success=True
        )

        try:
            pe = pefile.PE(data=file_data)

            # Extract PE information
            result.data = {
                "architecture": self._get_architecture(pe),
                "sections": self._extract_sections(pe),
                "imports": self._extract_imports(pe),
                "exports": self._extract_exports(pe),
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            }

            result.confidence_score = 1.0

        except Exception as e:
            result.success = False
            result.error_message = str(e)

        result.execution_time_ms = (time.time() - start_time) * 1000
        return result

    def get_priority(self) -> int:
        return 100  # FORMAT category: 100-199

    def _get_architecture(self, pe) -> str:
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            return "32-bit"
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            return "64-bit"
        return "unknown"
```

### Example 2: Consolidated KeyPlug Analyzer

```python
# analyzers/keyplug_analyzer.py

from base_analyzer import BaseAnalyzer, AnalyzerCapabilities
from typing import Dict, Any, List

class KeyPlugAnalyzer(BaseAnalyzer):
    """
    Consolidated analyzer for APT41 KeyPlug malware.

    Merges functionality from:
    - keyplug_extractor.py
    - keyplug_decompiler.py
    - keyplug_peb_detector.py
    - keyplug_memory_forensics.py
    - keyplug_combination_decrypt.py
    - keyplug_accelerated_multilayer.py
    - keyplug_cross_sample_correlator.py
    """

    def __init__(self, config: Dict = None):
        super().__init__(config)

        # Sub-components
        self.extractor = JPEGPayloadExtractor()
        self.decryptor = XORDecryptor()
        self.peb_detector = PEBTraversalDetector()

    def get_capabilities(self) -> AnalyzerCapabilities:
        return AnalyzerCapabilities(
            name="keyplug_analyzer",
            version="1.0.0",
            category=AnalyzerCategory.CONTENT,
            supported_file_types={FileType.JPEG, FileType.ODG, FileType.PE},
            supported_phases={
                AnalysisPhase.EXTRACTION,
                AnalysisPhase.DECRYPTION,
                AnalysisPhase.STATIC
            },
            can_extract_payloads=True,
            can_decrypt=True,
            supports_recursive=True,
            description="APT41 KeyPlug malware analyzer",
            dependencies={"pe_analyzer"}
        )

    def analyze(self, file_data: bytes, metadata: Dict) -> AnalysisResult:
        result = AnalysisResult(
            analyzer_name="keyplug_analyzer",
            analyzer_version="1.0.0",
            success=True
        )

        file_type = metadata.get("file_type")

        # Extract payloads from carriers
        if file_type in (FileType.JPEG, FileType.ODG):
            payloads = self.extractor.extract(file_data)
            result.data["extracted_payloads"] = len(payloads)

            for payload in payloads:
                result.extracted_files.append(payload.path)

        # Decrypt XOR-encrypted content
        if self._detect_xor_encryption(file_data):
            decrypted = self.decryptor.decrypt(file_data)
            if decrypted:
                result.data["decrypted"] = True
                result.add_threat_indicator("xor_encryption", "detected", 0.9)

        # Detect PEB traversal
        if file_type == FileType.PE:
            peb_findings = self.peb_detector.analyze(file_data)
            if peb_findings:
                result.data["peb_traversal"] = peb_findings
                result.add_threat_indicator("peb_traversal", "keyplug_technique", 0.95)

        result.confidence_score = self._calculate_confidence(result.data)
        return result

    def get_priority(self) -> int:
        return 250  # CONTENT category
```

### Example 3: Service Locator Pattern

```python
# service_locator.py

from typing import Dict, Any, Optional
from base_analyzer import BaseAnalyzer
from analyzer_registry import AnalyzerRegistry

class ServiceLocator:
    """
    Dependency injection container for analyzer services.

    Eliminates circular imports by providing lazy service resolution.
    """

    def __init__(self, registry: AnalyzerRegistry):
        self._registry = registry
        self._services: Dict[str, Any] = {}

    def register_service(self, name: str, service: Any):
        """Register a service"""
        self._services[name] = service

    def get_service(self, name: str) -> Optional[Any]:
        """Get a service by name"""
        return self._services.get(name)

    def get_analyzer(self, name: str, config: Dict = None) -> Optional[BaseAnalyzer]:
        """Get an analyzer from registry"""
        return self._registry.get_analyzer(name, config)


# Usage in analyzer
class MyAnalyzer(BaseAnalyzer):
    def __init__(self, config: Dict = None):
        super().__init__(config)
        self.service_locator = None  # Injected by pipeline

    def analyze(self, file_data: bytes, metadata: Dict) -> AnalysisResult:
        # Get dependent analyzer via service locator
        pe_analyzer = self.service_locator.get_analyzer("pe_analyzer")

        if pe_analyzer:
            pe_result = pe_analyzer.analyze(file_data, metadata)
            # Use pe_result
```

---

## Migration Strategy

See [MODULE_CONSOLIDATION_PLAN.md](MODULE_CONSOLIDATION_PLAN.md) for detailed migration plan.

**High-Level Steps:**

1. **Phase 1**: Implement base architecture (COMPLETE)
   - ✅ Create BaseAnalyzer
   - ✅ Create AnalyzerRegistry
   - ✅ Create data classes

2. **Phase 2**: Migrate FORMAT analyzers (Week 1-2)
   - Consolidate PE analyzers
   - Consolidate image analyzers
   - Test individually

3. **Phase 3**: Migrate CONTENT analyzers (Week 3-4)
   - Consolidate steganography analyzers
   - Consolidate polyglot analyzers
   - Integration testing

4. **Phase 4**: Migrate CRYPTOGRAPHIC analyzers (Week 5)
   - Consolidate decryption modules
   - Multi-layer decryption support

5. **Phase 5**: Migrate remaining analyzers (Week 6-8)
   - BEHAVIORAL, INTELLIGENCE, EXPORT categories
   - Full integration testing
   - Performance benchmarking

6. **Phase 6**: Deprecate old modules (Week 9-10)
   - Update all imports
   - Remove deprecated code
   - Documentation updates

---

## Benefits of Plugin Architecture

### 1. Modularity
- Each analyzer is self-contained
- Clear boundaries and responsibilities
- Easy to test in isolation

### 2. Extensibility
- New analyzers added without modifying core
- Plugin discovery is automatic
- No need to register manually

### 3. Maintainability
- Consistent interface reduces cognitive load
- Dependency tracking prevents circular imports
- Centralized configuration

### 4. Performance
- Load order optimization
- Lazy instantiation
- Resource cleanup

### 5. Reliability
- Graceful degradation on errors
- Dependency validation
- Version management

---

## Future Enhancements

### Planned Features

1. **Dynamic Plugin Loading**
   - Load/unload plugins at runtime
   - Hot-reload for development

2. **Plugin Marketplace**
   - Community-contributed analyzers
   - Version compatibility checking
   - Digital signatures

3. **Distributed Analysis**
   - Remote analyzer execution
   - Microservice architecture
   - gRPC communication

4. **Advanced Caching**
   - Result caching by file hash
   - Incremental analysis
   - Cache invalidation

5. **Performance Profiling**
   - Per-analyzer metrics
   - Bottleneck identification
   - Optimization recommendations

---

## Conclusion

The KP14 plugin architecture provides a robust, scalable foundation for analyzer consolidation. By standardizing the plugin interface, implementing automatic discovery, and resolving dependencies intelligently, we eliminate the circular import issues while enabling future extensibility.

**Next Steps:**
1. Review this design document
2. Begin Phase 2 migration (FORMAT analyzers)
3. Create migration scripts for automated refactoring
4. Update integration tests

For implementation details, see:
- [MODULE_CONSOLIDATION_PLAN.md](MODULE_CONSOLIDATION_PLAN.md)
- [MIGRATION_GUIDE.md](MIGRATION_GUIDE.md)
