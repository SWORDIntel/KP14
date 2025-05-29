# KEYPLUG Analysis System v2.0 Documentation

## Overview

The KEYPLUG Analysis System has undergone a comprehensive refactoring to improve maintainability, extensibility, and performance. This document details the architectural changes, new components, and enhanced capabilities of the system.

## Architecture Changes

### Previous Architecture (v1.0)
The previous version of KEYPLUG used a monolithic architecture with:
- A single orchestrator file containing most logic
- External script execution for analysis components
- Limited result sharing between components
- Basic reporting capabilities
- Manual OpenVINO integration in each module

### New Architecture (v2.0)
The refactored system uses a modular architecture with clear separation of concerns:

```
┌─────────────────────────┐     ┌───────────────────────┐
│                         │     │                       │
│ Unified Orchestrator    │◄────┤ Pipeline Config       │
│ (Main coordination)     │     │ (Defines execution    │
│                         │     │  order & dependencies)│
└────────────┬────────────┘     └───────────────────────┘
             │
             ▼
┌─────────────────────────┐     ┌───────────────────────┐
│                         │     │                       │
│ Module Loader           │────►│ Analysis Modules      │
│ (Dynamic loading with   │     │ (Various analyzers    │
│  fallback mechanisms)   │     │  with common interface)│
└────────────┬────────────┘     └───────────────────────┘
             │
             ▼
┌─────────────────────────┐
│                         │
│ Results Processor       │
│ (Aggregation, sharing,  │
│  and reporting)         │
│                         │
└─────────────────────────┘
```

## Core Components

### 1. Unified Orchestrator (`keyplug_unified_orchestrator.py`)

The main entry point and coordinator for the entire analysis system.

**Key Features:**
- CLI argument processing
- Coordinated execution of analysis modules respecting dependencies
- Support for parallel processing
- Integration of file, memory, and global analysis workflows
- Dynamic module loading and error handling
- Comprehensive logging and progress tracking

**Example Usage:**
```bash
# Analyze a single file
python keyplug_unified_orchestrator.py -f malware.bin

# Analyze all files in a directory
python keyplug_unified_orchestrator.py -d /samples -p "*.exe"

# Analyze a memory dump
python keyplug_unified_orchestrator.py --memory-dump memory.dmp

# Disable OpenVINO acceleration
python keyplug_unified_orchestrator.py -f malware.bin --no-openvino

# Enable parallel processing
python keyplug_unified_orchestrator.py -d /samples -p "*.exe" --parallel
```

### 2. Module Loader (`keyplug_module_loader.py`)

Handles the dynamic loading and instantiation of analysis modules.

**Key Features:**
- Dynamic module discovery and loading
- Fallback to placeholder implementations when modules are missing
- Centralized OpenVINO acceleration management
- Consistent initialization of modules with appropriate parameters
- Error recovery and graceful degradation

**Example Integration:**
```python
from keyplug_module_loader import ModuleLoader

# Initialize the module loader
loader = ModuleLoader(module_import_map)

# Create an instance of an analysis module
extractor = loader.create_instance("KeyplugExtractor", output_dir="./output/extractor")

# Use the module (same interface regardless of whether it's real or placeholder)
result = extractor.analyze(file_path)
```

### 3. Pipeline Configuration (`keyplug_pipeline_config.py`)

Defines the analysis pipeline structure, module dependencies, and execution order.

**Key Features:**
- Definition of pipeline stages with dependencies
- Mapping of module names to import paths
- Module grouping for selective enabling/disabling
- Module details including requirements and CLI flags
- Centralized configuration for the entire system

**Configuration Example:**
```python
# Stage definition with dependencies
("decryption", [
    "SimpleRC4", 
    "RC4Decrypt", 
    "SectionDecrypt", 
    "MultiLayerDecrypt", 
    "MultiLayerDecryptAdvanced", 
    "TargetedPatternDecrypt", 
    "KeyplugCombinationDecrypt"
], "basic_analysis")
```

### 4. Results Processor (`keyplug_results_processor.py`)

Manages the collection, sharing, and reporting of analysis results.

**Key Features:**
- Centralized results storage
- Result sharing between components
- Context passing for module communication
- Multi-format reporting (JSON, text, HTML, summary)
- Consistent reporting structure
- Report visualization enhancements

**Report Generation Example:**
```python
from keyplug_results_processor import ResultsProcessor

# Initialize the processor
processor = ResultsProcessor("./output")

# Register files and store results
processor.register_file(file_path)
processor.store_file_result(file_name, "ExtractPE", extraction_result)

# Generate consolidated reports
report_paths = processor.generate_reports()
print(f"Reports generated: {report_paths}")
```

## Enhanced Type Analysis and Propagation

### Type Propagation System (`type_propagation.py`)

The KEYPLUG Analysis System now features an enhanced type propagation system that significantly improves the accuracy of decompiled code analysis by correctly inferring and propagating types across code elements.

**Key Features:**
- Advanced AST-based C code analysis using pycparser
- Comprehensive type propagation mechanisms:
  - **Assignment Propagation**: Propagates types from right-hand side to left-hand side variables in assignments
  - **Function Call Return Propagation**: Propagates function return types to assigned variables
  - **Function Call Argument Propagation**: Propagates parameter types to arguments in function calls
- Support for generic type upgrading (e.g., `void*` → specific types)
- Typedef tracking and resolution
- Integration with external type signature databases
- Structured return format with detailed type information

**Type Propagation Process:**
```
┌───────────────────┐     ┌────────────────────┐     ┌────────────────────┐
│                   │     │                    │     │                    │
│ Parse C Code      │────►│ Process AST with   │────►│ Propagate Types    │
│ using pycparser   │     │ Multiple Visitors  │     │ Through Multiple   │
│                   │     │                    │     │ Propagation Passes │
└───────────────────┘     └────────────────────┘     └────────────────────┘
                                                               │
┌───────────────────┐     ┌────────────────────┐              │
│                   │     │                    │              ▼
│ Return Structured │◄────┤ Merge All Type    │◄─────────────┘
│ Type Information  │     │ Information        │
│                   │     │                    │
└───────────────────┘     └────────────────────┘
```

### Type Inference Engine (`type_inference.py`)

The Type Inference Engine has been integrated with the TypePropagator to provide more accurate type information for decompiled code.

**Key Features:**
- Hybrid type inference combining pattern matching and propagation
- Support for function signature databases to improve type inference
- Integration with OpenVINO for accelerated pattern recognition
- Handles Windows API function signatures for better analysis of Windows malware
- Scoped variable analysis to correctly handle function-local variables

**Example Usage:**
```python
from type_inference import TypeInferenceEngine

# Initialize with optional OpenVINO acceleration
engine = TypeInferenceEngine(use_openvino=True)

# Infer types in decompiled code with signature data
typed_code = engine.infer_types(
    decompiled_code="path/to/decompiled.c",
    signature_data_path="path/to/signatures.json"
)
```

### Source Code Extractor (`keyplug_source_extractor.py`)

The Source Code Extractor has been enhanced to leverage the improved type inference capabilities.

**Key Features:**
- Integration with TypePropagator for accurate type information
- Support for function signature data to improve analysis
- OpenVINO acceleration for faster processing
- Enhanced multi-stage extraction workflow:
  1. Detect function boundaries
  2. Decompile binary using selected decompiler
  3. Infer and propagate types using signature data
  4. Recover control flow
  5. Detect compiler idioms

**Command Line Options:**
```bash
# Basic extraction
python keyplug_source_extractor.py -f malware.bin -o output_dir

# With function signatures for improved type inference
python keyplug_source_extractor.py -f malware.bin -o output_dir --signatures signatures.json

# Batch processing with type inference
python keyplug_source_extractor.py -d /samples -p "*.exe" --signatures signatures.json
```

## Analysis Modules

The system integrates various analysis modules organized by functionality:

### Basic Analysis
- `ExtractPE`: Extracts embedded PE files
- `AnalyzePE`: Analyzes PE file structure and characteristics

### Static Analysis
- `FunctionBoundaryDetection`: Detects function boundaries
- `ControlFlowRecovery`: Recovers control flow graphs
- `TypeInference`: Infers variable and parameter types

### Decryption
- `SimpleRC4`: Basic RC4 implementation
- `RC4Decrypt`: Advanced RC4 with key discovery
- `SectionDecrypt`: PE section decryption
- `MultiLayerDecrypt`: Multi-layer decryption 
- `MultiLayerDecryptAdvanced`: ML-assisted multi-layer decryption
- `TargetedPatternDecrypt`: Pattern-based targeted decryption
- `KeyplugCombinationDecrypt`: Combination decryption

### Extraction
- `KeyplugExtractor`: Generic extraction tools
- `KeyplugMultilayerExtractor`: Multi-layer code extraction
- `KeyplugFunctionExtractor`: Function extraction

### Advanced Analysis
- `KeyplugAdvancedAnalysis`: Advanced static analysis
- `KeyplugApiSequenceDetector`: API call sequence detection
- `KeyplugAcceleratedMultilayer`: Accelerated multi-layer analysis
- `CompilerIdiomDetection`: Compiler idiom detection
- `PolyglotAnalyzer`: Analysis of polyglot files

### ML-Based Analysis
- `MLMalwareAnalyzer`: ML-based malware detection
- `MLPatternAnalyzer`: ML-based pattern analysis

### Memory Analysis
- `KeyplugMemoryAnalyzer`: Memory forensics analysis

### Global Analysis
- `KeyplugCrossSampleCorrelator`: Cross-sample correlation
- `KeyplugPatternDatabase`: Pattern database generation and updates

## Key Improvements

### 1. Performance Optimization
- Centralized OpenVINO acceleration
- Parallel processing capabilities
- Optimized module loading
- Efficient resource sharing

### 2. Maintainability
- Clear separation of concerns
- Modular architecture
- Consistent interfaces
- Reduced code duplication
- Better error handling

### 3. Extensibility
- Easy addition of new modules
- Pipeline configuration without code changes
- Placeholder mechanism for graceful degradation
- Well-defined interfaces for module development

### 4. Reporting
- Multi-format reporting (JSON, text, HTML, summary)
- Enhanced visualization
- Better organization of results
- Centralized result storage
- Cross-component correlation

## Upgrading from v1 to v2

### For Users
1. Replace the existing `keyplug_unified_orchestrator.py` with the new version
2. Add the new module files:
   - `keyplug_module_loader.py`
   - `keyplug_pipeline_config.py`
   - `keyplug_results_processor.py`
3. Update any custom scripts to use the new CLI interface
4. No changes needed to existing analysis modules

### For Developers
1. Follow the module interface convention:
   - Use `analyze(file_path, context=None, **kwargs)` method for file analysis
   - Use `analyze_dump(dump_path, profile=None, context=None, **kwargs)` for memory analysis
   - Accept `ov_core` and `device_name` parameters in initialization
2. Update the pipeline configuration to include your module
3. Use the context parameter for sharing data between modules

## Examples

### Adding a New Module

1. Create your module following the interface convention:

```python
class MyNewAnalyzer:
    def __init__(self, ov_core=None, device_name="CPU", output_dir=".", **kwargs):
        self.ov_core = ov_core
        self.device_name = device_name
        self.output_dir = output_dir
        # Initialize your analyzer
        
    def analyze(self, file_path, context=None, **kwargs):
        # Your analysis logic here
        return {
            "status": "completed",
            "findings": [
                {"severity": "medium", "description": "Interesting finding"}
            ]
        }
```

2. Update the pipeline configuration:

```python
# In keyplug_pipeline_config.py

# Add to MODULE_DETAILS
"MyNewAnalyzer": {
    "description": "My custom analyzer",
    "cli_flag": "my_analyzer",
    "default_enabled": True,
    "requires_openvino": False
}

# Add to module import map
"MyNewAnalyzer": "my_new_analyzer.MyNewAnalyzer"

# Add to appropriate pipeline stage
("advanced_analysis", [
    "TypeInference", 
    "PolyglotAnalyzer", 
    "KeyplugApiSequenceDetector", 
    "KeyplugAdvancedAnalysis",
    "MyNewAnalyzer"  # Added here
], ["structure_analysis", "deep_extraction"])
```

### Running Analysis

Basic file analysis:
```bash
python keyplug_unified_orchestrator.py -f malware.bin -o ./analysis_output
```

Memory dump analysis:
```bash
python keyplug_unified_orchestrator.py --memory-dump memory.dmp --memory-profile Win10x64
```

Combined analysis with all modules:
```bash
python keyplug_unified_orchestrator.py -f malware.bin --memory-dump memory.dmp -o ./output --parallel
```

Selective module enabling:
```bash
python keyplug_unified_orchestrator.py -f malware.bin --disable-static --enable-ml-malware
```

## Conclusion

The KEYPLUG Analysis System v2.0 represents a significant improvement in architecture, maintainability, and capability. The modular design allows for easier extension and customization while maintaining compatibility with existing analysis modules. The enhanced reporting capabilities provide better insight into analysis results, and the performance optimizations ensure efficient resource utilization.
