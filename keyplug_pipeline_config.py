#!/usr/bin/env python3
"""
KEYPLUG Pipeline Configuration
------------------------------
Defines the analysis pipeline order and component configurations.
This file specifies which modules are loaded, their order of execution,
dependencies between modules, and default settings.
"""

import os
from typing import Dict, List, Tuple, Any, Optional

# ===============================================================
# PIPELINE CONFIGURATION
# ===============================================================

# Module groups - for selective enabling/disabling of module groups
MODULE_GROUPS = {
    "basic": ["ExtractPE", "AnalyzePE", "FunctionBoundaryDetection", "ControlFlowRecovery"],
    "decompilation": ["DecompilerIntegration", "KeyplugDecompiler", "KeyplugFunctionExtractor"],
    "extraction": ["KeyplugExtractor", "KeyplugMultilayerExtractor"],
    "decryption": ["SimpleRC4", "RC4Decrypt", "SectionDecrypt", "MultiLayerDecrypt", 
                  "MultiLayerDecryptAdvanced", "TargetedPatternDecrypt", "KeyplugCombinationDecrypt"],
    "analysis": ["CompilerIdiomDetection", "KeyplugApiSequenceDetector", "TypeInference", 
                "PolyglotAnalyzer", "KeyplugAdvancedAnalysis"],
    "ml": ["MLPatternAnalyzer", "MLMalwareAnalyzer", "KeyplugAcceleratedMultilayer"],
    "behavioral": ["KeyplugBehavioralAnalyzer"],
    "memory": ["KeyplugMemoryAnalyzer"],
    "global": ["KeyplugCrossSampleCorrelator", "KeyplugPatternDatabase"],
}

# Pipeline stages define execution order and dependencies
# Format: (stage_name, [list of module class names], depends_on_stages)
PIPELINE_STAGES = [
    ("extraction", ["ExtractPE"], None),
    ("basic_analysis", ["AnalyzePE"], "extraction"),
    
    ("structure_analysis", [
        "FunctionBoundaryDetection", 
        "ControlFlowRecovery", 
        "CompilerIdiomDetection"
    ], "basic_analysis"),
    
    ("decryption", [
        "SimpleRC4", 
        "RC4Decrypt", 
        "SectionDecrypt", 
        "MultiLayerDecrypt", 
        "MultiLayerDecryptAdvanced", 
        "TargetedPatternDecrypt", 
        "KeyplugCombinationDecrypt"
    ], "basic_analysis"),
    
    ("deep_extraction", [
        "KeyplugExtractor", 
        "KeyplugMultilayerExtractor",
        "KeyplugFunctionExtractor"
    ], ["structure_analysis", "decryption"]),
    
    ("decompilation", [
        "KeyplugDecompiler", 
        "DecompilerIntegration"
    ], "deep_extraction"),
    
    ("advanced_analysis", [
        "TypeInference", 
        "PolyglotAnalyzer", 
        "KeyplugApiSequenceDetector", 
        "KeyplugAdvancedAnalysis",
    ], ["structure_analysis", "deep_extraction"]),
    
    ("ml_analysis", [
        "MLPatternAnalyzer", 
        "MLMalwareAnalyzer", 
        "KeyplugAcceleratedMultilayer"
    ], ["structure_analysis", "advanced_analysis"]),
    
    ("behavioral", [
        "KeyplugBehavioralAnalyzer"
    ], None),
    
    # Memory analysis has no dependencies on file analysis since it's 
    # analyzing memory dumps, not files
    ("memory", [
        "KeyplugMemoryAnalyzer"
    ], None),
    
    # Global analysis runs after all other analyses
    ("global", [
        "KeyplugCrossSampleCorrelator", 
        "KeyplugPatternDatabase"
    ], ["advanced_analysis", "ml_analysis", "behavioral", "memory"]),
]

# Module details for UI presentation and help text
MODULE_DETAILS = {
    "ExtractPE": {
        "description": "Extracts embedded PE files from the sample",
        "cli_flag": "extract_pe",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "files"
    },
    "AnalyzePE": {
        "description": "Analyzes PE file structure and characteristics",
        "cli_flag": "pe_analysis",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "json"
    },
    "FunctionBoundaryDetection": {
        "description": "Detects function boundaries in executable code",
        "cli_flag": "func_boundary",
        "default_enabled": True,
        "requires_openvino": True,
        "input_type": "file",
        "output_type": "json"
    },
    "ControlFlowRecovery": {
        "description": "Recovers control flow graphs from executable code",
        "cli_flag": "cfg_recovery",
        "default_enabled": True,
        "requires_openvino": True,
        "input_type": "file",
        "output_type": "json"
    },
    "SimpleRC4": {
        "description": "Simple RC4 decryption module",
        "cli_flag": "simple_rc4",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "file"
    },
    "RC4Decrypt": {
        "description": "Advanced RC4 decryption with key discovery",
        "cli_flag": "rc4_decrypt",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "file"
    },
    "SectionDecrypt": {
        "description": "PE section-based decryption",
        "cli_flag": "section_decrypt",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "file"
    },
    "MultiLayerDecrypt": {
        "description": "Multi-layer decryption for nested encryption",
        "cli_flag": "multi_layer",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "file"
    },
    "MultiLayerDecryptAdvanced": {
        "description": "Advanced multi-layer decryption with ML-assisted key discovery",
        "cli_flag": "multi_layer_adv",
        "default_enabled": True,
        "requires_openvino": True,
        "input_type": "file",
        "output_type": "file"
    },
    "TargetedPatternDecrypt": {
        "description": "Pattern-based targeted decryption",
        "cli_flag": "targeted_decrypt",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "file"
    },
    "KeyplugCombinationDecrypt": {
        "description": "Combination decryption algorithm discovery",
        "cli_flag": "combo_decrypt",
        "default_enabled": True,
        "requires_openvino": True,
        "input_type": "file",
        "output_type": "file"
    },
    "TypeInference": {
        "description": "Type inference for binary code",
        "cli_flag": "type_inference",
        "default_enabled": True,
        "requires_openvino": True,
        "input_type": "file",
        "output_type": "json"
    },
    "PolyglotAnalyzer": {
        "description": "Detects and analyzes polyglot files",
        "cli_flag": "polyglot",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "json"
    },
    "MLPatternAnalyzer": {
        "description": "Machine learning pattern analysis",
        "cli_flag": "ml_pattern",
        "default_enabled": True,
        "requires_openvino": True,
        "input_type": "file",
        "output_type": "json"
    },
    "MLMalwareAnalyzer": {
        "description": "ML-based malware detection and classification",
        "cli_flag": "ml_malware",
        "default_enabled": True,
        "requires_openvino": True,
        "input_type": "file",
        "output_type": "json"
    },
    "KeyplugMemoryAnalyzer": {
        "description": "Memory forensics analyzer",
        "cli_flag": "memory_analysis",
        "default_enabled": True,
        "requires_openvino": True,
        "input_type": "memory_dump",
        "output_type": "json"
    },
    "KeyplugCrossSampleCorrelator": {
        "description": "Cross-sample correlation engine",
        "cli_flag": "cross_sample",
        "default_enabled": True,
        "requires_openvino": True,
        "input_type": "results",
        "output_type": "json"
    },
    "KeyplugPatternDatabase": {
        "description": "Pattern database manager",
        "cli_flag": "pattern_db",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "results",
        "output_type": "database"
    },
    "KeyplugExtractor": {
        "description": "Extract and preprocess malware samples",
        "cli_flag": "extractor",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "files"
    },
    "KeyplugFunctionExtractor": {
        "description": "Extract functions from binary files",
        "cli_flag": "function_extract",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "files"
    },
    "KeyplugMultilayerExtractor": {
        "description": "Extract multi-layered code",
        "cli_flag": "multilayer",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "files"
    },
    "KeyplugAcceleratedMultilayer": {
        "description": "Accelerated multi-layer extraction using OpenVINO",
        "cli_flag": "acc_multilayer",
        "default_enabled": True,
        "requires_openvino": True,
        "input_type": "file",
        "output_type": "files"
    },
    "KeyplugAdvancedAnalysis": {
        "description": "Advanced static analysis",
        "cli_flag": "advanced",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "json"
    },
    "KeyplugApiSequenceDetector": {
        "description": "Detect API call sequences",
        "cli_flag": "api_sequence",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "json"
    },
    "CompilerIdiomDetection": {
        "description": "Detect compiler idioms",
        "cli_flag": "compiler_idiom",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "json"
    },
    "KeyplugDecompiler": {
        "description": "Decompile code to C-like representation",
        "cli_flag": "decompile",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "files"
    },
    "DecompilerIntegration": {
        "description": "Integration with external decompilers",
        "cli_flag": "ext_decompile",
        "default_enabled": False,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "files"
    },
    "KeyplugBehavioralAnalyzer": {
        "description": "Behavioral analysis of malware samples",
        "cli_flag": "behavioral",
        "default_enabled": True,
        "requires_openvino": False,
        "input_type": "file",
        "output_type": "json"
    },
}

# Import all analyzer modules from a common namespace
def get_module_import_map() -> Dict[str, str]:
    """
    Returns a mapping of module class names to their import paths.
    This allows dynamically importing modules as needed.
    """
    return {
        # Basic PE Analysis
        "ExtractPE": "extract_pe.ExtractPE",
        "AnalyzePE": "analyze_pe.AnalyzePE",
        
        # Code Analysis
        "FunctionBoundaryDetection": "function_boundary_detection.FunctionBoundaryDetection",
        "ControlFlowRecovery": "control_flow_recovery.ControlFlowRecovery",
        "CompilerIdiomDetection": "compiler_idiom_detection.CompilerIdiomDetection",
        
        # Decompilation
        "DecompilerIntegration": "decompiler_integration.DecompilerIntegration",
        "KeyplugDecompiler": "keyplug_decompiler.KeyplugDecompiler", 
        "KeyplugFunctionExtractor": "keyplug_function_extractor.KeyplugFunctionExtractor",
        
        # Extraction
        "KeyplugExtractor": "keyplug_extractor.KeyplugExtractor",
        "KeyplugMultilayerExtractor": "keyplug_multilayer_extractor.KeyplugMultilayerExtractor",
        
        # Decryption
        "SimpleRC4": "simple_rc4.SimpleRC4",
        "RC4Decrypt": "rc4_decrypt.RC4Decrypt",
        "SectionDecrypt": "section_decrypt.SectionDecrypt",
        "MultiLayerDecrypt": "multi_layer_decrypt.MultiLayerDecrypt",
        "MultiLayerDecryptAdvanced": "multi_layer_decrypt_advanced.MLDecryptionEngine",
        "TargetedPatternDecrypt": "targeted_pattern_decrypt.TargetedPatternDecrypt",
        "KeyplugCombinationDecrypt": "keyplug_combination_decrypt.KeyplugCombinationDecrypt",
        
        # Analysis
        "KeyplugApiSequenceDetector": "keyplug_api_sequence_detector.KeyplugApiSequenceDetector",
        "TypeInference": "type_inference.TypeInferenceEngine",
        "PolyglotAnalyzer": "polyglot_analyzer.PolyglotAnalyzer",
        "KeyplugAdvancedAnalysis": "keyplug_advanced_analysis.KeyplugAdvancedAnalysis",
        
        # ML-based Analysis
        "MLPatternAnalyzer": "ml_pattern_analyzer.MLPatternAnalyzer",
        "MLMalwareAnalyzer": "ml_malware_analyzer.MalwareML",
        "KeyplugAcceleratedMultilayer": "keyplug_accelerated_multilayer.KeyplugAcceleratedMultilayer",
        
        # Behavioral Analysis
        "KeyplugBehavioralAnalyzer": "keyplug_behavioral_analyzer.KeyplugBehavioralAnalyzer",
        
        # Memory Analysis
        "KeyplugMemoryAnalyzer": "keyplug_memory_forensics.KeyplugMemoryAnalyzer",
        
        # Global Analysis
        "KeyplugCrossSampleCorrelator": "keyplug_cross_sample_correlator.KeyplugCrossSampleCorrelator",
        "KeyplugPatternDatabase": "keyplug_pattern_database.KeyplugPatternDatabase",
    }

# Function to get the pipeline configuration
def get_pipeline_config() -> Dict[str, Any]:
    """Returns the complete pipeline configuration"""
    return {
        "module_groups": MODULE_GROUPS,
        "pipeline_stages": PIPELINE_STAGES,
        "module_details": MODULE_DETAILS,
        "module_imports": get_module_import_map()
    }

if __name__ == "__main__":
    # Display pipeline information if run directly
    import json
    
    print("KEYPLUG Analysis Pipeline Configuration")
    print("=======================================")
    print(f"Total modules: {sum(len(modules) for _, modules, _ in PIPELINE_STAGES)}")
    print(f"Pipeline stages: {len(PIPELINE_STAGES)}")
    
    print("\nPipeline execution order:")
    for i, (stage_name, modules, dependencies) in enumerate(PIPELINE_STAGES):
        deps = dependencies if dependencies else "none"
        print(f"{i+1}. {stage_name} (depends on: {deps})")
        for mod in modules:
            print(f"   - {mod}: {MODULE_DETAILS[mod]['description']}")
    
    print("\nModule groups:")
    for group, modules in MODULE_GROUPS.items():
        print(f"{group}: {len(modules)} modules")
