# STEGTEST/KP14 Unplugged Repository Feature Analysis

## Project Summary

The STEGTEST/KP14 Unplugged project aims to analyze and reverse engineer APT41's Key Plug malware, with a specific focus on detecting and decoding steganographic payloads hidden within JPEG images. It integrates machine learning techniques to identify and extract hidden data, effectively acting as a tool to counter malware that uses steganography for concealment. The project also encompasses a broader steganographic analysis framework.

## Core Steganography Features
*(Note: Current Python implementations for detection and extraction are largely placeholders; features are based on comments and README descriptions.)*

### Detection Capabilities
- **Goal:** Detect the presence and type of steganography in images.
- **Potential Methods:**
    - LSB (Least Significant Bit) analysis.
    - EXIF data analysis.
    - Detection of signatures from specific steganography tools.
- **File Types:** Primary focus on JPEG, with PNG also mentioned in utility contexts.

### Extraction Capabilities
- **Goal:** Extract hidden payloads from images.
- **Method:** Dependent on the steganography technique identified (e.g., LSB de-interleaving).
- **Scope:** Aims to extract from a variety of steganographic images.

### Specific Techniques & Image Types
- **Techniques:**
    - LSB (Least Significant Bit) steganography.
    - Use of EXIF data for hiding information.
- **Image Types:**
    - JPEG (explicitly mentioned for decoding).
    - PNG (mentioned in utility examples and segment parsing comments).

### Auxiliary Steganography Features
- Image loading.
- Parsing of image segments (e.g., JPEG APPn markers, PNG chunks - currently placeholder).
- Image corruption checking.

## Malware Analysis Features (with a focus on KeyPlug)

### KeyPlug-Specific Analysis
- **ODG File Analysis (`keyplug_extractor.py`):**
    - Treats ODG (OpenDocument Drawing) files as ZIP archives to access internal JPEGs, typically within a `Pictures/` directory.
- **Payload Extraction from JPEGs (`keyplug_extractor.py`):**
    - Extracts data appended after the JPEG End-Of-Image (EOI) marker.
    - Employs heuristics (e.g., high entropy scanning) to locate payloads within JPEG data.
- **XOR Decryption (`keyplug_extractor.py`):**
    - Applies a predefined list of known XOR keys (single and multi-byte) associated with APT41's KeyPlug to decrypt extracted payloads.
- **KeyPlug Signature Matching (`keyplug_extractor.py`):**
    - Searches payloads for specific string markers and patterns known to be associated with KeyPlug malware (e.g., "KEYP", "RC4", "cmd.exe", common API names like "VirtualAlloc").
- **General Project Goal (`README.md`):**
    - Explicitly aims to reverse engineer and rebuild the source code of APT41's KeyPlug.

### Reverse Engineering Tools
- **PE File Analysis (`analyze_pe.py`):**
    - Validates PE file structure (MZ and PE headers).
    - Parses PE headers (machine type, number of sections, timestamp, characteristics).
    - Parses the Optional Header (PE32/PE32+, subsystem type).
    - Details PE sections including name, size, virtual address, raw data pointer, and characteristics (e.g., code/data, R/W/X flags).
    - Extracts ASCII and Unicode strings from PE files.
    - Identifies potential Windows API names from these strings.
    - Detects PE files embedded within other PE files.
- **PE File Extraction (`extract_pe.py`):**
    - Carves out potential PE files from any binary data blob by searching for "MZ" signatures.
- **Malware Code Extraction & Reconstruction (`malware_code_extractor.py`):**
    - Detects probable CPU architecture (x86, x64, ARM) using instruction patterns.
    - Extracts ASCII/Unicode strings and identifies potential API call names within them.
    - Identifies potential function boundaries using common prologue/epilogue instruction patterns.
    - **Disassembly:** Integrates with Capstone (if available) for detailed instruction disassembly.
    - **Advanced Analysis with Radare2:** If `r2pipe` is available, it performs auto-analysis (`aaa`), lists functions with disassembly and variables, and attempts to generate pseudo-C code (`pdc`).
    - Attempts to generate basic pseudo-code snippets by combining disassembly, string/API references, and function boundaries.

### Cryptographic Analysis Tools
- **RC4 Decryption (`rc4_decrypt.py`, `multi_layer_decrypt.py`):**
    - Decrypts data using the RC4 algorithm with a user-supplied key. Leverages `Crypto.Cipher.ARC4`.
- **Multi-Layer Decryption (`multi_layer_decrypt.py`):**
    - Applies a user-defined sequence of decryption layers, supporting multiple stages of XOR (single or multi-byte keys) and RC4 decryption.
- **XOR Decryption (General):**
    - Also available in `keyplug_extractor.py` with its list of known KeyPlug-associated keys.

### Behavioral or Signature-Based Detection
- **API Sequence Detection (`api_sequence_detector.py`):**
    - Identifies known malicious behaviors by matching sequences of API calls against a configurable pattern database (JSON format). Patterns are categorized by threat type (e.g., C2 communication, process injection, persistence).
    - Intends to use OpenVINO for hardware acceleration of matching (currently placeholder).
    - Basic API call extraction is done by matching API names as strings in the binary.
- **API Hash Detection (`hash_detector/detector.py`):**
    - Identifies common API hashing algorithms used by malware to obfuscate API calls.
    - Uses pattern matching for hash constants and typical hashing operations (ROL, XOR, ADD).
    - Intends to use OpenVINO for pattern search acceleration (currently placeholder).
    - Groups matched patterns to identify algorithm implementations.
    - Identifies 32-bit hash values located near comparison instructions.
    - Resolves API names by reverse lookups of these hash values against a pre-computed database.
- **Network Indicator Extraction (`keyplug_extractor.py`):**
    - Uses regular expressions to find URLs, domain names, and IP addresses in binary data.
- **Entropy Calculation (`keyplug_extractor.py`):**
    - Calculates Shannon entropy to identify potentially encrypted or packed data sections.

## Advanced Analysis and Machine Learning Features

### Machine Learning Models/Classifiers
- **Payload Classification (`ml_classifier.py`):**
    - **Goal:** Classify extracted payloads (e.g., benign, malware, specific threat type).
    - **Implementation:** Currently a placeholder; mentions potential use of OpenVINO, TensorFlow, PyTorch, or scikit-learn models.
- **Malware Analysis & Detection (`ml_malware_analyzer.py`):**
    - **Features Extracted:** Works primarily with PE files, extracting basic metrics (size, entropy), PE structural details, byte histograms, section entropies, string counts, API call counts (general and categorized by function like network, file, crypto), and byte n-grams.
    - **Data Representation:** Includes functionality to convert binary data into a 2D grayscale image, potentially for use with Convolutional Neural Networks (CNNs).
    - **Classification:** Simulates malware detection and malware family classification (e.g., trojan, ransomware) based on heuristic combinations of the extracted features.
- **ML for Pattern Analysis in Encrypted Malware (`ml_pattern_analyzer.py`):**
    - **Data Preparation:** Prepares data for ML analysis by converting bytes to normalized float arrays and creating sliding windows.
    - **Inference:** Contains a placeholder for ML model inference, implying OpenVINO usage.
    - **Non-ML Augmentation:** Complements ML with techniques like entropy analysis, file signature detection, repeating byte pattern searches, string analysis, opcode sequence matching, and XOR key heuristics.

### Role of OpenVINO
- **Project-Wide Context (`README.md`):** The project documentation states that it "leverages cutting-edge machine learning techniques, hyper-optimized by OpenVINO."
- **Hardware Acceleration (`openvino_accelerator.py`):**
    - This module provides a class (`OpenVINOAccelerator`) intended to use OpenVINO for hardware-accelerating various computational tasks. These include binary pattern searching, multi-pattern searching, string extraction, entropy calculation, XOR decryption, rolling hash computation, and similarity calculations.
    - It can detect available OpenVINO-compatible hardware (GPU, NPU, CPU) and configure settings accordingly.
    - **Current Status:** The OpenVINO-accelerated functions are largely placeholders, often defaulting to NumPy operations or Python's concurrent processing rather than actual OpenVINO inference calls.
- **Integration in ML Modules:** Various analysis modules (`ml_malware_analyzer.py`, `ml_pattern_analyzer.py`, `api_sequence_detector.py`, `hash_detector/detector.py`) check for OpenVINO availability and initialize its components. This indicates a design goal to use OpenVINO for running ML models and speeding up computations.

### Symbolic Execution (`symbolic_executor.py`)
- **Engine:** Designed to use `angr` if it is available in the environment.
- **Core Functionality:**
    - Loads target binaries into an `angr.Project`.
    - Creates initial states for symbolic execution, starting from the binary's entry point or a user-specified address.
    - Manages the simulation process using `angr.SimulationManager`.
- **Path Exploration Capabilities:**
    - `run_symbolic_execution`: Explores execution paths to find a specific target address while avoiding other specified addresses. It can also perform general exploration without a defined target. The output includes information on paths found and whether the target was reached.
    - `discover_paths`: Specifically aims to find multiple execution paths between a given start and end address, returning each path as a list of basic block addresses.
- **Fallback Mechanism:** If `angr` is not available, the module provides placeholder responses.

### Program Synthesis (`program_synthesis_engine.py`)
- **Engine Concept:** This module simulates a program synthesis engine.
- **LLM Integration (Conceptual/Simulated):**
    - It is designed to conceptually integrate with Large Language Models (LLMs) for code generation. This is based on `observed_behavior` input, which could include natural language descriptions, pseudo-code, or input/output specifications.
    - The system can be configured for:
        - Simulated API-based LLMs (requiring a URL, API key, and model name).
        - Conceptual local LLMs, potentially utilizing OpenVINO Intermediate Representation (IR) models running on specified devices (CPU, GPU, NPU), with mention of INT8 quantization for performance.
- **`synthesize_code` Method:**
    - Based on the provided configuration, this method generates placeholder code snippets in a target language (e.g., Python, C). These snippets illustrate the kind of output an API-based or local/OpenVINO LLM might produce.
    - **Note:** Actual code generation through LLM inference (either via API calls or local OpenVINO execution) is not implemented; the module returns pre-defined, illustrative code strings.
- **Prompt Engineering:** The module demonstrates basic construction of prompts that would be sent to the simulated LLMs.

## Key Supporting Utilities

1.  **Encoded String Detector (`stego-analyzer/utils/string_decoder/string_detector.py`)**
    *   **Purpose:** Identifies and attempts to decode obfuscated or encoded strings within binary data.
    *   **Description:** Extracts plain ASCII and Unicode strings, then analyzes high-entropy regions for potential encoded content. Applies various decoding techniques (XOR, ADD/SUB, ROL/ROR with common keys; custom patterns) and scores decoded strings for relevance (e.g., resemblance to API names). Intends OpenVINO acceleration.

2.  **Entropy Calculation (`stego-analyzer/utils/entropy.py`)**
    *   **Purpose:** Calculates Shannon entropy to help identify encrypted or compressed data.
    *   **Description:** `calculate_entropy_map` (placeholder) aims to create a 2D entropy map of an image by analyzing blocks, useful for spotting anomalous regions.

3.  **Image Utilities (`stego-analyzer/utils/image_utils.py`)**
    *   **Purpose:** Offers foundational functions for basic image manipulation and inspection.
    *   **Description:** Includes placeholder functions for loading images, parsing image file segments (headers, metadata), and checking for image corruption.

4.  **Polyglot File Analyzer (`stego-analyzer/utils/polyglot_analyzer.py`)**
    *   **Purpose:** Analyzes files that might be polyglots (valid as multiple file types), focusing on ODG files to detect and extract hidden data appended after the legitimate file structure.
    *   **Description:** Finds the end of the primary file structure (e.g., ZIP in ODG), extracts subsequent data, and analyzes it for entropy, known signatures (e.g., KeyPlug markers), embedded PE files, network indicators, and attempts XOR decryption.

5.  **Compiler Idiom Detection (`stego-analyzer/utils/compiler_idiom_detection.py`)**
    *   **Purpose:** Improves decompiled code readability by replacing common compiler-generated instruction sequences with their higher-level semantic equivalents.
    *   **Description:** Uses regex to find patterns like shifts for multiplication/division, XOR-self for zeroing, byte swaps. Standardizes calls to common library functions. Intends OpenVINO acceleration.

6.  **Function Boundary Detection (`stego-analyzer/utils/function_boundary_detection.py`)**
    *   **Purpose:** Identifies function start/end points in binaries using common prologue/epilogue instruction patterns.
    *   **Description:** Detects architecture (x86/x64) from PE/ELF headers and uses pattern lists to locate boundaries. Includes a placeholder for OpenVINO-accelerated matching and basic filtering.

## Analysis Pipeline and Configuration

### Analysis Pipeline (`run_pipeline.py`)
- **Role:** Serves as the main entry point to execute the Stego Analyzer's capabilities.
- **Functionality:**
    1.  Parses command-line arguments, requiring at least the path to the target image file.
    2.  Calls a `main_pipeline` function (expected in `core.pipeline`, currently a placeholder) to orchestrate the analysis stages (steganography detection, payload extraction, malware scanning, ML classification).
- **Extensibility:** Designed for future arguments like analysis modes or output directory specifications.

### Configuration (`settings.ini`)
- **Purpose:** Allows users to customize the Stego Analyzer's behavior and environment. (Full integration is noted as a future enhancement).
- **Key Settings Areas:**
    1.  **General Settings:**
        *   `output_directory`: Default path for saving reports and extracted files.
        *   `log_level`: Controls logging verbosity (e.g., INFO, DEBUG).
    2.  **Paths:**
        *   `openvino_model_path`: Location of OpenVINO models, essential for ML features.
        *   Placeholders for other external tools.
    3.  **Analysis Options:**
        *   `analysis_timeout`: Default maximum duration for analysis processes.
        *   Conceptual toggles (e.g., `enable_static_analysis`, `enable_ml_classification`) suggesting modular control over pipeline stages.
        *   Placeholders for API keys (e.g., `virustotal_api_key`) for potential integration with external services.
- **Goal:** Aims to make the analyzer flexible by externalizing key operational parameters.
