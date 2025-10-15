"""
Analysis Pipeline Manager for KP14
==================================

This module manages the complete analysis pipeline, coordinating multiple
analyzer modules and managing the flow of data through the system.

Features:
- Orchestrates PE, code, obfuscation, polyglot, and steganography analyzers
- Memory-efficient chunked file processing
- Caching of analysis results
- Error handling and recovery
- Progress tracking and reporting

Author: KP14 Development Team
Version: 2.0.0
"""

import logging
import os
import json
import io  # For BytesIO when dealing with in-memory data for analyzers
import time
from typing import Any, Dict, List, Optional, Tuple, Union, TYPE_CHECKING

# Import chunked file reader for memory-efficient processing
from core_engine.chunked_file_reader import ChunkedFileReader, log_memory_usage

# Import caching components
from core_engine.cache_manager import get_cache_manager, cached
from core_engine.file_hasher import get_file_hasher

if TYPE_CHECKING:
    from core_engine.configuration_manager import ConfigurationManager

# Import actual analyzer modules
try:
    from modules.static_analyzer.pe_analyzer import PEAnalyzer
except ImportError as e:
    logging.getLogger(__name__).error(f"Failed to import PEAnalyzer: {e}. PE analysis will be skipped.")
    PEAnalyzer = None

try:
    from modules.static_analyzer.code_analyzer import CodeAnalyzer, CAPSTONE_AVAILABLE, R2PIPE_AVAILABLE
except ImportError as e:
    logging.getLogger(__name__).error(f"Failed to import CodeAnalyzer: {e}. Code analysis will be skipped.")
    CodeAnalyzer = None
    CAPSTONE_AVAILABLE = False # Assume unavailable if module fails
    R2PIPE_AVAILABLE = False

try:
    from modules.static_analyzer.obfuscation_analyzer import ObfuscationAnalyzer
except ImportError as e:
    logging.getLogger(__name__).error(f"Failed to import ObfuscationAnalyzer: {e}. Obfuscation analysis will be skipped.")
    ObfuscationAnalyzer = None

try:
    from modules.extraction_analyzer.polyglot_analyzer import PolyglotAnalyzer
except ImportError as e:
    logging.getLogger(__name__).error(f"Failed to import PolyglotAnalyzer: {e}. Polyglot analysis will be skipped.")
    PolyglotAnalyzer = None

try:
    from modules.extraction_analyzer.steganography_analyzer import SteganographyAnalyzer
except ImportError as e:
    logging.getLogger(__name__).error(f"Failed to import SteganographyAnalyzer: {e}. Steganography analysis will be skipped.")
    SteganographyAnalyzer = None

try:
    from modules.extraction_analyzer.crypto_analyzer import CryptoAnalyzer
except ImportError as e:
    logging.getLogger(__name__).error(f"Failed to import CryptoAnalyzer: {e}. Decryption will be skipped.")
    CryptoAnalyzer = None

# Magic numbers for simple file type ID
MAGIC_MZ = b'MZ'
MAGIC_ZIP = b'PK\x03\x04'
MAGIC_JPEG_SOI = b'\xFF\xD8'
MAGIC_PNG = b'\x89PNG\r\n\x1a\n'
MAGIC_GIF = b'GIF8' # GIF87a or GIF89a


class PipelineManager:
    """
    Core pipeline manager for orchestrating malware analysis workflows.

    This class coordinates multiple analysis stages including extraction,
    decryption, static analysis, and recursive payload analysis.
    """

    def __init__(self, config_manager: "ConfigurationManager") -> None:
        """
        Initialize pipeline manager with configuration.

        Args:
            config_manager: Configuration manager instance for settings
        """
        self.config_manager: "ConfigurationManager" = config_manager
        self.logger: logging.Logger = logging.getLogger(__name__)
        self._configure_logging()

        # Initialize caching
        self.cache_manager = get_cache_manager()
        self.file_hasher = get_file_hasher()
        self.cache_enabled: bool = config_manager.getboolean('cache', 'enabled', fallback=True)

        # Static Analyzers - Store class, instantiate per file/data
        self.pe_analyzer_template: Optional[type] = None
        self.code_analyzer_template: Optional[type] = None
        self.obfuscation_analyzer_template: Optional[type] = None

        # Extraction/Decryption Analyzers (instantiated once)
        self.polyglot_analyzer: Optional[Any] = None
        self.steganography_analyzer: Optional[Any] = None
        self.crypto_analyzer: Optional[Any] = None

        self._load_module_templates_and_analyzers()

    def _configure_logging(self) -> None:
        """Configure logging level and handlers based on configuration."""
        if getattr(self.logger, '_configured', False):
            return
        log_level_str: str = "INFO"
        if self.config_manager:
            log_level_str = self.config_manager.get('general', 'log_level', fallback='INFO').upper()

        try:
            level: int = getattr(logging, log_level_str)
        except AttributeError:
            level = logging.INFO

        self.logger.setLevel(level)
        if not self.logger.hasHandlers():
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch = logging.StreamHandler()
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)
        self.logger._configured = True

    def _load_module_templates_and_analyzers(self) -> None:
        # Load static analyzer classes/templates
        if PEAnalyzer and self.config_manager.getboolean('pe_analyzer', 'enabled', fallback=True):
            self.pe_analyzer_template = PEAnalyzer
            self.logger.info("PE Analyzer module loaded.")
        if CodeAnalyzer and self.config_manager.getboolean('code_analyzer', 'enabled', fallback=True):
            self.code_analyzer_template = CodeAnalyzer
            self.logger.info("Code Analyzer module loaded.")
        if ObfuscationAnalyzer and self.config_manager.getboolean('obfuscation_analyzer', 'enabled', fallback=True):
            self.obfuscation_analyzer_template = ObfuscationAnalyzer
            self.logger.info("Obfuscation Analyzer module loaded.")

        # Instantiate extraction/decryption analyzers (these are stateful with their configs but not per-file state)
        if PolyglotAnalyzer and self.config_manager.getboolean('polyglot_analyzer', 'enabled', fallback=True):
            try: self.polyglot_analyzer = PolyglotAnalyzer(self.config_manager)
            except Exception as e: self.logger.error(f"Failed to init PolyglotAnalyzer: {e}")
        if SteganographyAnalyzer and self.config_manager.getboolean('steganography_analyzer', 'enabled', fallback=True):
            try: self.steganography_analyzer = SteganographyAnalyzer(self.config_manager)
            except Exception as e: self.logger.error(f"Failed to init SteganographyAnalyzer: {e}")
        if CryptoAnalyzer and self.config_manager.getboolean('crypto_analyzer', 'enabled', fallback=True):
            try: self.crypto_analyzer = CryptoAnalyzer(self.config_manager)
            except Exception as e: self.logger.error(f"Failed to init CryptoAnalyzer: {e}")

    def _get_file_type(self, file_data_or_path: Union[bytes, str]) -> str:
        """
        Simple file type identification using magic numbers or extension.

        Supports both in-memory data and file paths. Uses chunked reading
        for file paths to avoid loading large files into memory.

        Args:
            file_data_or_path: Either raw bytes or file path string

        Returns:
            File type string (e.g., 'pe', 'jpeg', 'zip', 'unknown')
        """
        data_header: Optional[bytes] = None
        if isinstance(file_data_or_path, bytes):
            data_header = file_data_or_path[:16] # Read first few bytes
        elif isinstance(file_data_or_path, str) and os.path.exists(file_data_or_path):
            try:
                # Use ChunkedFileReader to read just the header
                with ChunkedFileReader(file_data_or_path) as reader:
                    data_header = reader.read_range(0, min(16, reader.get_file_size()))
            except Exception as e:
                self.logger.debug(f"Error reading file header: {e}")
                pass # Will fallback to extension or unknown

        if data_header:
            if data_header.startswith(MAGIC_MZ): return 'pe'
            if data_header.startswith(MAGIC_ZIP): return 'zip'
            if data_header.startswith(MAGIC_JPEG_SOI): return 'jpeg'
            if data_header.startswith(MAGIC_PNG): return 'png'
            if data_header.startswith(MAGIC_GIF): return 'gif'

        if isinstance(file_data_or_path, str): # Fallback to extension if path provided
            ext = os.path.splitext(file_data_or_path)[1].lower()
            if ext: return ext.lstrip('.')

        return 'unknown'

    def _run_static_analysis_on_pe_data(
        self,
        pe_data: Optional[bytes],
        source_description: str,
        original_file_path_for_codeanalyzer: Optional[str] = None,
        use_streaming: bool = False
    ) -> Dict[str, Any]:
        """
        Helper to run the static PE analysis suite (PE, Code, Obfuscation) on given PE data.

        Args:
            pe_data: PE file data (bytes or None if use_streaming=True)
            source_description: Where the pe_data came from
            original_file_path_for_codeanalyzer: File path for analyzers that need it
            use_streaming: If True, use ChunkedFileReader for large files

        Returns:
            Analysis results dictionary containing PE info, code analysis, and obfuscation details
        """
        self.logger.info(f"Running static PE analysis for: {source_description} (streaming={use_streaming})")
        log_memory_usage("Before PE analysis", self.logger)

        static_results = {
            "source": source_description,
            "pe_info": None, "code_analysis": None, "obfuscation_details": None, "errors": []
        }

        # In-memory file path for PEAnalyzer if data is from memory (not strictly needed by current PEAnalyzer)
        # Current PEAnalyzer takes file_path=None and then uses its get_analysis_summary, which expects self.file_path.
        # This needs a slight refactor in PEAnalyzer or careful handling here.
        # For now, PEAnalyzer might need to be instantiated per data chunk if file_path is core to it.
        # Let's assume PEAnalyzer is adapted to take file_data directly or a BytesIO stream.
        # Or, we save temp file, which is not ideal.
        # For now, we will assume that if PEAnalyzer template exists, we instantiate it.
        # PEAnalyzer's current __init__ takes file_path. Let's use that and save temp if needed.
        # This is a simplification; a better approach is to make analyzers work on data streams.

        temp_pe_file_for_analysis = None
        current_pe_file_path_for_analyzers = original_file_path_for_codeanalyzer

        if not current_pe_file_path_for_analyzers: # If source is not a file on disk (e.g. extracted data)
            # Save pe_data to a temporary file as current analyzers expect file paths primarily
            # This is a workaround for analyzers not fully supporting in-memory analysis.
            # In a real system, analyzers should be enhanced.
            temp_dir = self.config_manager.get('general', 'output_dir', fallback='output')
            os.makedirs(os.path.join(temp_dir, "temp_extracted"), exist_ok=True)
            temp_pe_file_for_analysis = os.path.join(temp_dir, "temp_extracted", f"temp_pe_{hash(pe_data)}.exe")
            with open(temp_pe_file_for_analysis, 'wb') as f:
                f.write(pe_data)
            current_pe_file_path_for_analyzers = temp_pe_file_for_analysis
            self.logger.debug(f"PE data for {source_description} saved to temporary file {temp_pe_file_for_analysis} for analysis.")


        # 1. PE Analysis
        if self.pe_analyzer_template:
            try:
                pe_analyzer_instance = self.pe_analyzer_template(file_path=current_pe_file_path_for_analyzers, config_manager=self.config_manager)
                pe_summary = pe_analyzer_instance.get_analysis_summary()
                if "error" in pe_summary and pe_summary["error"] == "PE file not loaded.":
                    static_results["errors"].append(f"PE Analysis ({source_description}): {pe_summary['error']}")
                else: static_results["pe_info"] = pe_summary
            except Exception as e: static_results["errors"].append(f"PE Analysis ({source_description}): {str(e)}")

        # 2. Code Analysis
        if self.code_analyzer_template and static_results["pe_info"] and static_results["pe_info"].get("sections"):
            try:
                # CodeAnalyzer needs file_path for r2, file_data for capstone.
                # It will load file_data itself if path is given and data is None.
                code_analyzer_instance = self.code_analyzer_template(file_path=current_pe_file_path_for_analyzers, config_manager=self.config_manager, file_data=pe_data)

                executable_sections = [s for s in static_results["pe_info"]["sections"] if "MEM_EXECUTE" in s.get("characteristics_flags", [])]
                code_analysis_section_results = {}
                for section in executable_sections:
                    s_name = section.get("name", "unknown")
                    s_bytes = pe_data[section.get("pointer_to_raw_data",0) : section.get("pointer_to_raw_data",0) + section.get("size_of_raw_data",0)]
                    s_va = section.get("virtual_address", 0)
                    if s_bytes:
                        code_analysis_section_results[s_name] = code_analyzer_instance.get_analysis_summary(s_bytes, offset=s_va)
                static_results["code_analysis"] = code_analysis_section_results
            except Exception as e: static_results["errors"].append(f"Code Analysis ({source_description}): {str(e)}")

        # 3. Obfuscation Analysis
        if self.obfuscation_analyzer_template: # ObfuscationAnalyzer is instantiated once
            try:
                # ObfuscationAnalyzer's methods take data buffer. API trace is more complex for sub-analysis.
                static_results["obfuscation_details"] = self.obfuscation_analyzer.analyze_obfuscation(pe_data, api_call_trace=None, offset_in_file=0)
            except Exception as e: static_results["errors"].append(f"Obfuscation Analysis ({source_description}): {str(e)}")

        if temp_pe_file_for_analysis and os.path.exists(temp_pe_file_for_analysis):
            try: os.remove(temp_pe_file_for_analysis)
            except OSError as e: self.logger.warning(f"Could not remove temporary PE file {temp_pe_file_for_analysis}: {e}")

        return static_results

    def run_pipeline(
        self,
        input_file_path: str,
        is_recursive_call: bool = False,
        original_source_desc: str = "original_file"
    ) -> Dict[str, Any]:
        """
        Main pipeline entry point - delegates to stage methods.

        Args:
            input_file_path: Path to file to analyze
            is_recursive_call: Whether this is a recursive analysis of extracted payload
            original_source_desc: Description of the original source file

        Returns:
            Complete analysis report dictionary
        """
        pipeline_start_time = time.time()
        self.logger.info(f"Pipeline run for: {input_file_path} (Source: {original_source_desc}, Recursive: {is_recursive_call})")

        # Check cache if enabled and not recursive
        if self.cache_enabled and not is_recursive_call:
            cached_result = self._check_pipeline_cache(input_file_path)
            if cached_result is not None:
                pipeline_time = time.time() - pipeline_start_time
                self.logger.info(f"Pipeline cache HIT for {input_file_path} (took {pipeline_time:.2f}s)")
                self._log_cache_stats()
                return cached_result

        # Initialize and validate
        file_data, error = self._initialize_pipeline(input_file_path, original_source_desc)
        if error:
            return error

        # Handle streaming mode for large files
        if file_data is None and error is None:
            self.logger.info(f"Processing {input_file_path} in streaming mode")
            return self._run_pipeline_streaming(input_file_path, is_recursive_call, original_source_desc)

        # Normal mode: file_data is loaded in memory
        # Setup report structure
        current_file_type = self._get_file_type(file_data)
        self.logger.info(f"Detected file type for {input_file_path}: {current_file_type}")

        report = self._create_report_structure(input_file_path, current_file_type, original_source_desc, is_recursive_call)

        # Run extraction stage
        extracted_payloads_meta = self._run_extraction_stage(input_file_path, file_data, current_file_type, original_source_desc, report)

        # Run decryption and static analysis stage
        self._run_analysis_stage(input_file_path, file_data, original_source_desc, current_file_type, extracted_payloads_meta, report)

        # Run recursive analysis stage
        self._run_recursive_analysis_stage(extracted_payloads_meta, report)

        # Cache result if enabled and not recursive
        if self.cache_enabled and not is_recursive_call:
            self._cache_pipeline_result(input_file_path, report)

        # Log performance metrics
        pipeline_time = time.time() - pipeline_start_time
        self.logger.info(f"Pipeline finished for: {input_file_path} (Source: {original_source_desc}) in {pipeline_time:.2f}s")

        # Log cache statistics if enabled
        if self.cache_enabled:
            self._log_cache_stats()

        return report

    def _initialize_pipeline(
        self,
        input_file_path: str,
        original_source_desc: str
    ) -> Tuple[Optional[bytes], Optional[Dict[str, Any]]]:
        """
        Initialize pipeline and validate input file.

        Uses memory-efficient reading strategy:
        - Files >100MB: Uses memory-mapped access via ChunkedFileReader
        - Files <=100MB: Reads into memory for performance

        Args:
            input_file_path: Path to file to analyze
            original_source_desc: Description of the original source

        Returns:
            Tuple of (file_data, error_dict). If both are None, use streaming mode.
        """
        if not os.path.exists(input_file_path):
            self.logger.error(f"Input file not found: {input_file_path}")
            return None, {"error": "Input file not found.", "file_path": input_file_path, "source_description": original_source_desc}

        try:
            # Check file size to determine read strategy
            file_size = os.path.getsize(input_file_path)
            file_size_mb = file_size / (1024 * 1024)

            self.logger.debug(f"File size: {file_size_mb:.1f} MB")
            log_memory_usage("Before loading file", self.logger)

            # For large files (>100MB), use streaming approach
            if file_size > ChunkedFileReader.MMAP_THRESHOLD:
                self.logger.info(f"Large file detected ({file_size_mb:.1f} MB), using memory-efficient processing")
                # Return a special marker indicating streaming mode
                # The actual file will be processed via ChunkedFileReader in analysis methods
                return None, None  # Signal to use streaming mode
            else:
                # For smaller files, read into memory for performance
                with open(input_file_path, 'rb') as f:
                    file_data = f.read()

                log_memory_usage("After loading file", self.logger)
                return file_data, None

        except IOError as e:
            self.logger.error(f"Could not read input file {input_file_path}: {e}")
            return None, {"error": f"File read error: {e}", "file_path": input_file_path, "source_description": original_source_desc}

    def _create_report_structure(
        self,
        input_file_path: str,
        current_file_type: str,
        original_source_desc: str,
        is_recursive_call: bool
    ) -> Dict[str, Any]:
        """
        Create initial report structure.

        Args:
            input_file_path: Path to file being analyzed
            current_file_type: Detected file type
            original_source_desc: Description of original source
            is_recursive_call: Whether this is a recursive analysis

        Returns:
            Initial report dictionary structure
        """
        return {
            "file_path": input_file_path,
            "original_file_type": current_file_type,
            "source_description": original_source_desc,
            "is_recursive_call": is_recursive_call,
            "extraction_analysis": None,
            "steganography_analysis": None,
            "decryption_analysis": None,
            "static_pe_analysis": None,
            "extracted_payload_analyses": [],
            "errors": []
        }

    def _run_extraction_stage(
        self,
        input_file_path: str,
        file_data: bytes,
        current_file_type: str,
        original_source_desc: str,
        report: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Run extraction analyzers (polyglot and steganography).

        Args:
            input_file_path: Path to file being analyzed
            file_data: Raw file bytes
            current_file_type: Detected file type
            original_source_desc: Description of original source
            report: Report dictionary to update

        Returns:
            List of extracted payload metadata dictionaries
        """
        extracted_payloads_meta = []

        # Polyglot analysis
        if self.polyglot_analyzer and current_file_type in ['zip', 'jpeg', 'unknown']:
            extracted_payloads_meta.extend(self._run_polyglot_analysis(input_file_path, file_data, original_source_desc, report))

        # Steganography analysis
        if self.steganography_analyzer:
            extracted_payloads_meta.extend(self._run_steganography_analysis(input_file_path, file_data, current_file_type, original_source_desc, report))

        return extracted_payloads_meta

    def _run_polyglot_analysis(
        self,
        input_file_path: str,
        file_data: bytes,
        original_source_desc: str,
        report: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Run polyglot analyzer and extract PE payloads.

        Args:
            input_file_path: Path to file being analyzed
            file_data: Raw file bytes
            original_source_desc: Description of original source
            report: Report dictionary to update

        Returns:
            List of extracted PE payload dictionaries
        """
        self.logger.info(f"Running PolyglotAnalyzer on {input_file_path}")
        extracted_payloads = []

        try:
            poly_results = self.polyglot_analyzer.analyze_file(file_path=input_file_path, file_data=file_data)
            report["extraction_analysis"] = {"polyglot": poly_results}

            for p_info in poly_results:
                if p_info['data'].startswith(MAGIC_MZ):
                    extracted_payloads.append({
                        "data": p_info['data'],
                        "source": f"{original_source_desc} -> polyglot:{p_info.get('carrier_type', 'unknown_carrier')}/{p_info.get('type_desc','unknown_payload')}@0x{p_info.get('offset',0):x}",
                        "original_file_path": None
                    })
        except Exception as e:
            report["errors"].append(f"PolyglotAnalysis: {str(e)}")

        return extracted_payloads

    def _run_steganography_analysis(
        self,
        input_file_path: str,
        file_data: bytes,
        current_file_type: str,
        original_source_desc: str,
        report: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Run steganography analyzer and extract PE payloads.

        Args:
            input_file_path: Path to file being analyzed
            file_data: Raw file bytes
            current_file_type: Detected file type
            original_source_desc: Description of original source
            report: Report dictionary to update

        Returns:
            List of extracted PE payload dictionaries
        """
        self.logger.info(f"Running SteganographyAnalyzer on {input_file_path}")
        extracted_payloads = []
        stego_results_detail = {}

        try:
            # Check for appended data
            appended_data_info = self.steganography_analyzer.check_for_appended_data(file_path=input_file_path, file_data=file_data)
            stego_results_detail["appended_data"] = appended_data_info

            for s_info in appended_data_info:
                if s_info['data'].startswith(MAGIC_MZ):
                    extracted_payloads.append({
                        "data": s_info['data'],
                        "source": f"{original_source_desc} -> stego:appended_data_in_{s_info.get('eof_marker_type')}@0x{s_info.get('offset',0):x}",
                        "original_file_path": None
                    })

            # Check for LSB steganography
            if current_file_type in self.steganography_analyzer.supported_lsb_formats:
                lsb_result = self.steganography_analyzer.analyze_lsb_steganography(file_path=input_file_path, file_data=file_data)
                stego_results_detail["lsb_analysis"] = lsb_result

                if lsb_result.get('status') == 'data_extracted' and lsb_result['data'].startswith(MAGIC_MZ):
                    extracted_payloads.append({
                        "data": lsb_result['data'],
                        "source": f"{original_source_desc} -> stego:lsb_in_{current_file_type}",
                        "original_file_path": None
                    })

            report["steganography_analysis"] = stego_results_detail
        except Exception as e:
            report["errors"].append(f"SteganographyAnalysis: {str(e)}")

        return extracted_payloads

    def _run_analysis_stage(
        self,
        input_file_path: str,
        file_data: bytes,
        data_source_description: str,
        current_file_type: str,
        extracted_payloads_meta: List[Dict[str, Any]],
        report: Dict[str, Any]
    ) -> None:
        """
        Run decryption and static analysis stages.

        Args:
            input_file_path: Path to file being analyzed
            file_data: Raw file bytes
            data_source_description: Description of data source
            current_file_type: Detected file type
            extracted_payloads_meta: List of extracted payload metadata
            report: Report dictionary to update
        """
        # Attempt decryption
        data_for_static_analysis, decryption_applied = self._attempt_decryption(file_data, data_source_description, report)

        # Run static analysis if PE detected
        if data_for_static_analysis.startswith(MAGIC_MZ):
            source_desc = f"{data_source_description}{' (after decryption)' if decryption_applied else ''}"
            original_path = input_file_path if data_for_static_analysis is file_data else None

            report["static_pe_analysis"] = self._run_static_analysis_on_pe_data(
                data_for_static_analysis,
                source_description=source_desc,
                original_file_path_for_codeanalyzer=original_path
            )
        elif not extracted_payloads_meta:
            self._handle_no_pe_found(input_file_path, current_file_type, report)

    def _attempt_decryption(
        self,
        file_data: bytes,
        data_source_description: str,
        report: Dict[str, Any]
    ) -> Tuple[bytes, bool]:
        """
        Attempt to decrypt file data if not already a PE.

        Args:
            file_data: Raw file bytes to decrypt
            data_source_description: Description of data source
            report: Report dictionary to update

        Returns:
            Tuple of (decrypted_or_original_data, decryption_applied_flag)
        """
        if not self.crypto_analyzer or file_data.startswith(MAGIC_MZ):
            status = "skipped_as_already_pe" if file_data.startswith(MAGIC_MZ) else "skipped_no_analyzer"
            report["decryption_analysis"] = {"status": status}
            return file_data, False

        self.logger.info(f"Attempting decryption for {data_source_description} if chains are configured.")
        chain_results = self.crypto_analyzer.try_known_decryption_chains(file_data)
        report["decryption_analysis"] = {"attempted_chains": {}}

        # Try each decryption chain
        for chain_name, decrypted_data in chain_results.items():
            if decrypted_data is not None:
                report["decryption_analysis"]["attempted_chains"][chain_name] = {
                    "status": "success",
                    "output_length": len(decrypted_data)
                }

                # Check if decryption produced a PE
                if decrypted_data.startswith(MAGIC_MZ):
                    self.logger.info(f"Decryption chain '{chain_name}' resulted in a PE file for {data_source_description}.")
                    report["decryption_analysis"]["applied_chain"] = chain_name
                    report["decryption_analysis"]["status"] = "decrypted_to_pe"
                    return decrypted_data, True
            else:
                report["decryption_analysis"]["attempted_chains"][chain_name] = {"status": "failed"}

        # No successful PE decryption
        self.logger.info(f"No configured decryption chain produced a PE file for {data_source_description}.")
        status = "no_pe_after_decryption_attempts" if chain_results else "no_chains_attempted"
        report["decryption_analysis"]["status"] = status
        return file_data, False

    def _handle_no_pe_found(
        self,
        input_file_path: str,
        current_file_type: str,
        report: Dict[str, Any]
    ) -> None:
        """
        Handle case where no PE file was identified.

        Args:
            input_file_path: Path to file being analyzed
            current_file_type: Detected file type
            report: Report dictionary to update
        """
        self.logger.info(f"No PE file identified for static analysis from {input_file_path} (type: {current_file_type}).")
        if not report["errors"] and not report["extraction_analysis"] and not report["steganography_analysis"]:
            report["status_message"] = "File is not a PE and no further payloads or steganographic content found."

    def _run_recursive_analysis_stage(
        self,
        extracted_payloads_meta: List[Dict[str, Any]],
        report: Dict[str, Any]
    ) -> None:
        """
        Recursively analyze extracted payloads.

        Args:
            extracted_payloads_meta: List of extracted payload metadata
            report: Report dictionary to update
        """
        for payload_info in extracted_payloads_meta:
            self.logger.info(f"Recursively analyzing extracted payload from: {payload_info['source']}")
            temp_payload_path = self._save_payload_to_temp_file(payload_info['data'])

            try:
                sub_analysis_report = self.run_pipeline(
                    input_file_path=temp_payload_path,
                    is_recursive_call=True,
                    original_source_desc=payload_info['source']
                )
                report["extracted_payload_analyses"].append(sub_analysis_report)
            except Exception as e:
                self.logger.error(f"Error during recursive analysis of payload from {payload_info['source']}: {e}")
                report["extracted_payload_analyses"].append({
                    "source": payload_info['source'],
                    "error": f"Recursive analysis failed: {str(e)}"
                })
            finally:
                self._cleanup_temp_file(temp_payload_path)

    def _run_pipeline_streaming(
        self,
        input_file_path: str,
        is_recursive_call: bool,
        original_source_desc: str
    ) -> Dict[str, Any]:
        """
        Memory-efficient pipeline for large files using streaming/memory-mapped access.

        This method is used for files >100MB to prevent OOM errors.
        It processes the file without loading it entirely into memory.

        Args:
            input_file_path: Path to large file to analyze
            is_recursive_call: Whether this is a recursive analysis
            original_source_desc: Description of original source

        Returns:
            Analysis report dictionary for large file
        """
        log_memory_usage("Start of streaming pipeline", self.logger)

        # Detect file type using chunked reader
        current_file_type = self._get_file_type(input_file_path)
        self.logger.info(f"Detected file type for {input_file_path}: {current_file_type}")

        report = self._create_report_structure(input_file_path, current_file_type, original_source_desc, is_recursive_call)

        # For large PE files, we can only do limited analysis without full memory load
        # Most extraction analyzers (polyglot, stego) need full data, so skip them
        if current_file_type == 'pe':
            self.logger.info(f"Processing large PE file in streaming mode: {input_file_path}")

            # Run static PE analysis using the file path (analyzers will handle file access)
            report["static_pe_analysis"] = self._run_static_analysis_on_pe_data(
                pe_data=None,  # Don't load data into memory
                source_description=original_source_desc,
                original_file_path_for_codeanalyzer=input_file_path,
                use_streaming=True
            )

            # Skip extraction analyzers for large files (they require full data)
            report["extraction_analysis"] = {
                "status": "skipped_large_file",
                "reason": "File too large for extraction analysis (>100MB)"
            }
            report["steganography_analysis"] = {
                "status": "skipped_large_file",
                "reason": "File too large for steganography analysis (>100MB)"
            }
            report["decryption_analysis"] = {
                "status": "skipped_large_file",
                "reason": "File too large for decryption analysis (>100MB)"
            }

        else:
            # For non-PE large files, we have limited options
            self.logger.warning(
                f"Large non-PE file detected ({current_file_type}). "
                f"Most analysis features require loading file into memory."
            )
            report["status_message"] = (
                f"Large {current_file_type} file (>100MB) - limited analysis available. "
                "Only PE files support streaming analysis."
            )

        log_memory_usage("End of streaming pipeline", self.logger)
        self.logger.info(f"Streaming pipeline finished for: {input_file_path}")
        return report

    def _save_payload_to_temp_file(self, payload_data: bytes) -> str:
        """
        Save payload to temporary file for analysis.

        Args:
            payload_data: Raw payload bytes

        Returns:
            Path to temporary file
        """
        temp_dir = self.config_manager.get('general', 'output_dir', fallback='output')
        os.makedirs(os.path.join(temp_dir, "temp_extracted_recursive"), exist_ok=True)
        temp_payload_path = os.path.join(temp_dir, "temp_extracted_recursive", f"payload_{hash(payload_data)}.bin")

        with open(temp_payload_path, 'wb') as f:
            f.write(payload_data)

        return temp_payload_path

    def _cleanup_temp_file(self, file_path: str) -> None:
        """
        Clean up temporary file.

        Args:
            file_path: Path to temporary file to remove
        """
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except OSError:
                self.logger.warning(f"Could not remove temp payload file: {file_path}")

    def _check_pipeline_cache(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        Check if pipeline result is cached.

        Args:
            file_path: Path to file being analyzed

        Returns:
            Cached report dictionary or None if not cached
        """
        try:
            # Calculate file hash for cache key
            file_hash = self.file_hasher.get_file_hash(file_path, 'sha256')
            cache_key = f"pipeline_result:{file_hash}"

            # Check persistent cache first (survives restarts)
            if self.cache_manager.persistent_cache:
                cached_result = self.cache_manager.persistent_cache.get(cache_key)
                if cached_result:
                    self.logger.debug(f"Pipeline cache hit (persistent) for {file_path}")
                    return cached_result

            return None

        except Exception as e:
            self.logger.warning(f"Error checking pipeline cache: {e}")
            return None

    def _cache_pipeline_result(self, file_path: str, report: Dict[str, Any]) -> None:
        """
        Cache pipeline result for future use.

        Args:
            file_path: Path to file being analyzed
            report: Analysis report to cache
        """
        try:
            # Calculate file hash for cache key
            file_hash = self.file_hasher.get_file_hash(file_path, 'sha256')
            cache_key = f"pipeline_result:{file_hash}"

            # Store in persistent cache (survives restarts)
            if self.cache_manager.persistent_cache:
                self.cache_manager.persistent_cache.put(cache_key, report)
                self.logger.debug(f"Cached pipeline result for {file_path}")

        except Exception as e:
            self.logger.warning(f"Error caching pipeline result: {e}")

    def _log_cache_stats(self) -> None:
        """Log cache performance statistics."""
        try:
            stats = self.cache_manager.get_aggregate_stats()

            # Log summary statistics
            if stats['total_requests'] > 0:
                self.logger.info(
                    f"Cache Performance: {stats['overall_hit_rate']:.1%} hit rate "
                    f"({stats['total_hits']} hits / {stats['total_requests']} requests)"
                )

                # Log detailed statistics at debug level
                if self.logger.isEnabledFor(logging.DEBUG):
                    for cache_name, cache_stats in stats['individual_caches'].items():
                        if cache_stats.get('hits', 0) + cache_stats.get('misses', 0) > 0:
                            self.logger.debug(
                                f"  {cache_name}: {cache_stats.get('hit_rate', 0):.1%} "
                                f"({cache_stats.get('size', 0)} items)"
                            )

        except Exception as e:
            self.logger.debug(f"Error logging cache stats: {e}")


if __name__ == '__main__':
    # This __main__ block is for basic testing of the PipelineManager itself.
    # It requires a settings.ini and a test file.
    print("Testing core_engine.pipeline_manager module directly...")

    # Simplified Mock ConfigurationManager for this test
    class MockConfigurationManagerForPipelineTest:
        def __init__(self, settings_path="dummy_pipeline_settings.ini"):
            self.settings_data = {
                "general": {"log_level": "DEBUG", "output_dir": "test_pipeline_output"},
                "pe_analyzer": {"enabled": True, "hash_algorithms": "md5,sha1", "fast_load": False},
                "code_analyzer": {"enabled": True, "use_radare2": False}, # Force Capstone due to r2 install issues
                "obfuscation_analyzer": {"enabled": True, "min_string_length": 4},
                "polyglot_analyzer": {"enabled": True, "supported_carriers": "zip,jpeg,generic"},
                "steganography_analyzer": {"enabled": True, "lsb_formats": "png,bmp", "max_appended_scan_size": 1024},
                "crypto_analyzer": {"enabled": True},
                "decryption_chains": { # Example chain for testing decryption path
                    "test_xor_pe_chain": "xor_int:0x55"
                }
            }
            # Create dummy settings file if it doesn't exist (needed by CM itself sometimes)
            if not os.path.exists(settings_path):
                with open(settings_path, "w") as f: # Create a basic ini
                    for section, options in self.settings_data.items():
                        f.write(f"[{section}]\n")
                        for k, v in options.items(): f.write(f"{k}={v}\n")
                        f.write("\n")

        def get(self, section, option, fallback=None): return self.settings_data.get(section, {}).get(option, fallback)
        def getboolean(self, section, option, fallback=None):
            val = self.settings_data.get(section, {}).get(option, fallback)
            return str(val).lower() in ('true', '1', 'yes')
        def getint(self, section, option, fallback=None): return int(self.settings_data.get(section, {}).get(option, fallback) or fallback)
        def getfloat(self, section, option, fallback=None): return float(self.settings_data.get(section, {}).get(option, fallback) or fallback)
        def get_section(self, section): return self.settings_data.get(section)


    # Path setup
    current_script_dir = os.path.dirname(os.path.abspath(__file__)) # core_engine directory
    project_root_dir = os.path.abspath(os.path.join(current_script_dir, ".."))

    # Ensure output directory for tests exists
    test_output_dir = os.path.join(project_root_dir, "test_pipeline_output", "temp_extracted")
    os.makedirs(test_output_dir, exist_ok=True)
    test_output_dir_recursive = os.path.join(project_root_dir, "test_pipeline_output", "temp_extracted_recursive")
    os.makedirs(test_output_dir_recursive, exist_ok=True)


    # Use the actual settings.ini if it exists at project root, else dummy
    actual_settings_ini_path = os.path.join(project_root_dir, "settings.ini")
    test_specific_settings_path = os.path.join(current_script_dir, "dummy_pipeline_settings.ini")

    if os.path.exists(actual_settings_ini_path):
        from core_engine.configuration_manager import ConfigurationManager as ActualCM
        try:
            config_mgr = ActualCM(settings_path=actual_settings_ini_path)
            print(f"Using actual ConfigurationManager from: {actual_settings_ini_path}")
        except Exception as e:
            print(f"Failed to load actual settings.ini ({e}), using MockConfigurationManagerForPipelineTest with {test_specific_settings_path}")
            config_mgr = MockConfigurationManagerForPipelineTest(settings_path=test_specific_settings_path)
    else:
        print(f"Actual settings.ini not found, using MockConfigurationManagerForPipelineTest with {test_specific_settings_path}")
        config_mgr = MockConfigurationManagerForPipelineTest(settings_path=test_specific_settings_path)


    pipeline_mgr_instance = PipelineManager(config_manager=config_mgr)

    # Test with the dummy PE file created in previous subtasks
    test_pe_file_path = os.path.join(project_root_dir, "tests", "static_analyzer", "test_valid_pe32.exe")

    if not os.path.exists(test_pe_file_path):
        print(f"Test PE file '{test_pe_file_path}' not found. Creating a temporary minimal PE for test.")
        # Create a minimal PE if it's missing for the test run
        temp_pe_path = os.path.join(test_output_dir, "minimal_test.exe")
        with open(temp_pe_path, "wb") as f_dummy:
            f_dummy.write(
                b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00' +
                (b'\x00'*0x24) + b'\x80\x00\x00\x00' + (b'\x00'*0x3C) + # e_lfanew points to 0x80 (128)
                b'PE\x00\x00\x4c\x01\x01\x00' + (b'\x00'*12) + b'\xe0\x00\x02\x01' + # COFF, OptHdrSize, Characteristics
                b'\x0b\x01\x02\x00' + (b'\x00'*15) + b'\x00\x10\x00\x00' + # OptHdr Magic, Linker, ... EntryPoint
                (b'\x00'*4) + b'\x00\x00\x40\x00' + (b'\x00'*40) + b'\x00\x02\x00\x00' + # ImageBase, ... SizeOfHeaders
                (b'\x00'*100) + # Rest of OptionalHeader
                b'.text\x00\x00\x00\x10\x00\x00\x00\x00\x10\x00\x00\x00\x02\x00\x00\x00\x02\x00\x00' + (b'\x00'*12) + b'\x20\x00\x00\x60' + # Section Hdr
                (b'\x00'*(0x200 - (0x80+4+20+224+40))) + (b'\xc3'*16) # Padding and RET sled
            )
        test_pe_file_to_run = temp_pe_path
    else:
        test_pe_file_to_run = test_pe_file_path
        print(f"Using existing test PE: {test_pe_file_to_run}")

    pipeline_results = pipeline_mgr_instance.run_pipeline(test_pe_file_to_run)
    print("\n--- Pipeline Execution Results (JSON) ---")
    # Custom default for json.dump to handle bytes (convert to hex string)
    def json_bytes_serializer(obj):
        if isinstance(obj, bytes):
            return obj.hex() # Or obj.decode('latin-1') if you prefer string representation
        raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

    print(json.dumps(pipeline_results, indent=2, default=json_bytes_serializer))

    # Clean up dummy files created by this test
    if os.path.exists(test_specific_settings_path): os.remove(test_specific_settings_path)
    if 'temp_pe_path' in locals() and os.path.exists(temp_pe_path): os.remove(temp_pe_path)
    # Potentially clean up test_pipeline_output directory
    # import shutil
    # if os.path.exists(os.path.join(project_root_dir, "test_pipeline_output")):
    # shutil.rmtree(os.path.join(project_root_dir, "test_pipeline_output"))
