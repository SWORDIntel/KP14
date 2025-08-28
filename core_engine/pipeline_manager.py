import logging
import os
import json
import io # For BytesIO when dealing with in-memory data for analyzers

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
    def __init__(self, config_manager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        self._configure_logging()

        # Static Analyzers
        self.pe_analyzer_template = None # Store class, instantiate per file/data
        self.code_analyzer_template = None
        self.obfuscation_analyzer_template = None

        # Extraction/Decryption Analyzers (instantiated once)
        self.polyglot_analyzer = None
        self.steganography_analyzer = None
        self.crypto_analyzer = None

        self._load_module_templates_and_analyzers()

    def _configure_logging(self):
        log_level_str = "INFO"
        if self.config_manager:
            log_level_str = self.config_manager.get('general', 'log_level', fallback='INFO').upper()

        try: level = getattr(logging, log_level_str)
        except AttributeError: level = logging.INFO

        self.logger.setLevel(level)
        if not self.logger.hasHandlers():
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            ch = logging.StreamHandler()
            ch.setFormatter(formatter)
            self.logger.addHandler(ch)

    def _load_module_templates_and_analyzers(self):
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

    def _get_file_type(self, file_data_or_path):
        """Simple file type identification using magic numbers or extension."""
        data_header = None
        if isinstance(file_data_or_path, bytes):
            data_header = file_data_or_path[:16] # Read first few bytes
        elif isinstance(file_data_or_path, str) and os.path.exists(file_data_or_path):
            try:
                with open(file_data_or_path, 'rb') as f:
                    data_header = f.read(16)
            except IOError:
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

    def _run_static_analysis_on_pe_data(self, pe_data, source_description, original_file_path_for_codeanalyzer=None):
        """
        Helper to run the static PE analysis suite (PE, Code, Obfuscation) on given PE data.
        `source_description` indicates where the pe_data came from (e.g., "original_file", "extracted_from_zip:member.exe").
        `original_file_path_for_codeanalyzer` is needed if CodeAnalyzer uses r2, which needs a file path.
        """
        self.logger.info(f"Running static PE analysis for: {source_description}")
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

    def run_pipeline(self, input_file_path: str, is_recursive_call=False, original_source_desc="original_file"):
        self.logger.info(f"Pipeline run for: {input_file_path} (Source: {original_source_desc}, Recursive: {is_recursive_call})")
        if not os.path.exists(input_file_path):
            self.logger.error(f"Input file not found: {input_file_path}")
            return {"error": "Input file not found.", "file_path": input_file_path, "source_description": original_source_desc}

        try:
            with open(input_file_path, 'rb') as f:
                file_data = f.read()
        except IOError as e:
            self.logger.error(f"Could not read input file {input_file_path}: {e}")
            return {"error": f"File read error: {e}", "file_path": input_file_path, "source_description": original_source_desc}

        current_file_type = self._get_file_type(file_data) # Use data for type detection
        self.logger.info(f"Detected file type for {input_file_path}: {current_file_type}")

        report = {
            "file_path": input_file_path,
            "original_file_type": current_file_type,
            "source_description": original_source_desc,
            "is_recursive_call": is_recursive_call,
            "extraction_analysis": None,
            "steganography_analysis": None,
            "decryption_analysis": None,
            "static_pe_analysis": None, # This will hold results from _run_static_analysis_on_pe_data
            "extracted_payload_analyses": [], # For recursive results
            "errors": []
        }

        data_to_analyze = file_data
        data_source_description = original_source_desc
        # If file is an archive/carrier, this will be updated with extracted data

        # --- Extraction Phase ---
        extracted_payloads_meta = [] # Store metadata of payloads that need further analysis
        if self.polyglot_analyzer and current_file_type in ['zip', 'jpeg', 'unknown']: # 'unknown' could be anything
            self.logger.info(f"Running PolyglotAnalyzer on {input_file_path}")
            try:
                poly_results = self.polyglot_analyzer.analyze_file(file_path=input_file_path, file_data=file_data)
                report["extraction_analysis"] = {"polyglot": poly_results}
                for p_info in poly_results:
                    # Check if extracted payload is PE for recursive analysis
                    if p_info['data'].startswith(MAGIC_MZ):
                        extracted_payloads_meta.append({
                            "data": p_info['data'],
                            "source": f"{original_source_desc} -> polyglot:{p_info.get('carrier_type', 'unknown_carrier')}/{p_info.get('type_desc','unknown_payload')}@0x{p_info.get('offset',0):x}",
                            "original_file_path": None # It's from memory
                        })
            except Exception as e: report["errors"].append(f"PolyglotAnalysis: {str(e)}")

        if self.steganography_analyzer: # Add more types if StegoAnalyzer supports them
            self.logger.info(f"Running SteganographyAnalyzer on {input_file_path}")
            stego_results_detail = {}
            try:
                appended_data_info = self.steganography_analyzer.check_for_appended_data(file_path=input_file_path, file_data=file_data)
                stego_results_detail["appended_data"] = appended_data_info
                for s_info in appended_data_info:
                    if s_info['data'].startswith(MAGIC_MZ):
                         extracted_payloads_meta.append({
                            "data": s_info['data'],
                            "source": f"{original_source_desc} -> stego:appended_data_in_{s_info.get('eof_marker_type')}@0x{s_info.get('offset',0):x}",
                            "original_file_path": None
                        })

                if current_file_type in self.steganography_analyzer.supported_lsb_formats:
                    lsb_result = self.steganography_analyzer.analyze_lsb_steganography(file_path=input_file_path, file_data=file_data)
                    stego_results_detail["lsb_analysis"] = lsb_result
                    if lsb_result.get('status') == 'data_extracted' and lsb_result['data'].startswith(MAGIC_MZ):
                        extracted_payloads_meta.append({
                            "data": lsb_result['data'],
                            "source": f"{original_source_desc} -> stego:lsb_in_{current_file_type}",
                            "original_file_path": None
                        })
                report["steganography_analysis"] = stego_results_detail
            except Exception as e: report["errors"].append(f"SteganographyAnalysis: {str(e)}")

        # --- Decryption Phase (on primary data stream) ---
        # This applies if the original file itself might be an encrypted PE.
        # For extracted files, decryption would happen before they are added to extracted_payloads_meta if needed.
        # Or, decryption is attempted before each static analysis run. Let's do it before static analysis.

        # Determine the primary data stream for static analysis
        # If no payloads extracted and file is not PE, analysis might stop or be limited.
        # If payloads were extracted, they are handled recursively later.
        # This part focuses on the current `data_to_analyze` (which is initially the full file).

        data_for_current_static_analysis = data_to_analyze
        is_pe_after_decryption = False

        if self.crypto_analyzer and data_for_current_static_analysis:
            self.logger.info(f"Attempting decryption for {data_source_description} if chains are configured.")
            # Try predefined chains. Heuristics for applying chains are complex and not implemented here.
            # Assume a chain named "default_pe_chain" or similar might be configured in settings.ini
            # For this example, let's try *all* known chains if the data isn't already a PE.
            # This is for demonstration; real-world usage would be more targeted.

            decryption_applied_successfully = False
            if not data_for_current_static_analysis.startswith(MAGIC_MZ): # Only try decrypting non-PEs
                chain_results = self.crypto_analyzer.try_known_decryption_chains(data_for_current_static_analysis)
                report["decryption_analysis"] = {"attempted_chains": {}}
                for chain_name, decrypted_data_or_none in chain_results.items():
                    if decrypted_data_or_none is not None:
                        report["decryption_analysis"]["attempted_chains"][chain_name] = {"status": "success", "output_length": len(decrypted_data_or_none)}
                        # Check if this decrypted version is a PE file
                        if decrypted_data_or_none.startswith(MAGIC_MZ):
                            self.logger.info(f"Decryption chain '{chain_name}' resulted in a PE file for {data_source_description}.")
                            data_for_current_static_analysis = decrypted_data_or_none # Analyze this
                            report["decryption_analysis"]["applied_chain"] = chain_name
                            report["decryption_analysis"]["status"] = "decrypted_to_pe"
                            is_pe_after_decryption = True
                            decryption_applied_successfully = True
                            break # Use the first successful PE decryption
                    else:
                         report["decryption_analysis"]["attempted_chains"][chain_name] = {"status": "failed"}
                if not decryption_applied_successfully:
                    self.logger.info(f"No configured decryption chain produced a PE file for {data_source_description}.")
                    report["decryption_analysis"]["status"] = "no_pe_after_decryption_attempts" if chain_results else "no_chains_attempted"
            else: # Already a PE, or no crypto analyzer
                report["decryption_analysis"] = {"status": "skipped_as_already_pe" if data_for_current_static_analysis.startswith(MAGIC_MZ) else "skipped_no_analyzer"}


        # --- Static Analysis Phase (on current data stream, which might be original or decrypted) ---
        if data_for_current_static_analysis.startswith(MAGIC_MZ) or is_pe_after_decryption:
            # Pass input_file_path for CodeAnalyzer if r2 needs it, even if data is from memory (it will be saved to temp file)
            # Pass data_for_current_static_analysis for actual analysis bytes
            report["static_pe_analysis"] = self._run_static_analysis_on_pe_data(
                data_for_current_static_analysis,
                source_description=f"{data_source_description}{' (after decryption)' if decryption_applied_successfully else ''}",
                original_file_path_for_codeanalyzer=input_file_path if data_for_current_static_analysis is file_data else None
            )
        elif not extracted_payloads_meta: # Only log if no PEs were found anywhere
            self.logger.info(f"No PE file identified for static analysis from {input_file_path} (type: {current_file_type}).")
            if not report["errors"] and not report["extraction_analysis"] and not report["steganography_analysis"]:
                 report["status_message"] = "File is not a PE and no further payloads or steganographic content found."


        # --- Recursive Analysis of Extracted Payloads ---
        for payload_info in extracted_payloads_meta:
            self.logger.info(f"Recursively analyzing extracted payload from: {payload_info['source']}")
            # Save payload to temp file to pass to pipeline (simplifies handling for now)
            # A more direct in-memory hand-off would be better.
            temp_dir = self.config_manager.get('general', 'output_dir', fallback='output')
            os.makedirs(os.path.join(temp_dir, "temp_extracted_recursive"), exist_ok=True)
            temp_payload_path = os.path.join(temp_dir, "temp_extracted_recursive", f"payload_{hash(payload_info['data'])}.bin")

            try:
                with open(temp_payload_path, 'wb') as f:
                    f.write(payload_info['data'])

                # Call run_pipeline recursively for this extracted payload
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
                if os.path.exists(temp_payload_path):
                    try: os.remove(temp_payload_path)
                    except OSError: self.logger.warning(f"Could not remove temp payload file: {temp_payload_path}")

        self.logger.info(f"Pipeline finished for: {input_file_path} (Source: {original_source_desc})")
        return report


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
```
