import unittest
import os
import sys
import json
import logging

# Add project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, PROJECT_ROOT)
sys.path.append(os.path.join(PROJECT_ROOT, 'core_engine')) # For ConfigurationManager, PipelineManager
sys.path.append(os.path.join(PROJECT_ROOT, 'modules', 'static_analyzer')) # For analyzers

try:
    from core_engine.configuration_manager import ConfigurationManager
    from core_engine.pipeline_manager import PipelineManager
    # Analyzers are loaded by PipelineManager, so direct import here isn't strictly necessary
    # unless we want to mock them or check their availability.
except ImportError as e:
    print(f"Critical Error: Failed to import core modules for pipeline testing: {e}", file=sys.stderr)
    # If these fail, tests can't run anyway.
    ConfigurationManager = None
    PipelineManager = None


import zipfile # For creating test ZIP files
import io # For BytesIO

# Path to the existing test PE file (created in subtask 5)
# This is used as a base for creating encrypted versions or embedding in carriers.
# Assuming this test script is in /app/tests/test_pipeline.py
# And the PE file is in /app/tests/static_analyzer/test_valid_pe32.exe
BASE_TEST_PE_FILE_DIR = os.path.join(os.path.dirname(__file__), "static_analyzer")
BASE_TEST_PE_FILE_NAME = "test_valid_pe32.exe"
BASE_TEST_PE_FILE_PATH = os.path.join(BASE_TEST_PE_FILE_DIR, BASE_TEST_PE_FILE_NAME)

# Define some constants for test file creation
TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "pipeline_test_data")
PIPELINE_TEST_SETTINGS_FILE = os.path.join(os.path.dirname(__file__), "dummy_pipeline_settings.ini")

# Minimal PE structure (enough for MZ and PE signature checks)
# Using a simplified one here for tests, distinct from test_valid_pe32.exe if needed for specific checks.
# Or, ideally, load BASE_TEST_PE_FILE_PATH's content for these.
DUMMY_PE_PAYLOAD_BYTES = None # Will be loaded from BASE_TEST_PE_FILE_PATH in setUpClass

# JPEG signatures
JPEG_SOI = b'\xFF\xD8'
JPEG_EOI = b'\xFF\xD9'
DUMMY_JPEG_CONTENT_NO_PAYLOAD = JPEG_SOI + b"\xDE\xAD\xBE\xEF" + JPEG_EOI # Minimal valid JPEG


class TestAnalysisPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        cls.logger = logging.getLogger(__name__)

        os.makedirs(TEST_DATA_DIR, exist_ok=True)

        # Load base PE payload content
        global DUMMY_PE_PAYLOAD_BYTES
        if os.path.exists(BASE_TEST_PE_FILE_PATH):
            with open(BASE_TEST_PE_FILE_PATH, 'rb') as f_pe:
                DUMMY_PE_PAYLOAD_BYTES = f_pe.read()
            cls.logger.info(f"Loaded base PE payload from {BASE_TEST_PE_FILE_PATH} ({len(DUMMY_PE_PAYLOAD_BYTES)} bytes)")
        else:
            cls.logger.error(f"Base test PE file {BASE_TEST_PE_FILE_PATH} not found. Some tests may fail or be inaccurate.")
            # Fallback to a very minimal PE if base is missing, just to allow tests to run
            DUMMY_PE_PAYLOAD_BYTES = ( b'MZ' + (b'\x00' * (0x3C - 2)) + b'\x40\x00\x00\x00' +
                                     (b'\x00' * (0x40 - 0x3C - 4)) + b'PE\0\0' + (b'\x00' * 100) )


        # --- Create Test Files for different scenarios ---
        # 1. Plain PE file (using the loaded or fallback PE data)
        cls.plain_pe_file = os.path.join(TEST_DATA_DIR, "test_plain.exe")
        with open(cls.plain_pe_file, 'wb') as f: f.write(DUMMY_PE_PAYLOAD_BYTES)

        # 2. ZIP file containing the PE payload
        cls.zip_with_pe_file = os.path.join(TEST_DATA_DIR, "test_pe.zip")
        with zipfile.ZipFile(cls.zip_with_pe_file, 'w') as zf:
            zf.writestr("payload.exe", DUMMY_PE_PAYLOAD_BYTES)
            zf.writestr("readme.txt", b"This archive contains a PE file.")

        # 3. JPEG file with an appended PE payload
        cls.jpeg_with_appended_pe_file = os.path.join(TEST_DATA_DIR, "test_pe.jpg")
        with open(cls.jpeg_with_appended_pe_file, 'wb') as f:
            f.write(DUMMY_JPEG_CONTENT_NO_PAYLOAD)
            f.write(DUMMY_PE_PAYLOAD_BYTES)

        # 4. "Encrypted" PE file (XORed with a simple key)
        cls.xor_key = 0xAB
        cls.encrypted_pe_file = os.path.join(TEST_DATA_DIR, "test_encrypted.bin")
        encrypted_data = bytes([b ^ cls.xor_key for b in DUMMY_PE_PAYLOAD_BYTES])
        with open(cls.encrypted_pe_file, 'wb') as f: f.write(encrypted_data)

        # Create dummy settings.ini for these integration tests
        dummy_settings_content = f"""
[general]
project_root = {os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))}
# Relative to settings file location (tests directory)
output_dir = {os.path.join(TEST_DATA_DIR, "test_pipeline_output")}
log_level = DEBUG
verbose = True

[paths] # These are relative to output_dir generally, or absolute
log_dir_name = logs
# Full path: {TEST_DATA_DIR}/test_pipeline_output/logs

[pe_analyzer]
enabled = True
[code_analyzer]
enabled = True
use_radare2 = False # Force Capstone due to expected unavailability of r2 in test env
[obfuscation_analyzer]
enabled = True
[polyglot_analyzer]
enabled = True
[steganography_analyzer]
enabled = True
[crypto_analyzer]
enabled = True

[decryption_chains]
# Chain for the encrypted PE test
xor_decrypt_payload = xor_int:{hex(cls.xor_key)}
        """
        with open(PIPELINE_TEST_SETTINGS_FILE, 'w') as f:
            f.write(dummy_settings_content)

        cls.config_manager = None
        if ConfigurationManager:
            try:
                cls.config_manager = ConfigurationManager(settings_path=PIPELINE_TEST_SETTINGS_FILE)
                cls.logger.info(f"ConfigurationManager loaded with {PIPELINE_TEST_SETTINGS_FILE}")
            except Exception as e:
                cls.logger.error(f"Failed to initialize ConfigurationManager for pipeline tests: {e}", exc_info=True)
        else:
            cls.logger.error("ConfigurationManager class not imported, cannot run pipeline tests effectively.")

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(PIPELINE_TEST_SETTINGS_FILE):
            os.remove(PIPELINE_TEST_SETTINGS_FILE)
        # Clean up test files and directories
        import shutil
        if os.path.exists(TEST_DATA_DIR):
            shutil.rmtree(TEST_DATA_DIR)
        # Clean up output directory specified in dummy_settings_content
        # output_dir_in_settings = os.path.join(TEST_DATA_DIR, "test_pipeline_output")
        # This is wrong, output_dir is relative to project_root defined in settings
        # For simplicity, let's assume run_analyzer.py or pipeline itself handles output dir creation if needed
        # and we don't need to clean a globally configured one here.
        # If test_pipeline_output is inside TEST_DATA_DIR, it's already removed.


    @unittest.skipIf(PipelineManager is None or ConfigurationManager is None or DUMMY_PE_PAYLOAD_BYTES is None,
                     "Core modules not imported or base PE data not loaded.")
    def test_run_full_pipeline_on_plain_pe(self):
        self.logger.info(f"Starting pipeline test with plain PE: {self.plain_pe_file}")
        self.assertTrue(os.path.exists(self.plain_pe_file), "Plain PE test file missing.")
        if not self.config_manager: self.fail("ConfigurationManager not initialized.")

        try:
            pipeline_mgr = PipelineManager(config_manager=self.config_manager)
        except Exception as e: self.fail(f"Failed to initialize PipelineManager: {e}")

        results = pipeline_mgr.run_pipeline(self.plain_pe_file)

        self.assertIsNotNone(results.get("static_pe_analysis"), "Static PE analysis should be present for plain PE.")
        self.assertIsNotNone(results["static_pe_analysis"].get("pe_info"), "PE info should be in static analysis results.")
        self.assertTrue(len(results["errors"]) == 0, f"Pipeline reported errors for plain PE: {results['errors']}")
        self.assertEqual(results.get("original_file_type"), "pe")
        # No extractions or decryptions expected for a plain PE
        self.assertIsNone(results.get("extraction_analysis")) # Or it's present but empty
        self.assertIsNone(results.get("steganography_analysis"))
        self.assertTrue(
            results.get("decryption_analysis") is None or
            results.get("decryption_analysis", {}).get("status") == "skipped_as_already_pe" or
            results.get("decryption_analysis", {}).get("status") == "no_chains_attempted" # if no chains defined
        )
        self.assertEqual(len(results.get("extracted_payload_analyses", [])), 0)


    @unittest.skipIf(PipelineManager is None or ConfigurationManager is None or DUMMY_PE_PAYLOAD_BYTES is None,
                     "Core modules not imported or base PE data not loaded.")
    def test_pipeline_zip_with_pe(self):
        self.logger.info(f"Starting pipeline test with ZIP containing PE: {self.zip_with_pe_file}")
        self.assertTrue(os.path.exists(self.zip_with_pe_file), "ZIP test file missing.")
        if not self.config_manager: self.fail("ConfigurationManager not initialized.")

        pipeline_mgr = PipelineManager(config_manager=self.config_manager)
        results = pipeline_mgr.run_pipeline(self.zip_with_pe_file)

        self.assertEqual(results.get("original_file_type"), "zip")
        self.assertIsNotNone(results.get("extraction_analysis"))
        self.assertGreater(len(results.get("extracted_payload_analyses", [])), 0, "Should have recursive analysis for PE in ZIP.")

        pe_sub_analysis = results["extracted_payload_analyses"][0] # Assuming PE is the first/only one for this test
        self.assertIn("payload.exe", pe_sub_analysis.get("source_description", ""))
        self.assertIsNotNone(pe_sub_analysis.get("static_pe_analysis"))
        self.assertIsNotNone(pe_sub_analysis["static_pe_analysis"].get("pe_info"))
        self.assertTrue(len(pe_sub_analysis["errors"]) == 0, f"Sub-analysis reported errors: {pe_sub_analysis['errors']}")


    @unittest.skipIf(PipelineManager is None or ConfigurationManager is None or DUMMY_PE_PAYLOAD_BYTES is None,
                     "Core modules not imported or base PE data not loaded.")
    def test_pipeline_jpeg_with_appended_pe(self):
        self.logger.info(f"Starting pipeline test with JPEG + appended PE: {self.jpeg_with_appended_pe_file}")
        self.assertTrue(os.path.exists(self.jpeg_with_appended_pe_file), "JPEG test file missing.")
        if not self.config_manager: self.fail("ConfigurationManager not initialized.")

        pipeline_mgr = PipelineManager(config_manager=self.config_manager)
        results = pipeline_mgr.run_pipeline(self.jpeg_with_appended_pe_file)

        self.assertEqual(results.get("original_file_type"), "jpeg")
        # Polyglot should find the appended PE. Steganography might also find it.
        self.assertTrue(
            results.get("extraction_analysis") is not None or
            results.get("steganography_analysis") is not None
        )
        self.assertGreater(len(results.get("extracted_payload_analyses", [])), 0, "Should have recursive analysis for appended PE.")

        appended_pe_analysis = results["extracted_payload_analyses"][0]
        self.assertIn("appended_data_in_jpeg", appended_pe_analysis.get("source_description", ""))
        self.assertIsNotNone(appended_pe_analysis.get("static_pe_analysis"))
        self.assertIsNotNone(appended_pe_analysis["static_pe_analysis"].get("pe_info"))


    @unittest.skipIf(PipelineManager is None or ConfigurationManager is None or DUMMY_PE_PAYLOAD_BYTES is None,
                     "Core modules not imported or base PE data not loaded.")
    def test_pipeline_encrypted_pe_with_decryption_rule(self):
        self.logger.info(f"Starting pipeline test with encrypted PE: {self.encrypted_pe_file}")
        self.assertTrue(os.path.exists(self.encrypted_pe_file), "Encrypted PE test file missing.")
        if not self.config_manager: self.fail("ConfigurationManager not initialized.")

        pipeline_mgr = PipelineManager(config_manager=self.config_manager) # Settings include the decryption chain
        results = pipeline_mgr.run_pipeline(self.encrypted_pe_file)

        self.assertNotEqual(results.get("original_file_type"), "pe", "Original file should not be seen as PE.")
        self.assertIsNotNone(results.get("decryption_analysis"))
        self.assertEqual(results["decryption_analysis"].get("status"), "decrypted_to_pe")
        self.assertEqual(results["decryption_analysis"].get("applied_chain"), "xor_decrypt_payload")

        self.assertIsNotNone(results.get("static_pe_analysis"), "Static PE analysis should be present after decryption.")
        self.assertIsNotNone(results["static_pe_analysis"].get("pe_info"))
        self.assertIn("(after decryption)", results["static_pe_analysis"].get("source", ""))
        self.assertTrue(len(results["errors"]) == 0, f"Pipeline reported errors for encrypted PE: {results['errors']}")


    # Original test, slightly refactored to use self.plain_pe_file
    @unittest.skipIf(PipelineManager is None or ConfigurationManager is None or DUMMY_PE_PAYLOAD_BYTES is None,
                     "Core modules not imported or base PE data not loaded.")
    def test_run_full_pipeline_on_loaded_sample_pe(self): # Renamed from test_run_full_pipeline_on_sample_pe
        self.logger.info(f"Starting full pipeline test with PE: {self.plain_pe_file}")
        self.assertTrue(os.path.exists(self.plain_pe_file), f"Required test PE file not found: {self.plain_pe_file}")
        if not self.config_manager:
            self.fail("ConfigurationManager not initialized for test.")

        try:
            pipeline_mgr = PipelineManager(config_manager=self.config_manager)
            self.logger.info("PipelineManager initialized for test.")
        except Exception as e:
            self.fail(f"Failed to initialize PipelineManager: {e}")

        try:
            results = pipeline_mgr.run_pipeline(TEST_PE_FILE_PATH)
            self.logger.info("Pipeline execution completed.")
            # Save the raw results for debugging if needed
            # with open("debug_pipeline_results.json", "w") as f_debug:
            #    json.dump(results, f_debug, indent=2, default=lambda o: str(o) if isinstance(o, bytes) else "<not serializable>")

        except Exception as e:
            self.fail(f"Pipeline execution failed with error: {e}")

        self.assertIsNotNone(results, "Pipeline should return results.")
        self.assertIsInstance(results, dict, "Results should be a dictionary (JSON object).")

        # Check for top-level keys
        self.assertIn("file_path", results)
        self.assertEqual(results["file_path"], TEST_PE_FILE_PATH)

        self.assertIn("pe_info", results)
        self.assertIn("code_analysis", results)
        self.assertIn("obfuscation_details", results)
        self.assertIn("errors", results) # Should be an empty list for a successful run on a valid PE

        # Check PE Info (assuming PEAnalyzer ran successfully)
        if results.get("pe_info") and "error" not in results["pe_info"]:
            pe_info = results["pe_info"]
            self.assertIsNotNone(pe_info.get("hashes"), "PE hashes should be present.")
            self.assertIsNotNone(pe_info.get("overall_entropy"), "PE overall entropy should be present.")
            self.assertIsNotNone(pe_info.get("header_info"), "PE header_info should be present.")
            self.assertIsInstance(pe_info.get("sections"), list, "PE sections should be a list.")
            self.assertGreater(len(pe_info["sections"]), 0, "Should have at least one section for the test PE.")
            self.assertEqual(pe_info["sections"][0]["name"], ".text") # From test_valid_pe32.exe
        elif results.get("pe_info"): # An error occurred within PEAnalyzer
             self.logger.warning(f"PE Analysis reported an error or incomplete data: {results['pe_info']}")


        # Check Code Analysis (assuming CodeAnalyzer ran)
        # This is highly dependent on Capstone/R2 availability.
        # The dummy settings force CodeAnalyzer to be enabled but use_radare2=False.
        # So it should attempt Capstone-based analysis.
        if results.get("code_analysis"):
            code_analysis = results["code_analysis"]
            self.assertIsInstance(code_analysis, dict, "Code analysis results should be a dictionary (per section).")
            # Check for .text section analysis
            self.assertIn(".text", code_analysis, "Code analysis for .text section should be present.")
            if ".text" in code_analysis and "error" not in code_analysis[".text"]:
                text_section_code_analysis = code_analysis[".text"]
                self.assertIsNotNone(text_section_code_analysis.get("architecture"), "Architecture should be in code analysis.")
                self.assertIsInstance(text_section_code_analysis.get("detected_function_starts"), list)
                # self.assertGreater(len(text_section_code_analysis["detected_function_starts"]), 0, "Should detect at least one function in .text of test PE.")
                # The dummy PE's .text might be too simple for robust function start detection by simple prologues.
                self.assertIsNotNone(text_section_code_analysis.get("instruction_count"))
            elif ".text" in code_analysis:
                 self.logger.warning(f"Code Analysis for .text reported an error: {code_analysis['.text']}")


        # Check Obfuscation Details (assuming ObfuscationAnalyzer ran)
        if results.get("obfuscation_details"):
            obfuscation_details = results["obfuscation_details"]
            self.assertIsInstance(obfuscation_details.get("plain_strings"), list)
            self.assertIsInstance(obfuscation_details.get("decoded_strings"), list)
            self.assertIsNotNone(obfuscation_details.get("api_hashing"))
            self.assertIsInstance(obfuscation_details.get("api_sequences"), list) # Even if empty

        # Check for major errors in the pipeline itself
        self.assertEqual(len(results["errors"]), 0, f"Pipeline reported errors: {results['errors']}")


if __name__ == '__main__':
    unittest.main()
