import unittest
import os
import sys
import hashlib
import pefile # Used for creating test files and some constants

# Add project root to sys.path to allow importing PEAnalyzer and ConfigurationManager
# This assumes tests are run from the project root or that the path is otherwise managed.
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
sys.path.insert(0, PROJECT_ROOT)

try:
    from modules.static_analyzer.pe_analyzer import PEAnalyzer
    from core_engine.configuration_manager import ConfigurationManager
except ImportError as e:
    print(f"Failed to import modules for testing: {e}")
    print(f"PROJECT_ROOT: {PROJECT_ROOT}")
    print(f"sys.path: {sys.path}")
    # As a fallback, try to import PEAnalyzer directly if it's in the same path for some reason
    # This is not ideal but can help in some CI environments if paths are tricky.
    if 'PEAnalyzer' not in globals():
        from modules.static_analyzer.pe_analyzer import PEAnalyzer
    if 'ConfigurationManager' not in globals():
         # This is more complex as ConfigurationManager has its own dependencies on settings.ini
         # For tests, we might mock it or use a dummy version if direct import fails.
        pass


# --- Test Data paths ---
# These files are expected to be created by tool calls before tests run.
# The actual byte data is no longer defined in this script.
TEST_DATA_DIR = os.path.dirname(__file__) # Tests are in tests/static_analyzer
MINIMAL_VALID_PE32_FILE_PATH = os.path.join(TEST_DATA_DIR, "test_valid_pe32.exe")
INVALID_PE_FILE_PATH = os.path.join(TEST_DATA_DIR, "test_invalid_pe.txt")
NO_OPT_HEADER_PE_FILE_PATH = os.path.join(TEST_DATA_DIR, "test_no_opt_header_pe.exe")

# Store the actual data for hash calculation if needed, or re-read from file.
# For simplicity in this refactor, hashes will be calculated by reading the created files.

class TestPEAnalyzer(unittest.TestCase):
    DUMMY_SETTINGS_FILE = os.path.join(TEST_DATA_DIR, "test_pe_analyzer_settings.ini")
    # VALID_PE_FILE, INVALID_PE_FILE, NO_OPT_HEADER_PE_FILE are now paths defined above

    # Expected data for the minimal valid PE, read from file for hash calculation
    _minimal_valid_pe32_data_content = None
    _no_opt_header_pe_data_content = None # For the no_opt_header file
    _invalid_pe_data_content = None # For the invalid PE file

    @classmethod
    def setUpClass(cls):
        # Create dummy settings for ConfigurationManager
        # Ensure settings file is in the same directory as test files for simplicity
        dummy_settings_content = """
[general]
project_root = ../..
# project_root is relative to the settings file, which will be in tests/static_analyzer
output_dir = test_analyzer_output
# output_dir will be relative to project_root: ../../test_analyzer_output
log_level = DEBUG

[paths]
log_dir_name = test_logs
# log_dir will be ../../test_analyzer_output/test_logs

[pe_analyzer]
enabled = True
hash_algorithms = md5,sha1,sha256,sha512
fast_load = False
entropy_buffer_size = 4096
        """
        os.makedirs(TEST_DATA_DIR, exist_ok=True) # Ensure dir exists
        with open(cls.DUMMY_SETTINGS_FILE, 'w') as f:
            f.write(dummy_settings_content)

        # Test files (MINIMAL_VALID_PE32_FILE_PATH etc.) must be created by tool calls before this script runs.
        # We will read the valid PE data here for hash verification later.
        try:
            if os.path.exists(MINIMAL_VALID_PE32_FILE_PATH):
                with open(MINIMAL_VALID_PE32_FILE_PATH, 'rb') as f_valid:
                    cls._minimal_valid_pe32_data_content = f_valid.read()
            else:
                print(f"WARNING: Test file {MINIMAL_VALID_PE32_FILE_PATH} not found during setUpClass.")

            if os.path.exists(NO_OPT_HEADER_PE_FILE_PATH):
                with open(NO_OPT_HEADER_PE_FILE_PATH, 'rb') as f_no_opt:
                    cls._no_opt_header_pe_data_content = f_no_opt.read()
            else:
                print(f"WARNING: Test file {NO_OPT_HEADER_PE_FILE_PATH} not found during setUpClass.")

            if os.path.exists(INVALID_PE_FILE_PATH):
                 with open(INVALID_PE_FILE_PATH, 'rb') as f_invalid:
                    cls._invalid_pe_data_content = f_invalid.read()
            else:
                print(f"WARNING: Test file {INVALID_PE_FILE_PATH} not found during setUpClass.")

        except FileNotFoundError as e:
            print(f"ERROR: A test file was not found during setUpClass: {e}. Ensure test files are created before running tests.")
            # This will likely cause tests to fail, which is intended if files aren't created.

        cls.config_manager = None
        if 'ConfigurationManager' in globals() and ConfigurationManager is not None:
            try:
                cls.config_manager = ConfigurationManager(settings_path=cls.DUMMY_SETTINGS_FILE)
            except Exception as e:
                print(f"Warning: Could not initialize ConfigurationManager for tests: {e}")
        else:
            print("Warning: ConfigurationManager class not found/imported. Tests needing it might be limited.")


    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.DUMMY_SETTINGS_FILE): os.remove(cls.DUMMY_SETTINGS_FILE)
        # The actual test PE files (MINIMAL_VALID_PE32_FILE_PATH, etc.)
        # should be cleaned up by the tool calls that create them, if necessary,
        # or left as artifacts if that's the desired behavior for debugging.
        # For now, we assume they are managed outside this script's direct cleanup.

        # Cleanup directories created by ConfigurationManager based on dummy settings
        # Note: project_root was ../.. from settings file in tests/static_analyzer
        # So output_dir is PROJECT_ROOT/test_analyzer_output = ../../test_analyzer_output
        # And log_dir is PROJECT_ROOT/test_analyzer_output/test_logs = ../../test_analyzer_output/test_logs

        # Construct paths relative to this test script's location for cleanup
        base_output_dir = os.path.join(TEST_DATA_DIR, "..", "..", "test_analyzer_output")
        log_dir = os.path.join(base_output_dir, "test_logs")

        if os.path.exists(log_dir):
            # Attempt to remove files in log_dir first if any were created
            # For this test, PEAnalyzer's logger is not configured to write to file by default.
            # However, if it were, this would be important.
            try:
                os.rmdir(log_dir)
            except OSError as e:
                print(f"Note: Could not remove log directory {log_dir}: {e}")
        if os.path.exists(base_output_dir):
            try:
                os.rmdir(base_output_dir)
            except OSError as e:
                print(f"Note: Could not remove base output directory {base_output_dir}: {e}")


    def test_load_valid_pe(self):
        self.assertIsNotNone(self._minimal_valid_pe32_data_content, "Valid PE test data not loaded.")
        analyzer = PEAnalyzer(MINIMAL_VALID_PE32_FILE_PATH, config_manager=self.config_manager)
        self.assertIsNotNone(analyzer.pe)
        self.assertTrue(analyzer.is_pe32())
        self.assertFalse(analyzer.is_pe32_plus())

    def test_load_invalid_pe(self):
        self.assertIsNotNone(self._invalid_pe_data_content, "Invalid PE test data not loaded.")
        with self.assertRaises(pefile.PEFormatError):
            PEAnalyzer(INVALID_PE_FILE_PATH, config_manager=self.config_manager)

    def test_parse_pe_header_valid(self):
        self.assertIsNotNone(self._minimal_valid_pe32_data_content, "Valid PE test data not loaded.")
        analyzer = PEAnalyzer(MINIMAL_VALID_PE32_FILE_PATH, config_manager=self.config_manager)
        header_info = analyzer.parse_pe_header()
        self.assertIsNotNone(header_info)
        self.assertEqual(header_info['machine_string'], 'IMAGE_FILE_MACHINE_I386')
        self.assertEqual(header_info['number_of_sections'], 1)
        self.assertTrue(header_info['is_exe'])
        self.assertIn('IMAGE_FILE_EXECUTABLE_IMAGE', header_info['characteristics_flags'])
        self.assertIn('IMAGE_FILE_32BIT_MACHINE', header_info['characteristics_flags'])

        optional_header = header_info.get('optional_header')
        self.assertIsNotNone(optional_header)
        self.assertEqual(optional_header['magic_string'], 'PE32')
        self.assertEqual(optional_header['address_of_entry_point'], 0x1000) # Adjusted for new minimal PE
        self.assertEqual(optional_header['image_base_pe32'], 0x400000)
        self.assertEqual(optional_header['subsystem_string'], 'IMAGE_SUBSYSTEM_WINDOWS_GUI')

    def test_analyze_sections_valid(self):
        self.assertIsNotNone(self._minimal_valid_pe32_data_content, "Valid PE test data not loaded.")
        analyzer = PEAnalyzer(MINIMAL_VALID_PE32_FILE_PATH, config_manager=self.config_manager)
        sections = analyzer.analyze_sections()
        self.assertIsNotNone(sections)
        self.assertEqual(len(sections), 1)
        text_section = sections[0]
        self.assertEqual(text_section['name'], '.text')
        self.assertEqual(text_section['virtual_address'], 0x1000)
        self.assertEqual(text_section['virtual_size'], 0x10) # Size of NOPs
        self.assertEqual(text_section['size_of_raw_data'], 0x200) # FileAlignment multiple
        self.assertAlmostEqual(text_section['entropy'], 0.0, places=3) # NOPs have zero entropy
        self.assertIn('MEM_EXECUTE', text_section['characteristics_flags'])
        self.assertIn('MEM_READ', text_section['characteristics_flags'])


    def test_calculate_hashes_valid(self):
        self.assertIsNotNone(self._minimal_valid_pe32_data_content, "Valid PE test data not loaded.")
        analyzer = PEAnalyzer(MINIMAL_VALID_PE32_FILE_PATH, config_manager=self.config_manager)
        hashes = analyzer.calculate_hashes()
        self.assertIsNotNone(hashes)

        expected_md5 = hashlib.md5(self._minimal_valid_pe32_data_content).hexdigest()
        expected_sha1 = hashlib.sha1(self._minimal_valid_pe32_data_content).hexdigest()
        expected_sha256 = hashlib.sha256(self._minimal_valid_pe32_data_content).hexdigest()

        self.assertEqual(hashes.get('md5'), expected_md5)
        self.assertEqual(hashes.get('sha1'), expected_sha1)
        self.assertEqual(hashes.get('sha256'), expected_sha256)
        if 'sha512' in analyzer.enabled_hashes:
            expected_sha512 = hashlib.sha512(self._minimal_valid_pe32_data_content).hexdigest()
            self.assertEqual(hashes.get('sha512'), expected_sha512)


    def test_calculate_entropy_valid(self):
        self.assertIsNotNone(self._minimal_valid_pe32_data_content, "Valid PE test data not loaded.")
        analyzer = PEAnalyzer(MINIMAL_VALID_PE32_FILE_PATH, config_manager=self.config_manager)
        # Test entropy of the whole file
        file_entropy_result = analyzer.calculate_entropy()
        self.assertIsNotNone(file_entropy_result.get('entropy'))
        self.assertGreater(file_entropy_result['entropy'], 0.0)
        # Test entropy of a specific data segment
        data_segment = b"\x00\x01\x02\x03\x04\x05\x06\x07" * 32 # Some patterned data
        segment_entropy_result = analyzer.calculate_entropy(data=data_segment)
        self.assertIsNotNone(segment_entropy_result.get('entropy'))
        self.assertAlmostEqual(segment_entropy_result['entropy'], 3.0, places=6) # Perfect entropy for 8 unique bytes

    def test_list_imports_exports_valid_minimal(self):
        # Our MINIMAL_VALID_PE32_DATA doesn't have import/export tables by default.
        # To test this properly, we'd need a more complex PE or to add them to MINIMAL_VALID_PE32_DATA.
        # For now, test that it runs and returns empty dict/list.
        analyzer = PEAnalyzer(self.VALID_PE_FILE, config_manager=self.config_manager)
        results = analyzer.list_imports_exports()
        self.assertIsNotNone(results)
        self.assertEqual(results['imports'], {}) # Expect empty for the minimal PE
        self.assertEqual(results['exports'], []) # Expect empty

    # Placeholder for a test with a PE that has imports
    @unittest.skip("Requires a PE file with actual imports for thorough testing.")
    def test_list_imports_with_data(self):
        # Create or find a PE file that has known imports
        # analyzer = PEAnalyzer("path_to_pe_with_imports.exe", config_manager=self.config_manager)
        # results = analyzer.list_imports_exports()
        # self.assertTrue(len(results['imports']) > 0)
        # self.assertIn('kernel32.dll', results['imports']) # Example
        pass

    # Placeholder for a test with a PE that has exports
    @unittest.skip("Requires a PE file with actual exports for thorough testing.")
    def test_list_exports_with_data(self):
        # Create or find a PE file that has known exports
        # analyzer = PEAnalyzer("path_to_pe_with_exports.dll", config_manager=self.config_manager)
        # results = analyzer.list_imports_exports()
        # self.assertTrue(len(results['exports']) > 0)
        # self.assertEqual(results['exports'][0]['name'], "KnownExportedFunction") # Example
        pass

    def test_get_analysis_summary_valid(self):
        analyzer = PEAnalyzer(self.VALID_PE_FILE, config_manager=self.config_manager)
        summary = analyzer.get_analysis_summary()
        self.assertIsNotNone(summary)
        self.assertNotIn("error", summary)
        self.assertEqual(summary['file_path'], self.VALID_PE_FILE)
        self.assertTrue(summary['is_pe32'])
        self.assertIsNotNone(summary['hashes'].get('md5'))
        self.assertGreater(summary['overall_entropy'], 0)
        self.assertEqual(summary['header_info']['number_of_sections'], 1)
        self.assertEqual(len(summary['sections']), 1)
        self.assertEqual(summary['sections'][0]['name'], '.text')
        self.assertEqual(summary['imports_exports'], {'imports': {}, 'exports': []})

    def test_pe_file_with_no_optional_header(self):
        # This test checks how pefile handles a PE with SizeOfOptionalHeader = 0.
        # pefile itself might raise an error before our analyzer gets deep.
        try:
            analyzer = PEAnalyzer(self.NO_OPT_HEADER_PE_FILE, config_manager=self.config_manager)
            header_info = analyzer.parse_pe_header()
            # Depending on pefile's strictness, it might parse COFF but OptionalHeader would be mostly empty/None
            self.assertIsNotNone(header_info)
            self.assertNotIn('optional_header', header_info) # Or it's present but all values are default/None
        except pefile.PEFormatError as e:
            # This is an acceptable outcome if pefile deems it too malformed.
            self.assertIn("No OptionalHeader found", str(e), "PEfile should complain about missing OptionalHeader")
        except Exception as e:
            self.fail(f"Unexpected exception for PE with no optional header: {e}")


if __name__ == '__main__':
    unittest.main()
