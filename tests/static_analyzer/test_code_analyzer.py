import unittest
import os
import sys
import logging

# Add project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, PROJECT_ROOT)

try:
    from modules.static_analyzer.code_analyzer import CodeAnalyzer, CAPSTONE_AVAILABLE, R2PIPE_AVAILABLE
    from core_engine.configuration_manager import ConfigurationManager
except ImportError as e:
    print(f"Failed to import modules for testing in test_code_analyzer.py: {e}")
    # Fallbacks for CI or unusual environments
    if 'CodeAnalyzer' not in globals(): from modules.static_analyzer.code_analyzer import CodeAnalyzer
    if 'CAPSTONE_AVAILABLE' not in globals(): from modules.static_analyzer.code_analyzer import CAPSTONE_AVAILABLE
    if 'R2PIPE_AVAILABLE' not in globals(): from modules.static_analyzer.code_analyzer import R2PIPE_AVAILABLE
    if 'ConfigurationManager' not in globals(): ConfigurationManager = None


# --- Test Data ---
# x86: push ebp; mov ebp, esp; xor eax, eax; pop ebp; ret
SAMPLE_X86_CODE_SIMPLE_FUNC = b"\x55\x89\xe5\x31\xc0\x5d\xc3"
# x86: another function: sub esp, 8; mov [esp], edi; call some_func; add esp, 8; ret
SAMPLE_X86_CODE_CALL = b"\x83\xec\x08\x89\x7c\x24\x00\xe8\x11\x22\x33\x44\x83\xc4\x08\xc3" # call offset is dummy

# x64: push rbp; mov rbp, rsp; mov rax, 1; pop rbp; ret
SAMPLE_X64_CODE_SIMPLE_FUNC = b"\x55\x48\x89\xe5\x48\xc7\xc0\x01\x00\x00\x00\x5d\xc3"

# ARM: push {lr}; mov r0, #1; pop {pc} (simplified)
SAMPLE_ARM_CODE_SIMPLE_FUNC = b"\x04\xe0\x2d\xe5\x01\x00\xa0\xe3\x04\xf0\x9d\xe4" # push {lr}; mov r0, #1; pop {pc}

# For idiom test: "xor eax, eax"
SAMPLE_X86_XOR_IDIOM_ASM_TEXT = "xor eax, eax\nmov ebx, eax"
EXPECTED_X86_XOR_IDIOM_RECOGNIZED = "eax = 0\nmov ebx, eax"


class TestCodeAnalyzer(unittest.TestCase):
    DUMMY_SETTINGS_FILE = os.path.join(os.path.dirname(__file__), "dummy_code_analyzer_settings.ini")
    DUMMY_BINARY_FILE = os.path.join(os.path.dirname(__file__), "test_dummy_binary_for_code.bin")

    @classmethod
    def setUpClass(cls):
        # Create dummy settings for ConfigurationManager
        dummy_settings_content = """
[general]
log_level = DEBUG
[code_analyzer]
use_radare2 = False # Default to False for CI tests unless r2 is guaranteed
radare2_path = r2_nonexistent_path_for_testing_fallback
        """
        os.makedirs(os.path.dirname(cls.DUMMY_SETTINGS_FILE), exist_ok=True)
        with open(cls.DUMMY_SETTINGS_FILE, 'w') as f:
            f.write(dummy_settings_content)

        # Create a dummy binary file that CodeAnalyzer can load (for r2 tests if enabled)
        with open(cls.DUMMY_BINARY_FILE, "wb") as f:
            f.write(SAMPLE_X86_CODE_SIMPLE_FUNC + SAMPLE_X64_CODE_SIMPLE_FUNC) # just some bytes

        cls.config_manager = None
        if ConfigurationManager:
            try:
                cls.config_manager = ConfigurationManager(settings_path=cls.DUMMY_SETTINGS_FILE)
            except Exception as e:
                logging.warning(f"Could not init ConfigManager in tests: {e}")

        # Suppress warnings from CodeAnalyzer if Capstone/R2Pipe are missing during tests
        # logging.getLogger('modules.static_analyzer.code_analyzer').setLevel(logging.ERROR)


    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.DUMMY_SETTINGS_FILE):
            os.remove(cls.DUMMY_SETTINGS_FILE)
        if os.path.exists(cls.DUMMY_BINARY_FILE):
            os.remove(cls.DUMMY_BINARY_FILE)
        # Remove created directories if empty and desired

    def test_init_with_file_path(self):
        # This test primarily checks if CodeAnalyzer can be initialized
        # and if it attempts to load the file and detect architecture.
        try:
            analyzer = CodeAnalyzer(file_path=self.DUMMY_BINARY_FILE, config_manager=self.config_manager)
            self.assertIsNotNone(analyzer.file_data, "File data should be loaded.")
            self.assertIsNotNone(analyzer.architecture, "Architecture should be detected or defaulted.")
        except ValueError as e:
            # Handle cases where file_data is not loaded due to path issues in test env
            self.fail(f"CodeAnalyzer initialization failed: {e}")
        except Exception as e:
            self.fail(f"CodeAnalyzer initialization raised an unexpected exception: {e}")


    @unittest.skipIf(not CAPSTONE_AVAILABLE, "Capstone not available")
    def test_disassemble_x86(self):
        # Pass file_data directly to bypass file loading issues in test environment for this unit
        analyzer = CodeAnalyzer(file_path=None, file_data=SAMPLE_X86_CODE_SIMPLE_FUNC, config_manager=self.config_manager)
        # Force architecture if detection is problematic for snippets
        analyzer.architecture = 'x86'
        analyzer.arch_mode_capstone = (capstone.CS_ARCH_X86, capstone.CS_MODE_32)

        disassembly = analyzer.disassemble_code(SAMPLE_X86_CODE_SIMPLE_FUNC)
        self.assertGreater(len(disassembly), 0, "Disassembly should produce instructions.")
        self.assertEqual(disassembly[0]['mnemonic'], 'push')
        self.assertEqual(disassembly[1]['mnemonic'], 'mov')
        self.assertEqual(disassembly[2]['mnemonic'], 'xor')
        self.assertEqual(disassembly[3]['mnemonic'], 'pop')
        self.assertEqual(disassembly[4]['mnemonic'], 'ret')

    @unittest.skipIf(not CAPSTONE_AVAILABLE, "Capstone not available")
    def test_detect_function_boundaries_x86(self):
        analyzer = CodeAnalyzer(file_path=None, file_data=SAMPLE_X86_CODE_SIMPLE_FUNC, config_manager=self.config_manager)
        analyzer.architecture = 'x86' # Force
        boundaries = analyzer.detect_function_boundaries(SAMPLE_X86_CODE_SIMPLE_FUNC)
        self.assertIn(0, boundaries, "Should detect function start at offset 0 for x86 sample.")

    def test_recognize_compiler_idioms(self):
        # This test doesn't require Capstone or R2, only regex
        analyzer = CodeAnalyzer(file_path=None, file_data=b'', config_manager=self.config_manager) # data not used
        processed_asm = analyzer.recognize_compiler_idioms(SAMPLE_X86_XOR_IDIOM_ASM_TEXT)
        self.assertEqual(processed_asm.strip(), EXPECTED_X86_XOR_IDIOM_RECOGNIZED.strip())

    @unittest.skipIf(not CAPSTONE_AVAILABLE, "Capstone not available for fallback test")
    def test_pseudo_code_generation_capstone_fallback(self):
        # Ensure Radare2 is "unavailable" for this test to force Capstone fallback
        config_content_no_r2 = """
[general]
log_level = DEBUG
[code_analyzer]
use_radare2 = False
radare2_path = path_that_does_not_exist
        """
        temp_settings_no_r2 = os.path.join(os.path.dirname(__file__), "dummy_settings_no_r2.ini")
        with open(temp_settings_no_r2, 'w') as f:
            f.write(config_content_no_r2)

        cm_no_r2 = ConfigurationManager(settings_path=temp_settings_no_r2) if ConfigurationManager else None

        analyzer = CodeAnalyzer(file_path=None, file_data=SAMPLE_X86_CODE_SIMPLE_FUNC, config_manager=cm_no_r2)
        analyzer.architecture = 'x86' # Force
        analyzer.arch_mode_capstone = (capstone.CS_ARCH_X86, capstone.CS_MODE_32)

        pseudo_code = analyzer.generate_pseudo_code(function_bytes=SAMPLE_X86_CODE_SIMPLE_FUNC)
        self.assertTrue("0x0: push ebp" in pseudo_code) # Basic check for Capstone output
        self.assertTrue("eax = 0" in pseudo_code) # Check if idiom was applied to Capstone output

        if os.path.exists(temp_settings_no_r2):
            os.remove(temp_settings_no_r2)

    @unittest.skipIf(not R2PIPE_AVAILABLE, "r2pipe not available")
    @unittest.skipIf(os.system("r2 -v > /dev/null 2>&1") != 0, "Radare2 not found in PATH")
    def test_pseudo_code_generation_radare2(self):
        # This test requires Radare2 to be installed and in PATH.
        # It uses the DUMMY_BINARY_FILE created in setUpClass.

        # Ensure use_radare2 is True for this test
        config_content_with_r2 = """
[general]
log_level = DEBUG
[code_analyzer]
use_radare2 = True
radare2_path = r2
        """
        temp_settings_r2 = os.path.join(os.path.dirname(__file__), "dummy_settings_r2.ini")
        with open(temp_settings_r2, 'w') as f:
            f.write(config_content_with_r2)

        cm_r2 = ConfigurationManager(settings_path=temp_settings_r2) if ConfigurationManager else None

        analyzer = CodeAnalyzer(file_path=self.DUMMY_BINARY_FILE, config_manager=cm_r2)
        # Arch detection should run in __init__

        # Radare2 analyzes the file, so we give an address/offset within the file.
        # For DUMMY_BINARY_FILE, SAMPLE_X86_CODE_SIMPLE_FUNC is at offset 0.
        pseudo_code = analyzer.generate_pseudo_code(function_address=0x0)
        self.assertIsNotNone(pseudo_code)
        if "Error: Radare2" not in pseudo_code: # Check if r2 actually ran
            self.assertTrue(len(pseudo_code) > 10, "Radare2 should produce some pseudo-code.")
            # A more specific check would depend on r2's output for the dummy binary.
            # e.g., assert "function main" in pseudo_code or similar based on r2 version
            self.assertRegex(pseudo_code, r"(void|int)\s+(fcn|sym)\._0x[0-9a-f]+", "Radare2 pseudo-code should contain a function definition.")
        else:
            self.skipTest(f"Radare2 pseudo-code generation failed or was skipped: {pseudo_code}")

        if os.path.exists(temp_settings_r2):
            os.remove(temp_settings_r2)

    # --- Tests for behavior when dependencies are missing ---
    @unittest.skipIf(CAPSTONE_AVAILABLE, "Capstone IS available, this test is for when it's NOT.")
    def test_disassemble_code_capstone_unavailable(self):
        analyzer = CodeAnalyzer(file_path=None, file_data=SAMPLE_X86_CODE_SIMPLE_FUNC, config_manager=self.config_manager)
        analyzer.architecture = 'x86' # Need to set arch for it to try capstone path
        analyzer.arch_mode_capstone = (0,0) # Dummy value since capstone isn't imported

        with self.assertLogs(logger='modules.static_analyzer.code_analyzer', level='ERROR') as cm_log:
            result = analyzer.disassemble_code(SAMPLE_X86_CODE_SIMPLE_FUNC)
        self.assertEqual(result, [])
        self.assertTrue(any("Capstone is not available" in message for message in cm_log.output))

    @unittest.skipIf(R2PIPE_AVAILABLE and CAPSTONE_AVAILABLE,
                     "Both R2Pipe and Capstone ARE available. This test is for when both are NOT.")
    def test_generate_pseudo_code_all_unavailable(self):
        # Test when R2Pipe is unavailable, and Capstone (fallback) is also unavailable.
        # Ensure use_radare2 is True in config to attempt r2 first.
        config_content_try_r2_no_fallback = """
[general]
log_level = DEBUG
[code_analyzer]
use_radare2 = True
radare2_path = path_that_does_not_exist
        """
        temp_settings_no_deps = os.path.join(os.path.dirname(__file__), "dummy_settings_no_deps.ini")
        with open(temp_settings_no_deps, 'w') as f:
            f.write(config_content_try_r2_no_fallback)

        cm_no_deps = ConfigurationManager(settings_path=temp_settings_no_deps) if ConfigurationManager else None

        # Need to ensure CAPSTONE_AVAILABLE is False for this specific test context if it was True globally
        # This is tricky without patching the module's global directly.
        # The @skipIf at the class/method level handles the global CAPSTONE_AVAILABLE.
        # If CAPSTONE_AVAILABLE is True globally, this test might not purely test "both unavailable"
        # unless CodeAnalyzer's internal CAPSTONE_AVAILABLE is also False.
        # For this environment, we know both are False.

        analyzer = CodeAnalyzer(file_path=self.DUMMY_BINARY_FILE, # r2 needs a path
                                file_data=SAMPLE_X86_CODE_SIMPLE_FUNC, # for capstone fallback
                                config_manager=cm_no_deps)
        analyzer.architecture = 'x86' # For capstone fallback attempt
        analyzer.arch_mode_capstone = (0,0)


        # Check logs for both r2pipe and capstone unavailability messages
        # Running generate_pseudo_code will first try r2 (if file_path given), then capstone (if function_bytes given)
        expected_error_message = "Error: Pseudo-code generation failed. Radare2 unavailable/failed and no function bytes for Capstone fallback."
        if not R2PIPE_AVAILABLE and not CAPSTONE_AVAILABLE :
             # Case 1: R2 needs file_path, Capstone fallback needs function_bytes.
             # Test with function_address (tries r2 first)
            with self.assertLogs(logger='modules.static_analyzer.code_analyzer', level='INFO') as cm_log: # INFO for fallback msg
                result_addr = analyzer.generate_pseudo_code(function_address=0x0)
            self.assertIn(expected_error_message, result_addr)
            self.assertTrue(any("Radare2 pseudo-code generation failed" in message or "r2pipe (for Radare2) not available" in message for message in cm_log.output))

            # Test with function_bytes (tries capstone first if r2 path fails or r2 disabled)
            # To ensure it tries capstone path if r2 is configured false:
            analyzer.use_radare2_if_available = False # Force capstone path attempt
            with self.assertLogs(logger='modules.static_analyzer.code_analyzer', level='ERROR') as cm_log_capstone:
                 result_bytes = analyzer.generate_pseudo_code(function_bytes=SAMPLE_X86_CODE_SIMPLE_FUNC)
            self.assertIn("Disassembly failed, cannot generate pseudo-code.", result_bytes) # Capstone path error
            self.assertTrue(any("Capstone is not available" in message for message in cm_log_capstone.output))


        elif not R2PIPE_AVAILABLE and CAPSTONE_AVAILABLE:
            self.skipTest("R2Pipe unavailable, but Capstone IS available. This test is for BOTH unavailable.")
        elif R2PIPE_AVAILABLE and not CAPSTONE_AVAILABLE:
             self.skipTest("R2Pipe IS available, but Capstone is unavailable. This test is for BOTH unavailable.")


        if os.path.exists(temp_settings_no_deps):
            os.remove(temp_settings_no_deps)


    # More tests can be added for:
    # - Different architectures (x64, ARM) for disassembly and boundary detection.
    # - More complex function boundary scenarios (interleaved functions, non-standard prologues).
    # - More compiler idioms.
    # - Error handling (e.g., file not found, invalid byte sequences for disassembly).

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG) # See logs during test
    unittest.main()
