import unittest
import os
import sys
import logging

# Add project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, PROJECT_ROOT)

try:
    from modules.static_analyzer.obfuscation_analyzer import ObfuscationAnalyzer
    from core_engine.configuration_manager import ConfigurationManager
except ImportError as e:
    print(f"Failed to import modules for testing in test_obfuscation_analyzer.py: {e}")
    if 'ObfuscationAnalyzer' not in globals(): from modules.static_analyzer.obfuscation_analyzer import ObfuscationAnalyzer
    if 'ConfigurationManager' not in globals(): ConfigurationManager = None


class TestObfuscationAnalyzer(unittest.TestCase):
    DUMMY_SETTINGS_FILE = os.path.join(os.path.dirname(__file__), "dummy_obfuscation_analyzer_settings.ini")

    @classmethod
    def setUpClass(cls):
        dummy_settings_content = """
[general]
log_level = DEBUG
[obfuscation_analyzer]
min_string_length = 4
string_score_threshold = 0.4 # Lower for tests to catch more
xor_keys = [0x41, 0x78] # Test specific keys
add_sub_keys = [0x05, 0x0A]
rol_ror_bits = [1, 3]
        """
        os.makedirs(os.path.dirname(cls.DUMMY_SETTINGS_FILE), exist_ok=True)
        with open(cls.DUMMY_SETTINGS_FILE, 'w') as f:
            f.write(dummy_settings_content)

        cls.config_manager = None
        if ConfigurationManager:
            try:
                cls.config_manager = ConfigurationManager(settings_path=cls.DUMMY_SETTINGS_FILE)
            except Exception as e:
                logging.warning(f"Could not init ConfigManager in tests: {e}")

        # Suppress logger output from the module itself during tests unless explicitly testing logging
        # logging.getLogger('modules.static_analyzer.obfuscation_analyzer').setLevel(logging.CRITICAL)


    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.DUMMY_SETTINGS_FILE):
            os.remove(cls.DUMMY_SETTINGS_FILE)

    def setUp(self):
        # Initialize analyzer for each test to ensure fresh state and config
        self.analyzer = ObfuscationAnalyzer(config_manager=self.config_manager)

    # --- String Decoding Tests ---
    def test_extract_plain_strings(self):
        data = b"ASCII_string\x00\x00Unicode\x00S\x00t\x00r\x00i\x00n\x00g\x00\x00\x00AnotherASCII"
        expected_ascii = (0, "ASCII_string", "ascii")
        expected_unicode = (16, "UnicodeString", "utf-16le") # Offset 14 + 2 for null bytes
        expected_ascii2 = (36, "AnotherASCII", "ascii")

        strings = self.analyzer.extract_plain_strings(data, min_length=5)

        self.assertIn(expected_ascii, strings)
        self.assertIn(expected_unicode, strings)
        self.assertIn(expected_ascii2, strings)

        # Test min_length
        short_strings = self.analyzer.extract_plain_strings(b"abc\x00defg\x00h\x00i\x00j\x00k\x00", min_length=4)
        self.assertTrue(any(s[1] == "defg" for s in short_strings))
        self.assertTrue(any(s[1] == "hijk" for s in short_strings))
        self.assertFalse(any(s[1] == "abc" for s in short_strings))


    def test_decode_xor_string(self):
        original_str = "XORedText"
        xor_key = 0x41 # From dummy_settings
        data = bytes([ord(c) ^ xor_key for c in original_str])

        decoded_results = self.analyzer.attempt_decode_buffer(data)
        self.assertTrue(any(res['decoded'] == original_str and res['encoding'] == f'XOR-{xor_key}' for res in decoded_results),
                        f"Expected '{original_str}' not found in {decoded_results}")

    def test_decode_add_sub_string(self):
        original_str = "AddSubText"
        add_key = 0x05 # From dummy_settings
        data_add = bytes([(ord(c) + add_key) & 0xFF for c in original_str])
        data_sub = bytes([(ord(c) - add_key) & 0xFF for c in original_str])

        decoded_add = self.analyzer.attempt_decode_buffer(data_add)
        self.assertTrue(any(res['decoded'] == original_str and res['encoding'] == f'SUB-{add_key}' for res in decoded_add),
                        f"ADD Test: Expected '{original_str}' not found in {decoded_add}")

        decoded_sub = self.analyzer.attempt_decode_buffer(data_sub)
        self.assertTrue(any(res['decoded'] == original_str and res['encoding'] == f'ADD-{add_key}' for res in decoded_sub),
                        f"SUB Test: Expected '{original_str}' not found in {decoded_sub}")

    def test_decode_rol_ror_string(self):
        original_str = "RotateText" # Must be careful with chars for ROL/ROR
        rol_key = 3 # From dummy_settings

        # ROL: (b << key) | (b >> (8 - key))) & 0xFF
        data_rol = bytes([((ord(c) << rol_key) | (ord(c) >> (8 - rol_key))) & 0xFF for c in original_str])
        # ROR: (b >> key) | (b << (8 - key))) & 0xFF
        data_ror = bytes([((ord(c) >> rol_key) | (ord(c) << (8 - rol_key))) & 0xFF for c in original_str])

        decoded_rol = self.analyzer.attempt_decode_buffer(data_rol)
        self.assertTrue(any(res['decoded'] == original_str and res['encoding'] == f'ROR-{rol_key}' for res in decoded_rol),
                        f"ROL Test: Expected '{original_str}' not found in {decoded_rol}")

        decoded_ror = self.analyzer.attempt_decode_buffer(data_ror)
        self.assertTrue(any(res['decoded'] == original_str and res['encoding'] == f'ROL-{rol_key}' for res in decoded_ror),
                        f"ROR Test: Expected '{original_str}' not found in {decoded_ror}")

    def test_string_scoring(self):
        # Test the _score_decoded_string method
        self.assertGreater(self.analyzer._score_decoded_string("LoadLibraryA"), 0.5)
        self.assertGreater(self.analyzer._score_decoded_string("C:\\Windows\\System32"), 0.3) # Paths also useful
        self.assertLess(self.analyzer._score_decoded_string("!@#$%^&*"), 0.1)
        self.assertEqual(self.analyzer._score_decoded_string("abc"), 0.0) # Too short

    # --- API Sequence Detection Tests ---
    def test_detect_api_sequences_positive(self):
        trace = ["SomeApi", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CloseHandle"]
        sequences = self.analyzer.detect_api_sequences(trace)
        self.assertEqual(len(sequences), 1)
        self.assertEqual(sequences[0]['category'], "process_injection")
        self.assertEqual(sequences[0]['sequence'], ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"])

    def test_detect_api_sequences_negative(self):
        trace = ["OpenProcess", "VirtualAllocEx", "SomeOtherApi", "CreateRemoteThread"] # Sequence broken
        sequences = self.analyzer.detect_api_sequences(trace)
        self.assertEqual(len(sequences), 0)

    def test_detect_api_sequences_multiple(self):
        trace = ["socket", "connect", "send", "recv", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]
        sequences = self.analyzer.detect_api_sequences(trace)
        self.assertEqual(len(sequences), 2)
        categories = {s['category'] for s in sequences}
        self.assertIn("c2_communication", categories)
        self.assertIn("process_injection", categories)

    # --- API Hash Detection Tests (Simplified) ---
    def test_detect_api_hashing_positive(self):
        # Data: ROR13_VAL pattern + some bytes + known hash for LoadLibraryA (DJB2-like)
        # Data: Includes a ROR13 pattern, a CMP EAX, imm32 opcode, and a known hash.
        ror13_pattern = self.analyzer.api_hash_detection_patterns.get("ror13_const", [b"\x0d"])[0] # Use default if not in custom
        cmp_eax_imm32_opcode = b"\x3D"
        loadlib_hash_djb2 = 0xec0e4e8e # Example: DJB2 for "LoadLibraryA"

        data = (
            b"prefix_data" +
            ror13_pattern +       # Algorithm hint pattern
            b"middle_data" +
            cmp_eax_imm32_opcode + # Instruction preceding the hash
            loadlib_hash_djb2.to_bytes(4, 'little') +
            b"suffix_data"
        )

        results = self.analyzer.detect_api_hashing(data)

        # Check if algorithm was detected (based on ror13_pattern)
        self.assertTrue(any(algo['algorithm'] == "custom_ror13_variant" for algo in results['algorithms']),
                        f"Expected 'custom_ror13_variant' not detected. Got: {results['algorithms']}")

        # Check if LoadLibraryA hash was found and resolved
        resolved_api_found = False
        for resolved in results['resolved_apis']:
            if resolved['hash_value'] == loadlib_hash_djb2:
                self.assertIn(cmp_eax_imm32_opcode.hex(), resolved.get("context_instruction_bytes",""))
                if any("LoadLibraryA" in name for name in resolved['resolved_names']):
                    resolved_api_found = True
                    break
        self.assertTrue(resolved_api_found,
                        f"LoadLibraryA hash (0x{loadlib_hash_djb2:x}) not found or not resolved correctly. Resolved: {results['resolved_apis']}")

    def test_detect_api_hashing_negative_no_pattern(self):
        # Data: Contains a CMP instruction and a hash, but no algorithm hint patterns.
        cmp_eax_imm32_opcode = b"\x3D"
        some_hash_value = (0x12345678).to_bytes(4, 'little')
        data = cmp_eax_imm32_opcode + some_hash_value

        results = self.analyzer.detect_api_hashing(data)
        # No patterns means no algorithm detected by current simplified logic
        self.assertEqual(len(results['algorithms']), 0)
        self.assertEqual(len(results['resolved_apis']), 0)

    def test_detect_api_hashing_negative_unknown_hash(self):
        ror13_pattern = self.analyzer.api_hash_detection_patterns["ror13_val"][0]
        unknown_hash = 0x12345678
        data = ror13_pattern + unknown_hash.to_bytes(4, 'little')

        results = self.analyzer.detect_api_hashing(data)
        self.assertGreater(len(results['algorithms']), 0) # Algorithm should be detected

        # Check if the unknown_hash is in resolved_apis but with empty resolved_names
        unknown_hash_present_but_unresolved = False
        for resolved in results['resolved_apis']:
            if resolved['hash_value'] == unknown_hash:
                if not resolved['resolved_names']: # Should be empty
                    unknown_hash_present_but_unresolved = True
                break
        # Depending on how strictly we define "resolved_apis", it might only include those with matches.
        # For this test, we check that if it *is* listed, it has no names.
        # Or, more simply, that no known API matches this unknown hash.
        self.assertFalse(any(res['hash_value'] == unknown_hash and res['resolved_names'] for res in results['resolved_apis']))


    # --- Full Analysis Test ---
    def test_analyze_obfuscation_comprehensive(self):
        original_str = "CreateFileA" # Part of default API sequences and scorable
        xor_key = 0x78 # From dummy_settings
        data_xor = bytes([ord(c) ^ xor_key for c in original_str])

        api_trace = ["InternetOpenA", "InternetConnectA", "HttpOpenRequestA", "HttpSendRequestA", "SomeOtherCall"]

        results = self.analyzer.analyze_obfuscation(data_xor, api_call_trace=api_trace, offset_in_file=0x1000)

        self.assertGreater(len(results['decoded_strings']), 0)
        self.assertTrue(any(s['decoded'] == original_str for s in results['decoded_strings']))

        self.assertGreater(len(results['api_sequences']), 0)
        self.assertEqual(results['api_sequences'][0]['sequence'][0], "InternetOpenA")

        # Hashing part is very basic, won't assert much unless more complex data is crafted
        self.assertIsNotNone(results['api_hashing'])


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    unittest.main()
