import unittest
import os
import sys
import logging

# Add project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, PROJECT_ROOT)
sys.path.append(os.path.join(PROJECT_ROOT, 'core_engine'))
sys.path.append(os.path.join(PROJECT_ROOT, 'modules', 'extraction_analyzer'))


try:
    from crypto_analyzer import CryptoAnalyzer
    # Mock ConfigurationManager for these tests, as the real one depends on settings files
    # and we want to isolate CryptoAnalyzer logic.
    class MockConfigurationManager:
        def __init__(self, settings_dict=None):
            self.settings = settings_dict if settings_dict is not None else {}

        def get(self, section, option, fallback=None):
            return self.settings.get(section, {}).get(option, fallback)

        def getboolean(self, section, option, fallback=None):
            val = self.settings.get(section, {}).get(option, fallback)
            if isinstance(val, bool): return val
            return str(val).lower() in ('true', 'yes', 'on', '1')

        def getint(self, section, option, fallback=None):
            val = self.settings.get(section, {}).get(option, fallback)
            try: return int(val)
            except (ValueError, TypeError): return fallback

        def get_section(self, section_name):
            return self.settings.get(section_name, None)

except ImportError as e:
    print(f"Critical Error: Failed to import modules for crypto testing: {e}", file=sys.stderr)
    CryptoAnalyzer = None
    MockConfigurationManager = None


@unittest.skipIf(CryptoAnalyzer is None, "CryptoAnalyzer class not imported.")
class TestCryptoAnalyzer(unittest.TestCase):

    def setUp(self):
        # Basic config for tests, can be overridden by specific tests
        self.mock_cm = MockConfigurationManager({
            "general": {"log_level": "DEBUG"},
            "crypto_analyzer_keys": {},
            "decryption_chains": {}
        })
        self.analyzer = CryptoAnalyzer(config_manager=self.mock_cm)
        # Suppress logging from the module unless specifically testing logging aspects
        logging.getLogger('modules.extraction_analyzer.crypto_analyzer').setLevel(logging.CRITICAL)


    # --- RC4 Tests ---
    def test_rc4_known_vector_1(self):
        # Test vector from Wikipedia: Key: "Key", Plaintext: "Plaintext"
        key = b"Key"
        plaintext = b"Plaintext"
        ciphertext_expected_hex = "BBF316E8D940AF0AD3" # Expected ciphertext
        ciphertext_expected = bytes.fromhex(ciphertext_expected_hex)

        encrypted = self.analyzer._rc4_decrypt(plaintext, key) # RC4 is symmetric
        self.assertEqual(encrypted, ciphertext_expected, "RC4 encryption failed for vector 1.")

        decrypted = self.analyzer._rc4_decrypt(ciphertext_expected, key)
        self.assertEqual(decrypted, plaintext, "RC4 decryption failed for vector 1.")

    def test_rc4_known_vector_2(self):
        # Test vector from Wikipedia: Key: "Wiki", Plaintext: "pedia"
        key = b"Wiki"
        plaintext = b"pedia"
        ciphertext_expected_hex = "1021BF0420"
        ciphertext_expected = bytes.fromhex(ciphertext_expected_hex)

        encrypted = self.analyzer._rc4_decrypt(plaintext, key)
        self.assertEqual(encrypted, ciphertext_expected, "RC4 encryption failed for vector 2.")

        decrypted = self.analyzer._rc4_decrypt(ciphertext_expected, key)
        self.assertEqual(decrypted, plaintext, "RC4 decryption failed for vector 2.")

    def test_rc4_known_vector_3(self):
        # Test vector from Wikipedia: Key: "Secret", Plaintext: "Attack at dawn"
        key = b"Secret"
        plaintext = b"Attack at dawn"
        ciphertext_expected_hex = "45A01F645FC35B383552544B9BF5"
        ciphertext_expected = bytes.fromhex(ciphertext_expected_hex)

        encrypted = self.analyzer._rc4_decrypt(plaintext, key)
        self.assertEqual(encrypted, ciphertext_expected, "RC4 encryption failed for vector 3.")

        decrypted = self.analyzer._rc4_decrypt(ciphertext_expected, key)
        self.assertEqual(decrypted, plaintext, "RC4 decryption failed for vector 3.")

    # --- XOR Tests ---
    def test_xor_single_byte_key_int(self):
        plaintext = b"Hello"
        key = 0xAA
        expected_ciphertext = bytes([ord('H') ^ 0xAA, ord('e') ^ 0xAA, ord('l') ^ 0xAA, ord('l') ^ 0xAA, ord('o') ^ 0xAA])

        encrypted = self.analyzer._xor_decrypt(plaintext, key)
        self.assertEqual(encrypted, expected_ciphertext)
        decrypted = self.analyzer._xor_decrypt(encrypted, key)
        self.assertEqual(decrypted, plaintext)

    def test_xor_multi_byte_key_bytes(self):
        plaintext = b"This is a longer test for XOR."
        key = b"\x01\x02\x03\x04\x05"

        encrypted_manual = bytearray()
        for i in range(len(plaintext)):
            encrypted_manual.append(plaintext[i] ^ key[i % len(key)])

        encrypted = self.analyzer._xor_decrypt(plaintext, key)
        self.assertEqual(encrypted, bytes(encrypted_manual))
        decrypted = self.analyzer._xor_decrypt(encrypted, key)
        self.assertEqual(decrypted, plaintext)

    def test_xor_empty_key(self):
        plaintext = b"TestWithEmptyKey"
        # XORing with empty key should ideally return original data or raise error.
        # Current implementation returns original data with a warning.
        self.assertEqual(self.analyzer._xor_decrypt(plaintext, b""), plaintext)


    # --- Layered Decryption Tests (`decrypt` method) ---
    def test_layered_xor_rc4(self):
        original = b"LayeredDecryptionTest"
        xor_k = 0xBC
        rc4_k = b"LayerKey"

        steps = [
            {"type": "xor", "key_type": "int", "value_raw": hex(xor_k)}, # hex() for "0x..." format
            {"type": "rc4", "key_type": "bytes_literal", "key_bytes": rc4_k}
        ]

        # Encrypt manually for verification data
        temp_xor = self.analyzer._xor_decrypt(original, xor_k)
        encrypted = self.analyzer._rc4_decrypt(temp_xor, rc4_k)

        decrypted = self.analyzer.decrypt(encrypted, steps)
        self.assertEqual(decrypted, original)

    def test_layered_rc4_xor_hexkey(self):
        original = b"AnotherLayerTest"
        rc4_k = b"SecretRC4"
        xor_k_hex = "aabbccddeeff"
        xor_k_bytes = bytes.fromhex(xor_k_hex)

        steps = [
            {"type": "rc4", "key_type": "bytes_literal", "key_bytes": rc4_k},
            {"type": "xor", "key_type": "hex", "value_raw": xor_k_hex}
        ]

        temp_rc4 = self.analyzer._rc4_decrypt(original, rc4_k)
        encrypted = self.analyzer._xor_decrypt(temp_rc4, xor_k_bytes)

        decrypted = self.analyzer.decrypt(encrypted, steps)
        self.assertEqual(decrypted, original)

    # --- Configuration and Key Management Tests ---
    def test_load_known_keys_from_config(self):
        config_data = {
            "general": {"log_level": "DEBUG"},
            "crypto_analyzer_keys": {
                "mykey1_hex": "hex:616263", # abc
                "mykey2_utf8": "utf8:secret",
                "mykey3_int": "int:65", # 'A'
                "mykey4_raw": "raw_string_key" # Default to utf8
            }
        }
        analyzer = CryptoAnalyzer(config_manager=MockConfigurationManager(config_data))
        self.assertEqual(analyzer.known_keys["mykey1_hex"], b"abc")
        self.assertEqual(analyzer.known_keys["mykey2_utf8"], b"secret")
        self.assertEqual(analyzer.known_keys["mykey3_int"], b"A") # Parsed as int 65, then used as such for _xor_decrypt
        self.assertEqual(analyzer.known_keys["mykey4_raw"], b"raw_string_key")


    def test_parse_and_use_decryption_chain(self):
        config_data = {
            "general": {"log_level": "DEBUG"},
            "crypto_analyzer_keys": {
                "chain_rc4_key": "utf8:ChainKey",
                "chain_xor_key_hex": "hex:1A2B"
            },
            "decryption_chains": {
                "test_chain_1": "rc4_known:chain_rc4_key, xor_known:chain_xor_key_hex"
            }
        }
        analyzer = CryptoAnalyzer(config_manager=MockConfigurationManager(config_data))
        self.assertIn("test_chain_1", analyzer.decryption_chains)

        original = b"TestingTheChain"
        rc4_k = b"ChainKey"
        xor_k = bytes.fromhex("1A2B")

        # Manually encrypt
        temp_rc4 = analyzer._rc4_decrypt(original, rc4_k)
        encrypted = analyzer._xor_decrypt(temp_rc4, xor_k)

        # Decrypt using the chain
        chain_results = analyzer.try_known_decryption_chains(encrypted)
        self.assertIn("test_chain_1", chain_results)
        self.assertEqual(chain_results["test_chain_1"], original)

    def test_invalid_key_type_in_chain_parsing(self):
        config_data = {
            "decryption_chains": {"bad_chain": "unknown_op:key"}}
        # Expect error log during init, chain might be skipped or empty
        analyzer = CryptoAnalyzer(config_manager=MockConfigurationManager(config_data))
        self.assertNotIn("bad_chain", analyzer.decryption_chains,
                         "Chain with unknown op type should not be added or should be empty/invalid.")

    def test_invalid_key_alias_in_chain_execution(self):
        config_data = {
            "decryption_chains": {"bad_key_alias_chain": "xor_known:non_existent_key"}}
        analyzer = CryptoAnalyzer(config_manager=MockConfigurationManager(config_data))
        with self.assertRaises(ValueError, msg="Should raise error for unknown key alias during execution."):
            analyzer.decrypt(b"data", analyzer.decryption_chains["bad_key_alias_chain"])

    # --- Error Handling Tests ---
    def test_decrypt_unsupported_type(self):
        steps = [{"type": "unknown_algo", "key_type": "hex", "value_raw": "aa"}]
        with self.assertRaises(ValueError):
            self.analyzer.decrypt(b"testdata", steps)

    def test_xor_invalid_key_type(self):
        with self.assertRaises(TypeError):
            self.analyzer._xor_decrypt(b"testdata", ["list", "isnot", "bytes", "or", "int"])

    def test_rc4_key_must_be_bytes(self):
        # _resolve_key_for_step should handle int for XOR, but RC4 needs bytes
        # Test what happens if an int key somehow gets to _rc4_decrypt
        # (e.g. if _resolve_key_for_step allowed it for RC4)
        with self.assertRaises(TypeError): # RC4 manual implementation expects key[i % len(key)]
            self.analyzer._rc4_decrypt(b"testdata", 123)


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.INFO) # See logs during test
    unittest.main()
