import unittest
import os
import sys
import zipfile
import io
import logging

# Add project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, PROJECT_ROOT)
sys.path.append(os.path.join(PROJECT_ROOT, 'core_engine'))
sys.path.append(os.path.join(PROJECT_ROOT, 'modules', 'extraction_analyzer'))

try:
    from polyglot_analyzer import PolyglotAnalyzer
    from core_engine.configuration_manager import MockConfigurationManager # Use mock from crypto tests
except ImportError as e:
    print(f"Critical Error: Failed to import modules for polyglot testing: {e}", file=sys.stderr)
    PolyglotAnalyzer = None
    MockConfigurationManager = None # Ensure it's defined for skipIf

# Test data (minimal valid structures)
# PE file signatures
TEST_PE_SIGNATURE_MZ = b'MZ'
TEST_PE_SIGNATURE_PE = b'PE\0\0'
# Minimal PE structure (enough for MZ and PE signature checks)
# Corrected e_lfanew to point to 'PE\0\0' (0x40 bytes after MZ start)
TEST_DUMMY_PE_PAYLOAD = (
    TEST_PE_SIGNATURE_MZ +
    (b'\x00' * (0x3C - len(TEST_PE_SIGNATURE_MZ))) +  # Padding up to e_lfanew
    b'\x40\x00\x00\x00' +  # e_lfanew pointing to 0x40
    (b'\x00' * (0x40 - 0x3C - 4)) + # Padding between e_lfanew and PE_SIGNATURE_OFFSET
    TEST_PE_SIGNATURE_PE +
    b'\x4c\x01' + # Machine: I386
    (b'\x00' * 100) # Some more dummy PE data
)


# JPEG signatures
TEST_JPEG_SOI = b'\xFF\xD8'
TEST_JPEG_EOI = b'\xFF\xD9'
DUMMY_JPEG_CONTENT = TEST_JPEG_SOI + b"\xde\xad\xbe\xef" + TEST_JPEG_EOI

# ZIP signature
TEST_ZIP_SIGNATURE = b'PK\x03\x04'


@unittest.skipIf(PolyglotAnalyzer is None or MockConfigurationManager is None, "Modules not imported.")
class TestPolyglotAnalyzer(unittest.TestCase):
    TEST_DIR = os.path.join(os.path.dirname(__file__), "polyglot_test_data")

    @classmethod
    def setUpClass(cls):
        os.makedirs(cls.TEST_DIR, exist_ok=True)
        cls.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.DEBUG)


        # --- Create Test Files ---
        # 1. JPEG with appended PE payload
        cls.jpeg_with_pe_path = os.path.join(cls.TEST_DIR, "jpeg_with_pe.jpg")
        with open(cls.jpeg_with_pe_path, 'wb') as f:
            f.write(DUMMY_JPEG_CONTENT)
            f.write(TEST_DUMMY_PE_PAYLOAD)

        # 2. ZIP file containing a clean JPEG and a PE file
        cls.zip_with_pe_and_jpeg_path = os.path.join(cls.TEST_DIR, "archive_with_pe.zip")
        with zipfile.ZipFile(cls.zip_with_pe_and_jpeg_path, 'w') as zf:
            zf.writestr("clean.jpg", DUMMY_JPEG_CONTENT)
            zf.writestr("payload.exe", TEST_DUMMY_PE_PAYLOAD)
            zf.writestr("notes.txt", b"Some text file.")

        # 3. ZIP file containing a JPEG which itself has an appended PE
        cls.zip_with_jpeg_polyglot_path = os.path.join(cls.TEST_DIR, "archive_with_jpeg_polyglot.zip")
        jpeg_polyglot_data = DUMMY_JPEG_CONTENT + TEST_DUMMY_PE_PAYLOAD
        with zipfile.ZipFile(cls.zip_with_jpeg_polyglot_path, 'w') as zf:
            zf.writestr("polyglot.jpg", jpeg_polyglot_data)

        # 4. A plain PE file (should not extract anything from itself via polyglot methods)
        cls.plain_pe_file_path = os.path.join(cls.TEST_DIR, "plain.exe")
        with open(cls.plain_pe_file_path, 'wb') as f:
            f.write(TEST_DUMMY_PE_PAYLOAD)

        # 5. A file that is just text (no known carrier signatures)
        cls.text_file_path = os.path.join(cls.TEST_DIR, "plain.txt")
        with open(cls.text_file_path, 'wb') as f:
            f.write(b"This is a simple text file, not a polyglot carrier.")


        cls.mock_cm = MockConfigurationManager({
            "general": {"log_level": "DEBUG"},
            "polyglot_analyzer": {
                "supported_carriers": "zip,jpeg,generic",
                "min_payload_size": 32 # Small for tests
            }
        })

    @classmethod
    def tearDownClass(cls):
        import shutil
        if os.path.exists(cls.TEST_DIR):
            shutil.rmtree(cls.TEST_DIR)

    def setUp(self):
        self.analyzer = PolyglotAnalyzer(config_manager=self.mock_cm)

    def test_analyze_jpeg_with_appended_pe(self):
        payloads = self.analyzer.analyze_file(self.jpeg_with_pe_path)
        self.assertEqual(len(payloads), 1, "Should find one appended PE payload.")
        payload_info = payloads[0]
        self.assertEqual(payload_info['type_desc'], 'appended_to_jpeg_eoi')
        self.assertEqual(payload_info['data'], TEST_DUMMY_PE_PAYLOAD)
        self.assertEqual(payload_info['offset'], len(DUMMY_JPEG_CONTENT))
        # Further check if the PE inside appended data was also found
        # This depends on how _extract_from_jpeg calls _find_generic_pe_payloads
        # Current PolyglotAnalyzer._extract_from_jpeg does call it on appended data.

        # Let's refine the check: one payload of type 'appended_to_jpeg_eoi' which *is* the PE,
        # and another of type 'embedded_pe_file' *from* that appended data.

        # Search for the PE file specifically
        found_pe_directly_in_appended = False
        for p in payloads:
            if p['type_desc'] == 'embedded_pe_file' and p['carrier_type'] == 'jpeg_appended_data':
                self.assertEqual(p['data'], TEST_DUMMY_PE_PAYLOAD)
                found_pe_directly_in_appended = True
                break
        # This structure might be a bit redundant (appended is the PE, then PE found in appended).
        # For this test, we'll expect the direct appended data first.
        # The PEAnalyzer's _find_generic_pe_payloads on the appended data should also find it.
        # So, potentially two ways of identifying the same PE payload if appended_data IS a PE.
        # The current test setup will lead to 'appended_to_jpeg_eoi' whose data is the PE.
        # And then 'embedded_pe_file' whose data is also the PE, offset relative to appended data.

        # Simpler check for this test: at least one payload is the PE.
        self.assertTrue(any(p['data'] == TEST_DUMMY_PE_PAYLOAD for p in payloads))


    def test_analyze_zip_with_pe_member(self):
        payloads = self.analyzer.analyze_file(self.zip_with_pe_and_jpeg_path)
        self.assertGreaterEqual(len(payloads), 1, "Should find at least the PE payload within the ZIP.")

        found_pe_member = False
        for p_info in payloads:
            if p_info['type_desc'] == 'embedded_pe_file' and "payload.exe" in p_info['carrier_file']:
                self.assertEqual(p_info['data'], TEST_DUMMY_PE_PAYLOAD)
                found_pe_member = True
                break
        self.assertTrue(found_pe_member, "PE file member 'payload.exe' not extracted correctly.")

    def test_analyze_zip_with_jpeg_polyglot_member(self):
        payloads = self.analyzer.analyze_file(self.zip_with_jpeg_polyglot_path)
        # Expected:
        # 1. PE found inside polyglot.jpg (which was extracted from zip)
        #    - The 'carrier_file' for this PE would be something like 'ZIP:archive.../polyglot.jpg'
        #    - The 'carrier_type' for this PE would be 'jpeg_appended_data' (or similar if _extract_from_jpeg is enhanced)

        self.assertGreaterEqual(len(payloads), 1, "Should find at least one PE payload from the JPEG within ZIP.")

        found_pe_in_jpeg_in_zip = False
        for p_info in payloads:
            self.logger.debug(f"Found in zip_with_jpeg_polyglot: {p_info}")
            if p_info['type_desc'] == 'embedded_pe_file' and \
               "polyglot.jpg" in p_info['carrier_file'] and \
               p_info['carrier_type'] == 'jpeg_appended_data': # Check specific carrier_type from JPEG analysis
                self.assertEqual(p_info['data'], TEST_DUMMY_PE_PAYLOAD, "Data of PE in JPEG in ZIP mismatch.")
                # Offset should be relative to the start of the appended data within the JPEG member
                self.assertEqual(p_info['offset'], 0, "Offset of PE within appended data should be 0.")
                found_pe_in_jpeg_in_zip = True
                break
        self.assertTrue(found_pe_in_jpeg_in_zip, "PE from JPEG member inside ZIP not extracted correctly.")


    def test_analyze_plain_pe_file(self):
        # Polyglot analyzer's job is to find payloads *within* other files.
        # If the file itself is a PE, it shouldn't extract itself unless specific logic is added for that.
        # Current implementation's `_find_generic_pe_payloads` might find it if `generic` is supported
        # and primary_file_type is 'pe', but the condition `primary_file_type not in ['pe', 'zip']` prevents this.
        payloads = self.analyzer.analyze_file(self.plain_pe_file_path)
        self.assertEqual(len(payloads), 0,
                         "Plain PE file should not yield embedded payloads from itself via polyglot methods as currently designed.")

    def test_analyze_text_file(self):
        # A file with no known carrier signatures and no embedded PEs.
        payloads = self.analyzer.analyze_file(self.text_file_path)
        # _find_generic_pe_payloads might run if 'generic' is supported.
        # Since the text file doesn't contain PE signatures, it should find nothing.
        self.assertEqual(len(payloads), 0, "Plain text file should not yield any payloads.")

    def test_get_file_type_detection(self):
        self.assertEqual(self.analyzer._get_file_type(TEST_ZIP_SIGNATURE + b"restofdata"), "zip")
        self.assertEqual(self.analyzer._get_file_type(TEST_JPEG_SOI + b"restofdata"), "jpeg")
        self.assertEqual(self.analyzer._get_file_type(TEST_DUMMY_PE_PAYLOAD), "pe")
        self.assertEqual(self.analyzer._get_file_type(b"other data"), "unknown")

if __name__ == '__main__':
    unittest.main()
