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
    from steganography_analyzer import SteganographyAnalyzer, PIL_AVAILABLE, COMMON_EOF_MARKERS
    from core_engine.configuration_manager import MockConfigurationManager # Use mock from crypto/polyglot tests
except ImportError as e:
    print(f"Critical Error: Failed to import modules for steganography testing: {e}", file=sys.stderr)
    SteganographyAnalyzer = None
    MockConfigurationManager = None
    PIL_AVAILABLE = False # Assume not available if import fails
    COMMON_EOF_MARKERS = {}


# Minimal JPEG data for testing appended data
TEST_JPEG_SOI = b'\xFF\xD8'
TEST_JPEG_EOI = b'\xFF\xD9'
DUMMY_JPEG_CONTENT_FOR_STEGO = TEST_JPEG_SOI + b"\x01\x02\x03\x04\x05" + TEST_JPEG_EOI

# Minimal GIF data for testing appended data
DUMMY_GIF_HEADER = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00" # Header + Logical Screen Descriptor
DUMMY_GIF_TRAILER = b"\x3B" # GIF Trailer (EOF)
DUMMY_GIF_CONTENT_FOR_STEGO = DUMMY_GIF_HEADER + DUMMY_GIF_TRAILER


@unittest.skipIf(SteganographyAnalyzer is None or MockConfigurationManager is None, "Modules not imported.")
class TestSteganographyAnalyzer(unittest.TestCase):
    TEST_DIR = os.path.join(os.path.dirname(__file__), "steganography_test_data")

    @classmethod
    def setUpClass(cls):
        os.makedirs(cls.TEST_DIR, exist_ok=True)
        cls.logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.DEBUG)

        # --- Create Test Files ---
        cls.jpeg_with_appended_path = os.path.join(cls.TEST_DIR, "appended.jpg")
        cls.appended_payload = b"SECRET_DATA_APPENDED_HERE"
        with open(cls.jpeg_with_appended_path, 'wb') as f:
            f.write(DUMMY_JPEG_CONTENT_FOR_STEGO)
            f.write(cls.appended_payload)

        cls.clean_jpeg_path = os.path.join(cls.TEST_DIR, "clean.jpg")
        with open(cls.clean_jpeg_path, 'wb') as f:
            f.write(DUMMY_JPEG_CONTENT_FOR_STEGO)

        cls.gif_with_appended_path = os.path.join(cls.TEST_DIR, "appended.gif")
        with open(cls.gif_with_appended_path, 'wb') as f:
            f.write(DUMMY_GIF_CONTENT_FOR_STEGO)
            f.write(cls.appended_payload)

        # For LSB (conceptual test, as PIL is likely unavailable)
        cls.dummy_png_path = os.path.join(cls.TEST_DIR, "dummy.png")
        with open(cls.dummy_png_path, 'wb') as f:
            # Minimal valid PNG: header, IHDR (1x1 pixel), IDAT (empty), IEND
            f.write(b'\x89PNG\r\n\x1a\n') # PNG signature
            f.write(b'\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90\x77\x53\xde') # IHDR 1x1 pixel, RGB
            f.write(b'\x00\x00\x00\x0cIDATx\x9cc\x60\x00\x00\x00\x0c\x00\x01\x05\x0f\x38\x7f') # Minimal IDAT (compressed empty data)
            f.write(b'\x00\x00\x00\x00IEND\xaeB`\x82') # IEND

        cls.mock_cm = MockConfigurationManager({
            "general": {"log_level": "DEBUG"},
            "steganography_analyzer": {
                "lsb_formats": "png,bmp", # Only these for testing
                "max_appended_scan_size": 2048
            }
        })

    @classmethod
    def tearDownClass(cls):
        import shutil
        if os.path.exists(cls.TEST_DIR):
            shutil.rmtree(cls.TEST_DIR)

    def setUp(self):
        self.analyzer = SteganographyAnalyzer(config_manager=self.mock_cm)

    # --- Appended Data Tests ---
    def test_jpeg_with_appended_data(self):
        results = self.analyzer.check_for_appended_data(self.jpeg_with_appended_path)
        self.assertEqual(len(results), 1)
        payload_info = results[0]
        self.assertEqual(payload_info['data'], self.appended_payload)
        self.assertEqual(payload_info['data_length'], len(self.appended_payload))
        self.assertEqual(payload_info['offset'], len(DUMMY_JPEG_CONTENT_FOR_STEGO))
        self.assertEqual(payload_info['eof_marker_type'], 'jpeg')

    def test_jpeg_clean(self):
        results = self.analyzer.check_for_appended_data(self.clean_jpeg_path)
        self.assertEqual(len(results), 0)

    def test_gif_with_appended_data(self):
        results = self.analyzer.check_for_appended_data(self.gif_with_appended_path)
        self.assertEqual(len(results), 1)
        payload_info = results[0]
        self.assertEqual(payload_info['data'], self.appended_payload)
        self.assertEqual(payload_info['data_length'], len(self.appended_payload))
        self.assertEqual(payload_info['offset'], len(DUMMY_GIF_CONTENT_FOR_STEGO))
        self.assertEqual(payload_info['eof_marker_type'], 'gif')


    # --- LSB Steganography Tests ---

    def test_lsb_extract_placeholder_when_pil_unavailable(self):
        if PIL_AVAILABLE: # This global reflects the real availability in the test env
            self.skipTest("PIL is available, this test is for when it's not.")

        # SteganographyAnalyzer's extract_lsb_data should return None if PIL is not available
        extracted = self.analyzer.extract_lsb_data(self.dummy_png_path)
        self.assertIsNone(extracted, "extract_lsb_data should return None when PIL is unavailable.")

    def test_lsb_detect_placeholder_when_pil_unavailable(self):
        if PIL_AVAILABLE:
            self.skipTest("PIL is available, this test is for when it's not.")

        detection = self.analyzer.detect_lsb_steganography(self.dummy_png_path)
        self.assertIsNotNone(detection)
        self.assertEqual(detection.get('confidence'), 0.0)
        self.assertIn("Skipped - PIL unavailable", detection.get('description', ""))

    def test_analyze_lsb_main_method_pil_unavailable(self):
        # This test explicitly checks the main LSB analysis method when PIL is unavailable.
        # We use a local SteganographyAnalyzer instance where PIL_AVAILABLE is forced to False for the test's scope.

        original_pil_available_state = self.analyzer.PIL_AVAILABLE # Save global state if analyzer uses it
        try:
            # Force the analyzer instance to think PIL is unavailable for this test
            # This requires SteganographyAnalyzer to check an instance variable or a passed-in state,
            # or for us to mock the global PIL_AVAILABLE for the duration of this test.
            # For simplicity, if SteganographyAnalyzer directly uses the global PIL_AVAILABLE,
            # this test relies on the global state being False.
            if PIL_AVAILABLE: # If PIL is actually available globally, this test is not for this scenario
                 self.skipTest("This test specifically targets behavior when PIL is globally unavailable.")

            results = self.analyzer.analyze_lsb_steganography(self.dummy_png_path)
            self.assertIsNotNone(results)
            self.assertEqual(results.get('status'), 'skipped')
            self.assertIn("PIL library not available", results.get('reason', ""),
                          "Reason should indicate PIL is unavailable.")
            self.logger.info("LSB (No PIL): Main LSB analysis method skipped as expected.")
        finally:
            # Restore global state if it was changed for the test (not directly possible here without patching)
            # self.analyzer.PIL_AVAILABLE = original_pil_available_state # if it was an instance var
            pass


    def test_analyze_lsb_unsupported_format(self):
        # Create a dummy .txt file, LSB analysis should be skipped for it.
        txt_file_path = os.path.join(self.TEST_DIR, "dummy.txt")
        with open(txt_file_path, "wb") as f: f.write(b"text data, not an image")

        # Analyzer is configured with "png,bmp" as lsb_formats.
        results_txt = self.analyzer.analyze_lsb_steganography(txt_file_path) # for .txt
        self.assertEqual(results_txt.get('status'), 'skipped')
        self.assertIn("Unsupported format txt for LSB", results_txt.get('reason', ""))
        self.logger.info("LSB (Unsupported Format): Test skipped as expected for .txt.")

        # Test with a supported format (PNG) but configure analyzer to not support it
        # This tests if config is respected even if PIL were available.
        custom_cm_only_bmp = MockConfigurationManager({
            "general": {"log_level": "DEBUG"},
            "steganography_analyzer": {"lsb_formats": "bmp"} # Only allow bmp
        })
        analyzer_only_bmp = SteganographyAnalyzer(config_manager=custom_cm_only_bmp)
        # Force its internal PIL_AVAILABLE to match global for consistency in this part of test
        # (This is tricky; ideally, PIL_AVAILABLE is checked once at module load or passed around)
        # For this test, we assume analyze_lsb_steganography checks format *before* PIL status if format is issue.

        original_pil_state_for_module = analyzer_only_bmp.PIL_AVAILABLE # Save for restoration
        try:
            # If we want to test format rejection *even if* PIL was available:
            # We'd set analyzer_only_bmp.PIL_AVAILABLE = True (if it was an instance var)
            # Or rely on the global PIL_AVAILABLE if the test environment has it (unlikely here)

            # If PIL_AVAILABLE is False globally, the reason will be "PIL unavailable" first.
            # If PIL_AVAILABLE is True globally, then it should be "Unsupported format".

            results_png_unsupported = analyzer_only_bmp.analyze_lsb_steganography(self.dummy_png_path)
            self.assertEqual(results_png_unsupported.get('status'), 'skipped')
            if PIL_AVAILABLE: # If PIL *is* available, then the reason must be format.
                self.assertIn("Unsupported format png for LSB", results_png_unsupported.get('reason', ""))
            else: # If PIL is *not* available, that takes precedence.
                self.assertIn("PIL library not available", results_png_unsupported.get('reason', ""))

            self.logger.info(f"LSB (PNG with restricted config): Skipped as expected. Reason: {results_png_unsupported.get('reason')}")
        finally:
            # analyzer_only_bmp.PIL_AVAILABLE = original_pil_state_for_module # Restore if changed
            pass


    @unittest.skipUnless(PIL_AVAILABLE, "Pillow (PIL) is required for actual LSB extraction tests.")
    def test_lsb_extract_data_pil_available(self):
        # This test requires a specially crafted image with known LSB data.
        # Since we can't create such an image without PIL here, this test is more of a template.
        # If we had a test image 'lsb_test_image.png' with "TestData" in 1 LSB:
        # extracted = self.analyzer.extract_lsb_data("path/to/lsb_test_image.png", num_lsb=1)
        # self.assertIsNotNone(extracted)
        # self.assertIn(b"TestData", extracted) # Or exact match if padding/termination is known
        self.logger.warning("Actual LSB data hiding/extraction test with PIL needs a pre-crafted image.")

        # Test with the dummy PNG; it should extract some (likely meaningless) data
        # or handle empty/small images gracefully.
        extracted_dummy_data = self.analyzer.extract_lsb_data(self.dummy_png_path, num_lsb=1, max_extract_bytes=10)
        self.assertIsNotNone(extracted_dummy_data, "LSB extraction from dummy PNG should return bytes or empty bytes, not None.")
        # The 1x1 pixel dummy PNG will produce very few bits.
        # 1 pixel * 3 channels * 1 LSB = 3 bits. Not enough for a byte.
        self.assertEqual(len(extracted_dummy_data), 0, "1x1 PNG should yield 0 full bytes from 1 LSB.")


    @unittest.skipUnless(PIL_AVAILABLE, "Pillow (PIL) is required for LSB detection tests.")
    def test_lsb_detect_steganography_pil_available(self):
        # Similar to extraction, actual detection needs well-defined test images (clean vs. LSB-encoded).
        # For now, test with dummy PNG. Detection is naive (printable chars).
        results = self.analyzer.detect_lsb_steganography(self.dummy_png_path)
        self.assertIsNotNone(results)
        self.assertIn('confidence', results)
        # Our dummy 1x1 PNG won't have many printable chars in its LSBs.
        self.assertLessEqual(results['confidence'], 0.1, "Dummy 1x1 PNG should have low LSB stego confidence.")
        self.logger.warning("Actual LSB detection test with PIL needs pre-crafted clean and LSB-encoded images.")


if __name__ == '__main__':
    # If PIL was available, the skips might not apply.
    # We can force PIL_AVAILABLE for local testing if needed, but not for CI.
    # print(f"PIL Available for tests: {PIL_AVAILABLE}")
    unittest.main()
