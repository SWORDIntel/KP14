import unittest
import os
import shutil
import sys

# Ensure stego_test can be imported.
# Assumes test_f5.py is in the same directory as stego_test.py (e.g., repo root)
try:
    from stego_test import embed_message_f5, extract_message_f5, DELIMITER_BIT_STRING
    # For a more precise message_too_large test, jpegio might be needed here,
    # but for now, we'll rely on a very long string.
    # import jpegio
except ImportError as e:
    print(f"ImportError: {e}. Ensure stego_test.py is in the Python path or the same directory as test_f5.py.")
    # Attempt to add parent directory to sys.path if running from a 'tests' subdirectory
    # This is a common structure.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.abspath(os.path.join(script_dir, '..'))
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
        print(f"Added {parent_dir} to sys.path. Retrying import...")
        try:
            from stego_test import embed_message_f5, extract_message_f5, DELIMITER_BIT_STRING
        except ImportError:
            print(f"Still unable to import from stego_test.py. Please check PYTHONPATH.")
            print(f"Current sys.path: {sys.path}")
            print(f"Current working directory: {os.getcwd()}")
            sys.exit(1)
    else: # Parent directory already in path, import failed for other reasons
        print(f"Parent directory {parent_dir} already in sys.path. Import failed.")
        print(f"Current sys.path: {sys.path}")
        print(f"Current working directory: {os.getcwd()}")
        sys.exit(1)


class TestF5(unittest.TestCase):

    TEST_IMAGE_DIR = "test_images_jpeg" # Relative to repo root
    TEMP_DIR_NAME = "temp_test_files_f5" # Specific temp dir for F5 tests

    # Source image (use a grayscale one as specified, good for consistent coefficient counts)
    SOURCE_JPEG = os.path.join(TEST_IMAGE_DIR, "jpeg_grayscale.jpg")
    # SOURCE_JPEG = os.path.join(TEST_IMAGE_DIR, "jpeg_low_quality_small.jpg") # Alternative

    def setUp(self):
        # Base directory for tests is the script's directory
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.temp_dir = os.path.join(self.base_dir, self.TEMP_DIR_NAME)

        os.makedirs(self.temp_dir, exist_ok=True)

        self.source_image_path_abs = os.path.join(self.base_dir, self.SOURCE_JPEG)
        if not os.path.exists(self.source_image_path_abs):
            # Fallback if running from repo root and paths are relative from there
            self.source_image_path_abs = self.SOURCE_JPEG
            if not os.path.exists(self.source_image_path_abs):
                 self.fail(f"Source test image not found: {self.SOURCE_JPEG} or {os.path.join(self.base_dir, self.SOURCE_JPEG)}")

        self.temp_image_path = os.path.join(self.temp_dir, "temp_f5_test_image.jpg")
        self.temp_output_path = os.path.join(self.temp_dir, "temp_f5_output_image.jpg")

        shutil.copy(self.source_image_path_abs, self.temp_image_path)

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_embed_extract_successful_f5(self):
        """Test basic F5 embedding and successful extraction."""
        secret_message = "Test F5 Algo!"
        print(f"\n[TestF5] Running test_embed_extract_successful_f5 with image: {self.temp_image_path}")

        embed_result = embed_message_f5(self.temp_image_path, secret_message, self.temp_output_path)
        self.assertTrue(embed_result, "F5 Embedding failed when it should have succeeded.")
        self.assertTrue(os.path.exists(self.temp_output_path), "F5 Output image was not created.")

        extracted_message = extract_message_f5(self.temp_output_path)
        self.assertIsNotNone(extracted_message, "F5 Extraction failed, returned None.")
        self.assertEqual(secret_message, extracted_message,
                         f"F5 Extracted message '{extracted_message}' does not match original '{secret_message}'.")

    def test_message_too_large_f5(self):
        """Test that F5 embedding fails if the message is too large."""
        # Create a message much larger than a small grayscale image can hold.
        # Each char = 8 bits. Delimiter is len(DELIMITER_BIT_STRING).
        # Grayscale 96x64 jpeg_grayscale.jpg has limited non-zero AC coeffs.
        # Max AC coeffs = 96/8 * 64/8 * 63 = 12 * 8 * 63 = 6048.
        # A 1000 char message = 8000 bits + delimiter. This should be enough.
        long_message = "A" * 1000
        print(f"\n[TestF5] Running test_message_too_large_f5 with image: {self.temp_image_path}")
        print(f"  Attempting to embed message of {len(long_message)} chars ({len(long_message)*8 + len(DELIMITER_BIT_STRING)} bits).")

        self.assertFalse(embed_message_f5(self.temp_image_path, long_message, self.temp_output_path),
                         "F5 Embedding should have failed for a very large message, but it succeeded or did not return False.")

    def test_extract_no_message_f5(self):
        """Test F5 extraction from an image with no embedded message."""
        print(f"\n[TestF5] Running test_extract_no_message_f5 with image: {self.temp_image_path}")
        extracted_message = extract_message_f5(self.temp_image_path) # temp_image_path is a fresh copy
        self.assertIsNone(extracted_message,
                          f"F5 Expected None when extracting from an image with no message, but got: '{extracted_message}'.")

    def test_input_file_not_found_f5_embed(self):
        """Test F5 embed function with a non-existent input file."""
        print(f"\n[TestF5] Running test_input_file_not_found_f5_embed")
        non_existent_image = os.path.join(self.temp_dir, "non_existent_f5.jpg")
        self.assertFalse(embed_message_f5(non_existent_image, "test", self.temp_output_path),
                         "embed_message_f5 should return False for non-existent input.")

    def test_input_file_not_found_f5_extract(self):
        """Test F5 extract function with a non-existent input file."""
        print(f"\n[TestF5] Running test_input_file_not_found_f5_extract")
        non_existent_image = os.path.join(self.temp_dir, "non_existent_f5.jpg")
        self.assertIsNone(extract_message_f5(non_existent_image),
                          "extract_message_f5 should return None for non-existent input.")

if __name__ == "__main__":
    # This setup assumes that test_f5.py is in the same directory as stego_test.py,
    # or stego_test.py is otherwise in the Python path.
    # The import block at the top tries to handle a common case of a 'tests' subdirectory.
    unittest.main()
