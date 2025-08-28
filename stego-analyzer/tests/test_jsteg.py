import unittest
import os
import shutil
import sys

# Ensure stego_test can be imported.
# If test_jsteg.py and stego_test.py are in the same directory, direct import should work.
# The sys.path manipulations are removed for simplicity in a flat structure.
try:
    from stego_test import embed_message_jsteg, extract_message_jsteg, DELIMITER_BIT_STRING
    import jpegio # Used for reading image properties for message capacity estimation
except ImportError as e:
    print(f"ImportError: {e}. Ensure stego_test.py is in the Python path or the same directory as test_jsteg.py.")
    print(f"Current sys.path: {sys.path}")
    print(f"Current working directory: {os.getcwd()}")
    # List files in current directory to help debug
    print(f"Files in CWD: {os.listdir('.')}")
    sys.exit(1)

class TestJSteg(unittest.TestCase):

    TEST_IMAGE_DIR = "test_images_jpeg"
    TEMP_DIR = "temp_test_files"

    # Source images (use relative paths from repo root)
    SOURCE_GRAYSCALE_JPEG = os.path.join(TEST_IMAGE_DIR, "jpeg_grayscale.jpg")
    SOURCE_SMALL_JPEG = os.path.join(TEST_IMAGE_DIR, "jpeg_low_quality_small.jpg")

    def setUp(self):
        # Create a temporary directory for test files
        os.makedirs(self.TEMP_DIR, exist_ok=True)

        self.temp_image_path = os.path.join(self.TEMP_DIR, "temp_test_image.jpg")
        self.temp_output_path = os.path.join(self.TEMP_DIR, "temp_output_image.jpg")

        # Copy a fresh image for each test
        # Choose a default image, can be overridden in specific tests if needed
        if not os.path.exists(self.SOURCE_SMALL_JPEG):
            raise FileNotFoundError(f"Source test image not found: {self.SOURCE_SMALL_JPEG}")
        shutil.copy(self.SOURCE_SMALL_JPEG, self.temp_image_path)

    def tearDown(self):
        # Remove the temporary directory and its contents
        if os.path.exists(self.TEMP_DIR):
            shutil.rmtree(self.TEMP_DIR)

    def _get_image_capacity_bits(self, image_path):
        """Helper to estimate steganographic capacity for testing 'message_too_large'."""
        try:
            jpeg_struct = jpegio.read(image_path)
            capacity = 0
            if jpeg_struct.coef_arrays:
                for component_array in jpeg_struct.coef_arrays:
                    if component_array.ndim == 2 and component_array.shape[0] % 8 == 0 and component_array.shape[1] % 8 == 0:
                        for r_block_start in range(0, component_array.shape[0], 8):
                            for c_block_start in range(0, component_array.shape[1], 8):
                                block = component_array[r_block_start:r_block_start+8, c_block_start:c_block_start+8]
                                # Count AC coefficients not equal to 0 or 1
                                for i in range(1, 64): # Zigzag indices 1 to 63 are AC
                                    # This is a simplified capacity check, actual zigzag access is more complex
                                    # For this helper, just iterate through flattened block after DC
                                    coeff_val = block.flatten()[i]
                                    if coeff_val != 0 and coeff_val != 1:
                                        capacity += 1
            return capacity
        except Exception:
            return 0 # Fallback

    def test_embed_extract_successful(self):
        """Test basic embedding and successful extraction."""
        secret_message = "Hello JSteg!"
        # Use the default temp_image_path copied in setUp

        # Ensure the source image for this test is the small one for faster processing
        # and more reliable capacity unless a specific large image test is needed.
        if not os.path.exists(self.SOURCE_SMALL_JPEG):
             self.fail(f"Source image {self.SOURCE_SMALL_JPEG} not found for test.")
        shutil.copy(self.SOURCE_SMALL_JPEG, self.temp_image_path)

        print(f"\n[TestJSteg] Running test_embed_extract_successful with image: {self.temp_image_path}")

        embed_result = embed_message_jsteg(self.temp_image_path, secret_message, self.temp_output_path)
        self.assertTrue(embed_result, "Embedding failed when it should have succeeded.")
        self.assertTrue(os.path.exists(self.temp_output_path), "Output image was not created.")

        extracted_message = extract_message_jsteg(self.temp_output_path)
        self.assertIsNotNone(extracted_message, "Extraction failed, returned None.")
        self.assertEqual(secret_message, extracted_message,
                         f"Extracted message '{extracted_message}' does not match original '{secret_message}'.")

    def test_embed_extract_grayscale_successful(self):
        """Test basic embedding and successful extraction with a grayscale JPEG."""
        secret_message = "Grayscale Test"
        # Override the default temp_image_path with the grayscale image
        if not os.path.exists(self.SOURCE_GRAYSCALE_JPEG):
             self.fail(f"Source image {self.SOURCE_GRAYSCALE_JPEG} not found for test.")
        shutil.copy(self.SOURCE_GRAYSCALE_JPEG, self.temp_image_path)

        print(f"\n[TestJSteg] Running test_embed_extract_grayscale_successful with image: {self.temp_image_path}")

        embed_result = embed_message_jsteg(self.temp_image_path, secret_message, self.temp_output_path)
        self.assertTrue(embed_result, "Embedding failed on grayscale image when it should have succeeded.")
        self.assertTrue(os.path.exists(self.temp_output_path), "Output image was not created for grayscale test.")

        extracted_message = extract_message_jsteg(self.temp_output_path)
        self.assertIsNotNone(extracted_message, "Extraction failed from grayscale image, returned None.")
        self.assertEqual(secret_message, extracted_message,
                         f"Extracted message '{extracted_message}' from grayscale does not match original '{secret_message}'.")


    def test_message_too_large(self):
        """Test that embedding fails if the message is too large."""
        # Estimate capacity (this is a rough guide, actual capacity depends on JSteg logic)
        # The _get_image_capacity_bits provides a count of available slots.
        # Each char is 8 bits. Add delimiter length.
        print(f"\n[TestJSteg] Running test_message_too_large with image: {self.temp_image_path}")

        # Use the smaller image for this test to make it easier to exceed capacity
        if not os.path.exists(self.SOURCE_SMALL_JPEG):
             self.fail(f"Source image {self.SOURCE_SMALL_JPEG} not found for test.")
        shutil.copy(self.SOURCE_SMALL_JPEG, self.temp_image_path)

        available_bits = self._get_image_capacity_bits(self.temp_image_path)
        print(f"Estimated available bits in {self.temp_image_path}: {available_bits}")

        # If capacity is zero or very low, the test itself might be flawed or image unsuitable.
        self.assertTrue(available_bits > len(DELIMITER_BIT_STRING) + 8,
                        f"Test image {self.temp_image_path} has insufficient base capacity ({available_bits} bits) for a meaningful 'message_too_large' test.")

        # Create a message that (number_of_slots + some_margin) * 8 bits long
        # Each character is 8 bits. Delimiter is DELIMITER_BIT_STRING long.
        # Message length in chars that would require more than available_bits:
        num_chars_to_exceed_capacity = (available_bits // 8) + 10 # 10 extra chars for buffer

        long_message = "A" * num_chars_to_exceed_capacity
        expected_bit_len = len(long_message) * 8 + len(DELIMITER_BIT_STRING)
        print(f"Attempting to embed message of {len(long_message)} chars, total bits: {expected_bit_len}")

        self.assertFalse(embed_message_jsteg(self.temp_image_path, long_message, self.temp_output_path),
                         f"Embedding should have failed for a message of {expected_bit_len} bits, but it succeeded. Capacity estimate: {available_bits} bits.")

    def test_extract_no_message(self):
        """Test extraction from an image with no embedded message."""
        print(f"\n[TestJSteg] Running test_extract_no_message with image: {self.temp_image_path}")
        # temp_image_path is a fresh copy of an original image
        extracted_message = extract_message_jsteg(self.temp_image_path)
        self.assertIsNone(extracted_message,
                          f"Expected None when extracting from an image with no message, but got: '{extracted_message}'.")

    def test_input_file_not_found_embed(self):
        """Test embed function with a non-existent input file."""
        print(f"\n[TestJSteg] Running test_input_file_not_found_embed")
        non_existent_image = os.path.join(self.TEMP_DIR, "non_existent.jpg")
        self.assertFalse(embed_message_jsteg(non_existent_image, "test", self.temp_output_path),
                         "embed_message_jsteg should return False for non-existent input.")

    def test_input_file_not_found_extract(self):
        """Test extract function with a non-existent input file."""
        print(f"\n[TestJSteg] Running test_input_file_not_found_extract")
        non_existent_image = os.path.join(self.TEMP_DIR, "non_existent.jpg")
        self.assertIsNone(extract_message_jsteg(non_existent_image),
                          "extract_message_jsteg should return None for non-existent input.")

if __name__ == "__main__":
    # This allows running the tests directly from the command line
    # Assuming test_jsteg.py is run from the repository root where stego_test.py also exists.
    # No complex os.chdir or sys.path manipulation should be needed at the end of the file
    # if the script is executed from the correct directory.

    # The print statements for CWD and sys.path at the beginning (on ImportError)
    # should give enough debug information if imports fail.

    unittest.main()
