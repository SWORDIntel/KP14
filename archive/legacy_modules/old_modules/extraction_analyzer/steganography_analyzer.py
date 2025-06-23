import logging
import os

# Assuming configuration_manager is in core_engine and accessible
try:
    from core_engine.configuration_manager import ConfigurationManager
except ImportError:
    ConfigurationManager = None
    logging.getLogger(__name__).warning("ConfigurationManager not found. SteganographyAnalyzer will use default settings.")

# Pillow (PIL) for LSB - import will likely fail in this environment
PIL_AVAILABLE = False
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    logging.getLogger(__name__).warning(
        "Pillow (PIL) library not found. LSB steganography analysis for images will be disabled or conceptual."
    )

# Common End-of-File (EOF) markers. This can be expanded.
# Key: file type (lowercase string)
# Value: list of possible EOF markers (bytes)
COMMON_EOF_MARKERS = {
    'jpeg': [b'\xFF\xD9'],
    'gif': [b'\x00\x3B'], # Semicolon is the GIF terminator
    'png': [b'IEND\xaeB`\x82'], # IEND chunk + CRC
    'pdf': [b'%%EOF'], # Can also be %%EOF\n or %%EOF\r\n
    # Add more types like zip, docx, etc. if needed
}


class SteganographyAnalyzer:
    def __init__(self, config_manager=None):
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager
        self._load_config()

    def _load_config(self):
        self.supported_lsb_formats = ['png', 'bmp', 'tiff'] # Formats where LSB is common
        self.max_appended_data_scan_size = 4096 # Scan up to X bytes of appended data by default
        self.eof_markers = COMMON_EOF_MARKERS

        if self.config_manager:
            log_level_str = self.config_manager.get('general', 'log_level', fallback='INFO').upper()
            self.logger.setLevel(getattr(logging, log_level_str, logging.INFO))

            lsb_formats_str = self.config_manager.get('steganography_analyzer', 'lsb_formats', fallback="png,bmp,tiff")
            self.supported_lsb_formats = [fmt.strip() for fmt in lsb_formats_str.split(',')]

            self.max_appended_data_scan_size = self.config_manager.getint(
                'steganography_analyzer', 'max_appended_scan_size', fallback=self.max_appended_data_scan_size
            )
            # Custom EOF markers could also be loaded from config if needed
        else:
            logging.basicConfig(level=logging.INFO)
            self.logger.info("SteganographyAnalyzer initialized without ConfigurationManager. Using default settings.")

        self.logger.info(f"SteganographyAnalyzer initialized. Supported LSB formats (if PIL available): {self.supported_lsb_formats}")

    def _get_file_type_from_extension(self, file_path):
        if not file_path or not isinstance(file_path, str):
            return None
        return os.path.splitext(file_path)[1].lower().lstrip('.')

    # --- Appended Data Detection ---
    def check_for_appended_data(self, file_path, file_data=None):
        """
        Checks for data appended after known EOF markers for various file types.
        Returns a list of dicts: {'offset': int, 'data': bytes, 'eof_marker_type': str}
        """
        if file_data is None:
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
            except IOError as e:
                self.logger.error(f"Could not read file {file_path}: {e}")
                return []

        file_type = self._get_file_type_from_extension(file_path)
        if not file_type:
            self.logger.debug(f"Could not determine file type from extension for: {file_path}")
            # Could try magic number based detection here if needed as a fallback
            return []

        self.logger.info(f"Checking for appended data in {file_path} (type: {file_type})")
        found_payloads = []

        relevant_eof_markers = self.eof_markers.get(file_type)
        if not relevant_eof_markers:
            self.logger.debug(f"No known EOF markers for file type '{file_type}'. Skipping appended data check.")
            return []

        for eof_marker in relevant_eof_markers:
            # Search for the last occurrence of the EOF marker
            eof_pos = file_data.rfind(eof_marker)
            if eof_pos != -1:
                appended_data_offset = eof_pos + len(eof_marker)
                if appended_data_offset < len(file_data):
                    appended_data = file_data[appended_data_offset:]
                    # Limit how much appended data we consider a "payload" vs just large file
                    if len(appended_data) > 0 :
                        self.logger.info(f"Found {len(appended_data)} bytes of data after '{file_type}' EOF marker ({eof_marker.hex()}) at offset 0x{appended_data_offset:x}.")
                        payload_info = {
                            'offset': appended_data_offset,
                            'data': appended_data[:self.max_appended_data_scan_size], # Return only a portion if very large
                            'data_length': len(appended_data),
                            'eof_marker_type': file_type,
                            'eof_marker_used': eof_marker.hex()
                        }
                        found_payloads.append(payload_info)
                        # For this example, we take the first one found if multiple EOFs exist (e.g. PDF)
                        # A more sophisticated approach might analyze all.
                        break
                else:
                    self.logger.debug(f"EOF marker ({eof_marker.hex()}) found at end of file. No appended data.")
            else:
                self.logger.debug(f"EOF marker ({eof_marker.hex()}) not found for type '{file_type}'.")

        return found_payloads

    # --- LSB Steganography ---
    def extract_lsb_data(self, image_path, num_lsb=1, data_format="bytes", max_extract_bytes=None):
        """
        (Conceptual if PIL unavailable) Extracts data hidden in the LSBs of an image.

        Args:
            image_path (str): Path to the image file.
            num_lsb (int): Number of LSBs to extract from each color channel (1 or 2 typically).
            data_format (str): 'bits' or 'bytes'. How to return the extracted data.
            max_extract_bytes (int, optional): Maximum number of bytes to attempt to extract.
                                            Useful if length is unknown or to prevent large reads.

        Returns:
            bytes or list[int]: Extracted data, or None if extraction fails or is skipped.
        """
        if not PIL_AVAILABLE:
            self.logger.warning(f"PIL not available. LSB extraction for {image_path} is a conceptual placeholder.")
            # Simulate what might be returned or indicate skipped
            return None

        self.logger.info(f"Attempting LSB data extraction from {image_path} using {num_lsb} LSB(s).")
        try:
            img = Image.open(image_path)
            img = img.convert("RGB") # Convert to common format for consistent LSB operations
            pixels = img.load()
            width, height = img.size

            extracted_bits = []
            bits_to_collect = (max_extract_bytes * 8) if max_extract_bytes else float('inf')

            for y in range(height):
                for x in range(width):
                    if len(extracted_bits) >= bits_to_collect: break
                    r, g, b = pixels[x, y]
                    for channel_val in [r, g, b]:
                        for bit_idx in range(num_lsb):
                            if len(extracted_bits) >= bits_to_collect: break
                            extracted_bits.append((channel_val >> bit_idx) & 1)
                        if len(extracted_bits) >= bits_to_collect: break
                    if len(extracted_bits) >= bits_to_collect: break
                if len(extracted_bits) >= bits_to_collect: break

            self.logger.debug(f"Collected {len(extracted_bits)} bits via LSB from {image_path}.")

            if data_format == "bits":
                return extracted_bits

            # Convert bits to bytes
            byte_array = bytearray()
            for i in range(0, len(extracted_bits) - 7, 8):
                byte_val = 0
                for j in range(8):
                    byte_val = (byte_val << 1) | extracted_bits[i+j]
                byte_array.append(byte_val)

            # TODO: Implement logic to find end of message if not using max_extract_bytes
            # e.g., null terminator, specific delimiter sequence, or length embedded in first N bytes.
            # For now, returns all converted bytes up to max_extract_bytes.

            return bytes(byte_array)

        except FileNotFoundError:
            self.logger.error(f"Image file not found for LSB extraction: {image_path}")
            return None
        except Exception as e:
            self.logger.error(f"Error during LSB extraction from {image_path}: {e}", exc_info=True)
            return None

    def detect_lsb_steganography(self, image_path, num_lsb=1):
        """
        (Conceptual if PIL unavailable) Detects if an image likely contains LSB steganography.

        Args:
            image_path (str): Path to the image file.
            num_lsb (int): Number of LSBs to analyze.

        Returns:
            dict: Analysis result, e.g., {'confidence': float, 'description': str}
                  Confidence 0.0 (no/low LSB) to 1.0 (high LSB).
        """
        if not PIL_AVAILABLE:
            self.logger.warning(f"PIL not available. LSB detection for {image_path} is a conceptual placeholder.")
            return {"confidence": 0.0, "description": "Skipped - PIL unavailable."}

        self.logger.info(f"Detecting LSB steganography in {image_path} (checking {num_lsb} LSBs).")

        # Placeholder for actual statistical analysis (e.g., chi-squared)
        # For now, a simplified approach: extract some LSB data and check its nature.
        # A more robust method would analyze LSB plane entropy or compare to expected noise.

        extracted_data = self.extract_lsb_data(image_path, num_lsb=num_lsb, max_extract_bytes=1024) # Extract a sample

        if extracted_data is None: # Error during extraction or file not found
            return {"confidence": 0.0, "description": "Error or file not found during LSB data extraction."}

        if not extracted_data: # No data extracted (e.g., image too small for max_extract_bytes)
            return {"confidence": 0.0, "description": "No LSB data extracted or image too small."}

        # Simple heuristic: if extracted LSB data has many printable ASCII characters, it might be hidden text.
        # This is very naive. Real detection is much more complex.
        printable_chars = sum(1 for byte in extracted_data if 32 <= byte <= 126)
        ratio_printable = printable_chars / len(extracted_data)

        if ratio_printable > 0.7 and len(extracted_data) > 20: # Arbitrary threshold
            self.logger.info(f"High ratio of printable chars ({ratio_printable:.2f}) in LSB data sample.")
            return {"confidence": 0.75, "description": f"High ratio of printable characters in LSB data ({num_lsb}-bit plane)."}

        # Another simple heuristic: check entropy of LSB plane (if enough data)
        # (Requires an entropy function, assume it exists or add it)
        # lsb_entropy = self._calculate_entropy(extracted_data) # Assuming _calculate_entropy exists
        # if lsb_entropy > 7.0: # Highly random, could be encrypted data
        # return {"confidence": 0.8, "description": f"High entropy in LSB data ({lsb_entropy:.2f})."}

        self.logger.debug(f"LSB detection for {image_path} did not find strong indicators in sample.")
        return {"confidence": 0.1, "description": f"Basic LSB analysis did not find obvious hidden data in sample ({num_lsb}-bit plane)."}


    def analyze_lsb_steganography(self, file_path, file_data=None): # Main method called by pipeline
        """
        Main LSB analysis method. Calls detection and extraction if applicable.
        """
        file_type = self._get_file_type_from_extension(file_path)
        if file_type not in self.supported_lsb_formats:
            self.logger.debug(f"LSB analysis skipped for {file_path}: unsupported format '{file_type}'.")
            return {"status": "skipped", "reason": f"Unsupported format {file_type} for LSB."}

        if not PIL_AVAILABLE: # Check again, as PIL_AVAILABLE might change if tests mock it
            self.logger.info(f"LSB analysis skipped for {file_path}: PIL unavailable.")
            return {"status": "skipped", "reason": "PIL library not available for LSB analysis."}

        self.logger.info(f"Starting LSB steganography analysis for {file_path}")

        # For file_data handling with Image.open, it's better to pass file_path directly
        # or ensure file_data is wrapped in io.BytesIO if Image.open is used with it.
        # The extract_lsb_data and detect_lsb_steganography methods take image_path.

        detection_result = self.detect_lsb_steganography(file_path, num_lsb=1) # Default to 1 LSB for detection

        extracted_payload = None
        if detection_result.get("confidence", 0.0) > 0.5: # If detection confidence is moderate
            self.logger.info(f"LSB presence suspected (confidence: {detection_result['confidence']:.2f}). Attempting extraction.")
            # Try extracting with 1 LSB, then maybe more if configured or heuristically determined
            extracted_payload = self.extract_lsb_data(file_path, num_lsb=1, max_extract_bytes=self.config_manager.getint('steganography_analyzer', 'lsb_max_extract_bytes', fallback=2048))
            if extracted_payload:
                 self.logger.info(f"Successfully extracted {len(extracted_payload)} bytes via LSB from {file_path}.")

        return {
            "status": "completed_lsb_analysis",
            "detection": detection_result,
            "extraction": {
                "data": extracted_payload.hex() if extracted_payload else None, # Return hex for JSON
                "length": len(extracted_payload) if extracted_payload else 0,
                "method_used": "1-LSB plane extraction" if extracted_payload else None
            } if extracted_payload else {"status": "no_data_extracted_or_low_confidence"}
        }


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Create dummy files for testing
    DUMMY_TEST_DIR = "steganography_test_files"
    os.makedirs(DUMMY_TEST_DIR, exist_ok=True)

    DUMMY_JPEG_PATH = os.path.join(DUMMY_TEST_DIR, "test_appended.jpg")
    DUMMY_PNG_PATH_LSB = os.path.join(DUMMY_TEST_DIR, "test_lsb.png") # For LSB (conceptual)

    # Create dummy JPEG with appended data
    appended_payload = b"ThisIsSecretAppendedData12345"
    with open(DUMMY_JPEG_PATH, 'wb') as f:
        f.write(b'\xFF\xD8\xFF\xE0\x00\x10JFIF\x00') # SOI + APP0
        f.write(b"some jpeg data ") * 10
        f.write(b'\xFF\xD9') # EOI
        f.write(appended_payload)

    # Create a dummy PNG (very basic, PIL might not even load it if not valid enough)
    # For LSB, a real image processed with an LSB tool would be needed for actual data.
    # This is just to test the file handling part.
    if PIL_AVAILABLE: # Only create if PIL can potentially process it
        try:
            img = Image.new('RGB', (10, 10), color = 'red') # Minimal image
            img.save(DUMMY_PNG_PATH_LSB, "PNG")
            logging.info(f"Created dummy PNG for LSB test: {DUMMY_PNG_PATH_LSB}")
        except Exception as e:
            logging.error(f"Could not create dummy PNG for LSB test: {e}. PIL might be misconfigured.")
            # Create an empty file to prevent later FileNotFoundError if Image.new fails
            with open(DUMMY_PNG_PATH_LSB, 'wb') as f_png_dummy: f_png_dummy.write(b"")

    else: # Create an empty file if PIL is not available
        with open(DUMMY_PNG_PATH_LSB, 'wb') as f_png_dummy: f_png_dummy.write(b"")
        logging.info(f"PIL not available, created empty file as placeholder: {DUMMY_PNG_PATH_LSB}")


    # --- Test SteganographyAnalyzer ---
    analyzer = SteganographyAnalyzer(config_manager=None) # No CM for this simple test

    print(f"\n--- Analyzing Appended Data for JPEG: {DUMMY_JPEG_PATH} ---")
    appended_results = analyzer.check_for_appended_data(DUMMY_JPEG_PATH)
    if appended_results:
        for res in appended_results:
            print(f"  Found: Offset=0x{res['offset']:x}, Length={res['data_length']}, Data Preview='{res['data'][:20].hex()}...'")
            if res['data'] == appended_payload:
                 print(f"    Payload MATCHED expected: {appended_payload}")
            else:
                 print(f"    Payload DOES NOT MATCH expected. Got: {res['data']}")

    else:
        print("  No appended data found by analyzer.")

    print(f"\n--- Analyzing LSB for PNG: {DUMMY_PNG_PATH_LSB} ---")
    lsb_results = analyzer.analyze_lsb_steganography(DUMMY_PNG_PATH_LSB)
    print(f"  LSB Analysis Result: {lsb_results.get('status')}")
    if lsb_results.get('status') == 'data_extracted':
        print(f"    Extracted {lsb_results.get('length')} bytes using {lsb_results.get('method')}.")
        print(f"    Data Preview: {lsb_results.get('data', b'')[:20].hex()}...")
    elif lsb_results.get('status') == 'error':
        print(f"    Error Reason: {lsb_results.get('reason')}")
    elif lsb_results.get('status') == 'skipped':
         print(f"    Skipped Reason: {lsb_results.get('reason')}")


    # Cleanup
    # import shutil
    # shutil.rmtree(DUMMY_TEST_DIR)
    print(f"\nTest files created in {DUMMY_TEST_DIR}. Please remove manually if needed.")

```
