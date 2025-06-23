import logging
import os
import zipfile
import io
import struct # For unpacking values from PE header

# Assuming configuration_manager is in core_engine and accessible
try:
    from core_engine.configuration_manager import ConfigurationManager
except ImportError:
    ConfigurationManager = None
    logging.getLogger(__name__).warning("ConfigurationManager not found. PolyglotAnalyzer will use default settings.")

# Known signatures for common file types / payloads
# PE file signatures
PE_SIGNATURE_MZ = b'MZ'
PE_SIGNATURE_PE = b'PE\0\0'

# JPEG signatures
JPEG_SOI = b'\xFF\xD8'
JPEG_EOI = b'\xFF\xD9'

# ZIP signature
ZIP_SIGNATURE = b'PK\x03\x04'


class PolyglotAnalyzer:
    def __init__(self, config_manager=None):
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager
        self._load_config()

    def _load_config(self):
        self.supported_carrier_types = ['zip', 'jpeg', 'generic'] # generic for any file type
        self.min_payload_size_heuristic = 64 # Minimum size for a heuristically found payload to be considered
        self.entropy_threshold = 7.0 # For entropy-based detection (if used)

        if self.config_manager:
            log_level_str = self.config_manager.get('general', 'log_level', fallback='INFO').upper()
            self.logger.setLevel(getattr(logging, log_level_str, logging.INFO))

            self.supported_carrier_types = self.config_manager.get(
                'polyglot_analyzer', 'supported_carriers', fallback="zip,jpeg,generic"
            ).split(',')
            self.min_payload_size_heuristic = self.config_manager.getint(
                'polyglot_analyzer', 'min_payload_size', fallback=self.min_payload_size_heuristic
            )
            self.entropy_threshold = self.config_manager.getfloat(
                 'polyglot_analyzer', 'entropy_threshold', fallback=self.entropy_threshold
            )
        else:
            logging.basicConfig(level=logging.INFO)
            self.logger.info("PolyglotAnalyzer initialized without ConfigurationManager. Using default settings.")
        self.logger.info(f"PolyglotAnalyzer initialized. Supported carriers: {self.supported_carrier_types}")

    def _get_file_type(self, file_data):
        """Rudimentary file type detection using magic numbers."""
        if file_data.startswith(ZIP_SIGNATURE):
            return 'zip'
        elif file_data.startswith(JPEG_SOI):
            return 'jpeg'
        # Add more types as needed (ELF, PDF, Office docs, etc.)
        elif file_data.startswith(PE_SIGNATURE_MZ): # Could be a PE file itself
            return 'pe'
        return 'unknown'

    def analyze_file(self, file_path, file_data=None):
        """
        Analyzes a file to find embedded payloads.
        Returns a list of extracted payloads, each as a dict with:
        {'data': bytes, 'offset': int, 'type_desc': str, 'carrier_type': str}
        """
        if file_data is None:
            try:
                with open(file_path, 'rb') as f:
                    file_data = f.read()
            except IOError as e:
                self.logger.error(f"Could not read file {file_path}: {e}")
                return []

        self.logger.info(f"Analyzing file: {file_path if file_path else 'memory buffer'} for polyglot payloads.")
        extracted_payloads = []
        primary_file_type = self._get_file_type(file_data)
        self.logger.debug(f"Detected primary file type: {primary_file_type}")

        if 'zip' in self.supported_carrier_types and primary_file_type == 'zip':
            payloads = self._extract_from_zip(file_data, file_path)
            extracted_payloads.extend(payloads)

        if 'jpeg' in self.supported_carrier_types and primary_file_type == 'jpeg':
            payloads = self._extract_from_jpeg(file_data, file_path)
            extracted_payloads.extend(payloads)

        # Always run generic PE search unless it's a PE file itself (to avoid extracting itself)
        # or if it's a ZIP (PEs inside ZIPs handled by _extract_from_zip recursively)
        if 'generic' in self.supported_carrier_types and primary_file_type not in ['pe', 'zip']:
            generic_payloads = self._find_generic_pe_payloads(file_data, file_path)
            extracted_payloads.extend(generic_payloads)

        # If the file itself is a PE, we might want to treat it as a "payload" in some contexts,
        # but typically PolyglotAnalyzer is for finding payloads *within* other files.
        # For now, if it's just a PE, we don't extract anything further from it here.

        self.logger.info(f"Found {len(extracted_payloads)} potential payloads in {file_path if file_path else 'memory buffer'}.")
        return extracted_payloads

    def _extract_from_zip(self, zip_file_data, original_file_path="memory_zip"):
        """Extracts payloads from members of a ZIP archive."""
        payloads = []
        try:
            with zipfile.ZipFile(io.BytesIO(zip_file_data), 'r') as zf:
                member_names = zf.namelist()
                self.logger.info(f"Found {len(member_names)} members in ZIP: {original_file_path}")
                for member_name in member_names:
                    self.logger.debug(f"Analyzing ZIP member: {member_name}")
                    try:
                        with zf.open(member_name) as member_file:
                            member_data = member_file.read()
                            # Recursively analyze or specifically look for PEs in members
                            # For now, let's just look for PEs directly in uncompressed members
                            # A more advanced version could determine member type and re-run full analysis.
                            member_pe_payloads = self._find_generic_pe_payloads(
                                member_data,
                                source_description=f"ZIP:{original_file_path}/{member_name}"
                            )
                            for payload_info in member_pe_payloads:
                                payload_info['carrier_type'] = f"zip_member ({member_name})"
                                payloads.append(payload_info)
                    except Exception as e:
                        self.logger.error(f"Failed to process member {member_name} in {original_file_path}: {e}")
        except zipfile.BadZipFile:
            self.logger.error(f"Not a valid ZIP file or corrupt: {original_file_path}")
        except Exception as e:
            self.logger.error(f"Error processing ZIP file {original_file_path}: {e}")
        return payloads

    def _extract_from_jpeg(self, jpeg_data, original_file_path="memory_jpeg"):
        """Extracts payloads from JPEG files (e.g., appended data)."""
        # Adapted from keyplug_extractor.extract_jpeg_payload (appended data part)
        payloads = []
        if not jpeg_data.startswith(JPEG_SOI):
            self.logger.warning(f"Data for {original_file_path} does not start with JPEG SOI.")
            return []

        eoi_pos = jpeg_data.rfind(JPEG_EOI)
        if eoi_pos != -1:
            appended_data_offset = eoi_pos + len(JPEG_EOI)
            if appended_data_offset < len(jpeg_data):
                appended_data = jpeg_data[appended_data_offset:]
                if len(appended_data) >= self.min_payload_size_heuristic:
                    self.logger.info(f"Found {len(appended_data)} bytes of appended data in JPEG: {original_file_path}")
                    payloads.append({
                        'data': appended_data,
                        'offset': appended_data_offset,
                        'type_desc': 'appended_to_jpeg_eoi',
                        'carrier_file': original_file_path,
                        'carrier_type': 'jpeg'
                    })
                    # Potentially scan this appended_data for PE files too
                    pe_in_appended = self._find_generic_pe_payloads(
                        appended_data,
                        source_description=f"appended_data_in_JPEG:{original_file_path}@0x{appended_data_offset:x}"
                    )
                    for pe_info in pe_in_appended:
                        pe_info['offset'] += appended_data_offset # Adjust offset relative to original file
                        pe_info['carrier_type'] = 'jpeg_appended_data'
                        payloads.append(pe_info)
                else:
                    self.logger.debug(f"Small amount of appended data ({len(appended_data)} bytes) found in JPEG, ignoring.")
        else:
            self.logger.debug(f"No JPEG EOI marker found in {original_file_path}.")

        # Placeholder for more advanced JPEG analysis (e.g., high entropy segments)
        # This would require calculate_entropy and more complex logic from keyplug_extractor
        return payloads

    def _find_generic_pe_payloads(self, data_buffer, source_description="current_file"):
        """
        Finds PE files embedded within a generic data buffer.
        Adapted from keyplug_extractor.find_embedded_pe.
        """
        payloads = []
        # Look for MZ header
        current_offset = 0
        while True:
            mz_offset_in_buffer = data_buffer.find(PE_SIGNATURE_MZ, current_offset)
            if mz_offset_in_buffer == -1:
                break # No more MZ headers

            # Check for PE signature
            # e_lfanew is at MZ_offset + 0x3C
            if mz_offset_in_buffer + 0x3C + 4 > len(data_buffer):
                current_offset = mz_offset_in_buffer + len(PE_SIGNATURE_MZ) # Move past this MZ
                continue

            try:
                pe_header_offset_in_mz = struct.unpack("<I", data_buffer[mz_offset_in_buffer + 0x3C : mz_offset_in_buffer + 0x3C + 4])[0]
                pe_signature_offset_in_buffer = mz_offset_in_buffer + pe_header_offset_in_mz

                if pe_signature_offset_in_buffer + len(PE_SIGNATURE_PE) <= len(data_buffer) and \
                   data_buffer[pe_signature_offset_in_buffer : pe_signature_offset_in_buffer + len(PE_SIGNATURE_PE)] == PE_SIGNATURE_PE:

                    # Found a PE file. For now, we'll just carve from MZ to end of buffer.
                    # A more robust way would be to parse PE headers to find SizeOfImage.
                    # For simplicity here, we take a large chunk or to the end.
                    # This is a simplified extraction.
                    extracted_pe_data = data_buffer[mz_offset_in_buffer:]

                    self.logger.info(f"Found embedded PE signature (MZ at 0x{mz_offset_in_buffer:x}) in {source_description}")
                    payloads.append({
                        'data': extracted_pe_data,
                        'offset': mz_offset_in_buffer,
                        'type_desc': 'embedded_pe_file',
                        'carrier_file': source_description, # This might be a path or "memory_buffer"
                        'carrier_type': 'generic_buffer' # Or more specific if known
                    })
                    # To avoid finding the same PE again if it's part of a larger extracted PE
                    current_offset = mz_offset_in_buffer + len(extracted_pe_data) # Skip past this found PE
                    # A better skip would be based on PE's SizeOfImage if parsed.
                else:
                    current_offset = mz_offset_in_buffer + len(PE_SIGNATURE_MZ) # Move past this MZ
            except struct.error: # Error unpacking e_lfanew, likely not a real PE
                current_offset = mz_offset_in_buffer + len(PE_SIGNATURE_MZ)
            except Exception as e:
                self.logger.debug(f"Error validating potential PE at offset {mz_offset_in_buffer} in {source_description}: {e}")
                current_offset = mz_offset_in_buffer + len(PE_SIGNATURE_MZ)
        return payloads


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Create dummy files for testing
    DUMMY_TEST_DIR = "polyglot_test_files"
    os.makedirs(DUMMY_TEST_DIR, exist_ok=True)

    DUMMY_JPEG_PATH = os.path.join(DUMMY_TEST_DIR, "test.jpg")
    DUMMY_ZIP_PATH = os.path.join(DUMMY_TEST_DIR, "test.zip")
    DUMMY_PE_PAYLOAD = PE_SIGNATURE_MZ + (b'\x00' * (0x3C - 2)) + b'\x40\x00\x00\x00' + \
                       (b'\x00' * (0x40 - 0x3C - 4)) + \
                       PE_SIGNATURE_PE + (b'\x00' * 100) # Minimal PE structure

    # Create dummy JPEG with appended PE
    with open(DUMMY_JPEG_PATH, 'wb') as f:
        f.write(JPEG_SOI)
        f.write(b"\x00\x01\x02\x03\x04\x05\x06\x07") # Some dummy JPEG data
        f.write(JPEG_EOI)
        f.write(DUMMY_PE_PAYLOAD)

    # Create dummy ZIP with a JPEG (that itself has appended data) and a direct PE
    with zipfile.ZipFile(DUMMY_ZIP_PATH, 'w') as zf:
        zf.writestr("image.jpg", JPEG_SOI + b"somedata" + JPEG_EOI + b"appended_text_to_image")
        zf.writestr("payload.exe", DUMMY_PE_PAYLOAD)
        zf.writestr("config.txt", b"This is a config file.")

    # --- Test PolyglotAnalyzer ---
    analyzer = PolyglotAnalyzer(config_manager=None) # No CM for this simple test

    print(f"\n--- Analyzing JPEG: {DUMMY_JPEG_PATH} ---")
    jpeg_payloads = analyzer.analyze_file(DUMMY_JPEG_PATH)
    for i, p_info in enumerate(jpeg_payloads):
        print(f"  Payload {i+1}: Type='{p_info['type_desc']}', Offset=0x{p_info['offset']:x}, Size={len(p_info['data'])}")
        if p_info['type_desc'] == 'embedded_pe_file':
            print(f"    PE Check: Starts with MZ = {p_info['data'].startswith(PE_SIGNATURE_MZ)}")

    print(f"\n--- Analyzing ZIP: {DUMMY_ZIP_PATH} ---")
    zip_payloads = analyzer.analyze_file(DUMMY_ZIP_PATH)
    for i, p_info in enumerate(zip_payloads):
        print(f"  Payload {i+1}: Carrier='{p_info['carrier_type']}', Type='{p_info['type_desc']}', Offset=0x{p_info['offset']:x} (in member), Size={len(p_info['data'])}")
        if p_info['type_desc'] == 'embedded_pe_file':
            print(f"    PE Check: Starts with MZ = {p_info['data'].startswith(PE_SIGNATURE_MZ)}")

    # Cleanup
    # import shutil
    # shutil.rmtree(DUMMY_TEST_DIR)
    print(f"\nTest files created in {DUMMY_TEST_DIR}. Please remove manually if needed.")

```
