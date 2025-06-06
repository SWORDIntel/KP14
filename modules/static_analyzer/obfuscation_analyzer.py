import logging
import re
import os
import binascii
from collections import Counter, defaultdict

# Assuming configuration_manager is in core_engine and accessible
try:
    from core_engine.configuration_manager import ConfigurationManager
except ImportError:
    ConfigurationManager = None
    logging.getLogger(__name__).warning("ConfigurationManager not found. ObfuscationAnalyzer will use default settings.")

# Placeholder for Hash related data that would come from hash_detector's sub-modules
# In a real scenario, these would be more sophisticated.
DEFAULT_HASH_PATTERNS = {
    # Constants often seen in hashing loops/setups
    "crc32_poly_rev": [rb"\xed\xb8\x83\x20"], # Reversed polynomial for CRC32 (0x04C11DB7 becomes 0xEDB88320)
    "ror13_const": [rb"\x0d"],          # ROR 13 often involves the number 13
    "djb2_init": [rb"\x35\x15\x05\x00"],   # Initial hash value 5381 (0x1505) in little endian (0x0515 actually, 00051535 if LE dword)
                                          # Let's use a more common representation if found directly as dword
                                          # Example: 5381 decimal is 0x1505. As a dword LE: 05150000
    "djb2_magic_mult": [rb"\x21"],      # Multiply by 33 (0x21)
    "common_seed_0": [rb"\x00\x00\x00\x00"], # Zero seed
    "common_seed_ffff": [rb"\xff\xff\xff\xff"], # -1 seed
}
DEFAULT_API_HASH_DB = {
    "kernel32.dll": {
        0xec0e4e8e: "LoadLibraryA",      # DJB2 "LoadLibraryA"
        0x16b3fe72: "CreateProcessA",    # DJB2 "CreateProcessA"
        0x60bd310c: "GetProcAddress",    # DJB2 "GetProcAddress"
        0xdf758009: "VirtualAlloc",      # DJB2 "VirtualAlloc"
        # CRC32 example (actual values would depend on exact CRC32 variant and input)
        0x4E079A64: "LoadLibraryA_CRC32", # Example placeholder
    },
    "advapi32.dll": {
        0x671716af: "RegOpenKeyExA",     # DJB2 "RegOpenKeyExA"
    },
    "user32.dll": {
        0x6314300F: "MessageBoxA",       # DJB2 "MessageBoxA"
    }
}

# Common comparison instructions (opcodes) that might precede a hash value
COMMON_CMP_INSTRUCTIONS_API_HASH = [
    # CMP reg, imm32 (e.g. CMP EAX, 0x12345678)
    b"\x3D",       # CMP EAX, imm32
    b"\x81\xF8",   # CMP EAX, imm32 (alternative form, less common for direct imm32)
    b"\x81\xF9",   # CMP ECX, imm32
    b"\x81\xFA",   # CMP EDX, imm32
    b"\x81\xFB",   # CMP EBX, imm32
    b"\x81\xFE",   # CMP ESI, imm32
    b"\x81\xFF",   # CMP EDI, imm32
    # CMP r/m32, imm32 (e.g. CMP [EBP-4], 0x12345678) - more complex to parse operand
    # For simplicity, we'll only check for immediate dword after these basic opcodes.
    # More advanced would require actual disassembly to confirm it's `cmp reg, imm32`.
]


# Simplified algorithm detection based on patterns
def detect_algorithm_from_matched_patterns(pattern_names):
    # This remains highly simplified. A real system needs more sophisticated logic.
    if "ror13_const" in pattern_names: # If ROR 13 constant is found
        return {"algorithm": "custom_ror13_variant", "confidence": 0.6}
    if "djb2_magic_mult" in pattern_names or "djb2_init" in pattern_names:
        return {"algorithm": "djb2_variant", "confidence": 0.7}
    if "crc32_poly_rev" in pattern_names:
        return {"algorithm": "crc32_variant", "confidence": 0.7}
    if not pattern_names:
        return {"algorithm": "unknown_due_to_no_patterns", "confidence": 0.0}
    return {"algorithm": "unknown_heuristic", "confidence": 0.2} # Some patterns, but not specific

# Simplified hash reversal
def reverse_lookup_hash_simple(hash_value, algorithm_name, api_hash_db):
    found_apis = []
    # Allow matching if algo name contains a keyword e.g. "djb2_variant" matches "djb2"
    algo_key_match = algorithm_name.split('_')[0] # e.g., "djb2" from "djb2_variant"

    for lib, api_hashes in api_hash_db.items():
        for h, name in api_hashes.items():
            if h == hash_value:
                # Check if the API name implies the algorithm for more confidence (optional)
                # Example: if algo_key_match is "crc32" and "_CRC32" is in `name`
                if algo_key_match.lower() in name.lower() or "_variant" in algorithm_name or "_custom" in algorithm_name or "unknown" in algorithm_name :
                    found_apis.append(f"{lib}:{name}")
                elif not name.lower().endswith(("_crc32", "_djb2", "_ror13")): # Generic name, add if algo is generic
                     found_apis.append(f"{lib}:{name}")
    return found_apis


class ObfuscationAnalyzer:
    def __init__(self, config_manager=None):
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager
        self._load_config()

    def _load_config(self):
        # String decoding settings
        self.min_string_length = 4
        self.max_string_length = 100 # For some decoding attempts
        self.xor_keys = [0x01, 0x02, 0x03, 0x07, 0x0A, 0x0D, 0x10, 0x20, 0x33, 0x55, 0x7F, 0xFF]
        self.add_sub_keys = [0x01, 0x02, 0x03, 0x05, 0x07, 0x0A, 0x10, 0x20, 0x30]
        self.rol_ror_bits = [1, 2, 3, 4, 5, 6, 7]
        self.string_score_threshold = 0.5

        # API sequence detection settings
        self.api_sequence_patterns = self._get_default_api_sequences()
        self.min_api_sequence_confidence = 0.5

        # API Hashing settings
        self.api_hash_detection_patterns = DEFAULT_HASH_PATTERNS
        self.api_hash_db = DEFAULT_API_HASH_DB # Simplified
        self.hash_pattern_proximity = 50
        self.min_hash_algo_confidence = 0.5


        if self.config_manager:
            log_level_str = self.config_manager.get('general', 'log_level', fallback='INFO').upper()
            self.logger.setLevel(getattr(logging, log_level_str, logging.INFO))

            # String settings from config
            self.min_string_length = self.config_manager.getint('obfuscation_analyzer', 'min_string_length', fallback=self.min_string_length)
            self.xor_keys = self.config_manager.get('obfuscation_analyzer', 'xor_keys', fallback=self.xor_keys) # Needs parsing if string
            # Similar for add_sub_keys, rol_ror_bits, string_score_threshold

            # API sequence patterns could be loaded from a file path specified in config
            # For now, using defaults.

            # API Hashing patterns could also be expanded/loaded from config
            # self.api_hash_db_path = self.config_manager.get('obfuscation_analyzer', 'api_hash_db_path', fallback=None)
            # if self.api_hash_db_path and os.path.exists(self.api_hash_db_path):
            # try: self.api_hash_db = json.load(open(self.api_hash_db_path)) except: pass

        self.logger.info("ObfuscationAnalyzer initialized.")

    def _get_default_api_sequences(self):
        # From api_sequence_detector.py
        return {
            "c2_communication": [
                {"sequence": ["socket", "connect", "send", "recv"], "description": "Basic C2", "confidence": 0.7},
                {"sequence": ["InternetOpenA", "InternetConnectA", "HttpOpenRequestA", "HttpSendRequestA"], "description": "HTTP C2", "confidence": 0.8},
            ],
            "process_injection": [
                {"sequence": ["OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"], "description": "Classic Injection", "confidence": 0.9},
            ]
            # Add more default patterns as needed
        }

    # --- Encoded String Detection and Decoding ---
    def extract_plain_strings(self, data, min_length=None):
        min_len = min_length if min_length is not None else self.min_string_length
        ascii_pattern = re.compile(b'[ -~]{%d,}' % min_len)
        strings = [(m.start(), m.group().decode('ascii', errors='ignore'), 'ascii') for m in ascii_pattern.finditer(data)]

        unicode_strings = []
        i = 0
        while i < len(data) - (min_len * 2 -1) : # Ensure enough bytes for min_len unicode string
            # Basic check for printable ASCII char followed by null byte
            is_potential_unicode = True
            for k in range(min_len):
                char_offset = i + k*2
                if not (char_offset + 1 < len(data) and 32 <= data[char_offset] <= 126 and data[char_offset+1] == 0):
                    is_potential_unicode = False
                    break

            if is_potential_unicode:
                string_bytes = bytearray()
                temp_i = i
                while temp_i + 1 < len(data) and data[temp_i] >=32 and data[temp_i] <= 126 and data[temp_i+1] == 0:
                    string_bytes.extend(data[temp_i:temp_i+2])
                    temp_i += 2

                if len(string_bytes) // 2 >= min_len:
                    try:
                        unicode_strings.append((i, string_bytes.decode('utf-16le'), 'utf-16le'))
                        i = temp_i # Move past this unicode string
                        continue
                    except UnicodeDecodeError:
                        pass # Not a valid utf-16 string
            i += 1

        strings.extend(unicode_strings)
        strings.sort(key=lambda x: x[0])
        self.logger.info(f"Extracted {len(strings)} plain strings (min_len={min_len}).")
        return strings

    def _decode_and_score_segment(self, segment, encoding_type, key=None):
        """Helper to decode a segment and score it."""
        decoded_strings = []
        if encoding_type == "xor":
            decoded_data = bytes(b ^ key for b in segment)
        elif encoding_type == "add":
            decoded_data = bytes((b + key) & 0xFF for b in segment)
        elif encoding_type == "sub":
            decoded_data = bytes((b - key) & 0xFF for b in segment)
        elif encoding_type == "rol":
            decoded_data = bytes(((b << key) | (b >> (8 - key))) & 0xFF for b in segment)
        elif encoding_type == "ror":
            decoded_data = bytes(((b >> key) | (b << (8 - key))) & 0xFF for b in segment)
        else:
            return []

        # Try to find printable strings in the decoded data
        # Using a simpler regex here as we are working with potentially small segments
        ascii_pattern = re.compile(b'[ -~]{%d,}' % self.min_string_length)
        for match in ascii_pattern.finditer(decoded_data):
            try:
                decoded_str = match.group().decode('ascii')
                score = self._score_decoded_string(decoded_str)
                if score >= self.string_score_threshold:
                    decoded_strings.append({
                        "decoded": decoded_str,
                        "encoding": f"{encoding_type.upper()}-{key if isinstance(key,int) else ''}{str(key) if not isinstance(key,int) else ''}",
                        "score": score,
                        "original_segment_length": len(segment),
                    })
            except UnicodeDecodeError:
                pass
        return decoded_strings

    def attempt_decode_buffer(self, data_buffer, offset_in_file=0):
        """Attempts various decoding techniques on a given data buffer."""
        found_strings = []
        # Iterate through common XOR keys
        for key in self.xor_keys:
            results = self._decode_and_score_segment(data_buffer, "xor", key)
            for r in results: r["offset_in_file"] = offset_in_file + data_buffer.find(r["decoded"].encode('ascii',errors='ignore')) # Approximate offset
            found_strings.extend(results)
        # Iterate through common ADD/SUB keys
        for key in self.add_sub_keys:
            results = self._decode_and_score_segment(data_buffer, "add", key)
            for r in results: r["offset_in_file"] = offset_in_file # Offset is of the buffer
            found_strings.extend(results)
            results = self._decode_and_score_segment(data_buffer, "sub", key)
            for r in results: r["offset_in_file"] = offset_in_file
            found_strings.extend(results)
        # Iterate through common ROL/ROR bits
        for bits in self.rol_ror_bits:
            results = self._decode_and_score_segment(data_buffer, "rol", bits)
            for r in results: r["offset_in_file"] = offset_in_file
            found_strings.extend(results)
            results = self._decode_and_score_segment(data_buffer, "ror", bits)
            for r in results: r["offset_in_file"] = offset_in_file
            found_strings.extend(results)

        # Sort by score and remove duplicates (based on string and offset)
        unique_strings = []
        seen = set()
        for s in sorted(found_strings, key=lambda x: x['score'], reverse=True):
            # Crude uniqueness for this example
            # A better way would be to check if the decoded string at that offset with that encoding was already found.
            # For now, just decoded string content.
            if s['decoded'] not in seen:
                unique_strings.append(s)
                seen.add(s['decoded'])

        return unique_strings

    def _score_decoded_string(self, s):
        """Scores a decoded string based on heuristics (e.g., looks like API name, path, etc.)."""
        # Adapted from EncodedStringDetector._score_potential_api_string
        score = 0.0
        if not s or len(s) < self.min_string_length: return 0.0

        if re.search(r'[a-z][A-Z]', s): score += 0.2 # CamelCase
        if any(s.startswith(p) for p in ["Create", "Get", "Set", "Open", "Read", "Write", "Load", "Reg", "Http"]): score += 0.25
        if any(s.endswith(suf) for suf in ["A", "W", "Ex", "ExA", "ExW", "Proc", "Func"]): score += 0.15
        if any(dll in s.lower() for dll in ["kernel32", "user32", "advapi32", "ntdll", "ws2_32", "wininet"]): score += 0.1
        if 6 <= len(s) <= 35: score += 0.1 # Typical API/path length
        if re.match(r'^[a-zA-Z0-9_.:\\/\-]+$', s): score += 0.1 # Common chars in paths/apis
        if sum(1 for c in s if not c.isalnum() and c not in '_.:\\/-') > 0: score -= 0.1 # Penalize too many other symbols
        if any(api in s for api in ["VirtualAlloc", "CreateProcess", "LoadLibrary", "GetProcAddress"]): score += 0.3
        return min(1.0, max(0.0, score)) # Ensure score is [0,1]

    # --- API Sequence Detection ---
    def detect_api_sequences(self, api_call_trace):
        """
        Detects known malicious API sequences in a given trace of API calls.
        api_call_trace: A list of strings, where each string is an API name.
        """
        detected_sequences = []
        if not api_call_trace: return []

        for category, patterns in self.api_sequence_patterns.items():
            for pattern_info in patterns:
                sequence = pattern_info["sequence"]
                confidence = pattern_info.get("confidence", 0.5)
                description = pattern_info.get("description", "")

                if confidence < self.min_api_sequence_confidence: continue

                # Find all occurrences of this sequence in the trace
                for i in range(len(api_call_trace) - len(sequence) + 1):
                    sub_trace = api_call_trace[i : i + len(sequence)]
                    if sub_trace == sequence:
                        detected_sequences.append({
                            "category": category,
                            "sequence": sequence,
                            "description": description,
                            "confidence": confidence,
                            "start_index_in_trace": i,
                        })
                        self.logger.debug(f"Matched API sequence: {category} - {description} at index {i}")

        self.logger.info(f"Detected {len(detected_sequences)} API sequences.")
        return detected_sequences

    # --- API Hash Detection ---
    def detect_api_hashing(self, data_buffer):
        """
        Detects API hashing algorithms and resolves hashes from a data buffer.
        This is a simplified version based on hash_detector.py.
        """
        # 1. Detect hashing algorithm patterns
        matched_patterns_info = []
        for pattern_name, byte_patterns in self.api_hash_detection_patterns.items():
            for byte_pattern in byte_patterns:
                for match in re.finditer(re.escape(byte_pattern), data_buffer): # re.escape for literal bytes
                    matched_patterns_info.append({
                        "name": pattern_name,
                        "offset": match.start(),
                        "pattern_length": len(byte_pattern)
                    })

        # Group patterns (simplified: just collect all pattern names for now)
        # A real implementation would group by proximity as in hash_detector.py
        if not matched_patterns_info:
            self.logger.info("No API hashing patterns found.")
            return {"algorithms": [], "resolved_apis": []}

        # For simplicity, assume all matched patterns in buffer belong to one algo attempt
        all_pattern_names = list(set(p['name'] for p in matched_patterns_info))
        detected_algo = detect_algorithm_from_matched_patterns(all_pattern_names)

        if detected_algo['confidence'] < self.min_hash_algo_confidence:
            self.logger.info(f"Detected hashing patterns, but algorithm confidence too low: {detected_algo}")
            return {"algorithms": [detected_algo] if detected_algo['algorithm'] != 'unknown' else [], "resolved_apis": []}

        self.logger.info(f"Potentially detected hashing algorithm: {detected_algo}")

        # 2. Find potential hash values (32-bit constants near CMP-like instructions)
        # This is highly simplified. Real hash finding is complex.
        potential_hashes = []
        # Example: find dwords after a common compare `cmp eax, dword_val` (0x3D <dword>)
        # Or `cmp [reg+off], dword_val` (e.g. 0x81 0x78 0x04 <dword> for cmp [eax+4], dword)
        # This requires disassembly context. For a buffer, we just look for dwords.
        # This is a placeholder for a more robust search.
        for i in range(len(data_buffer) - 3):
            # Heuristic: if a dword looks like a typical hash (not too small, not too large like pointers)
            # This is extremely naive.
            dword_val = int.from_bytes(data_buffer[i:i+4], 'little')
            if 0x1000 < dword_val < 0xFFFFFFFF and dword_val not in [0x7fffffff, 0x80000000]: # Avoid common non-hash values
                potential_hashes.append({"value": dword_val, "offset": i})

        # 3. Resolve hashes
        resolved_apis = []
        if detected_algo['algorithm'] != 'unknown':
            for ph in potential_hashes:
                api_names = reverse_lookup_hash_simple(ph['value'], detected_algo['algorithm'], self.api_hash_db)
                if api_names:
                    resolved_apis.append({
                        "hash_value": ph['value'],
                        "offset": ph['offset'],
                        "algorithm": detected_algo['algorithm'],
                        "resolved_names": api_names
                    })
        self.logger.info(f"Resolved {len(resolved_apis)} API hashes using algorithm {detected_algo['algorithm']}.")
        return {"algorithms": [detected_algo], "resolved_apis": resolved_apis}

    def analyze_obfuscation(self, data_buffer, api_call_trace=None, offset_in_file=0):
        """
        Performs a comprehensive obfuscation analysis on the data buffer.
        """
        self.logger.info(f"Starting obfuscation analysis for buffer of size {len(data_buffer)} at offset {hex(offset_in_file)}.")

        plain_strings = self.extract_plain_strings(data_buffer)
        decoded_strings_results = self.attempt_decode_buffer(data_buffer, offset_in_file)
        api_hashing_results = self.detect_api_hashing(data_buffer) # This is on the buffer, not full file context

        api_sequence_results = []
        if api_call_trace: # API sequence detection needs a list of API calls
            api_sequence_results = self.detect_api_sequences(api_call_trace)
        else:
            self.logger.info("No API call trace provided, skipping API sequence detection.")

        return {
            "plain_strings": plain_strings,
            "decoded_strings": decoded_strings_results,
            "api_hashing": api_hashing_results,
            "api_sequences": api_sequence_results
        }


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Example usage:
    # Create dummy settings for testing
    dummy_settings_content = """
[general]
log_level = DEBUG
[obfuscation_analyzer]
min_string_length = 5
string_score_threshold = 0.6
# xor_keys = [0x41, 0x42, 0x43] # Example of overriding
    """
    dummy_settings_file = "dummy_obfuscation_settings.ini"
    if not os.path.exists(dummy_settings_file):
        with open(dummy_settings_file, 'w') as f:
            f.write(dummy_settings_content)

    mock_cm = None
    if ConfigurationManager:
        try:
            mock_cm = ConfigurationManager(settings_path=dummy_settings_file)
            logging.info("Successfully loaded dummy_obfuscation_settings.ini for ObfuscationAnalyzer test.")
        except Exception as e:
            logging.error(f"Failed to load dummy_obfuscation_settings.ini: {e}")

    analyzer = ObfuscationAnalyzer(config_manager=mock_cm)

    # 1. Test String Decoding
    sample_data_xor = bytes([c ^ 0x41 for c in b"Kernel32.dll"]) # XORed "Kernel32.dll"
    sample_data_add = bytes([(c + 0x5) & 0xFF for c in b"LoadLibraryA"])
    sample_data_combined = sample_data_xor + b"\x00\x00" + sample_data_add

    logging.info("\n--- Testing String Decoding ---")
    decoded = analyzer.attempt_decode_buffer(sample_data_combined)
    for s in decoded:
        logging.info(f"  Decoded: '{s['decoded']}' (Encoding: {s['encoding']}, Score: {s['score']:.2f}, Offset: {s.get('offset_in_file',0)})")

    # 2. Test API Sequence Detection
    logging.info("\n--- Testing API Sequence Detection ---")
    sample_api_trace = ["SomeApi", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "CloseHandle"]
    sequences = analyzer.detect_api_sequences(sample_api_trace)
    for seq_info in sequences:
        logging.info(f"  Detected Sequence: {seq_info['description']} ({seq_info['category']}) - {' -> '.join(seq_info['sequence'])}")

    # 3. Test API Hashing Detection (very simplified)
    logging.info("\n--- Testing API Hashing Detection ---")
    # Create data with a known hash (djb2 for LoadLibraryA = 0xec0e4e8e) and a "pattern"
    # Pattern: ROR13_VAL (0x0d)
    # Hash: 0xec0e4e8e (little endian: 8e4e0eec)
    sample_hash_data = b"\x50\x51\x52" + DEFAULT_HASH_PATTERNS["ror13_val"][0] + b"\x58\x59" + b"\x8e\x4e\x0e\xec" + b"\x5a"
    hashing_info = analyzer.detect_api_hashing(sample_hash_data)
    logging.info(f"  Detected algorithms: {hashing_info['algorithms']}")
    for resolved in hashing_info['resolved_apis']:
        logging.info(f"  Resolved API: Hash 0x{resolved['hash_value']:x} -> {resolved['resolved_names']} at offset 0x{resolved['offset']:x}")

    # 4. Test Full Analysis
    logging.info("\n--- Testing Full Obfuscation Analysis ---")
    full_results = analyzer.analyze_obfuscation(sample_data_combined, api_call_trace=sample_api_trace)
    logging.info(f"  Found {len(full_results['plain_strings'])} plain strings.")
    logging.info(f"  Found {len(full_results['decoded_strings'])} decoded strings.")
    logging.info(f"  Hashing Algos: {len(full_results['api_hashing']['algorithms'])}")
    logging.info(f"  Resolved Hashes: {len(full_results['api_hashing']['resolved_apis'])}")
    logging.info(f"  Detected API Sequences: {len(full_results['api_sequences'])}")

    # Cleanup
    if os.path.exists(dummy_settings_file):
        os.remove(dummy_settings_file)
```
