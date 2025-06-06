import logging
import os

# Assuming configuration_manager is in core_engine and accessible
try:
    from core_engine.configuration_manager import ConfigurationManager
except ImportError:
    ConfigurationManager = None
    logging.getLogger(__name__).warning("ConfigurationManager not found. CryptoAnalyzer will use default settings.")


class CryptoAnalyzer:
    def __init__(self, config_manager=None):
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager
        self.known_keys = {}
        self.decryption_chains = {}
        self._load_config()

    def _load_config(self):
        if self.config_manager:
            log_level_str = self.config_manager.get('general', 'log_level', fallback='INFO').upper()
            self.logger.setLevel(getattr(logging, log_level_str, logging.INFO))

            # Load known keys (example structure in settings.ini)
            # [crypto_analyzer_keys]
            # key_payload1_hex = "9ed3a5"
            # key_payload2_utf8 = "secret"
            if self.config_manager.get_section('crypto_analyzer_keys'):
                for key_name, key_value_spec in self.config_manager.get_section('crypto_analyzer_keys').items():
                    self.known_keys[key_name] = self._parse_key_value_spec(key_value_spec)

            # Load predefined decryption chains
            # [decryption_chains]
            # chain_type1 = xor_hex:aa, rc4_known:key_payload1_hex, xor_int:0x41
            if self.config_manager.get_section('decryption_chains'):
                for chain_name, chain_spec_str in self.config_manager.get_section('decryption_chains').items():
                    try:
                        self.decryption_chains[chain_name] = self._parse_decryption_chain_spec(chain_spec_str)
                    except ValueError as e:
                        self.logger.error(f"Error parsing decryption chain '{chain_name}': {e}")
        else:
            logging.basicConfig(level=logging.INFO) # Default if no CM
            self.logger.info("CryptoAnalyzer initialized without ConfigurationManager. Using default settings/no preloaded keys.")

        self.logger.info(f"CryptoAnalyzer initialized. Loaded {len(self.known_keys)} known keys and {len(self.decryption_chains)} decryption chains.")

    def _parse_key_value_spec(self, key_value_spec):
        """ Parses a key value which might be 'hex:aabbcc', 'utf8:text', or 'bytes:[0xaa,0xbb]' """
        if isinstance(key_value_spec, str):
            parts = key_value_spec.split(':', 1)
            key_type = parts[0].lower()
            if len(parts) == 2:
                value_str = parts[1]
                try:
                    if key_type == 'hex':
                        return bytes.fromhex(value_str)
                    elif key_type == 'utf8' or key_type == 'utf-8':
                        return value_str.encode('utf-8')
                    elif key_type == 'bytes': # e.g., bytes:[0xaa, 0xbb, 0xcc] or bytes:[aa,bb,cc]
                        return bytes([int(b, 0) for b in value_str.strip('[]').split(',')])
                    else: # Assume raw string as key if no type specifier, or unknown type
                        self.logger.warning(f"Unknown key type '{key_type}' in spec '{key_value_spec}'. Treating value as raw UTF-8 string.")
                        return value_str.encode('utf-8') # Default to treating as string
                except ValueError as e:
                    self.logger.error(f"Invalid value for key type '{key_type}' in '{key_value_spec}': {e}")
                    return None # Or raise error
            else: # No type specifier, assume raw string
                return key_value_spec.encode('utf-8')
        return key_value_spec # If already bytes or other type

    def _parse_decryption_chain_spec(self, chain_spec_str):
        """ Parses a comma-separated chain string like 'xor_hex:aa,rc4_known:key1' """
        steps = []
        for step_str in chain_spec_str.split(','):
            step_str = step_str.strip()
            parts = step_str.split(':', 1)
            if len(parts) != 2:
                raise ValueError(f"Invalid step format '{step_str}'. Expected 'type:value'.")

            op_type_full, op_value_str = parts[0].lower(), parts[1]
            step_details = {"value_raw": op_value_str} # Store raw value for reference

            if op_type_full.startswith("xor"):
                step_details["type"] = "xor"
                if op_type_full == "xor_hex":
                    step_details["key_type"] = "hex"
                elif op_type_full == "xor_utf8":
                    step_details["key_type"] = "utf8"
                elif op_type_full == "xor_int":
                    step_details["key_type"] = "int"
                elif op_type_full == "xor_known": # Points to a key in self.known_keys
                    step_details["key_type"] = "known"
                else: # Default xor implies hex key if not int
                    try: int(op_value_str,0); step_details["key_type"] = "int"
                    except: step_details["key_type"] = "hex"
            elif op_type_full.startswith("rc4"):
                step_details["type"] = "rc4"
                if op_type_full == "rc4_hex":
                    step_details["key_type"] = "hex"
                elif op_type_full == "rc4_utf8":
                    step_details["key_type"] = "utf8"
                elif op_type_full == "rc4_known":
                    step_details["key_type"] = "known"
                else: # Default rc4 implies hex key
                    step_details["key_type"] = "hex"
            # Add other types like 'aes' here if needed
            else:
                raise ValueError(f"Unsupported decryption type in step: {op_type_full}")
            steps.append(step_details)
        return steps

    def _resolve_key_for_step(self, step_details):
        key_type = step_details.get("key_type", "hex") # Default to hex
        op_value_str = step_details["value_raw"]

        if key_type == "hex":
            return bytes.fromhex(op_value_str)
        elif key_type == "utf8":
            return op_value_str.encode('utf-8')
        elif key_type == "int":
            return int(op_value_str, 0) # Allow 0x prefix for hex ints
        elif key_type == "known":
            if op_value_str in self.known_keys:
                key = self.known_keys[op_value_str]
                if key is None: raise ValueError(f"Known key '{op_value_str}' resolved to None (likely parsing error).")
                return key
            else:
                raise ValueError(f"Unknown key alias '{op_value_str}' in decryption step.")
        elif key_type == "bytes_literal": # Actual bytes passed directly
            return step_details["key_bytes"]
        else:
            raise ValueError(f"Unsupported key type '{key_type}' in step resolution.")


    def _rc4_decrypt(self, data: bytes, key: bytes) -> bytes:
        """Manual RC4 decryption implementation."""
        S = list(range(256))
        j = 0
        # Key Scheduling Algorithm (KSA)
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]

        # Pseudo-Random Generation Algorithm (PRGA) and decryption
        i = 0
        j = 0
        decrypted_data = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            keystream_byte = S[(S[i] + S[j]) % 256]
            decrypted_data.append(byte ^ keystream_byte)
        return bytes(decrypted_data)

    def _xor_decrypt(self, data: bytes, key) -> bytes:
        """XOR decryption. Key can be int (single-byte) or bytes (multi-byte)."""
        if isinstance(key, int):
            # Ensure single byte XOR key is within byte range
            k = key & 0xFF
            return bytes([b ^ k for b in data])
        elif isinstance(key, bytes):
            if not key: # Empty key
                self.logger.warning("XOR decryption attempted with empty key. Returning original data.")
                return data
            key_len = len(key)
            return bytes([data[i] ^ key[i % key_len] for i in range(len(data))])
        else:
            raise TypeError("XOR key must be int or bytes.")

    def decrypt(self, data: bytes, decryption_steps: list) -> bytes:
        """
        Applies a sequence of decryption steps to the data.
        Each step in decryption_steps is a dictionary, e.g.:
        {'type': 'xor', 'key_type': 'hex', 'value_raw': 'aabbcc'}
        {'type': 'rc4', 'key_type': 'utf8', 'value_raw': 'secret'}
        {'type': 'xor', 'key_type': 'int', 'value_raw': '0x41'}
        {'type': 'rc4', 'key_type': 'known', 'value_raw': 'my_saved_rc4_key'}
        {'type': 'xor', 'key_type': 'bytes_literal', 'key_bytes': b'\x01\x02'}
        """
        current_data = data
        self.logger.info(f"Starting decryption process with {len(decryption_steps)} step(s).")

        for i, step_details in enumerate(decryption_steps):
            step_type = step_details.get("type", "").lower()
            self.logger.debug(f"Step {i+1}: Type '{step_type}', Details: {step_details}")

            try:
                key = self._resolve_key_for_step(step_details)

                if step_type == "xor":
                    current_data = self._xor_decrypt(current_data, key)
                    self.logger.debug(f"Applied XOR with key (type: {step_details.get('key_type')}). Data size: {len(current_data)}")
                elif step_type == "rc4":
                    if isinstance(key, int): # RC4 key must be bytes
                        self.logger.error(f"RC4 key for step {i+1} resolved to an integer. RC4 keys must be bytes.")
                        raise ValueError("RC4 key must be bytes, not int.")
                    current_data = self._rc4_decrypt(current_data, key)
                    self.logger.debug(f"Applied RC4. Data size: {len(current_data)}")
                # Add other decryption types like 'aes' here
                # elif step_type == "aes":
                #     current_data = self._aes_decrypt(current_data, key, step_details.get('mode'), ...)
                else:
                    self.logger.error(f"Unsupported decryption type '{step_type}' in step {i+1}.")
                    raise ValueError(f"Unsupported decryption type: {step_type}")
            except Exception as e:
                self.logger.error(f"Error during decryption step {i+1} ({step_type}): {e}", exc_info=True)
                # Optionally, re-raise or return partially decrypted data with error status
                raise # Re-raise to indicate failure

        self.logger.info("Decryption process completed.")
        return current_data

    def try_known_decryption_chains(self, data: bytes):
        """Tries all preloaded decryption chains on the data."""
        results = {}
        if not self.decryption_chains:
            self.logger.info("No predefined decryption chains to try.")
            return results

        self.logger.info(f"Trying {len(self.decryption_chains)} known decryption chain(s).")
        for chain_name, steps in self.decryption_chains.items():
            self.logger.debug(f"Attempting chain: {chain_name}")
            try:
                decrypted_data = self.decrypt(data, steps)
                results[chain_name] = decrypted_data
                # Optionally, add a heuristic here to check if decryption was "successful"
                # (e.g., high number of printable chars, known file signature, specific string)
                self.logger.info(f"Successfully applied chain '{chain_name}'.")
            except Exception as e:
                self.logger.warning(f"Chain '{chain_name}' failed: {e}")
                results[chain_name] = None # Indicate failure for this chain
        return results


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # Example usage:
    # Create dummy settings for testing
    dummy_settings_content = """
[general]
log_level = DEBUG

[crypto_analyzer_keys]
key1_hex = "deadbeef"
key2_utf8 = "secret"
key3_int = "0x41" # Single byte for XOR

[decryption_chains]
chain1 = xor_hex:112233, rc4_known:key2_utf8
chain2 = rc4_known:key1_hex, xor_known:key3_int
chain_bad = xor_hex:notvalid, rc4_known:nonexistentkey
    """
    dummy_settings_file = "dummy_crypto_settings.ini"
    if not os.path.exists(dummy_settings_file):
        with open(dummy_settings_file, 'w') as f:
            f.write(dummy_settings_content)

    mock_cm = None
    if ConfigurationManager:
        try:
            mock_cm = ConfigurationManager(settings_path=dummy_settings_file)
            logging.info("Successfully loaded dummy_crypto_settings.ini for CryptoAnalyzer test.")
        except Exception as e:
            logging.error(f"Failed to load dummy_crypto_settings.ini: {e}")

    analyzer = CryptoAnalyzer(config_manager=mock_cm)

    # 1. Test direct decryption
    logging.info("\n--- Testing Direct Decryption ---")
    original_data = b"Hello, World! This is a test."
    xor_key_bytes = b"\xAA\xBB\xCC"
    rc4_key_bytes = b"mysecretkey"

    # XOR -> RC4
    steps1 = [
        {"type": "xor", "key_type": "bytes_literal", "key_bytes": xor_key_bytes},
        {"type": "rc4", "key_type": "bytes_literal", "key_bytes": rc4_key_bytes}
    ]
    encrypted_s1 = analyzer._rc4_decrypt(analyzer._xor_decrypt(original_data, xor_key_bytes), rc4_key_bytes)
    decrypted_s1 = analyzer.decrypt(encrypted_s1, steps1)
    assert decrypted_s1 == original_data
    logging.info(f"Direct XOR->RC4 Decryption successful: {decrypted_s1 == original_data}")

    # RC4 -> XOR (single byte int)
    steps2 = [
        {"type": "rc4", "key_type": "bytes_literal", "key_bytes": rc4_key_bytes},
        {"type": "xor", "key_type": "int", "value_raw": "0x55"} # Use value_raw as it's parsed by _resolve_key
    ]
    encrypted_s2 = analyzer._xor_decrypt(analyzer._rc4_decrypt(original_data, rc4_key_bytes), 0x55)
    decrypted_s2 = analyzer.decrypt(encrypted_s2, steps2)
    assert decrypted_s2 == original_data
    logging.info(f"Direct RC4->XOR_int Decryption successful: {decrypted_s2 == original_data}")

    # 2. Test predefined chains (if config loaded)
    if mock_cm and analyzer.decryption_chains:
        logging.info("\n--- Testing Predefined Decryption Chains ---")
        # To test chain1: original -> xor with 0x112233 -> rc4 with "secret"
        # We need to encrypt it first to test decryption
        key_112233 = bytes.fromhex("112233")
        key_secret = "secret".encode('utf-8')

        encrypted_for_chain1 = analyzer._rc4_decrypt(analyzer._xor_decrypt(original_data, key_112233), key_secret)

        chain_results = analyzer.try_known_decryption_chains(encrypted_for_chain1)
        if "chain1" in chain_results and chain_results["chain1"] == original_data:
            logging.info(f"Chain 'chain1' successfully decrypted data: {chain_results['chain1']}")
        else:
            logging.error(f"Chain 'chain1' failed or produced incorrect result: {chain_results.get('chain1')}")

        if "chain_bad" in chain_results: # Should fail or be None
             logging.info(f"Chain 'chain_bad' correctly reported as failed (result: {chain_results['chain_bad']})")


    # Cleanup
    if os.path.exists(dummy_settings_file):
        os.remove(dummy_settings_file)
```
