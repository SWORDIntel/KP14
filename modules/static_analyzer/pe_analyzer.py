import pefile
import hashlib
import math
import logging
import os

# Assuming configuration_manager is in core_engine and accessible via sys.path
# This might need adjustment based on final project structure
try:
    from core_engine.configuration_manager import ConfigurationManager
except ImportError:
    # Fallback for direct execution or if core_engine is not yet in PYTHONPATH
    # In a real scenario, ensure PYTHONPATH is set correctly.
    print("Warning: Could not import ConfigurationManager. Using default pe_analyzer settings.")
    ConfigurationManager = None


class PEAnalyzer:
    def __init__(self, file_path, config_manager=None):
        self.file_path = file_path
        self.pe = None
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager
        self._load_config()

        try:
            self.logger.info(f"Loading PE file: {self.file_path}")
            self.pe = pefile.PE(self.file_path, fast_load=self.fast_load)
        except pefile.PEFormatError as e:
            self.logger.error(f"PEFormatError: {e} - Not a valid PE file or unsupported format.")
            raise
        except Exception as e:
            self.logger.error(f"Failed to load PE file {self.file_path}: {e}")
            raise

    def _load_config(self):
        """Loads PE analyzer specific configurations."""
        self.enabled_hashes = ['md5', 'sha1', 'sha256'] # Default
        self.fast_load = False # Default for pefile, loads data directories
        self.entropy_calculation_buffer_size = 4096 # Default

        if self.config_manager:
            self.enabled_hashes = self.config_manager.get('pe_analyzer', 'hash_algorithms', fallback=['md5', 'sha1', 'sha256'])
            if isinstance(self.enabled_hashes, str): # Convert from comma-separated string if needed
                self.enabled_hashes = [h.strip() for h in self.enabled_hashes.split(',')]
            self.fast_load = self.config_manager.getboolean('pe_analyzer', 'fast_load', fallback=False)
            self.entropy_calculation_buffer_size = self.config_manager.getint('pe_analyzer', 'entropy_buffer_size', fallback=4096)
            log_level_str = self.config_manager.get('general', 'log_level', fallback='INFO').upper()
            self.logger.setLevel(getattr(logging, log_level_str, logging.INFO))
        else:
            # Default logging if no config manager
            logging.basicConfig(level=logging.INFO)
            self.logger.info("PEAnalyzer initialized without a ConfigurationManager. Using default settings.")

    def is_pe32(self):
        """Check if the PE file is PE32 (32-bit)."""
        if not self.pe: return None
        return self.pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']

    def is_pe32_plus(self):
        """Check if the PE file is PE32+ (64-bit)."""
        if not self.pe: return None
        # IMAGE_FILE_MACHINE_AMD64 or IMAGE_FILE_MACHINE_IA64 for 64-bit
        return self.pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] or \
               self.pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_IA64']

    def parse_pe_header(self):
        """Parses and returns key PE header information."""
        if not self.pe:
            self.logger.warning("PE object not loaded, cannot parse header.")
            return None

        header_info = {
            "machine": self.pe.FILE_HEADER.Machine,
            "machine_string": pefile.MACHINE_TYPE.get(self.pe.FILE_HEADER.Machine, "UNKNOWN"),
            "number_of_sections": self.pe.FILE_HEADER.NumberOfSections,
            "timestamp": self.pe.FILE_HEADER.TimeDateStamp,
            "characteristics": self.pe.FILE_HEADER.Characteristics,
            "characteristics_flags": [flag for flag, value in pefile.CHARACTERISTICS.items() if self.pe.FILE_HEADER.Characteristics & value],
            "is_dll": self.pe.is_dll(),
            "is_exe": self.pe.is_exe(),
            "is_driver": self.pe.is_driver(),
        }

        if hasattr(self.pe, 'OPTIONAL_HEADER'):
            header_info["optional_header"] = {
                "magic": self.pe.OPTIONAL_HEADER.Magic,
                "magic_string": pefile.OPTIONAL_HEADER_MAGIC_TYPE.get(self.pe.OPTIONAL_HEADER.Magic, "UNKNOWN"),
                "address_of_entry_point": self.pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                "image_base": self.pe.OPTIONAL_HEADER.ImageBase,
                "subsystem": self.pe.OPTIONAL_HEADER.Subsystem,
                "subsystem_string": pefile.SUBSYSTEM_TYPE.get(self.pe.OPTIONAL_HEADER.Subsystem, "UNKNOWN"),
                "dll_characteristics": self.pe.OPTIONAL_HEADER.DllCharacteristics,
                "dll_characteristics_flags": [flag for flag, value in pefile.DLL_CHARACTERISTICS.items() if self.pe.OPTIONAL_HEADER.DllCharacteristics & value],
            }
            if self.is_pe32_plus(): # PE32+ specific fields
                 header_info["optional_header"]["image_base_pe32plus"] = self.pe.OPTIONAL_HEADER.ImageBase
            else: # PE32 specific fields
                 header_info["optional_header"]["image_base_pe32"] = self.pe.OPTIONAL_HEADER.ImageBase


        self.logger.info("Successfully parsed PE header.")
        return header_info

    def analyze_sections(self):
        """Analyzes and returns information about PE sections."""
        if not self.pe:
            self.logger.warning("PE object not loaded, cannot analyze sections.")
            return None

        sections_info = []
        for section in self.pe.sections:
            try:
                section_data = {
                    "name": section.Name.decode().strip('\x00'),
                    "virtual_address": section.VirtualAddress,
                    "virtual_size": section.Misc_VirtualSize,
                    "size_of_raw_data": section.SizeOfRawData,
                    "pointer_to_raw_data": section.PointerToRawData,
                    "characteristics": section.Characteristics,
                    "characteristics_flags": [flag for flag, value in pefile.SECTION_CHARACTERISTICS.items() if section.Characteristics & value],
                    "entropy": section.get_entropy() if section.SizeOfRawData > 0 else 0.0
                }
                sections_info.append(section_data)
            except Exception as e:
                self.logger.error(f"Error analyzing section {section.Name.decode(errors='ignore')}: {e}")
                sections_info.append({
                    "name": section.Name.decode(errors='ignore').strip('\x00'),
                    "error": str(e)
                })

        self.logger.info(f"Analyzed {len(sections_info)} sections.")
        return sections_info

    def list_imports_exports(self):
        """Lists imported and exported functions."""
        if not self.pe:
            self.logger.warning("PE object not loaded, cannot list imports/exports.")
            return None

        results = {"imports": {}, "exports": []}

        # Imports
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                imports_list = []
                for imp in entry.imports:
                    func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else None
                    ordinal = imp.ordinal if func_name is None else None
                    imports_list.append({"name": func_name, "ordinal": ordinal, "address": imp.address})
                results["imports"][dll_name] = imports_list
            self.logger.info(f"Found {sum(len(v) for v in results['imports'].values())} imports from {len(results['imports'])} DLLs.")

        # Exports
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                results["exports"].append({
                    "name": exp.name.decode('utf-8', errors='ignore') if exp.name else None,
                    "ordinal": exp.ordinal,
                    "address": self.pe.OPTIONAL_HEADER.ImageBase + exp.address
                })
            self.logger.info(f"Found {len(results['exports'])} exports.")

        return results

    def calculate_hashes(self):
        """Calculates specified cryptographic hashes of the entire PE file."""
        if not self.pe:
            self.logger.warning("PE object not loaded, cannot calculate hashes.")
            return None

        hashes = {}
        try:
            with open(self.file_path, 'rb') as f:
                file_data = f.read()

            if 'md5' in self.enabled_hashes:
                hashes['md5'] = hashlib.md5(file_data).hexdigest()
            if 'sha1' in self.enabled_hashes:
                hashes['sha1'] = hashlib.sha1(file_data).hexdigest()
            if 'sha256' in self.enabled_hashes:
                hashes['sha256'] = hashlib.sha256(file_data).hexdigest()
            # Add other hashes here if needed (e.g., ssdeep using another library)

            self.logger.info(f"Calculated hashes: {', '.join(hashes.keys())}")
        except FileNotFoundError:
            self.logger.error(f"File not found for hashing: {self.file_path}")
            return {"error": "File not found"}
        except Exception as e:
            self.logger.error(f"Error calculating hashes for {self.file_path}: {e}")
            return {"error": str(e)}
        return hashes

    def calculate_entropy(self, data=None):
        """Calculates Shannon entropy for the given data or the entire file if data is None."""
        if data is None:
            try:
                with open(self.file_path, 'rb') as f:
                    data_to_process = f.read()
                self.logger.info(f"Calculating entropy for the entire file: {self.file_path}")
            except FileNotFoundError:
                self.logger.error(f"File not found for entropy calculation: {self.file_path}")
                return {"error": "File not found", "entropy": None}
            except Exception as e:
                self.logger.error(f"Error reading file for entropy calculation {self.file_path}: {e}")
                return {"error": str(e), "entropy": None}
        else:
            data_to_process = data
            self.logger.info("Calculating entropy for provided data segment.")

        if not data_to_process:
            self.logger.warning("No data provided or read for entropy calculation.")
            return {"entropy": 0.0}

        entropy = 0.0
        data_len = len(data_to_process)

        # Use a buffer to count byte occurrences for large files to manage memory
        # However, for typical PE analysis, processing the whole file or section data at once is common.
        # The pefile section.get_entropy() does this efficiently.
        # This method provides entropy for arbitrary data or the whole file.

        byte_counts = [0] * 256
        for byte_val in data_to_process:
            byte_counts[byte_val] += 1

        for count in byte_counts:
            if count > 0:
                p_x = count / data_len
                entropy -= p_x * math.log2(p_x)

        # Normalize to range [0, 8] for bytes
        # Some normalize to [0,1] by dividing by 8, but raw entropy is often more informative.
        # self.logger.info(f"Calculated entropy: {entropy:.4f}")
        return {"entropy": entropy} # Raw entropy, not normalized to [0,1] by default.

    def get_analysis_summary(self):
        """Provides a summary of all PE analysis results."""
        if not self.pe:
            self.logger.error("PE file not loaded. Cannot generate summary.")
            return {"error": "PE file not loaded."}

        summary = {
            "file_path": self.file_path,
            "size": os.path.getsize(self.file_path) if os.path.exists(self.file_path) else -1,
            "is_pe32": self.is_pe32(),
            "is_pe32_plus": self.is_pe32_plus(),
            "hashes": self.calculate_hashes(),
            "overall_entropy": self.calculate_entropy()["entropy"], # Entropy of the whole file
            "header_info": self.parse_pe_header(),
            "sections": self.analyze_sections(),
            "imports_exports": self.list_imports_exports(),
            # Add more analysis results here as methods are developed (e.g., resources, TLS callbacks)
        }
        self.logger.info(f"Generated analysis summary for {self.file_path}")
        return summary

if __name__ == '__main__':
    # This is a basic example of how to use PEAnalyzer
    # For real usage, integrate with your main application flow (e.g., run_analyzer.py)

    # Setup basic logging for the example
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)

    # Create a dummy settings.ini for testing PEAnalyzer standalone
    dummy_settings_content = """
[general]
project_root = .
output_dir = pe_analyzer_test_output
log_level = DEBUG

[paths]
log_dir_name = logs

[pe_analyzer]
enabled = True
hash_algorithms = md5,sha256
fast_load = False
entropy_buffer_size = 8192
    """
    dummy_settings_file = "dummy_pe_settings.ini"
    with open(dummy_settings_file, 'w') as f:
        f.write(dummy_settings_content)

    # Mock ConfigurationManager for this example if not available via PYTHONPATH
    mock_cm = None
    if ConfigurationManager:
        try:
            mock_cm = ConfigurationManager(settings_path=dummy_settings_file)
            logger.info("Successfully loaded dummy_pe_settings.ini for PEAnalyzer test.")
        except Exception as e:
            logger.error(f"Failed to load dummy_pe_settings.ini: {e}. PEAnalyzer will use defaults.")
    else:
        logger.warning("ConfigurationManager class not found. PEAnalyzer will use defaults for testing.")

    # Example: Create a dummy PE file (or use a real one for testing)
    # A real PE file is needed for pefile to work.
    # For this example, let's assume you have a 'test.exe' in the current directory.
    # You can download a small, safe PE file for testing (e.g., putty.exe or calc.exe from an old Windows system)

    test_pe_file_path = "test.exe" # Replace with a path to a real PE file for testing

    # Create a tiny dummy PE-like file for basic testing if test.exe doesn't exist.
    # NOTE: This dummy file is NOT a valid PE and will likely cause pefile.PEFormatError.
    # It's just to allow the script to run without an external file for a very basic check.
    # For proper testing, use a real PE file.
    if not os.path.exists(test_pe_file_path):
        logger.warning(f"Test PE file '{test_pe_file_path}' not found. Creating a minimal dummy file.")
        logger.warning("This dummy file is NOT a valid PE and will likely fail full analysis.")
        try:
            with open(test_pe_file_path, 'wb') as f_dummy:
                # Basic MZ header + PE pointer + PE signature (very simplified)
                f_dummy.write(b'MZ\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
                f_dummy.write(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
                f_dummy.write(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00') # PE offset 0x40
                f_dummy.write(b'\x00' * (0x40 - f_dummy.tell())) # Padding to PE offset
                f_dummy.write(b'PE\0\0') # PE signature
                f_dummy.write(b'\x4c\x01') # Machine: I386
                f_dummy.write(b'\x01\x00') # NumberOfSections: 1
                f_dummy.write(b'\x00\x00\x00\x00') # TimeDateStamp
                f_dummy.write(b'\x00\x00\x00\x00') # PointerToSymbolTable
                f_dummy.write(b'\x00\x00\x00\x00') # NumberOfSymbols
                f_dummy.write(b'\xE0\x00') # SizeOfOptionalHeader
                f_dummy.write(b'\x02\x01') # Characteristics
                # Minimal OptionalHeader
                f_dummy.write(b'\x0B\x01') # Magic: PE32
                f_dummy.write(b'\x00' * 222) # Fill OptionalHeader
                # Minimal SectionHeader
                f_dummy.write(b'.text\x00\x00\x00')
                f_dummy.write(b'\x00\x00\x10\x00') # VirtualSize
                f_dummy.write(b'\x00\x00\x10\x00') # VirtualAddress
                f_dummy.write(b'\x00\x00\x02\x00') # SizeOfRawData
                f_dummy.write(b'\x00\x00\x04\x00') # PointerToRawData
                f_dummy.write(b'\x00' * 16) # Other section fields
            logger.info(f"Created dummy file: {test_pe_file_path}")
            is_dummy_file = True
        except Exception as e:
            logger.error(f"Could not create dummy PE file: {e}")
            is_dummy_file = False # Prevent further processing if creation fails
    else:
        is_dummy_file = False
        logger.info(f"Using existing file: {test_pe_file_path}")


    if os.path.exists(test_pe_file_path):
        try:
            logger.info(f"\n--- Analyzing PE file: {test_pe_file_path} ---")
            analyzer = PEAnalyzer(file_path=test_pe_file_path, config_manager=mock_cm)

            summary = analyzer.get_analysis_summary()

            if "error" in summary and summary["error"] == "PE file not loaded.":
                 logger.error("Could not load PE file for analysis. Summary generation aborted.")
            else:
                logger.info("\n--- PE Analysis Summary ---")
                logger.info(f"File Path: {summary.get('file_path')}")
                logger.info(f"File Size: {summary.get('size')} bytes")
                logger.info(f"Is PE32: {summary.get('is_pe32')}")
                logger.info(f"Is PE32+: {summary.get('is_pe32_plus')}")

                if summary.get('hashes'):
                    logger.info("Hashes:")
                    for algo, val in summary['hashes'].items():
                        logger.info(f"  {algo.upper()}: {val}")

                logger.info(f"Overall File Entropy: {summary.get('overall_entropy'):.4f}")

                if summary.get('header_info'):
                    header = summary['header_info']
                    logger.info("Header Info:")
                    logger.info(f"  Machine: {header.get('machine_string')}")
                    logger.info(f"  Num Sections: {header.get('number_of_sections')}")
                    logger.info(f"  Timestamp: {header.get('timestamp')}")
                    logger.info(f"  Is DLL: {header.get('is_dll')}, Is EXE: {header.get('is_exe')}")
                    if header.get('optional_header'):
                        opt_header = header['optional_header']
                        logger.info(f"  Entry Point: 0x{opt_header.get('address_of_entry_point', 0):X}")
                        logger.info(f"  Image Base: 0x{opt_header.get('image_base', 0):X}")
                        logger.info(f"  Subsystem: {opt_header.get('subsystem_string')}")

                if summary.get('sections'):
                    logger.info("Sections:")
                    for sec in summary['sections'][:3]: # Print first 3 sections
                        logger.info(f"  Name: {sec.get('name', 'N/A')}, Size: {sec.get('size_of_raw_data', 0)}, Entropy: {sec.get('entropy', 0.0):.4f}, Chars: {sec.get('characteristics_flags', [])}")
                    if len(summary['sections']) > 3:
                        logger.info(f"  ... and {len(summary['sections']) - 3} more sections.")

                if summary.get('imports_exports'):
                    imports = summary['imports_exports'].get('imports', {})
                    exports = summary['imports_exports'].get('exports', [])
                    logger.info(f"Imports ({sum(len(v) for v in imports.values())} total):")
                    for dll, funcs in list(imports.items())[:2]: # Print imports from first 2 DLLs
                        logger.info(f"  From {dll}:")
                        for func in funcs[:2]: # Print first 2 functions
                            logger.info(f"    - {func.get('name') or f'Ordinal {func.get('ordinal')}'} at 0x{func.get('address',0):X}")
                        if len(funcs) > 2: logger.info(f"    ... and {len(funcs)-2} more.")
                    if len(imports) > 2 : logger.info(f"  ... and imports from {len(imports)-2} more DLLs.")

                    logger.info(f"Exports ({len(exports)} total):")
                    for exp in exports[:3]: # Print first 3 exports
                         logger.info(f"  - {exp.get('name') or f'Ordinal {exp.get('ordinal')}'} at 0x{exp.get('address',0):X}")
                    if len(exports) > 3: logger.info(f"  ... and {len(exports)-3} more exports.")

        except pefile.PEFormatError as e:
            logger.error(f"Analysis failed for {test_pe_file_path}: It's not a valid PE file or format is unsupported. Error: {e}")
        except Exception as e:
            logger.error(f"An unexpected error occurred during PE analysis of {test_pe_file_path}: {e}", exc_info=True)
        finally:
            if is_dummy_file and os.path.exists(test_pe_file_path):
                try:
                    os.remove(test_pe_file_path)
                    logger.info(f"Cleaned up dummy file: {test_pe_file_path}")
                except OSError as e:
                    logger.error(f"Error removing dummy file {test_pe_file_path}: {e}")
            if os.path.exists(dummy_settings_file):
                try:
                    os.remove(dummy_settings_file)
                    logger.info(f"Cleaned up dummy settings file: {dummy_settings_file}")
                except OSError as e:
                     logger.error(f"Error removing dummy settings file {dummy_settings_file}: {e}")
            if os.path.exists("pe_analyzer_test_output/logs"): # Cleanup dummy output dirs
                os.rmdir("pe_analyzer_test_output/logs")
            if os.path.exists("pe_analyzer_test_output"):
                os.rmdir("pe_analyzer_test_output")

    else:
        logger.error(f"Test PE file '{test_pe_file_path}' not found and dummy creation failed/skipped. Cannot run PEAnalyzer example.")
