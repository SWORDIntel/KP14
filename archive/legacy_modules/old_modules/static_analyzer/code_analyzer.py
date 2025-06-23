import logging
import re
import os
import binascii

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    logging.getLogger(__name__).warning("Capstone disassembler not available. Disassembly functionality will be limited.")

try:
    import r2pipe
    R2PIPE_AVAILABLE = True
except ImportError:
    R2PIPE_AVAILABLE = False
    logging.getLogger(__name__).warning("r2pipe (for Radare2) not available. Advanced analysis and pseudo-code generation will be limited.")

# Assuming configuration_manager is in core_engine and accessible
try:
    from core_engine.configuration_manager import ConfigurationManager
except ImportError:
    ConfigurationManager = None
    logging.getLogger(__name__).warning("ConfigurationManager not found. CodeAnalyzer will use default settings.")


class CodeAnalyzer:
    # Common function prologue patterns (can be expanded and moved to config)
    # From function_boundary_detection.py and malware_code_extractor.py
    X86_PROLOGUES = [
        rb"\x55\x89\xe5",                # push ebp; mov ebp, esp
        rb"\x55\x8b\xec",                # push ebp; mov ebp, esp (alternate form)
        rb"\x55\x89\xe5\x83\xec",        # push ebp; mov ebp, esp; sub esp, XX
        rb"\x53\x56\x57",                # push ebx; push esi; push edi
    ]
    X64_PROLOGUES = [
        rb"\x55\x48\x89\xe5",            # push rbp; mov rbp, rsp
        rb"\x48\x83\xec",                # sub rsp, XX
        rb"\x40\x53",                    # push rbx (used in x64)
        rb"\x48\x89\x5c\x24",            # mov [rsp+X], rbx
    ]
    ARM_PROLOGUES = [
        rb"[\x00-\xff]{2}\x2d\xe9",     # push {XX, lr} (e.g., e92d40f0 push {r4-r7, lr})
        rb"\x0d\xc0\xa0\xe1",           # mov ip, sp (often part of prologue)
    ]

    # Common function epilogue patterns
    X86_EPILOGUES = [rb"\xc9\xc3", rb"\x5d\xc3"] # leave; ret | pop ebp; ret
    X64_EPILOGUES = [rb"\xc9\xc3", rb"\x5d\xc3", rb"\x48\x83\xc4.\xc3"] # leave; ret | pop rbp; ret | add rsp, XX; ret
    ARM_EPILOGUES = [rb"[\x00-\xff]{2}\xbd\xe8"] # pop {XX, pc} (e.g., e8bd80f0 pop {r4-r7, pc})

    # Compiler idioms (simplified, from compiler_idiom_detection.py)
    # These operate on textual assembly/decompiled code
    COMPILER_IDIOMS_REGEX = {
        r"(\w+)\s*\^\s*\1": (lambda m: f"{m.group(1)} = 0"), # xor reg, reg -> reg = 0
        # Add more complex regexes for shifts as division/multiplication by powers of 2, etc.
        # Example: mov eax, ebx; shl eax, 2; -> eax = ebx * 4
    }


    def __init__(self, file_path, config_manager=None, file_data=None):
        self.file_path = file_path
        self.file_data = file_data
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager
        self.architecture = None # Detected architecture (e.g., 'x86', 'x64', 'arm')
        self.arch_mode_capstone = None # Capstone specific arch/mode

        self._load_config()
        if self.file_data is None:
            self._load_file_data()

        if self.file_data:
            self._detect_architecture() # Detect architecture early
        else:
            self.logger.error(f"No file data available for analysis of {self.file_path}")
            raise ValueError(f"File data not loaded for {self.file_path}")

    def _load_config(self):
        self.use_radare2_if_available = True
        self.radare2_path = "r2" # Default path for radare2
        # Add more config options as needed

        if self.config_manager:
            self.use_radare2_if_available = self.config_manager.getboolean('code_analyzer', 'use_radare2', fallback=True)
            self.radare2_path = self.config_manager.get('code_analyzer', 'radare2_path', fallback="r2")
            log_level_str = self.config_manager.get('general', 'log_level', fallback='INFO').upper()
            self.logger.setLevel(getattr(logging, log_level_str, logging.INFO))
        else:
            logging.basicConfig(level=logging.INFO) # Default if no CM

    def _load_file_data(self):
        try:
            if self.file_path and os.path.exists(self.file_path):
                with open(self.file_path, 'rb') as f:
                    self.file_data = f.read()
                self.logger.info(f"Successfully loaded file data for {self.file_path}")
            else:
                self.logger.error(f"File not found: {self.file_path}")
                self.file_data = None
        except Exception as e:
            self.logger.error(f"Error loading file {self.file_path}: {e}")
            self.file_data = None

    def _detect_architecture(self):
        """
        Detects architecture using PE/ELF headers first, then falls back to patterns.
        Sets self.architecture and self.arch_mode_capstone.
        """
        if not self.file_data:
            self.logger.warning("No file data to detect architecture from.")
            return

        # Attempt PE header detection (simplified, assumes pefile was used by PEAnalyzer or similar)
        # This would typically be done by PEAnalyzer and passed to CodeAnalyzer,
        # or CodeAnalyzer would also use pefile. For now, simple signature check.
        if self.file_data.startswith(b'MZ'):
            try:
                pe_offset = int.from_bytes(self.file_data[0x3C:0x40], 'little')
                if self.file_data[pe_offset:pe_offset+4] == b'PE\0\0':
                    machine_type = int.from_bytes(self.file_data[pe_offset+4:pe_offset+6], 'little')
                    if machine_type == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                        self.architecture = 'x64'
                        self.arch_mode_capstone = (capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                        self.logger.info("Detected x64 architecture from PE header.")
                        return
                    elif machine_type == 0x014c:  # IMAGE_FILE_MACHINE_I386
                        self.architecture = 'x86'
                        self.arch_mode_capstone = (capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                        self.logger.info("Detected x86 architecture from PE header.")
                        return
                    elif machine_type == 0x01c0 or machine_type == 0x01c4: # ARM / ARMNT
                        self.architecture = 'arm'
                        self.arch_mode_capstone = (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM) # Add thumb later if needed
                        self.logger.info("Detected ARM architecture from PE header.")
                        return
            except Exception as e:
                self.logger.debug(f"Could not determine arch from PE header: {e}")

        # Fallback to pattern matching (from malware_code_extractor.py)
        # This is less reliable than PE/ELF headers.
        scores = {'x86': 0, 'x64': 0, 'arm': 0}
        arch_patterns = {'x86': self.X86_PROLOGUES, 'x64': self.X64_PROLOGUES, 'arm': self.ARM_PROLOGUES}
        for arch, patterns in arch_patterns.items():
            for pattern in patterns:
                try:
                    # Ensure pattern is bytes for regex
                    if isinstance(pattern, str): pattern_bytes = pattern.encode('latin-1')
                    else: pattern_bytes = pattern
                    matches = re.findall(pattern_bytes, self.file_data)
                    scores[arch] += len(matches)
                except Exception as e:
                    self.logger.debug(f"Regex error with pattern {pattern} for arch {arch}: {e}")

        if sum(scores.values()) > 0:
            detected_arch = max(scores, key=scores.get)
            if scores[detected_arch] > 0 : # Ensure there was at least one pattern match
                self.architecture = detected_arch
                if detected_arch == 'x64':
                    self.arch_mode_capstone = (capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                elif detected_arch == 'x86':
                    self.arch_mode_capstone = (capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                elif detected_arch == 'arm':
                    self.arch_mode_capstone = (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
                self.logger.info(f"Detected architecture '{self.architecture}' using fallback patterns.")
                return

        self.logger.warning("Failed to detect a definitive architecture. Defaulting to x86 for Capstone if used.")
        self.architecture = 'x86' # Default
        self.arch_mode_capstone = (capstone.CS_ARCH_X86, capstone.CS_MODE_32)


    def disassemble_code(self, code_bytes, offset=0x0):
        """Disassembles a byte sequence using Capstone."""
        if not CAPSTONE_AVAILABLE:
            self.logger.error("Capstone is not available for disassembly.")
            return []
        if not self.arch_mode_capstone:
            self.logger.error("Architecture not set for Capstone. Cannot disassemble.")
            return []

        disassembled_instructions = []
        try:
            md = capstone.Cs(self.arch_mode_capstone[0], self.arch_mode_capstone[1])
            md.detail = True # Enable details for idiom recognition if needed later from Capstone output
            for insn in md.disasm(code_bytes, offset):
                disassembled_instructions.append({
                    "address": insn.address,
                    "mnemonic": insn.mnemonic,
                    "op_str": insn.op_str,
                    "bytes": binascii.hexlify(insn.bytes).decode()
                })
            self.logger.info(f"Disassembled {len(disassembled_instructions)} instructions using Capstone.")
        except Exception as e:
            self.logger.error(f"Capstone disassembly failed: {e}")
        return disassembled_instructions

    def detect_function_boundaries(self, code_bytes, offset=0x0):
        """
        Detects function boundaries using prologue patterns.
        Returns a list of identified function start addresses.
        """
        if not self.architecture:
            self.logger.warning("Architecture not detected, cannot select appropriate prologue patterns.")
            return []

        if self.architecture == 'x86':
            prologues = self.X86_PROLOGUES
        elif self.architecture == 'x64':
            prologues = self.X64_PROLOGUES
        elif self.architecture == 'arm':
            prologues = self.ARM_PROLOGUES
        else:
            self.logger.warning(f"No defined prologue patterns for architecture: {self.architecture}")
            return []

        boundaries = []
        for pattern in prologues:
            try:
                for match in re.finditer(pattern, code_bytes):
                    boundaries.append(offset + match.start())
            except Exception as e: # Catch errors from re.finditer if pattern is malformed
                self.logger.debug(f"Error matching prologue pattern {pattern}: {e}")

        # Sort and remove duplicates
        unique_boundaries = sorted(list(set(boundaries)))
        self.logger.info(f"Detected {len(unique_boundaries)} potential function boundaries using prologues.")
        return unique_boundaries

    def recognize_compiler_idioms(self, assembly_text):
        """
        Recognizes and simplifies compiler idioms in textual assembly code.
        (Operates on string representation of assembly, not raw bytes or Capstone objects)
        """
        processed_text = assembly_text
        for pattern, handler_or_replacement in self.COMPILER_IDIOMS_REGEX.items():
            if callable(handler_or_replacement):
                # If it's a function, use re.sub with the handler
                processed_text = re.sub(pattern, handler_or_replacement, processed_text)
            else:
                # If it's a string, use it directly as replacement
                processed_text = re.sub(pattern, handler_or_replacement, processed_text)

        if processed_text != assembly_text:
            self.logger.info("Applied compiler idiom recognition to assembly text.")
        return processed_text

    def generate_pseudo_code(self, function_address=None, function_bytes=None):
        """
        Generates pseudo-code for a function using Radare2 (if available) or basic Capstone analysis.
        Either function_address (for analysis of the whole file) or function_bytes must be provided.
        """
        if self.use_radare2_if_available and R2PIPE_AVAILABLE and self.file_path:
            self.logger.info("Attempting pseudo-code generation with Radare2.")
            try:
                r2 = r2pipe.open(self.file_path, flags=['-N']) # -N for no analysis at start
                r2.cmd(f"e anal.arch={self.architecture or 'x86'}") # Set architecture
                r2.cmd("aaa") # Analyze all

                target_addr = f"0x{function_address:x}" if function_address is not None else "entry0"

                # Check if function exists at address
                # func_info = r2.cmdj(f"afij @ {target_addr}") # Get function info at address
                # if not func_info or not isinstance(func_info, list) or not func_info[0].get('offset'):
                #    self.logger.warning(f"Radare2: No function found at {target_addr}. Analyzing bytes if provided.")
                #    if not function_bytes: return "Error: Radare2 found no function at address and no bytes provided."

                pseudo_code = r2.cmd(f"pdc @ {target_addr}") # Decompile C code at address
                r2.quit()
                if pseudo_code and len(pseudo_code) > 10:
                    self.logger.info(f"Successfully generated pseudo-code for {target_addr} using Radare2.")
                    # Optional: Apply compiler idiom recognition to r2's output
                    # pseudo_code = self.recognize_compiler_idioms(pseudo_code) # This needs idiom patterns for C, not asm
                    return pseudo_code
                else:
                    self.logger.warning(f"Radare2 produced no/empty pseudo-code for {target_addr}.")
            except Exception as e:
                self.logger.error(f"Radare2 pseudo-code generation failed: {e}")
                if not function_bytes: # If r2 fails and we don't have bytes, we can't fallback
                    return "Error: Radare2 failed and no function bytes provided for fallback."

        # Fallback to basic Capstone-based pseudo-code if Radare2 fails or not used, and bytes are available
        if function_bytes:
            self.logger.info("Falling back to basic Capstone-based pseudo-code generation.")
            disassembly = self.disassemble_code(function_bytes, offset=function_address or 0x0)
            if not disassembly:
                return "Error: Disassembly failed, cannot generate pseudo-code."

            # Very basic pseudo-code: just list instructions with comments
            # A more advanced version would try to identify loops, conditions, etc.
            # This is similar to reconstruct_pseudo_code from malware_code_extractor.py
            output = [f"// Basic pseudo-code for function at 0x{function_address or 0:x}"]
            for insn in disassembly:
                line = f"0x{insn['address']:x}: {insn['mnemonic']} {insn['op_str']}"
                # Apply assembly-level idiom recognition
                line = self.recognize_compiler_idioms(line)
                output.append(line)
            return "\n".join(output)

        return "Error: Pseudo-code generation failed. Radare2 unavailable/failed and no function bytes for Capstone fallback."

    def get_analysis_summary(self, code_bytes, offset=0x0):
        """ Provides a summary of code analysis for a given byte sequence. """
        if not self.file_data and not code_bytes: # Ensure arch is detected or can be from code_bytes
            self.logger.error("No file data or code_bytes for analysis summary.")
            return {"error": "No data for analysis."}

        # If code_bytes is primary, ensure architecture is known or re-detected for this snippet
        # For simplicity, this example assumes architecture is set during __init__ from full file_data.
        # A real scenario might need to pass arch explicitly or run detection on code_bytes.

        disassembly = self.disassemble_code(code_bytes, offset)
        boundaries = self.detect_function_boundaries(code_bytes, offset)

        # For pseudo-code and idiom recognition, it's best done per function.
        # This summary provides overall disassembly and boundaries.
        # Idiom recognition is applied to the textual disassembly if desired.

        textual_disassembly = "\n".join([f"0x{i['address']:x}: {i['mnemonic']} {i['op_str']}" for i in disassembly])
        idiom_processed_disassembly = self.recognize_compiler_idioms(textual_disassembly)

        summary = {
            "architecture": self.architecture,
            "detected_function_starts": [hex(b) for b in boundaries],
            "instruction_count": len(disassembly),
            "disassembly_snippet": idiom_processed_disassembly[:1000], # First 1000 chars
        }
        return summary


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)

    # Example usage (requires a binary file for analysis)
    # Replace 'path_to_your_binary' with an actual file path
    # Note: Radare2 analysis needs a file path, not just bytes.

    # Create a dummy settings.ini for testing CodeAnalyzer standalone
    dummy_settings_content = """
[general]
log_level = DEBUG
[code_analyzer]
use_radare2 = True
# Set to False to test Capstone fallback, ensure r2 is not in PATH or radare2_path is invalid
radare2_path = r2
# Adjust if your r2 is elsewhere or named differently (e.g., radare2)
    """
    dummy_settings_file = "dummy_code_analyzer_settings.ini"
    if not os.path.exists(dummy_settings_file):
        with open(dummy_settings_file, 'w') as f:
            f.write(dummy_settings_content)

    mock_cm = None
    if ConfigurationManager:
        try:
            mock_cm = ConfigurationManager(settings_path=dummy_settings_file)
            logger.info("Successfully loaded dummy_code_analyzer_settings.ini for CodeAnalyzer test.")
        except Exception as e:
            logger.error(f"Failed to load dummy_code_analyzer_settings.ini: {e}. CodeAnalyzer will use defaults.")

    # Create a dummy binary file for testing
    dummy_bin_file = "test_dummy_binary.bin"
    # x86: push ebp; mov ebp, esp; xor eax, eax; mov eax, [ebp+8]; ret
    dummy_x86_code = b"\x55\x89\xe5\x31\xc0\x8b\x45\x08\xc3"
    if not os.path.exists(dummy_bin_file):
        with open(dummy_bin_file, "wb") as f:
            f.write(dummy_x86_code)
        logger.info(f"Created dummy binary file: {dummy_bin_file} for testing.")

    if not os.path.exists(dummy_bin_file):
        logger.error(f"Test binary '{dummy_bin_file}' not found. Cannot run CodeAnalyzer example.")
    else:
        try:
            logger.info(f"\n--- Analyzing file: {dummy_bin_file} ---")
            # Pass file_path for r2, file_data can be loaded by analyzer or passed directly
            analyzer = CodeAnalyzer(file_path=dummy_bin_file, config_manager=mock_cm)

            if analyzer.file_data:
                logger.info(f"Architecture: {analyzer.architecture}")

                # Test disassembly of the whole file data
                full_disassembly = analyzer.disassemble_code(analyzer.file_data)
                logger.info("\n--- Full Disassembly (first 5 instructions) ---")
                for instr in full_disassembly[:5]:
                    logger.info(f"0x{instr['address']:x}: {instr['mnemonic']} {instr['op_str']}")

                # Test function boundary detection on the whole file data
                boundaries = analyzer.detect_function_boundaries(analyzer.file_data)
                logger.info(f"\n--- Detected Function Boundaries ---")
                for boundary in boundaries:
                    logger.info(f"Potential function start at offset: {hex(boundary)}")

                # Test pseudo-code generation (for first detected boundary or whole file if no boundaries)
                target_address_for_pseudo = boundaries[0] if boundaries else 0
                logger.info(f"\n--- Pseudo-code for function at {hex(target_address_for_pseudo)} (or entry) ---")
                # If using r2, it analyzes the file_path. For capstone fallback, it would need bytes.
                # Let's assume r2 will analyze based on file_path and detected entry/functions.
                # If you want to analyze a specific snippet (e.g. dummy_x86_code), pass it as function_bytes
                pseudo_code = analyzer.generate_pseudo_code(function_address=target_address_for_pseudo)
                # To test capstone fallback with specific bytes:
                # pseudo_code = analyzer.generate_pseudo_code(function_bytes=dummy_x86_code, function_address=0)
                logger.info(pseudo_code)

                # Test idiom recognition on a sample assembly string
                logger.info("\n--- Compiler Idiom Recognition Test ---")
                sample_asm = "xor eax, eax\nmov ebx, eax"
                processed_asm = analyzer.recognize_compiler_idioms(sample_asm)
                logger.info(f"Original: {sample_asm.splitlines()}")
                logger.info(f"Processed: {processed_asm.splitlines()}")

                logger.info("\n--- Analysis Summary for dummy code snippet ---")
                summary = analyzer.get_analysis_summary(dummy_x86_code, offset=0x1000) # Analyze the snippet at a virtual offset
                for key, value in summary.items():
                    if key == "disassembly_snippet":
                        logger.info(f"  {key}: \n{value}")
                    else:
                        logger.info(f"  {key}: {value}")
            else:
                logger.error(f"Failed to load data for {dummy_bin_file}, cannot perform analysis.")

        except Exception as e:
            logger.error(f"An error occurred during CodeAnalyzer example: {e}", exc_info=True)
        finally:
            # Clean up dummy files
            if os.path.exists(dummy_settings_file):
                os.remove(dummy_settings_file)
            if os.path.exists(dummy_bin_file) and "dummy_binary" in dummy_bin_file : # Safety check
                os.remove(dummy_bin_file)
                logger.info(f"Cleaned up dummy binary file: {dummy_bin_file}")

```
