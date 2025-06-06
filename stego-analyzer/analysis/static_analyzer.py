# static_analyzer.py
# Provides functions for basic static analysis of executable files.

import pefile
import capstone
import string

class StaticAnalyzerError(Exception):
    """Custom exception for errors during static analysis."""
    pass

def extract_basic_pe_info(filepath):
    """
    Extracts basic information from a PE file.

    Args:
        filepath (str): Path to the PE file.

    Returns:
        dict: A dictionary containing PE information (sections, imports, exports, entry_point).
              Returns None if the file is not a PE file or an error occurs.
    """
    pe_info = {
        "sections": [],
        "imports": {},
        "exports": [],
        "entry_point": None,
        "architecture": None, # e.g., "32-bit", "64-bit"
    }
    try:
        pe = pefile.PE(filepath)

        # Architecture
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            pe_info["architecture"] = "32-bit"
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            pe_info["architecture"] = "64-bit"
        else:
            pe_info["architecture"] = "Unknown"

        pe_info["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase)

        for section in pe.sections:
            section_name = section.Name.decode('utf-8', 'ignore').rstrip('\x00')
            pe_info["sections"].append({
                "name": section_name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": hex(section.Misc_VirtualSize),
                "raw_size": section.SizeOfRawData,
                "characteristics": hex(section.Characteristics)
            })

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', 'ignore')
                functions = []
                for imp in entry.imports:
                    func_name = imp.name.decode('utf-8', 'ignore') if imp.name else f"ord({imp.ordinal})"
                    functions.append(func_name)
                pe_info["imports"][dll_name] = functions

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                pe_info["exports"].append({
                    "name": exp.name.decode('utf-8', 'ignore') if exp.name else "N/A",
                    "address": hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)
                })

        return pe_info

    except pefile.PEFormatError as e:
        # This indicates it's likely not a PE file or it's malformed
        # Depending on desired strictness, this could be logged or handled quietly
        raise StaticAnalyzerError(f"Not a valid PE file or PE format error: {filepath} - {e}")
    except Exception as e:
        raise StaticAnalyzerError(f"Error processing PE file {filepath}: {e}")


def extract_strings(filepath, min_length=4):
    """
    Extracts printable strings from a binary file.

    Args:
        filepath (str): Path to the binary file.
        min_length (int): Minimum length of a string to be extracted.

    Returns:
        list: A list of extracted strings.
    """
    strings_found = []
    try:
        with open(filepath, "rb") as f:
            data = f.read()

        current_string = ""
        for byte in data:
            char = chr(byte)
            if char in string.printable[:-5]: # Exclude control characters except tab, newline, etc.
                current_string += char
            else:
                if len(current_string) >= min_length:
                    strings_found.append(current_string)
                current_string = ""
        if len(current_string) >= min_length: # Catch string at EOF
            strings_found.append(current_string)

        return list(set(strings_found)) # Return unique strings

    except FileNotFoundError:
        raise StaticAnalyzerError(f"File not found: {filepath}")
    except Exception as e:
        raise StaticAnalyzerError(f"Error extracting strings from {filepath}: {e}")


def disassemble_entry_point(filepath, num_instructions=20):
    """
    Disassembles a specified number of instructions from the entry point of a PE file.

    Args:
        filepath (str): Path to the PE file.
        num_instructions (int): Number of instructions to disassemble.

    Returns:
        list: A list of strings, where each string is a disassembled instruction.
              Returns None if disassembly is not possible (e.g., not a PE, wrong architecture).
    """
    disassembled_code = []
    try:
        pe = pefile.PE(filepath)
        entry_point_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase

        code_section = None
        for section in pe.sections:
            if section.contains_rva(entry_point_rva):
                code_section = section
                break

        if not code_section:
            raise StaticAnalyzerError(f"Could not find code section for entry point in {filepath}")

        # Get code from the section
        code_start_offset = entry_point_rva - code_section.VirtualAddress
        code_data = code_section.get_data(code_start_offset, code_section.Misc_VirtualSize - code_start_offset)

        # Determine architecture for Capstone
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            raise StaticAnalyzerError(f"Unsupported PE architecture for disassembly: {pe.FILE_HEADER.Machine}")

        md.detail = True # Enable instruction details if needed later

        instruction_count = 0
        for i in md.disasm(code_data, image_base + entry_point_rva):
            if instruction_count >= num_instructions:
                break
            disassembled_code.append(f"0x{i.address:x}:	{i.mnemonic}	{i.op_str}")
            instruction_count += 1

        return disassembled_code

    except pefile.PEFormatError as e:
        raise StaticAnalyzerError(f"Not a valid PE file for disassembly: {filepath} - {e}")
    except capstone.CsError as e:
        raise StaticAnalyzerError(f"Capstone disassembly error for {filepath}: {e}")
    except Exception as e:
        raise StaticAnalyzerError(f"Error disassembling entry point of {filepath}: {e}")

if __name__ == '__main__':
    # This is for basic testing.
    # You would typically call these functions from your main pipeline.
    # Create a dummy PE file or use a known safe one for testing.
    # For example:
    # test_file = "path/to/your/test_executable.exe"
    # if os.path.exists(test_file):
    #     print(f"--- Basic PE Info for {test_file} ---")
    #     pe_info = extract_basic_pe_info(test_file)
    #     if pe_info:
    #         for key, value in pe_info.items():
    #             if key in ["imports", "sections", "exports"] and isinstance(value, (dict, list)):
    #                 print(f"  {key.capitalize()}:")
    #                 for item_key, item_value in (value.items() if isinstance(value, dict) else enumerate(value)):
    #                     print(f"    {item_key}: {item_value}")
    #             else:
    #                 print(f"  {key.capitalize()}: {value}")

    #     print(f"\n--- Strings in {test_file} ---")
    #     strings = extract_strings(test_file)
    #     for s in strings[:20]: # Print first 20 strings
    #         print(f"  {s}")
    #     if len(strings) > 20:
    #         print(f"  ... and {len(strings) - 20} more strings.")

    #     print(f"\n--- Entry Point Disassembly for {test_file} ---")
    #     asm = disassemble_entry_point(test_file)
    #     if asm:
    #         for line in asm:
    #             print(f"  {line}")
    # else:
    #     print(f"Test file {test_file} not found. Skipping example run.")
    pass
