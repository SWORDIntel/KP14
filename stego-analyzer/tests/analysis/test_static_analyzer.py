# test_static_analyzer.py
import unittest
from unittest.mock import patch, MagicMock, mock_open
import os

# Add stego-analyzer root to sys.path to allow direct import of modules
import sys
# Add project root to sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
sys.path.insert(0, PROJECT_ROOT)

from analysis.static_analyzer import (
    extract_basic_pe_info,
    extract_strings,
    disassemble_entry_point,
    StaticAnalyzerError
)
# Mock pefile and capstone as they are external dependencies and require actual files/data
# We are testing the logic of our functions, not the libraries themselves here.

class TestStaticAnalyzer(unittest.TestCase):

    def test_extract_strings_found(self):
        mock_data = b"Hello\x00World\nThis is a test\tstring\x01\x02Another"
        m_open = mock_open(read_data=mock_data)
        with patch("builtins.open", m_open):
            result = extract_strings("dummy/path.bin", min_length=4)
            self.assertIn("Hello", result)
            self.assertIn("World", result) # Separated by newline
            self.assertIn("This is a test", result) # Tab is printable
            self.assertIn("string", result)
            self.assertIn("Another", result)
            self.assertEqual(len(result), 5)

    def test_extract_strings_not_found(self):
        mock_data = b"\x01\x02\x03\x04\x05"
        m_open = mock_open(read_data=mock_data)
        with patch("builtins.open", m_open):
            result = extract_strings("dummy/path.bin", min_length=4)
            self.assertEqual(len(result), 0)

    def test_extract_strings_file_not_found(self):
        m_open = mock_open()
        m_open.side_effect = FileNotFoundError("File not found")
        with patch("builtins.open", m_open):
            with self.assertRaisesRegex(StaticAnalyzerError, "File not found: dummy/path.bin"):
                extract_strings("dummy/path.bin")

    @patch('analysis.static_analyzer.pefile.PE')
    def test_extract_basic_pe_info_success_32bit(self, mock_pe_constructor):
        mock_pe_instance = MagicMock()
        mock_pe_instance.FILE_HEADER.Machine = 0x014c # IMAGE_FILE_MACHINE_I386
        mock_pe_instance.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
        mock_pe_instance.OPTIONAL_HEADER.ImageBase = 0x400000

        mock_section1 = MagicMock()
        mock_section1.Name = b'.text\x00\x00\x00'
        mock_section1.VirtualAddress = 0x1000
        mock_section1.Misc_VirtualSize = 0x1234
        mock_section1.SizeOfRawData = 0x1200
        mock_section1.Characteristics = 0x60000020
        mock_pe_instance.sections = [mock_section1]

        mock_import_entry = MagicMock()
        mock_import_entry.dll = b'kernel32.dll'
        mock_import_func = MagicMock()
        mock_import_func.name = b'CreateFileA'
        mock_import_entry.imports = [mock_import_func]
        mock_pe_instance.DIRECTORY_ENTRY_IMPORT = [mock_import_entry]

        mock_export_symbol = MagicMock()
        mock_export_symbol.name = b'MyExport'
        mock_export_symbol.address = 0x2000
        mock_pe_instance.DIRECTORY_ENTRY_EXPORT.symbols = [mock_export_symbol]

        mock_pe_constructor.return_value = mock_pe_instance

        info = extract_basic_pe_info("dummy.exe")

        self.assertEqual(info['architecture'], "32-bit")
        self.assertEqual(info['entry_point'], hex(0x400000 + 0x1000))
        self.assertEqual(info['sections'][0]['name'], ".text")
        self.assertIn('kernel32.dll', info['imports'])
        self.assertEqual(info['imports']['kernel32.dll'][0], 'CreateFileA')
        self.assertEqual(info['exports'][0]['name'], 'MyExport')

    @patch('analysis.static_analyzer.pefile.PE')
    def test_extract_basic_pe_info_success_64bit(self, mock_pe_constructor):
        mock_pe_instance = MagicMock()
        mock_pe_instance.FILE_HEADER.Machine = 0x8664  # IMAGE_FILE_MACHINE_AMD64
        mock_pe_instance.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
        mock_pe_instance.OPTIONAL_HEADER.ImageBase = 0x140000000
        mock_pe_instance.sections = []
        mock_pe_instance.DIRECTORY_ENTRY_IMPORT = []
        mock_pe_instance.DIRECTORY_ENTRY_EXPORT.symbols = []
        mock_pe_constructor.return_value = mock_pe_instance

        info = extract_basic_pe_info("dummy_64.exe")
        self.assertEqual(info['architecture'], "64-bit")
        self.assertEqual(info['entry_point'], hex(0x140000000 + 0x1000))

    @patch('analysis.static_analyzer.pefile.PE')
    def test_extract_basic_pe_info_pe_format_error(self, mock_pe_constructor):
        # Ensure pefile is imported in the module under test, not here directly
        from analysis.static_analyzer import pefile as pefile_module
        mock_pe_constructor.side_effect = pefile_module.PEFormatError("Not a PE file")
        with self.assertRaisesRegex(StaticAnalyzerError, "Not a valid PE file or PE format error"):
            extract_basic_pe_info("not_a_pe.txt")

    @patch('analysis.static_analyzer.pefile.PE')
    @patch('analysis.static_analyzer.capstone.Cs')
    def test_disassemble_entry_point_success_32bit(self, mock_cs_constructor, mock_pe_constructor):
        # Mock PE Instance
        mock_pe_instance = MagicMock()
        mock_pe_instance.FILE_HEADER.Machine = 0x014c # I386
        mock_pe_instance.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
        mock_pe_instance.OPTIONAL_HEADER.ImageBase = 0x400000

        mock_code_section = MagicMock()
        mock_code_section.contains_rva.return_value = True
        mock_code_section.VirtualAddress = 0x1000
        mock_code_section.Misc_VirtualSize = 0x100
        mock_code_section.get_data.return_value = b'\x90\x90\x90' # NOPs
        mock_pe_instance.sections = [mock_code_section]
        mock_pe_constructor.return_value = mock_pe_instance

        # Mock Capstone Instance
        mock_cs_instance = MagicMock()
        mock_instruction = MagicMock()
        mock_instruction.address = 0x401000
        mock_instruction.mnemonic = 'nop'
        mock_instruction.op_str = ''
        mock_cs_instance.disasm.return_value = [mock_instruction] * 3 # 3 NOPs
        mock_cs_constructor.return_value = mock_cs_instance

        asm = disassemble_entry_point("dummy.exe", num_instructions=3)
        self.assertEqual(len(asm), 3)
        self.assertEqual(asm[0], "0x401000:\tnop\t")
        mock_cs_constructor.assert_called_with(0, 1) # CS_ARCH_X86, CS_MODE_32 (assuming capstone constants)
                                                     # Actual capstone.CS_ARCH_X86, capstone.CS_MODE_32

    @patch('analysis.static_analyzer.pefile.PE')
    @patch('analysis.static_analyzer.capstone.Cs')
    def test_disassemble_entry_point_unsupported_arch(self, mock_cs_constructor, mock_pe_constructor):
        mock_pe_instance = MagicMock()
        mock_pe_instance.FILE_HEADER.Machine = 0x0200 # IA64 (example of unsupported for this basic func)
        mock_pe_instance.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
        mock_pe_instance.OPTIONAL_HEADER.ImageBase = 0x400000
        mock_pe_instance.sections = [] # Not reached
        mock_pe_constructor.return_value = mock_pe_instance

        with self.assertRaisesRegex(StaticAnalyzerError, "Unsupported PE architecture for disassembly"):
            disassemble_entry_point("dummy_unsupported.exe")

    @patch('analysis.static_analyzer.pefile.PE')
    def test_disassemble_no_code_section(self, mock_pe_constructor):
        mock_pe_instance = MagicMock()
        mock_pe_instance.FILE_HEADER.Machine = 0x014c
        mock_pe_instance.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
        mock_pe_instance.OPTIONAL_HEADER.ImageBase = 0x400000

        mock_section = MagicMock()
        mock_section.contains_rva.return_value = False # EP not in this section
        mock_pe_instance.sections = [mock_section]
        mock_pe_constructor.return_value = mock_pe_instance

        with self.assertRaisesRegex(StaticAnalyzerError, "Could not find code section for entry point"):
            disassemble_entry_point("dummy_no_code_section.exe")

if __name__ == '__main__':
    unittest.main()
