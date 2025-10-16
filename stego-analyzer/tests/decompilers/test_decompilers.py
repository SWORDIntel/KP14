import unittest
import sys
import os
from unittest.mock import Mock, patch
from configparser import ConfigParser

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))
from stego_analyzer.decompilers.factory import DecompilerFactory
from stego_analyzer.decompilers.ghidra import GhidraDecompiler
from stego_analyzer.decompilers.radare2 import Radare2Decompiler


class TestDecompilerFramework(unittest.TestCase):
    def test_ghidra_decompiler_creation(self):
        config = ConfigParser()
        config.add_section("decompiler")
        config.set("decompiler", "backend", "ghidra")
        config.set("decompiler", "path", "/path/to/ghidra")

        decompiler = DecompilerFactory.create(config)
        self.assertIsInstance(decompiler, GhidraDecompiler)

    def test_radare2_decompiler_creation(self):
        config = ConfigParser()
        config.add_section("decompiler")
        config.set("decompiler", "backend", "radare2")
        config.set("decompiler", "path", "/path/to/radare2")

        decompiler = DecompilerFactory.create(config)
        self.assertIsInstance(decompiler, Radare2Decompiler)

    @patch("stego_analyzer.decompilers.ghidra.subprocess.run")
    def test_ghidra_decompiler_decompilation(self, mock_run):
        mock_run.return_value.returncode = 0
        config = ConfigParser()
        config.add_section("decompiler")
        config.set("decompiler", "backend", "ghidra")
        config.set("decompiler", "path", "/path/to/ghidra")

        decompiler = DecompilerFactory.create(config)
        with patch("builtins.open", unittest.mock.mock_open()) as mock_file:
            with patch("os.path.exists") as mock_exists:
                mock_exists.return_value = True
                decompiler.decompile("test.bin", "/tmp")
                mock_run.assert_called_once()
                mock_file.assert_called()

    @patch("stego_analyzer.decompilers.radare2.subprocess.run")
    def test_radare2_decompiler_decompilation(self, mock_run):
        mock_run.return_value.returncode = 0
        config = ConfigParser()
        config.add_section("decompiler")
        config.set("decompiler", "backend", "radare2")
        config.set("decompiler", "path", "/path/to/radare2")

        decompiler = DecompilerFactory.create(config)
        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = True
            decompiler.decompile("test.bin", "/tmp")
            mock_run.assert_called_once()


if __name__ == "__main__":
    unittest.main()