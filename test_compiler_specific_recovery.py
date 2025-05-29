import unittest
import logging
import os
import json
import tempfile
from pathlib import Path
import shutil # For tearDownClass if needed, or individual file cleanup

# Assuming compiler_specific_recovery.py is in the same directory or accessible in PYTHONPATH
try:
    from compiler_specific_recovery import CompilerSpecificRecovery
    COMPILER_RECOVERY_AVAILABLE = True
except ImportError:
    print("Failed to import CompilerSpecificRecovery. Ensure compiler_specific_recovery.py is in the Python path.")
    COMPILER_RECOVERY_AVAILABLE = False

@unittest.skipIf(not COMPILER_RECOVERY_AVAILABLE, "CompilerSpecificRecovery class not found, skipping tests.")
class TestCompilerSpecificRecovery(unittest.TestCase):

    def setUp(self):
        self.test_logger = logging.getLogger("TestCompilerSpecificRecovery")
        self.test_logger.setLevel(logging.DEBUG)
        if not self.test_logger.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.test_logger.addHandler(handler)

        # Create a temporary directory for the test-specific database
        self.temp_dir_obj = tempfile.TemporaryDirectory()
        self.temp_db_path = str(Path(self.temp_dir_obj.name) / "test_idioms_db.json")
        
        self.recovery_engine = CompilerSpecificRecovery(idiom_db_path=self.temp_db_path, logger=self.test_logger)
        # Ensure a clean, default DB for each test by calling initialize_idiom_database
        # The __init__ already calls this, but force_recreate ensures it's the default one.
        self.recovery_engine.initialize_idiom_database(force_recreate=True)
        self.test_logger.info(f"Setup complete. Test DB at: {self.temp_db_path}")

    def tearDown(self):
        # Cleanup the temporary directory and its contents
        self.temp_dir_obj.cleanup()
        self.test_logger.info(f"TearDown complete. Cleaned up: {self.temp_db_path}")

    def test_initialization_and_default_db(self):
        self.test_logger.info("--- Test: Initialization and Default DB ---")
        self.assertIsNotNone(self.recovery_engine.idioms_db)
        self.assertIn("metadata", self.recovery_engine.idioms_db)
        self.assertIn("compilers", self.recovery_engine.idioms_db)
        
        compilers = self.recovery_engine.idioms_db["compilers"]
        self.assertIn("MSVC_v19_x64_Release", compilers)
        self.assertIn("GCC_v9_x64_O2", compilers)
        
        msvc_profile = compilers["MSVC_v19_x64_Release"]
        self.assertGreater(len(msvc_profile.get("common_sequences", [])), 0, "MSVC profile should have default common_sequences.")
        # Check a specific default idiom regex pattern
        msvc_stack_setup_pattern = msvc_profile["common_sequences"][0]["assembly_pattern"][2] # "sub esp, 0x[0-9a-fA-F]+"
        self.assertEqual(msvc_stack_setup_pattern, r"^\s*sub\s+esp,\s*0x[0-9a-fA-F]+\s*$")

    def test_add_compiler_profile(self):
        self.test_logger.info("--- Test: Add Compiler Profile ---")
        profile_name = "TestCompiler_v1.0_x86"
        profile_details = {
            "name": "Test Compiler v1.0 for x86",
            "common_sequences": [{"id": "test_seq_001", "assembly_pattern": ["nop", "ret"]}],
            "idiomatic_optimizations": []
        }
        success = self.recovery_engine.add_compiler_profile(profile_name, profile_details)
        self.assertTrue(success, "Failed to add new compiler profile.")
        self.assertIn(profile_name, self.recovery_engine.idioms_db["compilers"])
        self.assertEqual(self.recovery_engine.idioms_db["compilers"][profile_name]["name"], profile_details["name"])

        # Test overwriting (implicitly, add_compiler_profile does this)
        new_details = {"name": "Test Compiler v1.0 for x86 (Updated)"}
        success_overwrite = self.recovery_engine.add_compiler_profile(profile_name, new_details)
        self.assertTrue(success_overwrite, "Failed to overwrite compiler profile.")
        self.assertEqual(self.recovery_engine.idioms_db["compilers"][profile_name]["name"], new_details["name"])
        # Ensure other keys like common_sequences are still there or handled as per add_compiler_profile logic
        self.assertEqual(len(self.recovery_engine.idioms_db["compilers"][profile_name].get("common_sequences", [])), 0) # Overwrite replaces

    def test_add_idiom(self):
        self.test_logger.info("--- Test: Add Idiom ---")
        profile_name = "TestProfileForIdioms"
        self.recovery_engine.add_compiler_profile(profile_name, {"name": "Test Profile"})

        common_idiom = {"id": "common01", "assembly_pattern": ["mov eax, 1"], "description": "Common mov"}
        opt_idiom = {"id": "opt01", "assembly_pattern": ["lea edi, [eax*4]"], "description": "Optimization lea"}

        success_common = self.recovery_engine.add_idiom(profile_name, "common_sequences", common_idiom)
        self.assertTrue(success_common)
        self.assertEqual(len(self.recovery_engine.idioms_db["compilers"][profile_name]["common_sequences"]), 1)
        self.assertEqual(self.recovery_engine.idioms_db["compilers"][profile_name]["common_sequences"][0]["id"], "common01")

        success_opt = self.recovery_engine.add_idiom(profile_name, "idiomatic_optimizations", opt_idiom)
        self.assertTrue(success_opt)
        self.assertEqual(len(self.recovery_engine.idioms_db["compilers"][profile_name]["idiomatic_optimizations"]), 1)

        # Test adding to non-existent profile
        self.assertFalse(self.recovery_engine.add_idiom("NonExistentProfile", "common_sequences", common_idiom))
        # Test adding with invalid idiom_type
        self.assertFalse(self.recovery_engine.add_idiom(profile_name, "invalid_type", common_idiom))

    def test_identify_compiler_from_idioms_msvc(self):
        self.test_logger.info("--- Test: Identify MSVC ---")
        msvc_snippets = [
            "push ebp",
            "mov ebp, esp",
            "sub esp, 0x40", 
            "mov [ebp-8], ecx", # Fastcall idiom part
            "call __security_init_cookie" # Specific call
        ]
        compiler = self.recovery_engine.identify_compiler_from_idioms(msvc_snippets)
        self.assertEqual(compiler, "MSVC_v19_x64_Release")

    def test_identify_compiler_from_idioms_gcc(self):
        self.test_logger.info("--- Test: Identify GCC ---")
        gcc_snippets = [
            "  push   rbp", 
            "mov RBP, rsp  ", 
            "mov QWORD PTR [rbp-0x8], rdi",
            "mov DWORD PTR [rbp-0xc], esi" 
        ]
        compiler = self.recovery_engine.identify_compiler_from_idioms(gcc_snippets)
        self.assertEqual(compiler, "GCC_v9_x64_O2")
        
    def test_identify_compiler_from_idioms_no_match(self):
        self.test_logger.info("--- Test: No Match ---")
        unknown_snippets = ["xor eax, eax", "ret", "add ecx, edx"]
        compiler = self.recovery_engine.identify_compiler_from_idioms(unknown_snippets)
        self.assertIsNone(compiler)

    def test_identify_compiler_from_idioms_empty_snippets(self):
        self.test_logger.info("--- Test: Empty Snippets ---")
        compiler = self.recovery_engine.identify_compiler_from_idioms([])
        self.assertIsNone(compiler)

    def test_identify_compiler_from_idioms_regex_in_idiom(self):
        self.test_logger.info("--- Test: Regex in Idiom ---")
        msvc_snippet_variant_stack = ["push ebp", "mov ebp, esp", "sub esp, 0x90"] # Different hex value
        compiler = self.recovery_engine.identify_compiler_from_idioms(msvc_snippet_variant_stack)
        self.assertEqual(compiler, "MSVC_v19_x64_Release")

        msvc_snippet_fastcall_variant = ["mov [ebp-24], ecx"] # Different offset
        compiler_fc = self.recovery_engine.identify_compiler_from_idioms(msvc_snippet_fastcall_variant)
        self.assertEqual(compiler_fc, "MSVC_v19_x64_Release")

    def test_identify_compiler_with_more_specific_profile(self):
        self.test_logger.info("--- Test: Tie Breaking / Specificity (Implicit) ---")
        # Add a more specific MSVC profile that matches more idioms from a snippet
        specific_msvc_profile_name = "MSVC_v19_x64_Release_Specific"
        self.recovery_engine.add_compiler_profile(specific_msvc_profile_name, {
            "name": "MSVC Specific Test Profile",
            "common_sequences": [
                {"id": "msvc_sp_prologue", "assembly_pattern": [r"^\s*push\s+ebp\s*$", r"^\s*mov\s+ebp,\s*esp\s*$", r"^\s*sub\s+esp,\s*0x[0-9a-fA-F]+\s*$"]},
                {"id": "msvc_sp_cookie", "assembly_pattern": [r"^\s*call\s+__security_init_cookie\s*$"]},
            ],
            "idiomatic_optimizations": [ # Add one more idiom that original MSVC profile has
                 {"id": "msvc_sp_fastcall", "assembly_pattern": [r"^\s*mov\s+\[ebp\s*-\s*0x[0-9a-fA-F]+\],\s*ecx\s*$"]},
                 {"id": "msvc_sp_extra", "assembly_pattern": [r"^\s*xor\s+eax,\s*eax\s*$"]} # An extra one
            ]
        })
        
        # This snippet should match 4 idioms for the specific profile, vs 3 for default MSVC
        test_snippets = [
            "push ebp", "mov ebp, esp", "sub esp, 0x40",
            "call __security_init_cookie",
            "mov [ebp-10h], ecx",
            "xor eax, eax" 
        ]
        compiler = self.recovery_engine.identify_compiler_from_idioms(test_snippets)
        self.assertEqual(compiler, specific_msvc_profile_name, 
                         f"Expected {specific_msvc_profile_name} due to higher score, got {compiler}")


if __name__ == '__main__':
    if not COMPILER_RECOVERY_AVAILABLE:
        print("WARNING: CompilerSpecificRecovery class not found. Skipping tests.")
        sys.exit(0)
        
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG, 
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    unittest.main()

```
