import logging
import json
import os
from datetime import datetime, timezone # For timezone-aware timestamps
from typing import Dict, List, Optional, Any
import re # For regex matching in idioms

class CompilerSpecificRecovery:
    def __init__(self, idiom_db_path: str = "compiler_idioms.json", logger: Optional[logging.Logger] = None):
        self.idiom_db_path: str = idiom_db_path
        self.logger = logger if logger else logging.getLogger(self.__class__.__name__)
        if not logger and not logging.getLogger().hasHandlers():
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        
        self.idioms_db: Dict[str, Any] = {}
        self.initialize_idiom_database()

    def _get_timestamp(self) -> str:
        """Returns a timezone-aware ISO formatted timestamp."""
        return datetime.now(timezone.utc).isoformat()

    def _get_default_idioms_db_structure(self) -> Dict[str, Any]:
        """Returns the default structure for a new idiom database."""
        return {
            "metadata": {
                "created_at": self._get_timestamp(),
                "updated_at": self._get_timestamp(),
                "version": "0.1.1", # Incremented version for new identify method
                "description": "Database of compiler-specific idioms and patterns."
            },
            "compilers": {
                "MSVC_v19_x64_Release": {
                    "name": "Microsoft Visual C++ v19 (VS 2015-2019) x64 Release",
                    "common_sequences": [
                        {
                            "id": "msvc19_x64_rel_stack_setup_001",
                            "description": "Common function prologue stack setup.",
                            # Regex: Allows for variations in hex value, ensures push/mov/sub sequence
                            "assembly_pattern": [
                                r"^\s*push\s+ebp\s*$", 
                                r"^\s*mov\s+ebp,\s*esp\s*$", 
                                r"^\s*sub\s+esp,\s*0x[0-9a-fA-F]+\s*$"
                            ],
                            "equivalent_c": "Function prologue setup.",
                            "notes": "Size of stack allocation varies."
                        },
                        {
                            "id": "msvc19_x64_rel_security_cookie_init_001",
                            "description": "Stack security cookie initialization (__security_init_cookie).",
                            "assembly_pattern": [r"^\s*call\s+__security_init_cookie\s*$"],
                            "equivalent_c": "// Calls to initialize stack security cookie.",
                            "notes": "Often seen at start of main or other key functions."
                        }
                    ],
                    "idiomatic_optimizations": [
                         {
                            "id": "msvc19_x64_rel_fastcall_ecx_param_001",
                            "description": "Use of ECX for first parameter in __fastcall.",
                            "assembly_pattern": [r"^\s*mov\s+\[ebp\s*-\s*(0x)?[0-9a-fA-F]+\],\s*ecx\s*$"], # Example: accepts both mov [ebp-8], ecx and mov [ebp-0x8], ecx
                            "equivalent_c": "// First parameter passed via ECX",
                            "notes": "Common in MSVC __fastcall convention."
                        }
                    ]
                },
                "GCC_v9_x64_O2": {
                    "name": "GCC v9.x x64 -O2 optimization",
                    "common_sequences": [
                        {
                            "id": "gcc9_x64_o2_func_prologue_001",
                            "description": "Typical GCC function prologue.",
                            "assembly_pattern": [
                                r"^\s*push\s+rbp\s*$", 
                                r"^\s*mov\s+rbp,\s*rsp\s*$"
                            ],
                            "equivalent_c": "Function prologue.",
                            "notes": ""
                        },
                        {
                            "id": "gcc9_x64_o2_red_zone_usage_001",
                            "description": "Use of red zone (no explicit stack allocation for leaf functions with small local vars).",
                            "assembly_pattern": [
                                r"^\s*mov\s+QWORD\s+PTR\s+\[rbp-0x[0-9a-fA-F]+\],\s*rdi\s*$", # Example: mov QWORD PTR [rbp-0x8], rdi
                                r"^\s*mov\s+DWORD\s+PTR\s+\[rbp-0x[0-9a-fA-F]+\],\s*esi\s*$"  # Example: mov DWORD PTR [rbp-0xc], esi
                                # This pattern is highly contextual and might need refinement or be part of a larger sequence.
                            ],
                            "equivalent_c": "// Parameters accessed relative to RBP without large stack frame setup.",
                            "notes": "Indicates potential use of red zone if no preceding 'sub rsp, ...'."
                        }
                    ],
                    "idiomatic_optimizations": []
                }
            }
        }

    def initialize_idiom_database(self, force_recreate: bool = False) -> None:
        if not force_recreate and os.path.exists(self.idiom_db_path):
            if self._load_database():
                self.logger.info(f"Successfully loaded existing idiom database from {self.idiom_db_path}")
                if "metadata" not in self.idioms_db: self.idioms_db["metadata"] = {}
                if "compilers" not in self.idioms_db: self.idioms_db["compilers"] = {}
                self.idioms_db["metadata"]["last_loaded_at"] = self._get_timestamp()
                return

            self.logger.warning(f"Failed to load idiom database from {self.idiom_db_path}. Will create a new one.")
        
        self.logger.info(f"Initializing new idiom database at {self.idiom_db_path} (force_recreate={force_recreate})")
        self.idioms_db = self._get_default_idioms_db_structure()
        if not self._save_database():
             self.logger.error(f"Failed to save newly created idiom database to {self.idiom_db_path}.")


    def _load_database(self) -> bool:
        try:
            if not os.path.exists(self.idiom_db_path):
                self.logger.info(f"Idiom database file {self.idiom_db_path} does not exist. Cannot load.")
                return False
            with open(self.idiom_db_path, 'r', encoding='utf-8') as f:
                self.idioms_db = json.load(f)
            self.logger.debug(f"Idiom database loaded successfully from {self.idiom_db_path}.")
            return True
        except Exception as e: 
            self.logger.error(f"Unexpected error loading idiom database {self.idiom_db_path}: {e}")
            self.idioms_db = {}
            return False

    def _save_database(self) -> bool:
        if not self.idioms_db: 
            self.logger.warning("Attempted to save an empty or uninitialized idioms_db. Save aborted.")
            return False
            
        try:
            if "metadata" not in self.idioms_db:
                self.idioms_db["metadata"] = {} 
            self.idioms_db["metadata"]["updated_at"] = self._get_timestamp()
            
            db_dir = os.path.dirname(self.idiom_db_path)
            if db_dir and not os.path.exists(db_dir): 
                os.makedirs(db_dir, exist_ok=True)
                self.logger.info(f"Created directory for idiom database: {db_dir}")

            with open(self.idiom_db_path, 'w', encoding='utf-8') as f:
                json.dump(self.idioms_db, f, indent=2, ensure_ascii=False)
            self.logger.debug(f"Idiom database saved successfully to {self.idiom_db_path}.")
            return True
        except Exception as e: 
            self.logger.error(f"Unexpected error saving idiom database {self.idiom_db_path}: {e}")
            return False

    def add_compiler_profile(self, profile_name: str, profile_details: Dict[str, Any]) -> bool:
        if "compilers" not in self.idioms_db:
            self.logger.error("Idiom database not correctly initialized (missing 'compilers' key). Cannot add profile.")
            self.idioms_db["compilers"] = {} 

        if profile_name in self.idioms_db["compilers"]:
            self.logger.warning(f"Compiler profile '{profile_name}' already exists. Overwriting with new details.")
        
        self.idioms_db["compilers"][profile_name] = {
            "name": profile_details.get("name", profile_name),
            "common_sequences": profile_details.get("common_sequences", []),
            "idiomatic_optimizations": profile_details.get("idiomatic_optimizations", []),
            "added_at": self._get_timestamp()
        }
        self.logger.info(f"Added/Updated compiler profile '{profile_name}'.")
        return self._save_database()

    def add_idiom(self, profile_name: str, idiom_type: str, idiom_details: Dict[str, Any]) -> bool:
        if "compilers" not in self.idioms_db or profile_name not in self.idioms_db["compilers"]:
            self.logger.error(f"Compiler profile '{profile_name}' not found. Cannot add idiom.")
            return False
        
        if idiom_type not in ["common_sequences", "idiomatic_optimizations"]:
            self.logger.error(f"Invalid idiom_type '{idiom_type}'. Must be 'common_sequences' or 'idiomatic_optimizations'.")
            return False

        if idiom_type not in self.idioms_db["compilers"][profile_name]:
            self.idioms_db["compilers"][profile_name][idiom_type] = []

        if "added_at" not in idiom_details:
            idiom_details["added_at"] = self._get_timestamp()
        
        self.idioms_db["compilers"][profile_name][idiom_type].append(idiom_details)
        self.logger.info(f"Added idiom to '{profile_name}' under '{idiom_type}'.")
        return self._save_database()

    def _normalize_line(self, line: str) -> str:
        """Normalizes an assembly line for matching."""
        line = line.strip()
        # Convert instruction mnemonic to lowercase, keep operands as is (case might matter for symbols/labels)
        parts = line.split(None, 1)
        if parts:
            parts[0] = parts[0].lower()
            return " ".join(parts)
        return ""

    def _match_line(self, pattern_regex: str, normalized_code_line: str) -> bool:
        """Matches a pattern regex against a normalized code line."""
        try:
            # Using re.fullmatch to ensure the entire line matches the pattern
            return bool(re.fullmatch(pattern_regex, normalized_code_line))
        except re.error as e:
            self.logger.error(f"Regex error for pattern '{pattern_regex}': {e}")
            return False

    def identify_compiler_from_idioms(self, code_snippets: List[str]) -> Optional[str]:
        if not code_snippets:
            self.logger.info("No code snippets provided for compiler identification.")
            return None
        
        self.logger.info(f"Attempting to identify compiler from {len(code_snippets)} code snippets.")
        
        normalized_input_lines = [self._normalize_line(line) for line in code_snippets]
        # Filter out empty normalized lines if they are not meaningful for sequence matching
        normalized_input_lines = [line for line in normalized_input_lines if line]

        if not normalized_input_lines:
            self.logger.info("Normalized code snippets are empty. Cannot identify compiler.")
            return None

        compiler_scores: Dict[str, int] = {}

        for profile_name, profile_data in self.idioms_db.get("compilers", {}).items():
            compiler_scores[profile_name] = 0
            all_idioms = profile_data.get("common_sequences", []) + profile_data.get("idiomatic_optimizations", [])
            
            self.logger.debug(f"Checking profile: {profile_name} with {len(all_idioms)} idioms.")

            for idiom_details in all_idioms:
                assembly_pattern = idiom_details.get("assembly_pattern", [])
                if not assembly_pattern:
                    continue
                
                pattern_len = len(assembly_pattern)
                if pattern_len == 0:
                    continue

                # Iterate through the input code snippets to find a match for this sequence
                for i in range(len(normalized_input_lines) - pattern_len + 1):
                    match_found = True
                    for j in range(pattern_len):
                        pattern_line_regex = assembly_pattern[j]
                        code_line_to_check = normalized_input_lines[i+j]
                        
                        if not self._match_line(pattern_line_regex, code_line_to_check):
                            match_found = False
                            break 
                    
                    if match_found:
                        self.logger.info(f"Matched idiom '{idiom_details.get('id', 'N/A')}' for compiler '{profile_name}'.")
                        compiler_scores[profile_name] += 1
                        # Optional: break from inner loop if an idiom should only be counted once per snippet set
                        # This means this idiom is "found" for this compiler, move to next idiom for this compiler.
                        break 
            self.logger.debug(f"Score for {profile_name}: {compiler_scores[profile_name]}")

        if not compiler_scores:
            self.logger.info("No compiler profiles found in the database.")
            return None

        # Determine the best match
        best_score = 0
        identified_compiler: Optional[str] = None
        for profile_name, score in compiler_scores.items():
            if score > best_score:
                best_score = score
                identified_compiler = profile_name
            # Simple tie-breaking: first one encountered with max score is kept.
            # Could collect all ties if needed: `if score == best_score: tied_compilers.append(profile_name)`
        
        if identified_compiler and best_score > 0:
            self.logger.info(f"Identified compiler: {identified_compiler} with score {best_score}.")
            return identified_compiler
        else:
            self.logger.info("No compiler identified with sufficient confidence (score > 0).")
            return None


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    main_logger = logging.getLogger("CompilerSpecificRecoveryExample")

    # Use a temporary specific path for tests to avoid interfering with default
    test_db_path = "test_compiler_idioms_identify.json"
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
        
    recovery_engine = CompilerSpecificRecovery(idiom_db_path=test_db_path, logger=main_logger)
    # The __init__ calls initialize_idiom_database, which creates default entries.

    main_logger.info("--- Test Case 1: Identify MSVC ---")
    msvc_snippets = [
        "push ebp",
        "mov ebp, esp",
        "sub esp, 0x40", # Matches regex
        "call __security_init_cookie"
    ]
    compiler = recovery_engine.identify_compiler_from_idioms(msvc_snippets)
    main_logger.info(f"Identified: {compiler}")
    assert compiler == "MSVC_v19_x64_Release"

    main_logger.info("--- Test Case 2: Identify GCC ---")
    gcc_snippets = [
        "  push   rbp", # Test whitespace normalization
        "mov RBP, rsp  ", # Test case normalization for mnemonic, varied spacing
        "mov QWORD PTR [rbp-0x8], rdi" # Part of a GCC idiom (simplified for test)
    ]
    compiler = recovery_engine.identify_compiler_from_idioms(gcc_snippets)
    main_logger.info(f"Identified: {compiler}")
    assert compiler == "GCC_v9_x64_O2"
    
    main_logger.info("--- Test Case 3: Ambiguous or Partial Match (should prefer higher score or first) ---")
    # This snippet has elements of both, but MSVC has more distinct patterns from default DB
    ambiguous_snippets = [
        "push ebp",         # MSVC / older GCC
        "mov ebp, esp",     # MSVC / older GCC
        "sub esp, 0x20",    # MSVC
        "mov eax, [ebp+8]", # Generic
        "call some_func"    # Generic
    ]
    compiler = recovery_engine.identify_compiler_from_idioms(ambiguous_snippets)
    main_logger.info(f"Identified (ambiguous): {compiler}")
    # Based on default DB, MSVC has "sub esp, 0x..." which is more specific than just push/mov
    assert compiler == "MSVC_v19_x64_Release" 

    main_logger.info("--- Test Case 4: No Match ---")
    unknown_snippets = [
        "xor eax, eax",
        "ret"
    ]
    compiler = recovery_engine.identify_compiler_from_idioms(unknown_snippets)
    main_logger.info(f"Identified (unknown): {compiler}")
    assert compiler is None

    main_logger.info("--- Test Case 5: Empty Snippets ---")
    compiler = recovery_engine.identify_compiler_from_idioms([])
    main_logger.info(f"Identified (empty): {compiler}")
    assert compiler is None

    main_logger.info("--- Test Case 6: MSVC fastcall idiom ---")
    msvc_fastcall_snippet = [
        "mov [ebp-8], ecx" 
    ]
    compiler = recovery_engine.identify_compiler_from_idioms(msvc_fastcall_snippet)
    main_logger.info(f"Identified (MSVC fastcall): {compiler}")
    assert compiler == "MSVC_v19_x64_Release"


    # Clean up
    main_logger.info("--- Cleaning up test files ---")
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
        main_logger.info(f"Removed {test_db_path}")
    
    main_logger.info("--- All tests completed ---")
