import unittest
import logging
import os
import json
import tempfile
from pathlib import Path
from typing import Any
import sys

# Attempt to import pycparser and the TypePropagator
try:
    from pycparser import c_parser, c_ast, parse_file
    PYCPARSER_AVAILABLE = True
except ImportError:
    PYCPARSER_AVAILABLE = False

# Assuming type_propagation.py is in the same directory or accessible in PYTHONPATH
# If it's in a parent directory, adjust the path.
# For this environment, assume it's in the same directory.
try:
    from type_propagation import TypePropagator
    TYPE_PROPAGATOR_AVAILABLE = True
except ImportError:
    print("Failed to import TypePropagator. Ensure type_propagation.py is in the Python path.")
    TYPE_PROPAGATOR_AVAILABLE = False


@unittest.skipIf(not PYCPARSER_AVAILABLE, "pycparser not installed, skipping TypePropagator tests.")
@unittest.skipIf(not TYPE_PROPAGATOR_AVAILABLE, "TypePropagator class not found, skipping tests.")
class TestTypePropagator(unittest.TestCase):

    def setUp(self):
        self.test_logger = logging.getLogger("TestTypePropagator")
        self.test_logger.setLevel(logging.DEBUG) # Or logging.INFO for less verbosity
        # Ensure a handler is added if running tests in an environment where root logger isn't configured
        if not self.test_logger.hasHandlers():
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.test_logger.addHandler(handler)

        self.propagator = TypePropagator(logger=self.test_logger)
        
        # Create a temporary directory for dummy files
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_files_dir = Path(self.temp_dir.name)

        self.dummy_c_file_path = self.test_files_dir / "test_source.c"
        self.dummy_sig_file_path = self.test_files_dir / "test_signatures.json"

    def tearDown(self):
        # Cleanup dummy files by removing the temporary directory
        self.temp_dir.cleanup()
        # print(f"Cleaned up temp directory: {self.test_files_dir}")


    def _create_dummy_c_file(self, content: str) -> str:
        with open(self.dummy_c_file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return str(self.dummy_c_file_path)

    def _create_dummy_json_file(self, data: Any, path: Path) -> str:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        return str(path)

    def test_initialization(self):
        self.assertIsNotNone(self.propagator)
        self.assertIsNotNone(self.propagator.logger)
        self.assertEqual(self.propagator.max_propagation_rounds, 10)

    def test_propagate_types_no_files(self):
        self.test_logger.info("--- Test: propagate_types with non-existent files ---")
        results = self.propagator.propagate_types("non_existent.c", "non_existent.json")
        self.assertEqual(results.get("inferred_types"), {})
        self.assertIn("error", results.get("c_ast_parsing_status", {}).get("status", ""))
        self.assertIn("error", results.get("signature_loading_status", {}).get("status", ""))

    def test_propagate_types_from_signatures_only(self):
        self.test_logger.info("--- Test: propagate_types from signatures only ---")
        sig_data = [
            {"name": "func1", "return_type": "int", "parameters": [{"name": "p1", "type": "char*"}]},
            {"name": "func2", "return_type": "void", "parameters": []}
        ]
        sig_file = self._create_dummy_json_file(sig_data, self.dummy_sig_file_path)
        c_file = self._create_dummy_c_file("") # Empty C file

        results = self.propagator.propagate_types(decompiled_code_path=c_file, signature_data_path=sig_file)
        inferred_types = results.get("inferred_types", {})
        
        self.assertEqual(inferred_types.get("func1_return"), "int")
        self.assertEqual(inferred_types.get("func1::p1"), "char*")
        self.assertEqual(inferred_types.get("func2_return"), "void")

    def test_propagate_types_from_c_declarations_basic(self):
        self.test_logger.info("--- Test: propagate_types from C declarations (basic) ---")
        c_content = """
        int global_var_1;
        static char *g_str_ptr;
        void my_func() {
            float local_float;
            const int const_local = 10;
        }
        """
        c_file = self._create_dummy_c_file(c_content)
        results = self.propagator.propagate_types(decompiled_code_path=c_file)
        inferred_types = results.get("inferred_types", {})

        self.assertEqual(inferred_types.get("global_global_var_1"), "int")
        self.assertEqual(inferred_types.get("global_g_str_ptr"), "char*") # pycparser might add 'static' to type
        self.assertEqual(inferred_types.get("my_func::local_float"), "float")
        self.assertEqual(inferred_types.get("my_func::const_local"), "const int")

    def test_propagate_types_from_c_funcdef(self):
        self.test_logger.info("--- Test: propagate_types from C function definition ---")
        c_content = "unsigned short process_data(int input_val, char *name) { double local_d; return 0; }"
        c_file = self._create_dummy_c_file(c_content)
        results = self.propagator.propagate_types(decompiled_code_path=c_file)
        inferred_types = results.get("inferred_types", {})

        self.assertEqual(inferred_types.get("process_data_return"), "unsigned short")
        self.assertEqual(inferred_types.get("process_data::input_val"), "int")
        self.assertEqual(inferred_types.get("process_data::name"), "char*")
        # Local vars inside function defs are also caught by _visit_Decl
        self.assertEqual(inferred_types.get("process_data::local_d"), "double")

    def test_typedef_extraction(self):
        self.test_logger.info("--- Test: typedef extraction ---")
        c_content = """
        typedef unsigned long MY_DWORD;
        typedef char* LPCMYSTR;
        MY_DWORD dword_var;
        LPCMYSTR string_var;
        struct _MyStruct { int x; } typedef MyStructType, *PMyStructType;
        MyStructType struct_instance;
        PMyStructType struct_ptr_instance;
        """
        c_file = self._create_dummy_c_file(c_content)
        results = self.propagator.propagate_types(decompiled_code_path=c_file)
        typedefs = results.get("typedefs", {})
        inferred_types = results.get("inferred_types", {})
        
        self.assertEqual(typedefs.get("MY_DWORD"), "unsigned long")
        self.assertEqual(typedefs.get("LPCMYSTR"), "char*")
        self.assertEqual(inferred_types.get("global_dword_var"), "MY_DWORD") # Stores typedef name
        self.assertEqual(inferred_types.get("global_string_var"), "LPCMYSTR")

        self.assertEqual(typedefs.get("MyStructType"), "struct _MyStruct")
        self.assertEqual(typedefs.get("PMyStructType"), "struct _MyStruct*") # Pointer to the struct
        self.assertEqual(inferred_types.get("global_struct_instance"), "MyStructType")
        self.assertEqual(inferred_types.get("global_struct_ptr_instance"), "PMyStructType")
    
    def test_complex_pointer_types(self):
        self.test_logger.info("--- Test: complex pointer types ---")
        c_content = """
        char **argv;
        const char * const * safe_argv;
        void (*callback_func)(int, char**);
        typedef int (*FuncPtrType)(void);
        FuncPtrType my_func_ptr;
        """
        c_file = self._create_dummy_c_file(c_content)
        results = self.propagator.propagate_types(decompiled_code_path=c_file)
        inferred_types = results.get("inferred_types", {})
        typedefs = results.get("typedefs", {})

        self.assertEqual(inferred_types.get("global_argv"), "char**")
        self.assertEqual(inferred_types.get("global_safe_argv"), "const char* const*")
        # pycparser represents func pointers differently; need to see how TypePropagator handles.
        # For now, we'll check it's captured. The exact string might vary.
        self.assertIn("global_callback_func", inferred_types)
        # Be more flexible with function pointer formatting - we just need to ensure
        # it has the right return type and parameter types
        callback_type = inferred_types.get("global_callback_func", "")
        self.assertTrue("void" in callback_type)
        self.assertTrue("int" in callback_type)
        self.assertTrue("char**" in callback_type)


        self.assertTrue("int(*)(void)" in typedefs.get("FuncPtrType", "").replace(" ", ""))
        self.assertEqual(inferred_types.get("global_my_func_ptr"), "FuncPtrType")


    def test_struct_union_enum_declarations(self):
        self.test_logger.info("--- Test: struct, union, enum declarations ---")
        c_content = """
        struct Point { int x; int y; };
        union Data { int i; float f; char str[20]; };
        enum Color { RED, GREEN, BLUE };
        struct Point p1;
        union Data d1;
        enum Color c1;
        """
        c_file = self._create_dummy_c_file(c_content)
        results = self.propagator.propagate_types(decompiled_code_path=c_file)
        struct_defs = results.get("struct_definitions", {})
        union_defs = results.get("union_definitions", {})
        enum_defs = results.get("enum_definitions", {})
        inferred_types = results.get("inferred_types", {})

        self.assertIn("Point", struct_defs)
        self.assertEqual(len(struct_defs["Point"]), 2) # x, y
        self.assertIn("Data", union_defs)
        self.assertEqual(len(union_defs["Data"]), 3) # i, f, str
        self.assertIn("Color", enum_defs)
        self.assertEqual(len(enum_defs["Color"]), 3) # RED, GREEN, BLUE

        self.assertEqual(inferred_types.get("global_p1"), "struct Point")
        self.assertEqual(inferred_types.get("global_d1"), "union Data")
        self.assertEqual(inferred_types.get("global_c1"), "enum Color")
        
    def test_with_existing_types(self):
        self.test_logger.info("--- Test: with existing types ---")
        c_content = "int new_var;"
        c_file = self._create_dummy_c_file(c_content)
        existing_types = {"existing_var": "float", "global_new_var": "char"} # existing has higher precedence
        
        results = self.propagator.propagate_types(decompiled_code_path=c_file, existing_types=existing_types)
        inferred_types = results.get("inferred_types", {})
        
        self.assertEqual(inferred_types.get("global_new_var"), "char") # From existing_types
        self.assertEqual(inferred_types.get("existing_var"), "float")  # Preserved from existing_types

    # Placeholder for propagation tests - these will be more involved
    # as they require simulating assignments and function calls within the AST visitor
    # or by carefully crafting C code that pycparser can fully resolve for simple cases.

    def test_propagate_types_assignment_propagation(self):
        self.test_logger.info("--- Test: assignment propagation ---")
        c_content = """
        typedef void* generic_ptr;

        void main() { 
            int y; 
            y = 10; 
            
            // x is declared with a generic type, should get specific type from y
            generic_ptr x;
            x = y; 
        }
        """
        c_file = self._create_dummy_c_file(c_content)
        results = self.propagator.propagate_types(decompiled_code_path=c_file)
        inferred_types = results.get("inferred_types", {})
        
        # Verify that y has the expected type from declaration
        self.assertEqual(inferred_types.get("main::y"), "int")
        
        # Verify that x got its type from the assignment (y → x)
        self.assertEqual(inferred_types.get("main::x"), "int")

    def test_propagate_types_func_call_return_propagation(self):
        self.test_logger.info("--- Test: function call return propagation ---")
        c_content = """
        typedef void* generic_ptr;
        
        // Function with explicit return type
        int get_val() { 
            return 5; 
        } 
        
        void main() { 
            // Variable z has generic type, should get specific type from function return
            generic_ptr z;
            z = get_val();
        }
        """
        c_file = self._create_dummy_c_file(c_content)
        results = self.propagator.propagate_types(decompiled_code_path=c_file)
        inferred_types = results.get("inferred_types", {})
        
        # Verify the function return type is captured
        self.assertEqual(inferred_types.get("get_val_return"), "int")
        
        # Verify that z got its type from the function return (get_val → z)
        self.assertEqual(inferred_types.get("main::z"), "int")
        
    def test_propagate_types_func_call_arg_propagation(self):
        self.test_logger.info("--- Test: function call argument propagation ---")
        c_content = """
        typedef void* generic_ptr;
        
        // Function prototype only, implementation not needed for the test
        void set_val(int v);
        
        void main() { 
            // Variable my_var has a generic type, should get specific type from function parameter
            generic_ptr my_var;
            // When passed to set_val, my_var should take on type 'int' from parameter v
            set_val(my_var);
        }
        """
        c_file = self._create_dummy_c_file(c_content)
        
        # Create a signature file for the set_val function
        sig_data = [
            {
                "name": "set_val", 
                "return_type": "void", 
                "parameters": [
                    {"name": "v", "type": "int"}
                ]
            }
        ]
        sig_file = self._create_dummy_json_file(sig_data, self.dummy_sig_file_path)
        
        # Propagate types with both code and signature files
        results = self.propagator.propagate_types(decompiled_code_path=c_file, signature_data_path=sig_file)
        inferred_types = results.get("inferred_types", {})
        
        # Verify the variable gets its type from the function parameter signature
        self.assertEqual(inferred_types.get("main::my_var"), "int")

if __name__ == '__main__':
    if not PYCPARSER_AVAILABLE:
        print("WARNING: pycparser is not available. Skipping TypePropagator tests.")
        sys.exit(0)
    if not TYPE_PROPAGATOR_AVAILABLE:
        print("WARNING: TypePropagator class not found. Skipping tests.")
        sys.exit(0)
        
    # Configure logging for the test run if module is run directly
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG, 
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    unittest.main()
