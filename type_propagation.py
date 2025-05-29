import json
import re
import logging
import os # Added for os.path.exists and example usage
from typing import Optional, Dict, List # For type hinting

class TypePropagator:
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger if logger else logging.getLogger(self.__class__.__name__)
        if not logger: # Basic config only if no logger is provided by the caller
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    def propagate_types(self, decompiled_code_path: str, signature_data_path: Optional[str] = None, existing_types: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        self.logger.info(f"Starting type propagation for {decompiled_code_path}")
        inferred_types: Dict[str, str] = {}

        if existing_types:
            inferred_types.update(existing_types)
            self.logger.info(f"Initialized with {len(existing_types)} existing types.")

        # Load and process signatures
        if signature_data_path and os.path.exists(signature_data_path):
            self.logger.info(f"Loading signatures from {signature_data_path}")
            try:
                with open(signature_data_path, 'r', encoding='utf-8') as f:
                    signatures: List[Dict] = json.load(f)
                
                types_from_sigs_count = 0
                for func_sig in signatures:
                    func_name = func_sig.get("name")
                    if not func_name:
                        self.logger.warning("Found a signature entry without a function name. Skipping.")
                        continue

                    if func_sig.get("return_type"):
                        key = f"{func_name}_return"
                        inferred_types[key] = func_sig["return_type"]
                        types_from_sigs_count +=1
                    
                    for param in func_sig.get("parameters", []):
                        param_name = param.get("name")
                        param_type = param.get("type")
                        if param_name and param_type:
                            key = f"{func_name}_{param_name}"
                            inferred_types[key] = param_type
                            types_from_sigs_count += 1
                        elif param_type: # Handle unnamed parameters if type is available
                            key = f"{func_name}_param_{param_type}" # Generic key for unnamed param
                            inferred_types[key] = param_type
                            types_from_sigs_count += 1


                self.logger.info(f"Found {types_from_sigs_count} type entries from signatures.")
            except json.JSONDecodeError as e:
                self.logger.error(f"Error decoding JSON from signature file {signature_data_path}: {e}")
            except Exception as e:
                self.logger.error(f"Error loading or processing signature file {signature_data_path}: {e}")
        else:
            if signature_data_path:
                self.logger.warning(f"Signature data path provided but file does not exist: {signature_data_path}")
            else:
                self.logger.info("No signature data path provided.")

        # Basic parsing of decompiled code for local variable declarations
        self.logger.info(f"Parsing decompiled code from {decompiled_code_path} for local variables.")
        try:
            if not os.path.exists(decompiled_code_path):
                self.logger.error(f"Decompiled code file not found: {decompiled_code_path}")
                # Still return types found so far (e.g. from signatures or existing_types)
                return inferred_types

            with open(decompiled_code_path, 'r', encoding='utf-8') as f:
                code_content = f.read()
            
            # Simple regex for C variable declarations (type name;) - very basic
            # Example: int var1; char *str_ptr; struct MyStruct an_instance; const unsigned long int val;
            # This regex attempts to capture multi-word types (like "unsigned long int") and pointers.
            # It's still naive and won't handle complex declarations, function pointers, arrays correctly.
            # It also doesn't understand scope (all variables are considered "local_").
            variable_declarations = re.findall(
                r"^\s*(?:const\s+)?((?:[a-zA-Z_][a-zA-Z0-9_]*\s*(?:\*\s*|\s+))+)([a-zA-Z_][a-zA-Z0-9_]*)\s*;", 
                code_content, 
                re.MULTILINE
            )
            
            local_vars_found = 0
            for var_type, var_name in variable_declarations:
                clean_type = " ".join(var_type.strip().split()) # Normalize whitespace, keep '*'
                key = f"local_{var_name}"
                if key not in inferred_types: # Avoid overwriting signature types if names (unlikely prefix clash)
                     inferred_types[key] = clean_type
                     local_vars_found +=1
                else:
                    self.logger.debug(f"Local variable key {key} already exists, possibly from signatures or existing types. Not overwriting.")
            self.logger.info(f"Found {local_vars_found} new local variable declarations via regex.")

        except FileNotFoundError:
             self.logger.error(f"Decompiled code file not found during parsing attempt: {decompiled_code_path}")
        except Exception as e:
            self.logger.error(f"Error reading or parsing decompiled code {decompiled_code_path}: {e}")

        self.logger.info(f"Finished type propagation. Total types identified: {len(inferred_types)}")
        return inferred_types

if __name__ == '__main__':
    # Example Usage (for testing the stub)
    # Create a logger for the test script itself
    test_logger = logging.getLogger("TestTypePropagator")
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    tp = TypePropagator(logger=test_logger) # Pass the test logger
    
    # Create dummy files for testing
    dummy_c_file = "dummy_decompiled.c"
    dummy_sig_file = "dummy_signatures.json"

    # More comprehensive C dummy file
    with open(dummy_c_file, "w", encoding='utf-8') as f:
        f.write("int main(int argc, char **argv) {\n") # Function with params
        f.write("  int local_var = 10;\n")
        f.write("  const char * my_string = \"hello\";\n") // const pointer
        f.write("  unsigned long int counter;\n") // multi-word type
        f.write("  struct MyData data_point;\n") // struct type
        f.write("  return 0;\n")
        f.write("}\n\n")
        f.write("void another_func(int p1, struct AnotherStruct* p_struct) {\n") // Pointer to struct param
        f.write("  float local_float;\n")
        f.write("  int *p_int;\n") // Pointer declaration
        f.write("}\n")

    dummy_signatures = [
        {"name": "main", "return_type": "int", "parameters": [
            {"name": "argc", "type": "int"},
            {"name": "argv", "type": "char **"}
        ]},
        {"name": "another_func", "return_type": "void", "parameters": [
            {"name": "p1", "type": "int"},
            {"name": "p_struct", "type": "struct AnotherStruct*"}
        ]}
    ]
    with open(dummy_sig_file, "w", encoding='utf-8') as f:
        json.dump(dummy_signatures, f, indent=2)

    existing_test_types = {"predefined_global_type": "GlobalHandle"}
    test_logger.info("----- Running Test 1: With Signatures and Existing Types -----")
    results1 = tp.propagate_types(dummy_c_file, dummy_sig_file, existing_types=existing_test_types)
    print("\nResults (Test 1):")
    for k, v in results1.items():
        print(f"  {k}: {v}")
    
    test_logger.info("----- Running Test 2: Decompiled Code Only -----")
    results2 = tp.propagate_types(dummy_c_file)
    print("\nResults (Test 2):")
    for k, v in results2.items():
        print(f"  {k}: {v}")

    test_logger.info("----- Running Test 3: Signatures Only -----")
    # Create an empty C file for this test case or use a non-existent one to test that path
    empty_c_file = "empty_decompiled.c"
    with open(empty_c_file, "w", encoding='utf-8') as f:
        f.write("// Empty C file\n")
    results3 = tp.propagate_types(empty_c_file, dummy_sig_file)
    print("\nResults (Test 3):")
    for k, v in results3.items():
        print(f"  {k}: {v}")

    test_logger.info("----- Running Test 4: Non-existent signature file -----")
    results4 = tp.propagate_types(dummy_c_file, "non_existent_signatures.json")
    print("\nResults (Test 4):")
    for k, v in results4.items():
        print(f"  {k}: {v}")
    
    test_logger.info("----- Running Test 5: Non-existent C file -----")
    results5 = tp.propagate_types("non_existent_c_file.c", dummy_sig_file)
    print("\nResults (Test 5):")
    for k, v in results5.items():
        print(f"  {k}: {v}")

    # Clean up dummy files
    os.remove(dummy_c_file)
    os.remove(dummy_sig_file)
    os.remove(empty_c_file)
    test_logger.info("Cleaned up dummy files.")

```
