import importlib
import json
import sys
import os

# Add the /app directory to sys.path to find stego_analyzer
# and keyplug_pipeline_config.py
module_path = '/app'
if module_path not in sys.path:
    sys.path.insert(0, module_path)

try:
    import keyplug_pipeline_config
except ImportError as e:
    print(f"Error importing keyplug_pipeline_config (sys.path: {sys.path}): {e}")
    exit(1)

def run_import_tests():
    print("Starting import tests for modules in keyplug_pipeline_config.py...")
    config = keyplug_pipeline_config.get_pipeline_config()
    module_imports = config.get("module_imports", {})

    all_successful = True
    successful_imports = 0
    failed_imports = 0

    if not module_imports:
        print("No module import map found in the configuration.")
        return False

    for module_name, import_path in module_imports.items():
        try:
            # The import path is typically 'stego_analyzer.utils.extract_pe.ExtractPE'
            # We need to import the module 'stego_analyzer.utils.extract_pe'
            # And then check if 'ExtractPE' class/attr exists
            module_part = '.'.join(import_path.split('.')[:-1])
            class_name = import_path.split('.')[-1]

            print(f"Attempting to import module: {module_part} for class {class_name} (Original: {module_name})")
            imported_module = importlib.import_module(module_part)

            if hasattr(imported_module, class_name):
                print(f"Successfully imported {import_path} (Class: {class_name})")
                successful_imports += 1
            else:
                print(f"Failed: Class {class_name} not found in module {module_part} (Original: {module_name})")
                all_successful = False
                failed_imports += 1

        except ImportError as e:
            print(f"Failed to import {import_path} (Original: {module_name}): {e}")
            all_successful = False
            failed_imports += 1
        except Exception as e:
            print(f"An unexpected error occurred while importing {import_path} (Original: {module_name}): {e}")
            all_successful = False
            failed_imports += 1

    print("\n--- Import Test Summary ---")
    print(f"Total modules checked: {len(module_imports)}")
    print(f"Successful imports: {successful_imports}")
    print(f"Failed imports: {failed_imports}")

    if all_successful:
        print("All modules imported successfully!")
    else:
        print("Some modules failed to import.")

    return all_successful

if __name__ == "__main__":
    if run_import_tests():
        exit(0)
    else:
        exit(1)
