# import_resolver.py
# A utility to parse, analyze, and refactor Python import paths within the KP14 framework.

import argparse
import ast
import os
import json

class ImportReviser(ast.NodeTransformer):
    def __init__(self, project_root, rules, filepath=""):
        super().__init__()
        self.project_root = project_root
        self.rules = rules
        self.filepath = filepath
        self.current_file_changed = False # Overall flag for the file
        self.found_imports = []
        self.proposed_changes = [] # To store {"lineno":..., "original_import_str":..., "new_import_str":...}

    def _unparse_node_to_string(self, node):
        try:
            # Attempt to use ast.unparse (Python 3.9+)
            return ast.unparse(node).strip()
        except AttributeError:
            # Basic fallback for older Python versions (for display purposes mainly)
            if isinstance(node, ast.Import):
                return "import " + ", ".join([n.name + (f" as {n.asname}" if n.asname else "") for n in node.names])
            elif isinstance(node, ast.ImportFrom):
                module_part = "." * node.level + (node.module if node.module else "")
                names_part = ", ".join([n.name + (f" as {n.asname}" if n.asname else "") for n in node.names])
                return f"from {module_part} import {names_part}"
            return "[AST node display not fully supported for this Python version]"
        except Exception as e:
            return f"[Error unparsing node: {e}]"

    def visit_Import(self, node):
        alias_rules = self.rules.get("alias_paths", {})
        node_changed_here = False # Flag for changes to this specific node

        original_import_str = self._unparse_node_to_string(node) # Capture before any changes

        for alias_node in node.names: # ast.alias objects
            if alias_node.name in alias_rules:
                new_name = alias_rules[alias_node.name]
                if alias_node.name != new_name: # Important: check if it's an actual change
                    alias_node.name = new_name
                    self.current_file_changed = True # File has changed
                    node_changed_here = True       # This specific node changed

        if node_changed_here:
            new_import_str = self._unparse_node_to_string(node)
            self.proposed_changes.append({
                "lineno": node.lineno,
                "col_offset": node.col_offset,
                "original_import_str": original_import_str,
                "new_import_str": new_import_str
            })

        # Log final state to found_imports (as done previously)
        for alias_node_final in node.names:
            self.found_imports.append({
                "type": "import", "file": self.filepath, "module_name": alias_node_final.name,
                "alias": alias_node_final.asname, "lineno": node.lineno, "col_offset": node.col_offset,
                "modified": node_changed_here
            })
        return node

    def visit_ImportFrom(self, node):
        alias_rules = self.rules.get("alias_paths", {})
        node_changed_here = False

        original_import_str = self._unparse_node_to_string(node)

        if node.module and node.module in alias_rules:
            new_module_name = alias_rules[node.module]
            if node.module != new_module_name: # Important: check if it's an actual change
                node.module = new_module_name
                self.current_file_changed = True
                node_changed_here = True

        if node_changed_here:
            new_import_str = self._unparse_node_to_string(node)
            self.proposed_changes.append({
                "lineno": node.lineno,
                "col_offset": node.col_offset,
                "original_import_str": original_import_str,
                "new_import_str": new_import_str
            })

        # Log final state to found_imports (as done previously)
        self.found_imports.append({
            "type": "from_import", "file": self.filepath, "module_name": node.module,
            "level": node.level, "imported_names": [{"name": alias.name, "alias": alias.asname} for alias in node.names],
            "lineno": node.lineno, "col_offset": node.col_offset, "modified": node_changed_here
        })
        return node

def scan_python_files(target_dir):
    """Recursively scans a directory for .py files."""
    py_files = []
    for root, _, files in os.walk(target_dir):
        for file in files:
            if file.endswith(".py"):
                py_files.append(os.path.join(root, file))
    return py_files

def load_rules(config_path):
    """Loads pathing rules from a JSON configuration file."""
    if not config_path:
        return {}
    try:
        with open(config_path, 'r') as f:
            rules = json.load(f)
        return rules
    except FileNotFoundError:
        print(f"Warning: Rules config file not found: {config_path}. Proceeding without rules.")
        return {}
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON from {config_path}: {e}. Proceeding without rules.")
        return {}

def main():
    parser = argparse.ArgumentParser(
        description="Analyzes and refactors Python import statements based on specified rules.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "target_directory",
        help="The directory to recursively scan for Python files."
    )
    parser.add_argument(
        "--project-root",
        help="Path to the project's root directory. Used for resolving absolute imports. \n"
             "If not provided, attempts to infer it (e.g., as parent of target_directory or CWD)."
    )
    parser.add_argument(
        "--rules-config",
        help="Path to a JSON configuration file defining pathing rules and refactoring actions."
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Show proposed changes without modifying files."
    )
    mode_group.add_argument(
        "--apply",
        action="store_true",
        help="Apply the refactoring changes to the files."
    )

    args = parser.parse_args()

    project_root = args.project_root
    if not project_root:
        project_root = os.path.abspath(os.path.join(args.target_directory, os.pardir))
        print(f"Info: --project-root not specified. Inferred as: {project_root}")

    rules = load_rules(args.rules_config)
    if not rules and args.apply:
        print("Warning: Running in --apply mode without any rules defined. No changes will be made.")

    python_files = scan_python_files(args.target_directory)

    if not python_files:
        print(f"No Python files found in {args.target_directory}")
        return

    print(f"Found {len(python_files)} Python files to analyze.")

    files_would_change_count = 0
    files_changed_count = 0

    # Temporary logging of all found imports (can be removed or kept under a verbosity flag)
    all_found_imports_summary = []


    for filepath in python_files:
        # print(f"\nProcessing: {filepath}") # Kept for verbose, can be removed/conditional
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                source_code = f.read()

            tree = ast.parse(source_code, filename=filepath)

            reviser = ImportReviser(project_root, rules, filepath=filepath)
            new_tree = reviser.visit(tree)

            # Consolidate found imports for summary later
            all_found_imports_summary.extend(reviser.found_imports)

            if reviser.current_file_changed:
                files_would_change_count +=1
                if args.dry_run:
                    print(f"\n[Dry Run] Changes proposed for {filepath}:") # Changed from "  " to "\n" for better separation
                    for change in sorted(reviser.proposed_changes, key=lambda x: x['lineno']): # Sort by line number
                        print(f"  L{change['lineno']}:")
                        print(f"    - {change['original_import_str']}")
                        print(f"    + {change['new_import_str']}")
                elif args.apply:
                    print(f"\n[Apply] Modifying {filepath}...") # Changed from "  " to "\n"
                    try:
                        ast.fix_missing_locations(new_tree) # Ensure locations are fixed
                        new_source_code = ast.unparse(new_tree)
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(new_source_code)
                        files_changed_count += 1
                        # print(f"    Successfully modified {filepath}") # Can be made less verbose
                    except AttributeError: # ast.unparse not available
                        print(f"    ERROR: ast.unparse is not available for {filepath}. You might need Python 3.9+ or an external library like 'astunparse'. File not modified.")
                    except Exception as e_write:
                        print(f"    ERROR writing changes to {filepath}: {e_write}")
            # else: # No changes for this file
                # if args.dry_run: print(f"  [Dry Run] No changes proposed for {filepath}.")
                # else: print(f"  No changes needed for {filepath}")


        except FileNotFoundError:
            print(f"  Error: File not found during processing: {filepath}")
        except SyntaxError as e_syn:
            print(f"  Error: Could not parse {filepath}. Syntax error: {e_syn}")
        except Exception as e_gen:
            print(f"  An unexpected error occurred processing {filepath}: {e_gen}")

    if args.apply:
        print(f"\nRefactoring complete. {files_changed_count} file(s) modified.")
    elif args.dry_run:
        print(f"\nDry run complete. {files_would_change_count} file(s) would be modified if '--apply' was used.")

    # Optional: Summary of all imports (can be very verbose)
    # print("\n--- Summary of all imports found across all files (final state) ---")
    # for imp_data in sorted(all_found_imports_summary, key=lambda x: (x['file'], x['lineno'])):
    #     modified_indicator = " (Modified)" if imp_data.get("modified") else ""
    #     file_info = f"File: {imp_data['file']}, L{imp_data['lineno']}"
    #     if imp_data['type'] == 'import':
    #         print(f"  {file_info}: import {imp_data['module_name']}" + (f" as {imp_data['alias']}" if imp_data['alias'] else "") + modified_indicator)
    #     elif imp_data['type'] == 'from_import':
    #         names_str = ", ".join([n['name'] + (f" as {n['alias']}" if n['alias'] else "") for n in imp_data['imported_names']])
    #         module_prefix = "." * imp_data['level'] + (imp_data['module_name'] if imp_data['module_name'] else "")
    #         print(f"  {file_info}: from {module_prefix} import {names_str}" + modified_indicator)


if __name__ == "__main__":
    main()
