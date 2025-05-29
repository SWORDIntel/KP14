import json
import re
import logging
import os 
from typing import Optional, Dict, List 

from pycparser import c_parser, c_ast, parse_file
from pycparser.plyparser import ParseError

class TypeExtractorVisitor(c_ast.NodeVisitor):
    def __init__(self, inferred_types: Dict[str, str], logger: logging.Logger):
        self.inferred_types = inferred_types 
        self.logger = logger
        self.current_function_name = None
        self.changed_in_pass = False 

    def _stringify_type(self, type_node):
        if isinstance(type_node, c_ast.TypeDecl):
            if hasattr(type_node, 'declname') and type_node.declname:
                 pass 

            quals = list(type_node.quals) if hasattr(type_node, 'quals') else []
            
            if isinstance(type_node.type, c_ast.IdentifierType):
                names = list(type_node.type.names) if hasattr(type_node.type, 'names') else []
                return ' '.join(quals + names).strip()
            elif isinstance(type_node.type, c_ast.Struct):
                struct_name = type_node.type.name if type_node.type.name else ""
                full_type_parts = quals + ['struct']
                if struct_name:
                    full_type_parts.append(struct_name)
                return ' '.join(full_type_parts).strip()
            elif isinstance(type_node.type, c_ast.Union):
                union_name = type_node.type.name if type_node.type.name else ""
                full_type_parts = quals + ['union']
                if union_name:
                    full_type_parts.append(union_name)
                return ' '.join(full_type_parts).strip()
            elif isinstance(type_node.type, c_ast.Enum):
                enum_name = type_node.type.name if type_node.type.name else ""
                full_type_parts = quals + ['enum']
                if enum_name:
                    full_type_parts.append(enum_name)
                return ' '.join(full_type_parts).strip()
            return ' '.join(quals).strip() 
        elif isinstance(type_node, c_ast.PtrDecl):
            return self._stringify_type(type_node.type) + '*'
        elif isinstance(type_node, c_ast.ArrayDecl):
            return self._stringify_type(type_node.type) + '[]' 
        elif isinstance(type_node, c_ast.IdentifierType): 
            return ' '.join(type_node.names)
        elif isinstance(type_node, c_ast.FuncDecl): 
            return self._stringify_type(type_node.type) + " (*)(...)" 
        
        self.logger.debug(f"Unknown type_node encountered in _stringify_type: {type(type_node)}")
        return "unknown_ast_type"

    def _get_var_key(self, var_name):
        return f"{self.current_function_name}::{var_name}" if self.current_function_name else f"global_{var_name}"

    def visit_Decl(self, node):
        if 'typedef' in node.storage: 
            self.generic_visit(node) 
            return

        if node.name is None:
            if isinstance(node.type, (c_ast.Struct, c_ast.Union, c_ast.Enum)) and node.type.name:
                 pass 
            self.generic_visit(node)
            return
        
        var_name = node.name
        var_type_str = self._stringify_type(node.type)
        type_key = self._get_var_key(var_name)
        
        if type_key not in self.inferred_types or self.inferred_types[type_key] == "unknown_ast_type":
            if var_type_str != "unknown_ast_type" and var_type_str.strip() != "":
                self.inferred_types[type_key] = var_type_str
                self.changed_in_pass = True
                self.logger.debug(f"Declaration: Inferred type for '{type_key}' as '{var_type_str}'")
        self.generic_visit(node)

    def visit_FuncDef(self, node):
        func_name = node.decl.name
        self.current_function_name = func_name
        
        return_type_str = self._stringify_type(node.decl.type.type)
        return_key = f"{func_name}_return"
        if return_key not in self.inferred_types or self.inferred_types[return_key] == "unknown_ast_type":
            if return_type_str != "unknown_ast_type" and return_type_str.strip() != "":
                self.inferred_types[return_key] = return_type_str
                self.changed_in_pass = True
                self.logger.debug(f"Function Def: Inferred return type for '{func_name}' as '{return_type_str}'")
        
        param_keys_ordered = []
        if node.decl.type.args: 
            for i, param_decl in enumerate(node.decl.type.args.params):
                if isinstance(param_decl, c_ast.EllipsisParam):
                    param_keys_ordered.append(f"{func_name}::param_{i}_ellipsis") # Store a placeholder for ellipsis
                    continue
                
                param_name = param_decl.name
                param_type_str = self._stringify_type(param_decl.type)
                param_key = f"{func_name}::{param_name}"
                param_keys_ordered.append(param_key)

                if param_key not in self.inferred_types or self.inferred_types[param_key] == "unknown_ast_type":
                     if param_type_str != "unknown_ast_type" and param_type_str.strip() != "":
                        self.inferred_types[param_key] = param_type_str
                        self.changed_in_pass = True
                        self.logger.debug(f"Function Def: Inferred param type for '{param_key}' as '{param_type_str}'")
            
            # Store the ordered list of parameter keys for visit_FuncCall
            param_order_key = f"{func_name}::param_order"
            if param_order_key not in self.inferred_types or self.inferred_types[param_order_key] != param_keys_ordered : # Store if new or different
                self.inferred_types[param_order_key] = param_keys_ordered
                self.changed_in_pass = True # Recording parameter order is a change
                self.logger.debug(f"Function Def: Stored parameter order for '{func_name}'.")

        if node.body: 
            self.visit(node.body) 
        
        self.current_function_name = None 

    def visit_Typedef(self, node):
        name = node.name
        type_str = self._stringify_type(node.type)
        typedef_key = f"typedef_{name}"
        if typedef_key not in self.inferred_types or self.inferred_types[typedef_key] == "unknown_ast_type":
            if type_str != "unknown_ast_type" and type_str.strip() != "":
                self.inferred_types[typedef_key] = type_str 
                self.changed_in_pass = True
                self.logger.debug(f"Typedef: Stored typedef '{typedef_key}' as '{type_str}'")
        self.generic_visit(node)

    def visit_Assignment(self, node):
        if not isinstance(node.lvalue, c_ast.ID):
            self.generic_visit(node) 
            return

        lhs_name = node.lvalue.name
        lhs_key = self._get_var_key(lhs_name)
        
        rhs_type = None
        if isinstance(node.rvalue, c_ast.ID): 
            rhs_key = self._get_var_key(node.rvalue.name)
            rhs_type = self.inferred_types.get(rhs_key)
            if rhs_type:
                 self.logger.debug(f"Assignment: RHS var '{node.rvalue.name}' (key: {rhs_key}) has type '{rhs_type}'")
        elif isinstance(node.rvalue, c_ast.FuncCall): 
            if isinstance(node.rvalue.name, c_ast.ID):
                func_name = node.rvalue.name.name
                return_key = f"{func_name}_return"
                rhs_type = self.inferred_types.get(return_key)
                if rhs_type:
                    self.logger.debug(f"Assignment: RHS func_call '{func_name}' has return type '{rhs_type}'")
        elif isinstance(node.rvalue, c_ast.Constant): 
            if node.rvalue.type == 'int':
                rhs_type = 'int'
            elif node.rvalue.type == 'string':
                rhs_type = 'char*' 
            elif node.rvalue.type == 'float':
                rhs_type = 'double' 
            elif node.rvalue.type == 'char':
                 rhs_type = 'char'
            if rhs_type:
                self.logger.debug(f"Assignment: RHS constant has inferred type '{rhs_type}'")

        if rhs_type and rhs_type != "unknown_ast_type":
            current_lhs_type = self.inferred_types.get(lhs_key)
            if not current_lhs_type or current_lhs_type == "unknown_ast_type" or current_lhs_type == "void*":
                self.inferred_types[lhs_key] = rhs_type
                self.changed_in_pass = True
                self.logger.info(f"Assignment: Propagated type for '{lhs_key}' to '{rhs_type}' from RHS.")
            elif current_lhs_type != rhs_type: 
                 self.logger.debug(f"Assignment: LHS '{lhs_key}' has type '{current_lhs_type}', RHS type is '{rhs_type}'. Not updating.")
        
        self.generic_visit(node)

    def visit_FuncCall(self, node):
        called_func_name = None
        if isinstance(node.name, c_ast.ID):
            called_func_name = node.name.name
        else:
            # Could be a function pointer or more complex expression. For now, we only handle direct calls by ID.
            self.logger.debug(f"FuncCall: Skipping call via non-ID: {type(node.name)}")
            self.generic_visit(node)
            return

        param_order_key = f"{called_func_name}::param_order"
        param_keys_ordered = self.inferred_types.get(param_order_key)

        if not isinstance(param_keys_ordered, list): # Check if it's a list (it might be None or a type string if a var has this name)
            self.logger.debug(f"FuncCall: No parameter order list found for '{called_func_name}' (key: {param_order_key}). Skipping arg type propagation.")
            self.generic_visit(node)
            return

        if node.args:
            for i, arg_node in enumerate(node.args.exprs):
                if isinstance(arg_node, c_ast.ID): # Argument is a variable
                    arg_name = arg_node.name
                    arg_key = self._get_var_key(arg_name) # Correctly scope the argument variable
                    
                    current_arg_type = self.inferred_types.get(arg_key)

                    if i < len(param_keys_ordered):
                        param_key = param_keys_ordered[i]
                        if param_key.endswith("_ellipsis"): # Skip ellipsis
                            continue
                        
                        param_type = self.inferred_types.get(param_key)

                        if param_type and param_type != "unknown_ast_type":
                            # Condition for updating: arg type is unknown, or generic (void*), or param_type is more specific (not implemented yet)
                            if not current_arg_type or current_arg_type == "unknown_ast_type" or current_arg_type == "void*":
                                self.inferred_types[arg_key] = param_type
                                self.changed_in_pass = True
                                self.logger.info(f"FuncCall: Propagated type for arg '{arg_name}' (key: {arg_key}) to '{param_type}' from param '{param_key}' of func '{called_func_name}'.")
                            elif current_arg_type != param_type:
                                self.logger.debug(f"FuncCall: Arg '{arg_key}' type '{current_arg_type}' differs from param '{param_key}' type '{param_type}'. Not updating.")
                        else:
                             self.logger.debug(f"FuncCall: Param type for '{param_key}' of func '{called_func_name}' is unknown. Cannot propagate to arg '{arg_name}'.")
                    else:
                        self.logger.debug(f"FuncCall: More arguments than parameters with known order for '{called_func_name}'. Arg '{arg_name}' at index {i} cannot be mapped.")
                
                # Recursively visit the argument node in case it's an expression or nested call
                self.visit(arg_node) 
        # self.generic_visit(node) # Already called self.visit on children (args)

class TypePropagator:
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger if logger else logging.getLogger(self.__class__.__name__)
        if not logger: 
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    def propagate_types(self, decompiled_code_path: str, signature_data_path: Optional[str] = None, existing_types: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        self.logger.info(f"Starting type propagation for {decompiled_code_path}")
        inferred_types: Dict[str, str] = {}

        if existing_types:
            inferred_types.update(existing_types)
            self.logger.info(f"Initialized with {len(existing_types)} existing types.")

        if signature_data_path and os.path.exists(signature_data_path):
            self.logger.info(f"Loading signatures from {signature_data_path}")
            try:
                with open(signature_data_path, 'r', encoding='utf-8') as f:
                    signatures: List[Dict] = json.load(f)
                
                types_from_sigs_count = 0
                param_orders_from_sigs = {} # Temp store for ordered param keys from sigs

                for func_sig in signatures:
                    func_name = func_sig.get("name")
                    if not func_name:
                        self.logger.warning("Found a signature entry without a function name. Skipping.")
                        continue

                    if func_sig.get("return_type"):
                        key = f"{func_name}_return"
                        if key not in inferred_types: 
                           inferred_types[key] = func_sig["return_type"]
                           types_from_sigs_count +=1
                    
                    ordered_param_keys_for_func = []
                    for param in func_sig.get("parameters", []):
                        param_name = param.get("name")
                        param_type = param.get("type")
                        if param_name and param_type:
                            key = f"{func_name}::{param_name}" 
                            ordered_param_keys_for_func.append(key)
                            if key not in inferred_types:
                                inferred_types[key] = param_type
                                types_from_sigs_count += 1
                        elif param_type: 
                            # For unnamed params from signatures, create a positional key
                            # This might not be directly used by visit_FuncCall if names are expected
                            key = f"{func_name}::param_unnamed_idx{len(ordered_param_keys_for_func)}_{param_type}" 
                            ordered_param_keys_for_func.append(key) # Still add a placeholder for order
                            if key not in inferred_types:
                                inferred_types[key] = param_type
                                types_from_sigs_count += 1
                    
                    if ordered_param_keys_for_func:
                        param_orders_from_sigs[f"{func_name}::param_order"] = ordered_param_keys_for_func
                
                # Add parameter order from signatures to inferred_types
                for key, val in param_orders_from_sigs.items():
                    if key not in inferred_types: # Check if AST pass already added it
                         inferred_types[key] = val
                         # self.changed_in_pass = True # Not in visitor context
                self.logger.info(f"Added {types_from_sigs_count} type entries and param orders from signatures.")

            except json.JSONDecodeError as e:
                self.logger.error(f"Error decoding JSON from signature file {signature_data_path}: {e}")
            except Exception as e:
                self.logger.error(f"Error loading or processing signature file {signature_data_path}: {e}")
        else:
            if signature_data_path:
                self.logger.warning(f"Signature data path provided but file does not exist: {signature_data_path}")
            else:
                self.logger.info("No signature data path provided.")

        ast = None
        if os.path.exists(decompiled_code_path):
            self.logger.info(f"Attempting to parse {decompiled_code_path} with pycparser.")
            try:
                ast = parse_file(decompiled_code_path, use_cpp=True,
                                 cpp_path='cpp',
                                 cpp_args=[r'-Ipycparser/utils/fake_libc_include', '-nostdinc'])
                self.logger.info(f"Successfully parsed {decompiled_code_path} with pycparser.")
            except ParseError as e:
                self.logger.error(f"Failed to parse C code with pycparser from {decompiled_code_path}: {e}")
            except Exception as e_general:
                self.logger.error(f"An unexpected error occurred during pycparser processing of {decompiled_code_path}: {e_general}")
        else:
            self.logger.error(f"Decompiled code file not found: {decompiled_code_path}")

        if ast:
            try:
                visitor = TypeExtractorVisitor(inferred_types=inferred_types, logger=self.logger)
                
                max_passes = 3 
                current_pass = 0
                self.logger.info(f"Starting AST processing with up to {max_passes} propagation passes.")
                while current_pass < max_passes:
                    current_pass += 1
                    self.logger.info(f"Starting propagation pass {current_pass}/{max_passes}.")
                    visitor.changed_in_pass = False 
                    visitor.visit(ast) 
                    self.logger.info(f"Propagation pass {current_pass} complete. Changes made in this pass: {visitor.changed_in_pass}. Total types: {len(inferred_types)}")
                    if not visitor.changed_in_pass and current_pass > 0 : 
                        self.logger.info(f"No changes in pass {current_pass}. Halting propagation passes.")
                        break
                if current_pass == max_passes and visitor.changed_in_pass: 
                    self.logger.info(f"Reached max_passes ({max_passes}) and changes were still made in the last pass.")
            except Exception as e_visitor:
                self.logger.error(f"Error during AST traversal with TypeExtractorVisitor for {decompiled_code_path}: {e_visitor}")
        
        self.logger.info(f"Finished type propagation. Total types identified: {len(inferred_types)}")
        return inferred_types

if __name__ == '__main__':
    test_logger = logging.getLogger("TestTypePropagator")
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    tp = TypePropagator(logger=test_logger) 
    
    dummy_c_file = "dummy_decompiled.c"
    dummy_sig_file = "dummy_signatures.json"

    with open(dummy_c_file, "w", encoding='utf-8') as f:
        f.write("typedef int MyInt;\n")
        f.write("struct Point { int x; int y; };\n")
        f.write("int global_var = 10;\n")
        f.write("char* global_str = \"test\";\n")
        f.write("MyInt global_myint;\n")
        f.write("int add(int a, int b) {\n")
        f.write("  int sum = a + b;\n")
        f.write("  return sum;\n")
        f.write("}\n")
        f.write("void process_data(MyInt val, char* name) {\n")
        f.write("  MyInt local_val_copy;\n")
        f.write("  local_val_copy = val;\n")
        f.write("  global_var = local_val_copy;\n")
        f.write("  global_str = name;\n")
        f.write("}\n")
        f.write("int main(int argc, char **argv) {\n")
        f.write("  int res;\n")
        f.write("  char *my_local_str;\n")
        f.write("  MyInt typedeffed_int_main;\n")
        f.write("  struct Point p1;\n")
        f.write("  p1.x = 1;\n") 
        f.write("  res = add(1, 2);\n")
        f.write("  typedeffed_int_main = res; // Test assignment propagation\n")
        f.write("  process_data(typedeffed_int_main, \"literal_string_arg\"); // Test func call arg type propagation\n")
        f.write("  my_local_str = global_str;\n")
        f.write("  global_myint = typedeffed_int_main;\n")
        f.write("  return 0;\n")
        f.write("}\n")

    dummy_signatures = [
        {"name": "add", "return_type": "int", "parameters": [
            {"name": "a", "type": "int"},
            {"name": "b", "type": "int"}
        ]},
         {"name": "process_data", "return_type": "void", "parameters": [
            {"name": "val", "type": "MyInt"},
            {"name": "name", "type": "char*"}
        ]}
    ]
    with open(dummy_sig_file, "w", encoding='utf-8') as f:
        json.dump(dummy_signatures, f, indent=2)

    test_logger.info("----- Running Test with Propagation -----")
    results = tp.propagate_types(dummy_c_file, dummy_sig_file)
    print("\nResults (Test with Propagation):")
    for k, v in sorted(results.items()): 
        print(f"  {k}: {v}")
    
    os.remove(dummy_c_file)
    os.remove(dummy_sig_file)
    test_logger.info("Cleaned up dummy files.")
```
