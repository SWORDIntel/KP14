import os
import json # For JSON output
import idaapi
import idautils
import idc
import ida_hexrays # For decompiler and type info
import ida_kernwin # For showing messages (optional, for debugging within IDA GUI)

# Helper function to parse IDA type string (simplified)
def parse_ida_type_str(type_str, func_name):
    parsed_params = []
    return_type = "unknown"
    try:
        # Example type_str: "int __cdecl(int arg1, char *arg2)"
        # Or from HexRays: "int (__fastcall *)(int a, _BYTE *b)"
        
        # Clean known calling conventions and modifiers
        conventions = ["__cdecl", "__stdcall", "__thiscall", "__fastcall", "__userpurge", "__usercall", "EFIAPI"]
        for conv in conventions:
            type_str = type_str.replace(conv, "").strip()
        
        # Remove potential pointer syntax around function name for HexRays types like "int (__fastcall *sub_XXXX)(...)"
        if '*' in type_str and '(' in type_str.split('*')[-1]:
             type_str = type_str.replace('*', '', 1) # Remove first '*', assuming it's for function pointer

        # Split return type from parameters
        if '(' not in type_str: # Not a function type string we can parse easily
            return_type = type_str.strip() if type_str else "unknown"
            return return_type, parsed_params

        parts = type_str.split('(', 1)
        return_type_candidate = parts[0].strip()
        
        if len(parts) > 1:
            params_str = parts[1].rsplit(')', 1)[0] # Get content between outer parentheses
        else: # No parameters part
            params_str = ""

        # Check if return_type_candidate is actually part of a function name (e.g. if no space)
        # This logic is tricky because function names can be complex.
        # We rely on idc.get_func_name for the actual name, and this is for type parsing.
        # For now, assume parts[0] is the return type or contains it.
        # Example: "void * ( *)(...)" is a function pointer return type.
        
        # Simplistic assignment for return type
        return_type = return_type_candidate

        if params_str and params_str.lower() != 'void':
            params_list = params_str.split(',')
            for i, p_item in enumerate(params_list):
                p_item = p_item.strip()
                p_name = "param_%d" % (i + 1) # Default name
                p_type = p_item
                
                # Try to split type and name (e.g., "int x", "char *s")
                # This is very basic. IDA's tinfo_t would be better if fully usable.
                last_space = p_item.rfind(' ')
                if last_space != -1:
                    potential_name = p_item[last_space+1:]
                    # Avoid taking part of type (like "unsigned int") as name
                    if potential_name and not potential_name.startswith('*') and potential_name not in ["int", "char", "short", "long", "float", "double", "void"]:
                        p_type = p_item[:last_space].strip()
                        p_name = potential_name
                        if p_name.startswith('*'): # If name is like *myvar
                            p_type += '*'
                            p_name = p_name[1:]
                    else: # Likely just a type, or a type ending with a keyword
                        p_type = p_item
                
                # Further clean param type if name was part of it
                if p_name in p_type: # e.g. p_type = "int param_1", p_name = "param_1"
                    p_type = p_type.replace(p_name, "").strip()

                parsed_params.append({"name": p_name, "type": p_type})
    except Exception as e:
        # ida_kernwin.msg("Exception in parse_ida_type_str for '%s' (func: %s): %s\\n" % (type_str, func_name, str(e)))
        if not return_type or return_type == "unknown": # If return type wasn't parsed before error
             return_type = type_str.split('(')[0].strip() if '(' in type_str else type_str # best guess
        # Keep parsed_params as is, or empty if error was early

    return return_type, parsed_params


def get_func_details(ea):
    func_data = {}
    func_data['address'] = "0x%x" % ea
    name = idc.get_func_name(ea)
    if not name: name = "sub_%X" % ea
    func_data['name'] = name

    type_str = None
    params_from_hexrays = []
    return_type_from_hexrays = "unknown"

    try:
        if ida_hexrays.init_hexrays_plugin(): 
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                hexrays_type_str = str(cfunc.type) 
                return_type_from_hexrays, params_from_hexrays = parse_ida_type_str(hexrays_type_str, name)

    except Exception as e_hex:
        pass 

    if not params_from_hexrays: 
        idc_type_str = idaapi.idc_get_type(ea)
        if idc_type_str:
            return_type_idc, params_idc = parse_ida_type_str(idc_type_str, name)
            if not params_from_hexrays and params_idc: 
                 params_from_hexrays = params_idc
            if return_type_from_hexrays == "unknown" and return_type_idc != "unknown":
                 return_type_from_hexrays = return_type_idc
        else: 
            if return_type_from_hexrays == "unknown": return_type_from_hexrays = "not_determined"
            
    func_data['return_type'] = return_type_from_hexrays
    func_data['parameters'] = params_from_hexrays
        
    return func_data

def main():
    idaapi.auto_wait() 
    
    output_dir_str = r"%s"
    c_output_filename_str = r"%s"
    json_output_filename_str = r"%s"

    if not os.path.exists(output_dir_str):
        os.makedirs(output_dir_str)
    
    c_output_path = os.path.join(output_dir_str, c_output_filename_str)
    json_output_path = os.path.join(output_dir_str, json_output_filename_str)
    
    all_funcs_data = []
    
    hexrays_initialized = False
    try:
        if ida_hexrays.init_hexrays_plugin():
            hexrays_initialized = True
    except Exception as e_init:
        ida_kernwin.warning("Hex-Rays plugin could not be initialized: %s" % str(e_init))

    if not hexrays_initialized:
        ida_kernwin.warning("Hex-Rays plugin is not available or failed to initialize. C code output will be empty.")
        with open(c_output_path, "w") as c_file:
            c_file.write("// Error: Hex-Rays not available or failed to initialize.\\n")
        with open(json_output_path, "w") as json_file:
            json.dump([], json_file)
        idc.qexit(1) 
        return

    functions_to_process = []
    ida_funcs_env_str = os.getenv("IDA_FUNCTIONS_TO_DECOMPILE")
    if ida_funcs_env_str:
        for func_item in ida_funcs_env_str.split(','):
            func_item = func_item.strip()
            ea = idaapi.BADADDR
            try: 
                ea = int(func_item, 0) 
            except ValueError: 
                ea = idc.get_name_ea_simple(func_item)
            
            if ea != idaapi.BADADDR and idaapi.get_func(ea):
                functions_to_process.append(ea)
            else:
                ida_kernwin.warning("Could not find function via item: %s" % func_item)
    else: 
        for ea in idautils.Functions():
            functions_to_process.append(ea)

    with open(c_output_path, "w") as c_file:
        c_file.write("// Decompiled with IDA Pro (Hex-Rays)\\n")
        c_file.write("// Binary: " + idaapi.get_input_file_path() + "\\n")
        c_file.write("// Timestamp: " + idaapi.get_root_filename() + " IDA Version: " + idaapi.get_ida_version() + "\\n\\n")

        for func_ea in functions_to_process:
            func_name_str = idc.get_func_name(func_ea)
            if not func_name_str: func_name_str = "sub_%X" % func_ea

            func_details = get_func_details(func_ea)
            
            try:
                cfunc = ida_hexrays.decompile(func_ea)
                if cfunc:
                    c_file.write("// Function: %s\\n" % func_name_str)
                    c_file.write("// Address: 0x%x\\n\\n" % func_ea)
                    c_file.write(str(cfunc))
                    c_file.write("\\n\\n")
                else:
                    c_file.write("// Failed to decompile function: %s (0x%x)\\n\\n" % (func_name_str, func_ea))
            except ida_hexrays.DecompilationFailure as e:
                c_file.write("// Decompilation failed for %s (0x%x): %s\\n\\n" % (func_name_str, func_ea, str(e)))
            except Exception as e_decompile: 
                c_file.write("// General Decompilation error for %s (0x%x): %s\\n\\n" % (func_name_str, func_ea, str(e_decompile)))

            all_funcs_data.append(func_details)

    try:
        with open(json_output_path, "w") as json_file:
            json.dump(all_funcs_data, json_file, indent=2)
    except IOError as e_io:
        ida_kernwin.warning("IOError writing JSON file %s: %s" % (json_output_path, str(e_io)))
    except Exception as e_json_write: 
        ida_kernwin.warning("Failed to write JSON output to %s: %s" % (json_output_path, str(e_json_write)))

    idc.qexit(0) 

if __name__ == '__main__':
    main()

%s
```
