# keyplug_memory_forensics.py
import json
import openvino.runtime as ov # For OpenVINO integration
import os # For path checking

# Volatility 3 imports
from volatility3.framework import contexts, automagic, plugins
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import framework as vol_framework
from volatility3.cli import UnifiedProgressContext
# Example plugins (can be expanded)
from volatility3.plugins.windows import pslist as windows_pslist 
from volatility3.plugins.linux import pslist as linux_pslist
from volatility3.plugins.windows import memmap as windows_memmap
from volatility3.plugins.linux import maps as linux_maps # For process memory maps
from volatility3.plugins.windows import dlllist as windows_dlllist # For Windows module analysis
from volatility3.plugins.linux import ldrmodules as linux_ldrmodules # For Linux module analysis
from volatility3.plugins.windows import netscan as windows_netscan # For Windows network analysis
from volatility3.plugins.linux import netstat as linux_netstat # For Linux network analysis
from volatility3.plugins.windows import apihooks # For Windows API hook detection (entire module)
from volatility3.framework.automagic import symbol_finder # For profile guessing
from volatility3.framework.exceptions import VolatilityLayerError # For memory reading errors


KEYPLUG_PATTERNS = [
    b"\x4D\x5A\x90\x00",  # Common MZ header start
    b"\x50\x45\x00\x00",  # Common PE header start
    # Add more specific or relevant Keyplug patterns here
    # b"\xDE\xAD\xBE\xEF", # Example Keyplug pattern 1
    # b"\xCA\xFE\xBA\xBE"  # Example Keyplug pattern 2
]

class KeyplugMemoryAnalyzer:
    def __init__(self, ov_core, device_name="CPU"):
        """
        Initializes the KeyplugMemoryAnalyzer.
        
        :param ov_core: An instance of openvino.runtime.Core.
        :param device_name: The OpenVINO device to use (e.g., "CPU", "GPU").
        """
        self.ov_core = ov_core
        self.device_name = device_name
        self.vol_context = contexts.Context()  # Initialize Volatility context here
        self.constructed_layer_name = None
        self.profile = None
        print("KeyplugMemoryAnalyzer initialized with Volatility context.")
        # Placeholder: Load OpenVINO models for pattern matching if applicable
        # self.pattern_matching_model = self._load_openvino_pattern_model("path/to/model.xml")

    def _initialize_volatility(self, dump_path):
        """
        Initializes Volatility 3 framework for a given dump.
        Constructs the translation layer for the memory dump.
        """
        print(f"Initializing Volatility for {dump_path}")
        if not os.path.exists(dump_path):
            print(f"ERROR: Memory dump file not found at {dump_path}")
            return False
        try:
            # Construct the file layer URL
            file_url = f"file:{dump_path}"
            if not dump_path.startswith("file:"):
                 file_url = f"file:{os.path.abspath(dump_path)}" # Use absolute path
            else:
                file_url = dump_path

            # This will discover available layers and attempt to stack them
            # automagics_list = automagic.available_automagic(self.vol_context) # Get all automagic modules
            
            # We need a primary layer (TranslationLayerRequirement)
            # The automagic system will find suitable FileLayers and stack them.
            # Create a new context for each dump to avoid state issues.
            self.vol_context = contexts.Context()

            primary_layer_req = requirements.TranslationLayerRequirement(name='primary_layer',
                                                                          description='Memory layer for the dump file',
                                                                          architectures=["Intel32", "Intel64"])
            
            # Attempt to construct the layer using automagic
            # This is a common way to let Volatility figure out the layer stack
            self.constructed_layer_name = automagic.construct_layers(self.vol_context,
                                                                     [primary_layer_req],
                                                                     base_layer_name=None, # Let automagic find it
                                                                     filter_callable=lambda x: x.check_path(file_url))


            if self.constructed_layer_name:
                print(f"Volatility initialized. Constructed layer: {self.constructed_layer_name}")
                return True
            else:
                # Fallback or more specific attempts might be needed here if construct_layers fails.
                # For now, we treat it as a failure if no layer is constructed.
                print(f"Could not construct a suitable layer for {dump_path} using available automagic.")
                print("This might be due to an unsupported dump format or Volatility configuration issues.")
                print(f"Attempted URL: {file_url}")
                # You can list available file handlers to debug:
                # for am_cls in automagics.available_automagic(self.vol_context):
                # print(f"Available automagic: {am_cls.__name__}, path check for {file_url}: {am_cls.check_path(file_url)}")
                return False

        except FileNotFoundError: # Should be caught by os.path.exists, but good to have
            print(f"ERROR: Memory dump file not found at {dump_path}")
            return False
        except Exception as e:
            print(f"ERROR: Failed to initialize Volatility for {dump_path}: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _guess_profile(self):
        """
        Guesses the memory dump's OS profile using Volatility's symbol_finder automagic.
        Uses self.constructed_layer_name.
        """
        if not self.constructed_layer_name:
            print("ERROR: Volatility not initialized or layer not constructed, cannot guess profile.")
            return None
        
        print(f"Guessing OS profile for layer {self.constructed_layer_name}")
        try:
            # Symbol tables automagic will try to find the best symbol table (profile)
            # for the constructed layer.
            # The SymbolFinderAutodetection is part of the automagic system.
            # It requires the context and the layer name.
            # It updates the context's config with the found symbol table name.
            automagic.SymbolFinderAutodetection(self.vol_context, self.constructed_layer_name).find_aslr_symbol_table()
            
            # Retrieve the guessed profile name from the context's configuration
            self.profile = self.vol_context.config.get('automagic.symbol_finder.symbol_table_name', None)

            if self.profile:
                print(f"Guessed profile: {self.profile}")
                # Set it in the context for other plugins to use
                self.vol_context.config['automagic.symbol_finder.symbol_table_name'] = self.profile
                return self.profile
            else:
                print("WARNING: Could not guess OS profile for the dump.")
                # Attempt to list available symbol tables for the layer if guessing fails
                print("Attempting to list available symbol tables (profiles) for this layer:")
                for table_name in self.vol_context.symbol_space.get_symbol_table_names():
                    if self.constructed_layer_name in table_name or 'windows' in table_name or 'linux' in table_name: # Basic filter
                        print(f"  - {table_name}")
                return None
        except Exception as e:
            print(f"Error guessing profile: {e}")
            import traceback
            traceback.print_exc()
            return None

    def analyze_dump(self, dump_path, profile=None):
        """
        Main function to analyze a memory dump.
        Orchestrates various analysis steps.
        """
        print(f"Starting memory forensics analysis for: {dump_path}")
        results = {}

        # 1. Initialize Volatility
        if not self._initialize_volatility(dump_path):
            print("ERROR: Failed to initialize Volatility for the memory dump.")
            results["error"] = "Failed to initialize Volatility for the memory dump."
            return results
        
        # 2. Guess profile if not provided
        if not profile:
            print("No profile provided, attempting to guess...")
            guessed_profile = self._guess_profile() # Uses self.constructed_layer_name
            if guessed_profile:
                self.profile = guessed_profile # self.profile is updated by _guess_profile
                print(f"Using guessed profile: {self.profile}")
            else:
                print("WARNING: Could not guess OS profile. Analysis may be limited or fail.")
                results["warning"] = "Could not guess OS profile. Proceeding without a specific profile."
                # Some plugins might work without a full profile, or with a base profile.
        else:
            self.profile = profile
            # If a profile is provided, set it in the context
            # Note: _guess_profile already sets it if successful. This is for externally provided profiles.
            self.vol_context.config['automagic.symbol_finder.symbol_table_name'] = self.profile
            print(f"Using provided profile: {self.profile}")


        # 3. Process Listing
        processes = self._list_processes() # No longer needs dump_path and profile args directly
        results["processes"] = processes

        # 4. Scan for KEYPLUG artifacts in process memory (OpenVINO accelerated)
        keyplug_artifacts = self._scan_process_memory_for_keyplug(processes)
        results["keyplug_artifacts"] = keyplug_artifacts
        
        # 5. Module/DLL Analysis (can be part of process scanning or separate)
        module_info = self._analyze_modules(processes)
        results["module_analysis"] = module_info

        # 6. Network Connection Analysis
        network_info = self._extract_network_info()
        results["network_info"] = network_info

        # 7. API Hook Detection
        api_hooks = self._detect_api_hooks(processes)
        results["api_hooks"] = api_hooks
        
        print(f"Memory forensics analysis complete for: {dump_path}")
        return results

    def _list_processes(self):
        """
        Placeholder for listing processes from the memory dump using Volatility.
        """
        if not self.constructed_layer_name:
            return {"info": "Process listing failed: Volatility not initialized.", "processes": []}
        if not self.profile:
            print("Warning: No profile set for process listing. Results may be inaccurate or fail.")
        
        print(f"Placeholder: Listing processes from layer {self.constructed_layer_name} (Profile: {self.profile or 'None'})")
        if not (self.vol_context and self.constructed_layer_name and self.profile):
            return {"info": "Volatility not initialized or profile not guessed. Cannot list processes.", 
                    "processes": [], "suspicious_processes_identified": []}

        process_list_data = []
        suspicious_processes = []
        
        try:
            print(f"Attempting to list processes for profile: {self.profile} on layer: {self.constructed_layer_name}")

            plugin_class = None
            if "windows" in self.profile.lower():
                # Assuming plugins.windows.pslist.PsList is the correct class
                # Volatility 3 often has a single PsList that adapts or there are specific ones.
                # For this example, we use the specific import.
                plugin_class = windows_pslist.PsList
                # Define expected columns for Windows
                # From volatility3/plugins/windows/pslist.py:
                # return TreeGrid([("PID", int), ("PPID", int), ("ImageFileName", str), ("Offset(V)", format_hints.Hex),
                #                  ("Threads", int), ("Handles", int), ("SessionId", int), ("Wow64", bool),
                #                  ("CreateTime", datetime.datetime), ("ExitTime", datetime.datetime),
                #                  ("File output", str)], ...)
                # We'll try to get these, but handle if some are missing.
                # CreateTime might be datetime object, need conversion to string.
                column_map = {
                    'pid': 'PID', 'ppid': 'PPID', 'name': 'ImageFileName', 
                    'create_time': 'CreateTime', 'exit_time': 'ExitTime',
                    'offset': 'Offset(V)' # Example of another field
                }
            elif "linux" in self.profile.lower():
                plugin_class = linux_pslist.PsList
                # From volatility3/plugins/linux/pslist.py:
                # return TreeGrid([("PID", int), ("PPID", int), ("COMM", str), ("State", str), ("UID", int), ("GID", int),
                #                  ("TGID", int), ("Threads", int), ("File output", str)], ...)
                # Linux pslist doesn't typically have CreateTime. "COMM" is the process name.
                column_map = {
                    'pid': 'PID', 'ppid': 'PPID', 'name': 'COMM',
                    # No standard 'CreateTime' or 'ExitTime' in linux pslist output
                }
            else:
                return {"info": f"Unsupported profile for PsList: {self.profile}", 
                        "processes": [], "suspicious_processes_identified": []}

            # Instantiate the plugin
            # The config_path is usually not needed if context is set up.
            # UnifiedProgressContext is for progress reporting, good practice to include.
            # The plugin needs the primary layer name and the symbol table (profile)
            # These are typically configured in the context or can be passed as plugin options.
            # The `automagic.run_plugin` helper can simplify this.

            # Option 1: Configure context and run (more manual)
            # self.vol_context.config['primary'] = self.constructed_layer_name # Ensure this is set if needed
            # self.vol_context.config['symbol_table'] = self.profile # Ensure this is set if needed
            # process_plugin = plugin_class(self.vol_context, UnifiedProgressContext(), None) 
            # tree_grid = process_plugin.run()

            # Option 2: Using automagic.run_plugin (preferred if it works for the plugin)
            # This often handles setting up the plugin's requirements from the context.
            # The plugin_config for PsList usually requires the layer name and symbol table.
            # However, PsList is designed to get these from the context if they are set by automagic.
            
            # For PsList, it expects the layer name and symbol table to be available.
            # The layer name is `self.constructed_layer_name`.
            # The symbol table (profile) is `self.profile`.
            # PsList might require these as configuration options if not picked up automatically.
            
            # We will set the required configuration for the plugin directly in a temporary config path
            # for the plugin instance. This is a common pattern.
            plugin_config_path = f"plugins.{plugin_class.__name__}" # e.g. "plugins.PsList"

            # Ensure the primary layer and symbol table are in the context for the plugin.
            # `self.profile` should already be in `self.vol_context.config['automagic.symbol_finder.symbol_table_name']`
            # `self.constructed_layer_name` is the name of the primary translation layer.
            # PsList plugins often look for `kernel_layer` or `primary_layer` and `symbol_table_name` in config.
            
            # Let's try running the plugin with the existing context.
            # PsList constructor: PsList(context, config_path, progress_callback)
            # The config_path here is for the plugin's specific config subtree.
            # We don't typically pass a file path, but a path in the config tree.
            
            # Create a progress callback
            progress_callback = UnifiedProgressContext()
            
            # Instantiate and run the plugin
            # The PsList plugins are designed to pick up the primary layer and symbol table
            # from the context if they have been set (e.g., by automagic).
            kernel_layer_name = self.constructed_layer_name # The main memory layer
            
            # The plugin configuration for PsList might require `layer_name` and `symbol_table`
            # to be explicitly passed if not picked up automatically.
            # However, usually, the context configured by automagic is sufficient.
            
            # Let's assume context is configured enough.
            # process_plugin = plugin_class(context=self.vol_context,
            #                               config_path=plugin_config_path, # Path in config tree
            #                               progress_callback=progress_callback)
            
            # The `run` method of PsList and other plugins often returns a `TreeGrid`.
            # tree_grid = process_plugin.run()

            # Simpler way to run plugins if you know their name and parameters:
            # This might be more robust if the plugin system handles configuration.
            # However, direct instantiation is also common.
            # For this task, direct instantiation is fine.

            # Define plugin arguments, if any are needed beyond context.
            # PsList typically gets layer and symbol table from context.
            # Some plugins might take `pid` or other filters. PsList usually does not for basic listing.
            plugin_args = {
                 # For some plugins, you might need to specify the layer or symbol table if not default
                 # "layer_name": self.constructed_layer_name,
                 # "symbol_table": self.profile 
            }
            
            # Using the full plugin path for construction
            if "windows" in self.profile.lower():
                plugin_full_name = "windows.pslist.PsList"
            elif "linux" in self.profile.lower():
                plugin_full_name = "linux.pslist.PsList"
            
            # Construct the plugin using the full path.
            # This uses Volatility's plugin loading mechanism.
            constructed_plugin = vol_framework.꿋construct_plugin(self.vol_context, plugin_full_name, **plugin_args)
            tree_grid = constructed_plugin.run()


            # Get column indices from the tree_grid.columns
            # This is crucial as direct attribute access on rows is not how TreeGrid works.
            # Rows are tuples/lists, and columns define what each element is.
            header = [col.name for col in tree_grid.columns]
            
            # Create a map of desired_field -> index_in_row
            col_indices = {}
            for desired_field, actual_col_name in column_map.items():
                try:
                    col_indices[desired_field] = header.index(actual_col_name)
                except ValueError:
                    print(f"Warning: Column '{actual_col_name}' not found in PsList output for profile {self.profile}. Field '{desired_field}' will be missing.")
                    col_indices[desired_field] = -1 # Mark as not found

            for row_values in tree_grid.values():
                process_info = {}
                
                # Extract values using mapped indices
                pid_val = row_values[col_indices['pid']] if col_indices.get('pid', -1) != -1 else 'N/A'
                # Ensure PID is an int if found, otherwise keep as is (e.g. 'N/A')
                try:
                    process_info['pid'] = int(pid_val)
                except ValueError:
                    process_info['pid'] = pid_val

                ppid_val = row_values[col_indices['ppid']] if col_indices.get('ppid', -1) != -1 else 'N/A'
                try:
                    process_info['ppid'] = int(ppid_val)
                except ValueError:
                    process_info['ppid'] = ppid_val
                
                process_info['name'] = str(row_values[col_indices['name']]) if col_indices.get('name', -1) != -1 else 'N/A'
                
                if 'create_time' in col_indices and col_indices['create_time'] != -1:
                    create_time_val = row_values[col_indices['create_time']]
                    # CreateTime can be a datetime object, string, or None (vol.objects.NotApplicable)
                    if create_time_val and not isinstance(create_time_val, str) and hasattr(create_time_val, 'isoformat'):
                        process_info['create_time'] = create_time_val.isoformat()
                    else:
                        process_info['create_time'] = str(create_time_val) if create_time_val else 'N/A'
                else:
                    process_info['create_time'] = 'N/A'

                if 'exit_time' in col_indices and col_indices['exit_time'] != -1: # Specific to Windows
                    exit_time_val = row_values[col_indices['exit_time']]
                    if exit_time_val and not isinstance(exit_time_val, str) and hasattr(exit_time_val, 'isoformat'):
                        process_info['exit_time'] = exit_time_val.isoformat()
                    else:
                        process_info['exit_time'] = str(exit_time_val) if exit_time_val else 'N/A'
                else:
                    process_info['exit_time'] = 'N/A'
                
                if 'offset' in col_indices and col_indices['offset'] != -1: # Specific to Windows
                    offset_val = row_values[col_indices['offset']]
                    # Offset might be a format_hints.Hex object, convert to string
                    process_info['offset'] = str(offset_val) if offset_val else 'N/A'
                else:
                    process_info['offset'] = 'N/A'

                process_info['command_line'] = 'N/A' # cmdline plugin needed for this usually
                process_info['suspicious_reason'] = None

                # Basic suspicious process heuristic (placeholder)
                if process_info['name'].lower() == "malware.exe":
                    process_info['suspicious_reason'] = "Known malware name pattern."
                    suspicious_processes.append(process_info)
                elif process_info['name'].lower() == "svchost.exe" and process_info.get('ppid', 0) != 0: # Example
                    # This is a very naive check, real svchost parent checks are more complex
                    # parent_proc = next((p for p in process_list_data if p['pid'] == process_info['ppid']), None)
                    # if parent_proc and parent_proc['name'].lower() not in ['services.exe', 'smss.exe', ...]:
                    #    process_info['suspicious_reason'] = "svchost.exe with potentially unusual parent."
                    #    suspicious_processes.append(process_info)
                    pass


                process_list_data.append(process_info)
            
            if not process_list_data and tree_grid.values(): # Check if values were processed but list is empty
                print("Warning: PsList plugin ran and found processes, but data extraction might have issues.")
            elif not tree_grid.values():
                 print("PsList plugin ran but returned no processes.")


            return {
                "info": "Successfully listed processes.",
                "processes": process_list_data,
                "suspicious_processes_identified": suspicious_processes
            }

        except Exception as e:
            import traceback
            print(f"Error running PsList plugin: {e}")
            traceback.print_exc()
            return {"info": f"Error running PsList plugin: {e}", 
                    "processes": [], "suspicious_processes_identified": []}

    def _scan_process_memory_for_keyplug(self, process_list_result):
        """
        Scans memory regions of specified processes for KEYPLUG patterns.
        Uses Volatility 3 to access process memory and a mock OpenVINO scanner.
        """
        if not (self.vol_context and self.constructed_layer_name and self.profile):
            return {
                "info": "Memory scanning failed: Volatility not initialized or profile not guessed.",
                "scanned_processes_count": 0,
                "total_regions_scanned": 0,
                "found_keyplug_artifacts": []
            }

        if not process_list_result or not process_list_result.get("processes"):
            return {
                "info": "No processes provided or process list is invalid.",
                "scanned_processes_count": 0,
                "total_regions_scanned": 0,
                "found_keyplug_artifacts": []
            }

        all_found_artifacts = []
        scanned_processes_count = 0
        total_regions_scanned = 0
        
        # Limit number of processes to scan for this example, can be configurable
        # processes_to_scan = process_list_result["processes"][:5] # Scan first 5
        processes_to_scan = process_list_result["processes"] # Scan all for now

        for proc_data in processes_to_scan:
            pid = proc_data.get("pid")
            proc_name = proc_data.get("name", "N/A")

            if pid is None or not isinstance(pid, int):
                print(f"Skipping process with invalid PID: {pid} (Name: {proc_name})")
                continue
            
            print(f"Starting memory scan for PID: {pid} ({proc_name})")
            scanned_processes_count += 1
            
            try:
                memmap_plugin_class = None
                plugin_full_path_name = None # For construct_plugin
                if "windows" in self.profile.lower():
                    memmap_plugin_class = windows_memmap.Memmap
                    plugin_full_path_name = "volatility3.plugins.windows.memmap.Memmap"
                    # Columns: Offset(V), Start, End, Size, State, Protect, Type, Tag, File output, Mapped path
                    # We need: Start, Size, Protect (permissions)
                    # Start is usually a vol_object (e.g., vol.objects.Pointer), needs to be int()
                    # Size is usually an int. Protect is a string.
                    col_map = {'start': 'Start', 'size': 'Size', 'protection': 'Protect', 'type': 'Type', 'tag': 'Tag'}
                elif "linux" in self.profile.lower():
                    memmap_plugin_class = linux_maps.Maps 
                    plugin_full_path_name = "volatility3.plugins.linux.maps.Maps"
                    # Columns: Start, End, Size, Path, Major, Minor, Inode, Flags
                    # We need: Start, Size, Flags (permissions, e.g. "r-xp")
                    col_map = {'start': 'Start', 'size': 'Size', 'protection': 'Flags', 'path': 'Path'}
                else:
                    print(f"Unsupported profile for memory scanning: {self.profile} for PID {pid}")
                    continue

                # Instantiate and run the memmap plugin for the specific PID
                # The plugin needs `pid` as a filter.
                
                memmap_plugin = vol_framework.construct_plugin(
                    self.vol_context,
                    plugin_full_path_name, 
                    pid=pid # Pass pid as a filter
                )
                
                memory_regions = memmap_plugin.run() # Returns a TreeGrid

                # Get column indices
                header = [col.name for col in memory_regions.columns]
                idx_map = {}
                for key, name in col_map.items():
                    try:
                        idx_map[key] = header.index(name)
                    except ValueError:
                        # print(f"Warning: Column '{name}' not found in {memmap_plugin_class.__name__} output for PID {pid}. Field '{key}' will be missing.")
                        idx_map[key] = -1 # Mark as not found to avoid KeyError later
                
                if idx_map.get('start', -1) == -1 or idx_map.get('size', -1) == -1:
                    print(f"Critical columns 'Start' or 'Size' missing for PID {pid} in {memmap_plugin_class.__name__} output. Cannot scan memory regions.")
                    continue

                for region_values in memory_regions.values():
                    try:
                        start_addr_obj = region_values[idx_map['start']]
                        region_start_addr = int(start_addr_obj) 
                        
                        size_obj = region_values[idx_map['size']]
                        region_size = int(size_obj)

                        protection = str(region_values[idx_map['protection']]) if idx_map.get('protection', -1) != -1 else "N/A"
                        region_type = str(region_values[idx_map.get('type', -1)]) if 'type' in idx_map and idx_map['type'] != -1 else "N/A" # Win only
                        tag = str(region_values[idx_map.get('tag', -1)]) if 'tag' in idx_map and idx_map['tag'] != -1 else "N/A" # Win only
                        path = str(region_values[idx_map.get('path', -1)]) if 'path' in idx_map and idx_map['path'] != -1 else "N/A" # Linux only


                        is_readable = False
                        if "windows" in self.profile.lower():
                            # Example: PAGE_READONLY, PAGE_READWRITE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE
                            # Also check State for MEM_COMMIT if available and relevant
                            if "READ" in protection.upper() or "EXECUTE" in protection.upper():
                                is_readable = True
                        elif "linux" in self.profile.lower():
                            if 'r' in protection.lower(): 
                                is_readable = True
                        
                        if not is_readable:
                            continue
                        
                        if region_size == 0 or region_size > (500 * 1024 * 1024): # Skip zero-size or very large (e.g. >500MB) regions
                            # print(f"Skipping region for PID {pid} at {hex(region_start_addr)} due to size: {region_size}")
                            continue

                        # print(f"  Scanning region for PID {pid}: Addr={hex(region_start_addr)} Size={region_size} Protect='{protection}' Type='{region_type}' Tag='{tag}' Path='{path}'")
                        total_regions_scanned += 1
                        
                        memory_chunk = self.vol_context.layers[self.constructed_layer_name].read(
                            region_start_addr, region_size, pad=True
                        )
                        
                        found_in_chunk = self._mock_scan_memory_with_openvino(memory_chunk, KEYPLUG_PATTERNS)
                        
                        for artifact in found_in_chunk:
                            all_found_artifacts.append({
                                "pid": pid,
                                "process_name": proc_name,
                                "region_address": hex(region_start_addr),
                                "region_size": region_size,
                                "region_protection": protection,
                                "region_details": f"Type: {region_type}, Tag: {tag}" if "windows" in self.profile.lower() else f"Path: {path}",
                                "pattern_name": artifact["pattern_name"],
                                "pattern_bytes": artifact["pattern_bytes"],
                                "offset_in_region": artifact["offset_in_chunk"], 
                                "absolute_offset": hex(region_start_addr + artifact["offset_in_chunk"]),
                                "data_preview": artifact["data_preview"]
                            })
                    
                    except VolatilityLayerError as vle:
                        # This is common for paged out memory or inaccessible regions
                        # print(f"    Read error for PID {pid} at {hex(region_start_addr)} (size {region_size}): {vle}")
                        pass # Continue to next region
                    except ValueError as ve: 
                        print(f"    Skipping region due to value error (e.g., converting address/size) for PID {pid}: {ve}")
                    except Exception as e_region:
                        # import traceback
                        print(f"    Unexpected error processing region for PID {pid} at {hex(region_start_addr if 'region_start_addr' in locals() else -1)}: {e_region}")
                        # traceback.print_exc() 

            except Exception as e_proc:
                # import traceback
                print(f"Error processing memory for PID {pid} ({proc_name}): {e_proc}")
                # traceback.print_exc()

        return {
            "info": "Memory scanning completed." if scanned_processes_count > 0 else "No processes were scanned.",
            "scanned_processes_count": scanned_processes_count,
            "total_regions_scanned": total_regions_scanned,
            "found_keyplug_artifacts": all_found_artifacts
        }

    def _analyze_modules(self, process_list_result):
        """
        Analyzes loaded modules/DLLs for each process using Volatility 3.
        """
        if not (self.vol_context and self.constructed_layer_name and self.profile):
            return {
                "info": "Module analysis failed: Volatility not initialized or profile not guessed.",
                "analyzed_processes_count": 0,
                "modules_by_process": [],
                "suspicious_modules_summary": []
            }

        if not process_list_result or not process_list_result.get("processes"):
            return {
                "info": "No processes provided or process list is invalid for module analysis.",
                "analyzed_processes_count": 0,
                "modules_by_process": [],
                "suspicious_modules_summary": []
            }

        all_modules_by_process = []
        all_suspicious_modules = []
        analyzed_processes_count = 0

        processes_to_analyze = process_list_result["processes"]

        for proc_data in processes_to_analyze:
            pid = proc_data.get("pid")
            proc_name = proc_data.get("name", "N/A")

            if pid is None or not isinstance(pid, int):
                print(f"Skipping module analysis for invalid PID: {pid} (Name: {proc_name})")
                continue
            
            # print(f"Starting module analysis for PID: {pid} ({proc_name})")
            analyzed_processes_count += 1
            process_modules_info = {"pid": pid, "process_name": proc_name, "modules": [], "errors": None}
            
            try:
                module_plugin_class = None
                plugin_full_path_name = None
                col_map = {}
                is_windows = "windows" in self.profile.lower()
                is_linux = "linux" in self.profile.lower()

                if is_windows:
                    module_plugin_class = windows_dlllist.DllList
                    plugin_full_path_name = "volatility3.plugins.windows.dlllist.DllList"
                    # DllList columns: PID, Process, Base, Size, Path, LoadCount
                    # The flags InLoad, InInit, InMem are not directly in TreeGrid columns.
                    # Anomaly based on Path emptiness primarily.
                    col_map = {'base': 'Base', 'size': 'Size', 'path': 'Path', 'load_count': 'LoadCount'}
                elif is_linux:
                    module_plugin_class = linux_ldrmodules.LdrModules
                    plugin_full_path_name = "volatility3.plugins.linux.ldrmodules.LdrModules"
                    # LdrModules columns: PID, Process, Start, End, Name
                    col_map = {'base': 'Start', 'end': 'End', 'path': 'Name'} # Size will be calculated
                else:
                    msg = f"Unsupported profile for module listing: {self.profile} for PID {pid}"
                    # print(msg)
                    process_modules_info["errors"] = msg
                    all_modules_by_process.append(process_modules_info)
                    continue
                
                module_plugin = vol_framework.construct_plugin(
                    self.vol_context,
                    plugin_full_path_name,
                    pid=pid # Filter by PID
                )
                
                modules_grid = module_plugin.run()

                header = [col.name for col in modules_grid.columns]
                idx_map = {}
                for key, name in col_map.items():
                    try:
                        idx_map[key] = header.index(name)
                    except ValueError:
                        idx_map[key] = -1 # Mark as not found

                if idx_map.get('base', -1) == -1 or idx_map.get('path', -1) == -1:
                    msg = f"Critical columns ('Base'/'Start' or 'Path'/'Name') missing for PID {pid} in {module_plugin_class.__name__} output."
                    # print(msg)
                    process_modules_info["errors"] = msg
                    all_modules_by_process.append(process_modules_info)
                    continue

                for mod_values in modules_grid.values():
                    module_info = {}
                    anomaly_reason = None

                    base_addr_obj = mod_values[idx_map['base']]
                    module_info['base'] = hex(int(base_addr_obj)) if base_addr_obj else 'N/A'
                    
                    module_path = str(mod_values[idx_map['path']]) if idx_map['path'] != -1 else ""
                    module_info['path'] = module_path

                    if is_windows:
                        size_obj = mod_values[idx_map.get('size', -1)] if idx_map.get('size', -1) != -1 else 'N/A'
                        module_info['size'] = int(size_obj) if isinstance(size_obj, int) else (str(size_obj) if size_obj else 'N/A')
                        module_info['load_count'] = str(mod_values[idx_map.get('load_count',-1)]) if idx_map.get('load_count',-1) != -1 else 'N/A'
                        # Anomaly for Windows: Empty path often indicates manually mapped DLL / in-memory module
                        if not module_path:
                            anomaly_reason = "Empty module path (potentially in-memory/manually mapped)"
                        # Add more specific DllList flags (InLoad, InInit, InMem) if they become available
                        # For now, this is based on path. A more advanced check would inspect PE headers for unbacked modules.
                    
                    elif is_linux:
                        end_addr_obj = mod_values[idx_map.get('end', -1)] if idx_map.get('end', -1) != -1 else None
                        if base_addr_obj and end_addr_obj:
                            module_info['size'] = hex(int(end_addr_obj) - int(base_addr_obj))
                        else:
                            module_info['size'] = 'N/A'
                        if not module_path:
                            anomaly_reason = "Empty module name/path"
                    
                    module_info['anomaly_reason'] = anomaly_reason
                    process_modules_info["modules"].append(module_info)

                    if anomaly_reason:
                        all_suspicious_modules.append({
                            "pid": pid,
                            "process_name": proc_name,
                            "module_path": module_path,
                            "module_base": module_info['base'],
                            "reason": anomaly_reason
                        })
                
                all_modules_by_process.append(process_modules_info)

            except Exception as e_proc_mod:
                import traceback
                error_msg = f"Error analyzing modules for PID {pid} ({proc_name}): {e_proc_mod}"
                # print(error_msg)
                # traceback.print_exc()
                process_modules_info["errors"] = error_msg
                all_modules_by_process.append(process_modules_info)
        
        return {
            "info": "Module analysis completed." if analyzed_processes_count > 0 else "No processes were analyzed for modules.",
            "analyzed_processes_count": analyzed_processes_count,
            "modules_by_process": all_modules_by_process,
            "suspicious_modules_summary": all_suspicious_modules
        }

    def _extract_network_info(self):
        """
        Extracts network connection and listener information using Volatility 3.
        """
        if not (self.vol_context and self.constructed_layer_name and self.profile):
            return {
                "info": "Network info extraction failed: Volatility not initialized or profile not guessed.",
                "connections_and_listeners": [],
                "dns_cache": {"info": "DNS cache extraction not implemented in this version."}
            }

        connections_data = []
        
        try:
            network_plugin_class = None
            plugin_full_path_name = None
            col_map = {}
            is_windows = "windows" in self.profile.lower()
            is_linux = "linux" in self.profile.lower()

            if is_windows:
                network_plugin_class = windows_netscan.NetScan
                plugin_full_path_name = "volatility3.plugins.windows.netscan.NetScan"
                # Columns: Offset(V), Proto, LocalAddr, LocalPort, ForeignAddr, ForeignPort, State, PID, Owner, CreateTime
                col_map = {
                    'proto': 'Proto', 'local_addr': 'LocalAddr', 'local_port': 'LocalPort',
                    'remote_addr': 'ForeignAddr', 'remote_port': 'ForeignPort', 
                    'state': 'State', 'pid': 'PID', 'owner': 'Owner', 'created_time': 'CreateTime'
                }
            elif is_linux:
                network_plugin_class = linux_netstat.NetStat
                plugin_full_path_name = "volatility3.plugins.linux.netstat.NetStat"
                # Columns: Netstat (obj), Family, Type, Laddr, Lport, Raddr, Rport, State, PID, Path
                # We derive protocol from Type.
                col_map = {
                    'type': 'Type', 'local_addr': 'Laddr', 'local_port': 'Lport',
                    'remote_addr': 'Raddr', 'remote_port': 'Rport',
                    'state': 'State', 'pid': 'PID', 'program_name': 'Path' 
                }
            else:
                msg = f"Unsupported profile for network information extraction: {self.profile}"
                # print(msg)
                return {
                    "info": msg,
                    "connections_and_listeners": [],
                    "dns_cache": {"info": "DNS cache extraction not implemented in this version."}
                }

            network_plugin = vol_framework.construct_plugin(
                self.vol_context,
                plugin_full_path_name
            )
            
            network_grid = network_plugin.run()

            header = [col.name for col in network_grid.columns]
            idx_map = {}
            for key, name in col_map.items():
                try:
                    idx_map[key] = header.index(name)
                except ValueError:
                    idx_map[key] = -1 # Mark as not found

            # Check for essential columns
            if (is_windows and (idx_map.get('proto', -1) == -1 or idx_map.get('local_addr', -1) == -1 or idx_map.get('pid', -1) == -1)) or \
               (is_linux and (idx_map.get('type', -1) == -1 or idx_map.get('local_addr', -1) == -1 or idx_map.get('pid', -1) == -1)):
                msg = f"Critical columns missing in {network_plugin_class.__name__} output for profile {self.profile}."
                # print(msg)
                return {
                    "info": msg,
                    "connections_and_listeners": connections_data, # Return any partial data if some rows processed
                    "dns_cache": {"info": "DNS cache extraction not implemented in this version."}
                }

            for item_values in network_grid.values():
                conn_info = {}
                
                # Helper to safely extract and convert values
                def get_val(key, default='N/A', conversion=None):
                    idx = idx_map.get(key, -1)
                    if idx == -1: return default
                    val = item_values[idx]
                    if val is None or isinstance(val, framework.interfaces.objects.NotApplicable): # Check for Vol's N/A
                        return default
                    if conversion:
                        try:
                            return conversion(val)
                        except (ValueError, TypeError):
                            return default
                    return str(val) # Default to string if no specific conversion

                if is_windows:
                    conn_info['protocol'] = get_val('proto')
                    conn_info['local_addr'] = get_val('local_addr')
                    conn_info['local_port'] = get_val('local_port', conversion=int)
                    conn_info['remote_addr'] = get_val('remote_addr')
                    conn_info['remote_port'] = get_val('remote_port', conversion=int)
                    conn_info['state'] = get_val('state')
                    conn_info['pid'] = get_val('pid', conversion=int)
                    conn_info['process_name'] = get_val('owner') # 'Owner' in NetScan is process name
                    # conn_info['created_time'] = get_val('created_time') # Optional
                
                elif is_linux:
                    socket_type = get_val('type')
                    if "STREAM" in socket_type.upper(): conn_info['protocol'] = "TCP"
                    elif "DGRAM" in socket_type.upper(): conn_info['protocol'] = "UDP"
                    else: conn_info['protocol'] = socket_type # or 'UNKNOWN'
                    
                    conn_info['local_addr'] = get_val('local_addr')
                    conn_info['local_port'] = get_val('local_port', conversion=int)
                    conn_info['remote_addr'] = get_val('remote_addr')
                    conn_info['remote_port'] = get_val('remote_port', conversion=int)
                    conn_info['state'] = get_val('state')
                    conn_info['pid'] = get_val('pid', conversion=int)
                    conn_info['process_name'] = get_val('program_name') # 'Path' in NetStat is program name

                connections_data.append(conn_info)

            return {
                "info": "Network information extraction completed.",
                "connections_and_listeners": connections_data,
                "dns_cache": {"info": "DNS cache extraction not implemented in this version."}
            }

        except Exception as e:
            import traceback
            error_msg = f"Error extracting network information: {e}"
            # print(error_msg)
            # traceback.print_exc()
            return {
                "info": error_msg,
                "connections_and_listeners": [],
                "dns_cache": {"info": "DNS cache extraction not implemented in this version."}
            }

    def _detect_api_hooks(self, process_list_result):
        """
        Detects API hooks, focusing on Windows using ApiHooks plugin.
        Linux hook detection is placeholder.
        """
        if not (self.vol_context and self.constructed_layer_name and self.profile):
            return {
                "info": "API hook detection failed: Volatility not initialized or profile not guessed.",
                "detected_hooks": [],
                "errors": ["Volatility not initialized or profile not guessed."]
            }

        # process_list_result is available if specific PIDs are needed, but ApiHooks often runs system-wide
        # or uses its own config for filtering. For this pass, we'll run it system-wide.

        detected_hooks_list = []
        errors_list = []
        info_message = "API hook detection process completed."

        try:
            is_windows = "windows" in self.profile.lower()
            is_linux = "linux" in self.profile.lower()

            if is_windows:
                print("Starting Windows API hook detection (ApiHooks plugin)... This may take some time.")
                plugin_full_path_name = "volatility3.plugins.windows.apihooks.ApiHooks"
                
                # ApiHooks columns: PID, Process, HookObjectAddress, HookType, VictimModule, VictimFunction, 
                #                   HookAddress, HookingModule, Disassembly
                col_map = {
                    'pid': 'PID', 'process_name': 'Process', 
                    'hook_obj_addr': 'HookObjectAddress', 'hook_type': 'HookType',
                    'victim_module': 'VictimModule', 'victim_function': 'VictimFunction',
                    'hook_address': 'HookAddress', 'hooking_module': 'HookingModule',
                    'details': 'Disassembly' # Or 'Description' depending on plugin version/output
                }
                
                # Instantiate and run ApiHooks plugin (system-wide)
                # No specific PID filter here for simplicity in first pass, ApiHooks can be slow.
                # If PID filtering is desired and supported via construct_plugin args for ApiHooks:
                # pids_to_scan = [str(p['pid']) for p in process_list_result.get("processes", []) if isinstance(p.get('pid'), int)]
                # plugin_args = {'pid': ",".join(pids_to_scan)} if pids_to_scan else {}
                # apihooks_plugin = vol_framework.construct_plugin(self.vol_context, plugin_full_path_name, **plugin_args)
                
                apihooks_plugin = vol_framework.construct_plugin(self.vol_context, plugin_full_path_name)
                apihooks_grid = apihooks_plugin.run()

                header = [col.name for col in apihooks_grid.columns]
                idx_map = {}
                for key, name in col_map.items():
                    try:
                        idx_map[key] = header.index(name)
                    except ValueError:
                        idx_map[key] = -1 # Mark as not found

                # Check for essential columns
                critical_cols_present = all(idx_map.get(k, -1) != -1 for k in ['pid', 'hook_type', 'victim_module', 'victim_function', 'hook_address'])
                if not critical_cols_present:
                    msg = f"Critical columns missing in ApiHooks output for profile {self.profile}."
                    errors_list.append(msg)
                    info_message = "API hook detection completed with errors (missing critical columns)."
                else:
                    for hook_values in apihooks_grid.values():
                        hook_info = {}
                        
                        def get_val(key, default='N/A', conversion=None):
                            idx = idx_map.get(key, -1)
                            if idx == -1: return default
                            val = hook_values[idx]
                            if val is None or isinstance(val, framework.interfaces.objects.NotApplicable):
                                return default
                            if conversion:
                                try: return conversion(val)
                                except (ValueError, TypeError): return default
                            return str(val)

                        hook_info['pid'] = get_val('pid', conversion=int)
                        hook_info['process_name'] = get_val('process_name')
                        # hook_info['hook_object_address'] = get_val('hook_obj_addr', conversion=lambda x: hex(int(x)) if x else 'N/A') # Address
                        hook_info['hook_type'] = get_val('hook_type')
                        hook_info['victim_module'] = get_val('victim_module')
                        hook_info['victim_function'] = get_val('victim_function')
                        hook_info['hook_address'] = get_val('hook_address', conversion=lambda x: hex(int(x)) if x else 'N/A') # Address
                        hook_info['hooking_module'] = get_val('hooking_module')
                        hook_info['details'] = get_val('details') # Disassembly or description
                        
                        detected_hooks_list.append(hook_info)
                    info_message = f"Windows API hook detection completed. Found {len(detected_hooks_list)} potential hooks."
                
            elif is_linux:
                info_message = "API hook detection for Linux is complex from memory dumps and not implemented in this initial version."
                # Optional: Check LD_PRELOAD if feasible and desired for a basic check.
                # This would involve finding environment variables for each process.
                # For now, per instructions, this is sufficient.
                print(info_message)

            else:
                info_message = f"API hook detection not supported for profile: {self.profile}"
                errors_list.append(info_message)

        except Exception as e:
            import traceback
            error_msg = f"Error during API hook detection: {e}"
            # print(error_msg)
            # traceback.print_exc()
            errors_list.append(error_msg)
            info_message = "API hook detection completed with errors."

        return {
            "info": info_message,
            "detected_hooks": detected_hooks_list,
            "errors": errors_list
        }

    def _load_openvino_pattern_model(self, model_path):
        """
        Placeholder for loading an OpenVINO model.
        """
        print(f"Placeholder: Loading OpenVINO model from {model_path}")
        try:
            model = self.ov_core.read_model(model_path)
            compiled_model = self.ov_core.compile_model(model, self.device_name)
            print(f"Model {model_path} loaded and compiled for {self.device_name}")
            return compiled_model
        except Exception as e:
            print(f"Error loading OpenVINO model {model_path}: {e}")
            return None
        # pass # Original pass removed

    def _mock_scan_memory_with_openvino(self, memory_chunk_bytes, patterns_list):
        """
        Mocks scanning a memory chunk for a list of byte patterns.
        Simulates finding patterns and returns their details.
        """
        found_artifacts = []
        if not memory_chunk_bytes or not patterns_list:
            return found_artifacts
            
        for pattern_idx, pattern in enumerate(patterns_list):
            offset = 0
            pattern_name = f"Pattern_{pattern_idx}_{pattern.hex()[:8]}" # Default name
            # Could have a map of pattern_bytes to pattern_name if more descriptive names are needed
            if pattern == b"\x4D\x5A\x90\x00": pattern_name = "MZ_Header"
            if pattern == b"\x50\x45\x00\x00": pattern_name = "PE_Header"

            while True:
                idx = memory_chunk_bytes.find(pattern, offset)
                if idx == -1:
                    break
                found_artifacts.append({
                    "pattern_name": pattern_name,
                    "pattern_bytes": pattern.hex(),
                    "offset_in_chunk": idx, # Offset relative to the start of memory_chunk_bytes
                    "data_preview": memory_chunk_bytes[idx:idx+16].hex()
                })
                offset = idx + len(pattern) # Continue search after this find
        return found_artifacts


if __name__ == "__main__":
    print("Keyplug Memory Forensics Module - Volatility Integration Test")
    
    ov_core_instance = None
    try:
        ov_core_instance = ov.Core()
        print("OpenVINO Core initialized successfully.")
    except Exception as e:
        print(f"Failed to initialize OpenVINO Core: {e}. Some features might be unavailable.")

    # Create analyzer instance (even if OpenVINO core failed, for Volatility testing)
    analyzer = KeyplugMemoryAnalyzer(ov_core=ov_core_instance)
    
    # Test with a non-existent dump file to check error handling
    test_dump_file = "non_existent_dump.mem" 
    print(f"\n--- Attempting analysis on a non-existent dump: {test_dump_file} ---")
    analysis_results = analyzer.analyze_dump(test_dump_file)
    print("\nAnalysis Results (non-existent dump):")
    print(json.dumps(analysis_results, indent=2))

    # To actually test Volatility's layer construction and profile guessing,
    # you would need a real (or minimal valid) memory dump file.
    # For example, if you have 'sample.mem':
    #
    # 1. Create a dummy file for testing if you don't have a real one
    #    (This dummy file will likely NOT be recognized by Volatility as a valid dump,
    #     but it will pass the os.path.exists check)
    dummy_dump_file = "dummy_sample.mem"
    try:
        with open(dummy_dump_file, 'wb') as f:
            f.write(b'\0' * 1024 * 1024) # Create a 1MB dummy file
        print(f"\n--- Attempting analysis on a DUMMY dump: {dummy_dump_file} ---")
        print("NOTE: This dummy file is NOT a valid memory image and Volatility will likely fail to process it,")
        print("but it allows testing the _initialize_volatility path beyond file not found.")
        # Increase log verbosity for Volatility if needed for debugging
        # import logging
        # logging.basicConfig(level=logging.DEBUG) 
        analysis_results_dummy = analyzer.analyze_dump(dummy_dump_file)
        print("\nAnalysis Results (dummy dump):")
        print(json.dumps(analysis_results_dummy, indent=2))
    except IOError as e:
        print(f"Could not create dummy dump file: {e}")
    finally:
        if os.path.exists(dummy_dump_file):
            os.remove(dummy_dump_file)
            print(f"Cleaned up dummy file: {dummy_dump_file}")

    print("\nTo test fully, replace 'non_existent_dump.mem' or 'dummy_sample.mem' with a path to a REAL memory dump.")
    print("Ensure Volatility 3 and its dependencies are correctly installed and configured.")
