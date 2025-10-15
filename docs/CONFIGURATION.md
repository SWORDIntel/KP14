[general]
; project_root should ideally be the absolute path to the project's root directory.
; Using '.' assumes this settings.ini file is at the project root.
project_root = .
; Default directory for saving analysis reports and extracted files.
; This can be an absolute path or relative to project_root.
output_dir = analysis_output
; Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
log_level = INFO
; Verbose output from the application
verbose = True

[paths]
; These are names of subdirectories that will be created within the output_dir.
log_dir_name = logs
extracted_dir_name = extracted_files
graphs_dir_name = analysis_graphs
; This is the name of the directory (relative to project_root or absolute) where models are stored.
models_dir_name = models

[pe_analyzer]
enabled = True
; Maximum file size in Megabytes for PE files to be processed.
max_file_size_mb = 100
; Whether to automatically scan PE files upon import (e.g., when a new file is added to a monitored directory).
scan_on_import = False
; Other PE analyzer specific settings can be added here
; example_pe_option = value

[code_analyzer]
enabled = True
; Maximum recursion depth for static analysis of code structures (e.g., function calls, class hierarchies).
max_recursion_depth = 10
; Whether to attempt to analyze external libraries or dependencies found in the code.
analyze_libraries = False
; Other code analyzer specific settings
; example_code_option = value

[obfuscation_analyzer]
enabled = True
; Entropy threshold for detecting obfuscated strings. Higher values indicate more randomness.
string_entropy_threshold = 4.5
; Maximum number of loops with suspicious characteristics (e.g., high complexity, potential packing) before flagging.
max_suspicious_loops = 5
; Other obfuscation analyzer specific settings
; example_obfuscation_option = value

[cache]
; Enable result caching for dramatic performance improvements on repeated analysis
enabled = True
; Maximum cache size in megabytes (default: 1024 MB = 1 GB)
max_size_mb = 1024
; Default time-to-live for cache entries in seconds (default: 3600 = 1 hour)
default_ttl = 3600
; Enable persistent disk-backed caching (survives application restarts)
persist_to_disk = True
; Directory for cache storage (relative to project_root or absolute path)
cache_directory = .cache
; Individual cache sizes (number of entries)
file_hash_cache_size = 500
pe_header_cache_size = 200
ml_inference_cache_size = 1000
pattern_match_cache_size = 2000

[c2_extraction]
; Enable optimized sampling for large file binary scanning
; When enabled, files >10MB use intelligent sampling instead of full scan
; This provides 5-10x performance improvement with minimal accuracy impact
enable_sampling = True
; File size threshold in MB for enabling sampling (default: 10 MB)
; Files smaller than this will use full scan for maximum accuracy
sampling_threshold_mb = 10
; Sampling interval in bytes for large files (default: 1024 bytes = 1 KB)
; Smaller values = more thorough but slower, larger values = faster but may miss indicators
; Recommended range: 512-4096 bytes
sample_interval_bytes = 1024
; Enable parallel scanning for very large files (>50MB)
; Uses multiple CPU cores to process file chunks concurrently
enable_parallel_scan = True
; Maximum number of worker processes for parallel scanning (default: 4)
; Set to number of CPU cores for best performance
max_workers = 4

; You can add more sections for other analysis modules or global settings as needed.
; [another_module]
; setting1 = value1
; setting2 = value2
