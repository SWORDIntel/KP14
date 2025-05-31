"""Placeholder for config module.

This module defines configuration variables for the Stego Analyzer project,
including paths to various directories and default settings.
"""
import os

# Project Root: Resolves to the 'stego-analyzer' directory
# Assuming this config.py is in stego-analyzer/core/
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Output directories
OUTPUT_DIR = os.path.join(PROJECT_ROOT, 'output')
LOG_DIR = os.path.join(OUTPUT_DIR, 'logs')
EXTRACTED_DIR = os.path.join(OUTPUT_DIR, 'extracted')
GRAPHS_DIR = os.path.join(OUTPUT_DIR, 'graphs')

# Ensure output directories exist
# It's good practice to create them if they don't, though this might also be handled at runtime.
# For now, we assume they are created by the initial setup or pipeline.
# os.makedirs(LOG_DIR, exist_ok=True)
# os.makedirs(EXTRACTED_DIR, exist_ok=True)
# os.makedirs(GRAPHS_DIR, exist_ok=True)

# Model directories
MODEL_DIR = os.path.join(PROJECT_ROOT, 'models')
OPENVINO_MODEL_DIR = os.path.join(MODEL_DIR, 'openvino')

# Log file configuration
DEFAULT_LOG_FILE = os.path.join(LOG_DIR, 'pipeline.log')
LOG_LEVEL = 'INFO' # Example: 'DEBUG', 'INFO', 'WARNING', 'ERROR'

# Analysis settings
VERBOSE = True
DEFAULT_DETECTION_THRESHOLD = 0.65 # Example threshold for steganography detection

# Placeholder for API keys or external service configs, if any
# SOME_API_KEY = os.environ.get('STEGO_ANALYZER_API_KEY', 'your_default_api_key_here')


if __name__ == '__main__':
    # This section can be used to print out the configured paths for verification
    print(f"PROJECT_ROOT: {PROJECT_ROOT}")
    print(f"OUTPUT_DIR: {OUTPUT_DIR}")
    print(f"LOG_DIR: {LOG_DIR}")
    print(f"EXTRACTED_DIR: {EXTRACTED_DIR}")
    print(f"GRAPHS_DIR: {GRAPHS_DIR}")
    print(f"MODEL_DIR: {MODEL_DIR}")
    print(f"OPENVINO_MODEL_DIR: {OPENVINO_MODEL_DIR}")
    print(f"DEFAULT_LOG_FILE: {DEFAULT_LOG_FILE}")
    print(f"VERBOSE: {VERBOSE}")
    print(f"LOG_LEVEL: {LOG_LEVEL}")
    print(f"DEFAULT_DETECTION_THRESHOLD: {DEFAULT_DETECTION_THRESHOLD}")

    # Verify that the paths point to the correct, existing subdirectories
    # This requires the directory structure to be present relative to this script's location
    # For example, if this script is run from /app/stego-analyzer/core:
    print(f"LOG_DIR exists: {os.path.exists(LOG_DIR)}") # Should be /app/stego-analyzer/output/logs
    print(f"OPENVINO_MODEL_DIR exists: {os.path.exists(OPENVINO_MODEL_DIR)}") # Should be /app/stego-analyzer/models/openvino
