# Main entry point for the Ariadne Thread analysis framework.

import argparse
import json
import sys # Import sys module
from core_engine.configuration_manager import ConfigurationManager
from core_engine.pipeline_manager import PipelineManager

# Helper function to serialize bytes to hex for JSON
def json_bytes_serializer(obj):
    if isinstance(obj, bytes):
        return obj.hex()
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

def main():
    parser = argparse.ArgumentParser(description="Ariadne Thread analysis framework.")
    parser.add_argument("input_file", help="Path to the file to be analyzed.")
    parser.add_argument("-s", "--settings", dest="settings_file", default="settings.ini",
                        help="Path to the settings.ini file (default: settings.ini)")

    args = parser.parse_args()

    # No need to print these here, will be evident from execution or errors
    # print(f"Input file: {args.input_file}")
    # print(f"Settings file: {args.settings_file}")

    try:
        config_manager = ConfigurationManager(args.settings_file)
        print(f"ConfigurationManager created using '{args.settings_file}'.")
    except FileNotFoundError:
        print(f"Error: Settings file not found at '{args.settings_file}'.")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: Invalid configuration in settings file '{args.settings_file}'. Details: {e}")
        sys.exit(1)
    except Exception as e: # Catch any other unexpected errors during config loading
        print(f"An unexpected error occurred while loading settings from '{args.settings_file}': {e}")
        sys.exit(1)

    try:
        pipeline_manager = PipelineManager(config_manager)
        print("PipelineManager created.")

        print(f"Running analysis pipeline for input file: '{args.input_file}'...")
        report = pipeline_manager.run_pipeline(args.input_file)
        print("Analysis pipeline finished.")

        try:
            report_json = json.dumps(report, default=json_bytes_serializer, indent=2)
            print("Analysis Report (JSON):")
            print(report_json)
        except TypeError as e:
            print(f"Error: Could not serialize the analysis report to JSON. Details: {e}")
            # Optionally, print raw report if serialization fails and it's deemed useful
            # print("Raw report data (serialization failed):")
            # print(report)
            sys.exit(1)

    except FileNotFoundError: # Specifically for input_file in run_pipeline
        print(f"Error: Input file not found at '{args.input_file}'.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred during analysis: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
