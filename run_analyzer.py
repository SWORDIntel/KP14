import argparse
import os
import sys

# Add core_engine to Python path.
# This assumes run_analyzer.py is at the project root.
sys.path.append(os.path.join(os.path.dirname(__file__), 'core_engine'))

try:
    from configuration_manager import ConfigurationManager
    from pipeline_manager import PipelineManager
except ImportError as e:
    print(f"Error importing core modules: {e}")
    print("Make sure 'core_engine' is in your PYTHONPATH or accessible.")
    print("If running from the project root, 'core_engine' directory should be present.")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="File Analyzer Engine")
    parser.add_argument("input_file", help="Path to the file to be analyzed.")
    parser.add_argument("-o", "--output-dir",
                        help="Directory to save analysis results. Overrides settings.ini if provided.")
    parser.add_argument("-s", "--settings", default="settings.ini",
                        help="Path to the settings.ini file. Defaults to 'settings.ini' in the current directory.")
    # Add more specific arguments as needed, e.g., to enable/disable specific analyzers
    # parser.add_argument("--disable-pe", action="store_true", help="Disable PE analyzer module.")

    args = parser.parse_args()

    # Validate input file path
    if not os.path.isfile(args.input_file):
        print(f"Error: Input file not found: {args.input_file}")
        sys.exit(1)

    # Validate settings file path
    if not os.path.isfile(args.settings):
        print(f"Error: Settings file not found: {args.settings}")
        sys.exit(1)

    print(f"Starting analysis for: {args.input_file}")

    # Initialize ConfigurationManager
    try:
        # Pass the absolute path of settings.ini to ConfigurationManager
        absolute_settings_path = os.path.abspath(args.settings)
        config_manager = ConfigurationManager(settings_path=absolute_settings_path)
        print(f"Configuration loaded from: {absolute_settings_path}")
    except FileNotFoundError:
        print(f"Error: Settings file not found at {absolute_settings_path}. Please check the path.")
        sys.exit(1)
    except ValueError as e:
        print(f"Error in configuration file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while loading configuration: {e}")
        sys.exit(1)

    # Override output directory if provided via command line
    if args.output_dir:
        # Ensure output_dir is absolute. If not, make it relative to CWD.
        abs_output_dir = args.output_dir if os.path.isabs(args.output_dir) else os.path.abspath(args.output_dir)
        config_manager.loaded_config['general']['output_dir'] = abs_output_dir
        os.makedirs(abs_output_dir, exist_ok=True)
        print(f"Output directory overridden by command line: {abs_output_dir}")

    # Initialize PipelineManager with the (potentially modified) configuration
    try:
        pipeline_manager = PipelineManager(config=config_manager)
    except Exception as e:
        print(f"Error initializing PipelineManager: {e}")
        sys.exit(1)

    # Run the analysis pipeline
    try:
        print(f"\nRunning analysis pipeline for {args.input_file}...")
        results = pipeline_manager.run_pipeline(args.input_file)
        print("\n--- Analysis Complete ---")
        # Process or display results as needed
        # For example, save results to a file in the configured output directory
        output_path = config_manager.get('general', 'output_dir')
        results_file_path = os.path.join(output_path, f"{os.path.basename(args.input_file)}_analysis_results.txt")

        with open(results_file_path, 'w') as f:
            for module, result in results.items():
                f.write(f"--- {module} ---\n")
                if isinstance(result, dict):
                    for k, v in result.items():
                        f.write(f"  {k}: {v}\n")
                else:
                    f.write(f"  {result}\n")
                f.write("\n")
        print(f"Analysis results saved to: {results_file_path}")

    except Exception as e:
        print(f"An error occurred during pipeline execution: {e}")
        # Consider logging the error to the configured log file
        # log_event(f"Pipeline error: {e}", "CRITICAL", config_manager)
        sys.exit(1)

    print("\nAnalysis finished successfully.")

if __name__ == "__main__":
    main()
