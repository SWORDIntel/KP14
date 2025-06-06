import argparse
import os
import sys
import json
import logging

# Add core_engine to Python path.
# This assumes run_analyzer.py is at the project root.
sys.path.append(os.path.join(os.path.dirname(__file__), 'core_engine'))

try:
    from configuration_manager import ConfigurationManager
    from pipeline_manager import PipelineManager
except ImportError as e:
    # Use print here as logger might not be configured yet if ConfigurationManager fails
    print(f"Critical Error: Failed to import core modules (ConfigurationManager or PipelineManager): {e}", file=sys.stderr)
    print("Ensure 'core_engine' is in PYTHONPATH and all dependencies are installed.", file=sys.stderr)
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="File Analyzer Engine")
    parser.add_argument("input_file", help="Path to the file to be analyzed.")
    parser.add_argument("-o", "--output-file",
                        help="Path to save the JSON analysis report. If not provided, prints to console.")
    parser.add_argument("-s", "--settings", default="settings.ini",
                        help="Path to the settings.ini file. Defaults to 'settings.ini' in the current directory.")

    args = parser.parse_args()

    # Setup basic console logging for run_analyzer itself.
    # Modules loaded via PipelineManager will use logging configured by ConfigurationManager.
    # If ConfigurationManager itself fails to load, this basic logging will still be active.
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__) # Logger for run_analyzer specific messages

    # Validate input file path
    if not os.path.isfile(args.input_file):
        logger.error(f"Input file not found: {args.input_file}")
        sys.exit(1)

    # Validate settings file path
    if not os.path.isfile(args.settings):
        logger.error(f"Settings file not found: {args.settings}")
        sys.exit(1)

    logger.info(f"Starting analysis for input file: {args.input_file}")
    logger.info(f"Using settings file: {args.settings}")

    # Initialize ConfigurationManager
    config_manager = None # Ensure it's in scope for finally block if needed
    try:
        absolute_settings_path = os.path.abspath(args.settings)
        config_manager = ConfigurationManager(settings_path=absolute_settings_path)
        logger.info(f"Configuration loaded successfully from: {absolute_settings_path}")
    except FileNotFoundError:
        # This specific error is already handled by the isfile check, but good practice.
        logger.error(f"Settings file was not found at {absolute_settings_path} during ConfigurationManager init.")
        sys.exit(1)
    except ValueError as e: # For errors within configparser or schema validation
        logger.error(f"Error processing configuration file '{args.settings}': {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred while loading configuration: {e}", exc_info=True)
        sys.exit(1)

    # Initialize PipelineManager
    pipeline_manager = None
    try:
        pipeline_manager = PipelineManager(config_manager=config_manager)
        logger.info("PipelineManager initialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing PipelineManager: {e}", exc_info=True)
        sys.exit(1)

    # Run the analysis pipeline
    try:
        logger.info(f"Running analysis pipeline for {args.input_file}...")
        results = pipeline_manager.run_pipeline(args.input_file)
        logger.info("--- Analysis Pipeline Complete ---")

        # Handle JSON report output
        if args.output_file:
            output_file_path = os.path.abspath(args.output_file)
            output_dir = os.path.dirname(output_file_path)
            if output_dir: # Ensure output directory exists if specified path includes one
                os.makedirs(output_dir, exist_ok=True)

            try:
                # Custom default handler for json.dump to handle bytes (convert to hex string)
                def json_serializer_default(obj):
                    if isinstance(obj, bytes):
                        try:
                            # Try decoding as UTF-8 if it makes sense, otherwise hex
                            return obj.decode('utf-8')
                        except UnicodeDecodeError:
                            return obj.hex() # Fallback to hex if not valid UTF-8
                    return f"<not serializable: {type(obj).__name__}>"

                with open(output_file_path, 'w') as f:
                    json.dump(results, f, indent=2, default=json_serializer_default)
                logger.info(f"Analysis report saved to: {output_file_path}")
            except IOError as e:
                logger.error(f"Failed to write report to {output_file_path}: {e}")
            except TypeError as e:
                logger.error(f"Data serialization error when writing JSON report: {e}. Some data might not be standard JSON types.")
                # Fallback: try printing to console if file write fails due to serialization
                print("--- JSON Output (Serialization Error Fallback, attempting basic str conversion) ---")
                print(json.dumps(results, indent=2, default=lambda o: str(o)))


        else:
            # Print to console
            logger.info("Printing analysis report to console:")
            try:
                # Custom default handler for json.dump to handle bytes (convert to hex string)
                def json_serializer_default_console(obj):
                    if isinstance(obj, bytes):
                        try: return obj.decode('utf-8')
                        except UnicodeDecodeError: return obj.hex()
                    return f"<not serializable: {type(obj).__name__}>"
                print(json.dumps(results, indent=2, default=json_serializer_default_console))
            except TypeError as e:
                 logger.error(f"Data serialization error when printing JSON to console: {e}. Some data might not be standard JSON types.")
                 print(json.dumps(results, indent=2, default=lambda o: str(o))) # Basic fallback


    except Exception as e:
        logger.error(f"An critical error occurred during pipeline execution: {e}", exc_info=True)
        sys.exit(1)

    logger.info("Analysis finished successfully.")

if __name__ == "__main__":
    main()
