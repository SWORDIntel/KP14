# Placeholder for run_pipeline script.
import argparse
from core.pipeline import main_pipeline  # Placeholder import
from analysis.static_analyzer import extract_basic_pe_info, extract_strings, disassemble_entry_point, StaticAnalyzerError
from core.reporting import format_static_analysis_results_text
import os

def run():
    """Configures argument parsing and initiates the steganography analysis pipeline."""
    parser = argparse.ArgumentParser(description='Steganography analysis pipeline.')
    parser.add_argument('image_path', help='Path to the image file to analyze.')
    # Future arguments for different analysis modes or output options can be added here.
    # For example:
    # parser.add_argument('--mode', choices=['full', 'quick'], default='full', help='Analysis mode.')
    # parser.add_argument('-o', '--output', help='Directory to save analysis results.')
    parser.add_argument(
        '--enable-static-analysis',
        action='store_true',
        help='Enable static analysis of the input file (if it is a PE/executable).'
    )

    args = parser.parse_args()

    print(f'Starting analysis for image: {args.image_path}')
    main_pipeline(args.image_path) # Call the main pipeline function

    if args.enable_static_analysis:
        print(f"\n--- Attempting Static Analysis on: {args.image_path} ---")
        # In a real scenario, this would run on *extracted payloads*.
        # For now, we run it on the input image_path for demonstration if it's a PE.

        static_analysis_data = {}
        # Check if the file exists before attempting analysis
        if not os.path.exists(args.image_path):
            print(f"[!] Static Analysis Skipped: File not found at {args.image_path}")
        else:
            try:
                print("  Extracting PE info...")
                static_analysis_data['pe_info'] = extract_basic_pe_info(args.image_path)
            except StaticAnalyzerError as e:
                print(f"  PE Info Extraction Error: {e}")
                static_analysis_data['pe_info'] = None # Ensure key exists

            try:
                print("  Extracting strings...")
                static_analysis_data['strings'] = extract_strings(args.image_path)
            except StaticAnalyzerError as e:
                print(f"  String Extraction Error: {e}")
                static_analysis_data['strings'] = []

            try:
                # Only attempt disassembly if PE info was successfully extracted and arch is known
                if static_analysis_data.get('pe_info') and static_analysis_data['pe_info'].get('architecture') != "Unknown":
                    print("  Disassembling entry point...")
                    static_analysis_data['disassembly'] = disassemble_entry_point(args.image_path)
                elif static_analysis_data.get('pe_info'): # PE info exists but arch is unknown
                    print("  Skipping disassembly: PE architecture unknown or unsupported.")
                    static_analysis_data['disassembly'] = []
                else: # PE info extraction failed
                     print("  Skipping disassembly: PE information not available.")
                     static_analysis_data['disassembly'] = []
            except StaticAnalyzerError as e:
                print(f"  Disassembly Error: {e}")
                static_analysis_data['disassembly'] = []

            # Generate and print the text report
            if static_analysis_data.get('pe_info') or static_analysis_data.get('strings') or static_analysis_data.get('disassembly'):
                report_text = format_static_analysis_results_text(static_analysis_data, args.image_path)
                print("\n--- Static Analysis Report ---")
                print(report_text)
            else:
                print("\n[!] No static analysis results to report.")
        print("--- Static Analysis Attempt Finished ---")

    print(f'Analysis finished for image: {args.image_path}')

if __name__ == '__main__':
    run()
