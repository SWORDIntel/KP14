"""Placeholder for run_pipeline script."""
import argparse
from core.pipeline import main_pipeline  # Placeholder import

def run():
    """Configures argument parsing and initiates the steganography analysis pipeline."""
    parser = argparse.ArgumentParser(description='Steganography analysis pipeline.')
    parser.add_argument('image_path', help='Path to the image file to analyze.')
    # Future arguments for different analysis modes or output options can be added here.
    # For example:
    # parser.add_argument('--mode', choices=['full', 'quick'], default='full', help='Analysis mode.')
    # parser.add_argument('-o', '--output', help='Directory to save analysis results.')

    args = parser.parse_args()

    print(f'Starting analysis for image: {args.image_path}')
    main_pipeline(args.image_path) # Call the main pipeline function
    print(f'Analysis finished for image: {args.image_path}')

if __name__ == '__main__':
    run()
