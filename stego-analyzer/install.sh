#!/bin/bash

# Script to set up the KP14 Steganography Analyzer environment

# Exit immediately if a command exits with a non-zero status.
set -e

echo "Creating Python virtual environment 'kp14_venv'..."
python3 -m venv kp14_venv

echo "Activating virtual environment..."
source kp14_venv/bin/activate

echo "Installing dependencies from requirements.txt..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "ERROR: requirements.txt not found!"
    exit 1
fi

echo "Making run_pipeline.py executable..."
if [ -f "run_pipeline.py" ]; then
    chmod +x run_pipeline.py
else
    echo "WARNING: run_pipeline.py not found. Skipping chmod."
fi

echo ""
echo "Setup complete!"
echo "To activate the virtual environment in your current shell, run:"
echo "  source kp14_venv/bin/activate"
echo "To deactivate the virtual environment, run:"
echo "  deactivate"
echo "To run the analyzer (after activating the environment):"
echo "  ./run_pipeline.py <arguments>"
echo ""
