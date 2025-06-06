# Stego Analyzer Project
This project aims to detect, extract, and analyze payloads from steganographic images.

---
(Content from original project README) ---

# KP1
KP1ANALYSIS

## Getting Started

This section provides instructions on how to set up and run the KP14 Steganography Analyzer.

### Installation

1.  **Clone the repository (if you haven't already):**
    ```bash
    git clone <repository_url>
    cd <repository_directory>/stego-analyzer
    ```

2.  **Run the installation script:**
    This script will create a Python virtual environment named `kp14_venv` and install the necessary dependencies.
    ```bash
    bash install.sh
    ```
    The installer will also take care of new dependencies required for features like static PE file analysis, such as `capstone` and `pefile`.

3.  **Activate the virtual environment:**
    Before running the analyzer, you need to activate the virtual environment:
    ```bash
    source kp14_venv/bin/activate
    ```
    You should see `(kp14_venv)` at the beginning of your shell prompt.

4.  **To deactivate the virtual environment** when you are done:
    ```bash
    deactivate
    ```

### Configuration (`settings.ini`)

A template configuration file named `settings.ini` is provided in the `stego-analyzer` directory. You can customize this file to specify:
-   Default output directories for analysis results.
-   Paths to external tools or models (like OpenVINO).
-   Logging preferences.
-   Default analysis options.

Copy or rename `settings.ini` to your preferred configuration file and modify it according to your needs. The application will eventually load settings from this file (Note: Integration of `settings.ini` into the application's configuration loading logic is a future enhancement).

### Sample Files (`samples/`)

The `stego-analyzer/samples/` directory is provided for you to place sample images or files for analysis. This can include:
-   Benign (clean) images.
-   Images that you suspect contain hidden data.

Using a variety of sample files can help you test the analyzer's capabilities and understand its output. The directory contains a `README.md` with more information and a couple of placeholder image files to get you started.

### Running the Analyzer

Once the environment is activated and configured, you can run the main analysis pipeline:
```bash
./run_pipeline.py [arguments...]
```

**Static Analysis:**
The analyzer now includes a basic static analysis module for PE files (e.g., .exe, .dll). If you suspect an input file (or an extracted payload, once that feature is more developed) is a Windows executable, you can enable static analysis:

```bash
./run_pipeline.py your_file.exe --enable-static-analysis
```
This will attempt to:
- Extract PE header information (sections, imports, exports, entry point).
- Extract printable strings from the file.
- Disassemble the first few instructions at the entry point.

The results will be printed to the console.

Refer to `docs/usage_examples.md` or use `python run_pipeline.py --help` (once implemented) for more details on command-line arguments and usage.
