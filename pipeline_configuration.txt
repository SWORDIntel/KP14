Analysis Pipeline and Configuration:

**Analysis Pipeline (`run_pipeline.py`):**
The `run_pipeline.py` script serves as the main entry point to execute the Stego Analyzer's analysis capabilities. Its primary role is to:
1.  Parse command-line arguments, with the path to the target image file (`image_path`) being essential.
2.  Initiate the core analysis process by calling a `main_pipeline` function (expected to be in `core.pipeline`). This central function would then orchestrate the various stages of the analysis, such as steganography detection, payload extraction, malware scanning, and machine learning classification, by invoking the appropriate modules within the `stego-analyzer` project.
The script is designed to be extensible for future arguments, potentially allowing users to select different analysis modes or specify output locations.

**Configuration (`settings.ini`):**
The `settings.ini` file provides a mechanism for users to customize the behavior and environment of the Stego Analyzer. Although its full integration into the application is noted as a future enhancement, its structure indicates several key configuration areas:

1.  **General Settings:**
    *   `output_directory`: Defines the default path where analysis reports, extracted files, and other outputs will be saved.
    *   `log_level`: Controls the verbosity of logging during the analysis process (e.g., INFO, DEBUG).

2.  **Paths:**
    *   `openvino_model_path`: Specifies the location of OpenVINO models, which is critical for leveraging OpenVINO for machine learning model inference and hardware acceleration.
    *   Placeholders for other external tools or resources that the analyzer might need.

3.  **Analysis Options:**
    *   `analysis_timeout`: Sets a default maximum duration for individual analysis stages or the entire pipeline.
    *   Conceptual toggles (`enable_static_analysis`, `enable_ml_classification`): These suggest that users might be able to enable or disable specific analysis modules, allowing for tailored analysis runs.
    *   Placeholders for API keys (e.g., `virustotal_api_key`): Indicates potential future integration with external services for enhanced analysis (like threat intelligence lookups).

The `settings.ini` file aims to make the Stego Analyzer flexible and adaptable to different user needs and environments by externalizing key operational parameters.
