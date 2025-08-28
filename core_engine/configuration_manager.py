"""Configuration manager for the analysis engine.

This module handles loading and validating configurations from a settings.ini file.
"""
import configparser
import os

# Define the expected schema for settings.ini
# This helps in validating the configuration file.
# Format: {section: {option: (type, required, default_if_not_required)}}
CONFIG_SCHEMA = {
    'general': {
        'project_root': (str, True, None),
        'output_dir': (str, True, 'output'),
        'log_level': (str, False, 'INFO'),
        'verbose': (bool, False, True)
    },
    'paths': {
        'log_dir_name': (str, False, 'logs'),
        'extracted_dir_name': (str, False, 'extracted'),
        'graphs_dir_name': (str, False, 'graphs'),
        'models_dir_name': (str, False, 'models')
    },
    'pe_analyzer': {
        'enabled': (bool, False, True),
        'max_file_size_mb': (int, False, 100),
        'scan_on_import': (bool, False, False)
    },
    'code_analyzer': {
        'enabled': (bool, False, True),
        'max_recursion_depth': (int, False, 10),
        'analyze_libraries': (bool, False, False)
    },
    'obfuscation_analyzer': {
        'enabled': (bool, False, True),
        'string_entropy_threshold': (float, False, 4.5),
        'max_suspicious_loops': (int, False, 5)
    }
    # Add other sections and their options as needed (e.g., specific tool paths, API keys)
}

class ConfigurationManager:
    def __init__(self, settings_path='settings.ini'):
        self.settings_path = settings_path
        self.config = configparser.ConfigParser()
        self.loaded_config = {}
        self._load_and_validate()

    def _validate_config(self):
        """Validates the loaded configuration against the schema."""
        for section, schema_options in CONFIG_SCHEMA.items():
            if not self.config.has_section(section) and any(req for _, req, _ in schema_options.values()):
                raise ValueError(f"Missing required section [{section}] in {self.settings_path}")

            if section not in self.loaded_config:
                self.loaded_config[section] = {}

            for option, (expected_type, required, default) in schema_options.items():
                if self.config.has_option(section, option):
                    value_str = self.config.get(section, option)
                    try:
                        if expected_type == bool:
                            value = self.config.getboolean(section, option)
                        elif expected_type == int:
                            value = self.config.getint(section, option)
                        elif expected_type == float:
                            value = self.config.getfloat(section, option)
                        else: # str
                            value = value_str
                        self.loaded_config[section][option] = value
                    except ValueError as e:
                        raise ValueError(f"Invalid type for {option} in [{section}]. Expected {expected_type.__name__}. Error: {e}")
                elif required:
                    raise ValueError(f"Missing required option '{option}' in section '[{section}]' in {self.settings_path}")
                else:
                    self.loaded_config[section][option] = default
        print("Configuration validated successfully.")


    def _resolve_paths(self):
        """Resolves relative paths to absolute paths based on project_root."""
        project_root = self.get('general', 'project_root')
        if not os.path.isabs(project_root):
            # Assuming settings.ini is in the project root or one level down (e.g. /config)
            # For this project, settings.ini will be at the root.
            project_root = os.path.abspath(os.path.join(os.path.dirname(self.settings_path), project_root))
            # If settings.ini is intended to be at the very root, this might need adjustment
            # For now, let's assume settings.ini is at the root, so project_root IS the root.
            if os.path.basename(self.settings_path) == 'settings.ini': # common case
                 project_root = os.path.dirname(os.path.abspath(self.settings_path))

        self.loaded_config['general']['project_root'] = project_root

        # Resolve output_dir (can be absolute or relative to project_root)
        output_dir_config = self.get('general', 'output_dir', 'output')
        if not os.path.isabs(output_dir_config):
            output_dir_config = os.path.join(project_root, output_dir_config)
        self.loaded_config['general']['output_dir'] = output_dir_config
        os.makedirs(output_dir_config, exist_ok=True)


        # Resolve sub-directories within output_dir
        paths_config = self.get_section('paths', {})
        for dir_key, dir_name in paths_config.items():
            # dir_key is e.g. 'log_dir_name', dir_name is its value e.g. 'logs'
            # We want to store the absolute path in loaded_config['paths'][dir_key_absolute]
            abs_path_key = dir_key.replace('_name', '') # e.g. log_dir
            abs_path = os.path.join(output_dir_config, dir_name)
            self.loaded_config['paths'][abs_path_key] = abs_path
            os.makedirs(abs_path, exist_ok=True)

        # Resolve models_dir (can be absolute or relative to project_root)
        models_dir_name = self.get('paths', 'models_dir_name', 'models')
        models_dir_path = models_dir_name # Use directly if absolute
        if not os.path.isabs(models_dir_name):
            models_dir_path = os.path.join(project_root, models_dir_name)
        self.loaded_config['paths']['models_dir'] = models_dir_path
        # We don't create models_dir here, it should pre-exist with models.

        print(f"Project root resolved to: {self.loaded_config['general']['project_root']}")
        print(f"Output directory resolved to: {self.loaded_config['general']['output_dir']}")


    def _load_and_validate(self):
        """Loads the .ini file, validates it, and resolves paths."""
        if not os.path.exists(self.settings_path):
            raise FileNotFoundError(f"Settings file not found: {self.settings_path}")

        try:
            self.config.read(self.settings_path)
        except configparser.Error as e:
            raise ValueError(f"Error parsing {self.settings_path}: {e}")

        self._validate_config()
        self._resolve_paths() # Resolve paths after basic validation
        print(f"Configuration loaded and validated from {self.settings_path}")

    def get(self, section: str, option: str, fallback=None):
        """Gets a configuration value. Returns fallback if not found or section/option doesn't exist."""
        return self.loaded_config.get(section, {}).get(option, fallback)

    def get_section(self, section: str, fallback=None):
        """Gets a whole configuration section. Returns fallback if section doesn't exist."""
        return self.loaded_config.get(section, fallback)

    def getboolean(self, section: str, option: str, fallback=None) -> bool:
        val = self.get(section, option, fallback)
        if isinstance(val, bool):
            return val
        # Should have been converted during validation, but as a safeguard:
        if isinstance(val, str):
            if val.lower() in ('true', 'yes', 'on', '1'):
                return True
            if val.lower() in ('false', 'no', 'off', '0'):
                return False
        return bool(fallback) # Or raise error

    def getint(self, section: str, option: str, fallback=None) -> int:
        val = self.get(section, option, fallback)
        try:
            return int(val)
        except (ValueError, TypeError):
            return int(fallback) # Or raise error

    def getfloat(self, section: str, option: str, fallback=None) -> float:
        val = self.get(section, option, fallback)
        try:
            return float(val)
        except (ValueError, TypeError):
            return float(fallback) # Or raise error

if __name__ == '__main__':
    # This section demonstrates usage and helps in testing the ConfigurationManager.
    # Create a dummy settings.ini for testing if it doesn't exist.
    # In a real scenario, settings.ini would be part of the project.
    dummy_settings_content = """
[general]
project_root = .
output_dir = project_output
log_level = DEBUG
verbose = True

[paths]
log_dir_name = app_logs
extracted_dir_name = app_extracted
graphs_dir_name = app_graphs
models_dir_name = app_models

[pe_analyzer]
enabled = True
max_file_size_mb = 50
scan_on_import = False

[code_analyzer]
enabled = True

[obfuscation_analyzer]
enabled = False
string_entropy_threshold = 4.2
"""
    dummy_settings_path = "dummy_settings.ini"
    if not os.path.exists(dummy_settings_path):
        with open(dummy_settings_path, 'w') as f:
            f.write(dummy_settings_content)
        print(f"Created dummy settings file: {dummy_settings_path}")

    try:
        # Assuming settings.ini is at the project root for this test
        # Adjust the path if your `run_analyzer.py` or main script is elsewhere
        print(f"Current working directory: {os.getcwd()}")
        # If dummy_settings.ini is created in /app, and project_root = ., then root is /app

        config_manager = ConfigurationManager(settings_path=dummy_settings_path)

        print("\n--- Retrieved Configuration Values ---")
        print(f"Project Root: {config_manager.get('general', 'project_root')}")
        print(f"Output Dir: {config_manager.get('general', 'output_dir')}")
        print(f"Log Dir (absolute): {config_manager.get('paths', 'log_dir')}")
        print(f"Models Dir (absolute): {config_manager.get('paths', 'models_dir')}")
        print(f"Log Level: {config_manager.get('general', 'log_level')}")
        print(f"Verbose: {config_manager.getboolean('general', 'verbose')}")

        print(f"PE Analyzer Enabled: {config_manager.getboolean('pe_analyzer', 'enabled')}")
        print(f"PE Max File Size: {config_manager.getint('pe_analyzer', 'max_file_size_mb')}")

        print(f"Code Analyzer Enabled (default): {config_manager.getboolean('code_analyzer', 'enabled', fallback=False)}") # Tests fallback for missing option
        print(f"Code Analyzer Max Recursion (default): {config_manager.getint('code_analyzer', 'max_recursion_depth')}")

        print(f"Obfuscation Analyzer Enabled: {config_manager.getboolean('obfuscation_analyzer', 'enabled')}")
        print(f"Obfuscation String Entropy: {config_manager.getfloat('obfuscation_analyzer', 'string_entropy_threshold')}")

        # Test getting a whole section
        pe_config = config_manager.get_section('pe_analyzer')
        print(f"PE Analyzer Section: {pe_config}")

        # Test non-existent option with fallback
        print(f"Non-existent option (general, foo): {config_manager.get('general', 'foo', 'default_value')}")

        # Test path resolutions make sense
        # Expected: project_output, app_logs, app_extracted, app_graphs, app_models are inside /app if dummy_settings.ini is in /app
        # And project_root is /app
        # And output_dir is /app/project_output

    except Exception as e:
        print(f"Error during ConfigurationManager test: {e}")
    finally:
        # Clean up dummy file
        if os.path.exists(dummy_settings_path) and "dummy" in dummy_settings_path :
             os.remove(dummy_settings_path)
             print(f"Removed dummy settings file: {dummy_settings_path}")
        # Clean up created directories by dummy run
        if os.path.exists("./project_output/app_logs") and "project_output" in "./project_output/app_logs": # very careful
            os.rmdir("./project_output/app_logs")
        if os.path.exists("./project_output/app_extracted") and "project_output" in "./project_output/app_extracted": # very careful
            os.rmdir("./project_output/app_extracted")
        if os.path.exists("./project_output/app_graphs") and "project_output" in "./project_output/app_graphs": # very careful
            os.rmdir("./project_output/app_graphs")
        if os.path.exists("./project_output") and "project_output" in "./project_output": # very careful
            os.rmdir("./project_output")
