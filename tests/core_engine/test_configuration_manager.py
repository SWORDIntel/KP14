"""
Comprehensive tests for core_engine/configuration_manager.py

Tests cover:
- Config loading (valid/invalid)
- Config validation
- Default values
- Path resolution
- Environment variable override (if implemented)
- Error handling for missing/corrupted files
"""

import pytest
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core_engine.configuration_manager import ConfigurationManager, ConfigurationError, CONFIG_SCHEMA


class TestConfigurationLoading:
    """Test configuration file loading."""

    def test_load_valid_config(self, test_config_file):
        """Test loading a valid configuration file."""
        config = ConfigurationManager(test_config_file)

        assert config is not None
        assert config.settings_path == test_config_file

    def test_load_missing_config_file(self, temp_dir):
        """Test error when config file doesn't exist."""
        missing_file = os.path.join(temp_dir, "nonexistent.ini")

        with pytest.raises(ConfigurationError) as exc_info:
            ConfigurationManager(missing_file)

        assert "not found" in str(exc_info.value).lower()

    def test_load_unreadable_config_file(self, test_config_file):
        """Test error when config file is not readable."""
        # Make file unreadable (Unix permissions)
        if os.name != 'nt':  # Skip on Windows
            os.chmod(test_config_file, 0o000)

            try:
                with pytest.raises(ConfigurationError) as exc_info:
                    ConfigurationManager(test_config_file)

                assert "not readable" in str(exc_info.value).lower()
            finally:
                # Restore permissions for cleanup
                os.chmod(test_config_file, 0o644)

    def test_load_corrupted_config_file(self, temp_dir):
        """Test error when config file is corrupted."""
        corrupted_file = os.path.join(temp_dir, "corrupted.ini")
        with open(corrupted_file, 'w') as f:
            f.write("[general\nthis is not valid ini format\n")

        with pytest.raises(ConfigurationError) as exc_info:
            ConfigurationManager(corrupted_file)

        assert "parsing" in str(exc_info.value).lower() or "error" in str(exc_info.value).lower()


class TestConfigurationValidation:
    """Test configuration validation against schema."""

    def test_validate_all_required_sections(self, test_config_file):
        """Test validation passes when all required sections present."""
        config = ConfigurationManager(test_config_file)

        # Should have loaded config successfully
        assert config.loaded_config is not None

    def test_validate_missing_required_section(self, temp_dir):
        """Test error when required section is missing."""
        incomplete_file = os.path.join(temp_dir, "incomplete.ini")
        with open(incomplete_file, 'w') as f:
            f.write("[paths]\nlog_dir_name = logs\n")

        with pytest.raises(ConfigurationError) as exc_info:
            ConfigurationManager(incomplete_file)

        assert "section" in str(exc_info.value).lower()

    def test_validate_missing_required_option(self, temp_dir):
        """Test error when required option is missing."""
        missing_option_file = os.path.join(temp_dir, "missing_option.ini")
        with open(missing_option_file, 'w') as f:
            f.write("""
[general]
output_dir = test_output
log_level = INFO

[paths]
log_dir_name = logs

[pe_analyzer]
enabled = True

[code_analyzer]
enabled = True

[obfuscation_analyzer]
enabled = True
""")
        # Missing project_root which is required

        with pytest.raises(ConfigurationError) as exc_info:
            ConfigurationManager(missing_option_file)

        assert "project_root" in str(exc_info.value).lower() or "missing" in str(exc_info.value).lower()

    def test_validate_invalid_type_boolean(self, temp_dir):
        """Test error when boolean option has invalid value."""
        invalid_bool_file = os.path.join(temp_dir, "invalid_bool.ini")
        with open(invalid_bool_file, 'w') as f:
            f.write("""
[general]
project_root = .
output_dir = test
log_level = INFO
verbose = not_a_boolean

[paths]
log_dir_name = logs

[pe_analyzer]
enabled = True

[code_analyzer]
enabled = True

[obfuscation_analyzer]
enabled = True
""")

        with pytest.raises(ConfigurationError) as exc_info:
            ConfigurationManager(invalid_bool_file)

        assert "type" in str(exc_info.value).lower() or "bool" in str(exc_info.value).lower()

    def test_validate_invalid_type_int(self, temp_dir):
        """Test error when integer option has invalid value."""
        invalid_int_file = os.path.join(temp_dir, "invalid_int.ini")
        with open(invalid_int_file, 'w') as f:
            f.write("""
[general]
project_root = .
output_dir = test
log_level = INFO

[paths]
log_dir_name = logs

[pe_analyzer]
enabled = True
max_file_size_mb = not_a_number

[code_analyzer]
enabled = True

[obfuscation_analyzer]
enabled = True
""")

        with pytest.raises(ConfigurationError) as exc_info:
            ConfigurationManager(invalid_int_file)

        assert "type" in str(exc_info.value).lower() or "int" in str(exc_info.value).lower()

    def test_validate_invalid_type_float(self, temp_dir):
        """Test error when float option has invalid value."""
        invalid_float_file = os.path.join(temp_dir, "invalid_float.ini")
        with open(invalid_float_file, 'w') as f:
            f.write("""
[general]
project_root = .
output_dir = test
log_level = INFO

[paths]
log_dir_name = logs

[pe_analyzer]
enabled = True

[code_analyzer]
enabled = True

[obfuscation_analyzer]
enabled = True
string_entropy_threshold = not_a_float
""")

        with pytest.raises(ConfigurationError) as exc_info:
            ConfigurationManager(invalid_float_file)

        assert "type" in str(exc_info.value).lower() or "float" in str(exc_info.value).lower()


class TestDefaultValues:
    """Test default value handling."""

    def test_default_values_for_optional_fields(self, temp_dir):
        """Test that optional fields get default values."""
        minimal_file = os.path.join(temp_dir, "minimal.ini")
        with open(minimal_file, 'w') as f:
            f.write("""
[general]
project_root = .

[paths]

[pe_analyzer]

[code_analyzer]

[obfuscation_analyzer]
""")

        config = ConfigurationManager(minimal_file)

        # Check defaults from schema
        assert config.get('general', 'log_level') == 'INFO'
        assert config.get('general', 'output_dir') == 'output'
        assert config.getboolean('pe_analyzer', 'enabled') is True
        assert config.getint('pe_analyzer', 'max_file_size_mb') == 100

    def test_get_with_fallback(self, test_config_file):
        """Test get method with fallback for missing option."""
        config = ConfigurationManager(test_config_file)

        # Non-existent option should return fallback
        value = config.get('general', 'nonexistent_option', fallback='default_value')

        assert value == 'default_value'

    def test_getboolean_with_fallback(self, test_config_file):
        """Test getboolean method with fallback."""
        config = ConfigurationManager(test_config_file)

        value = config.getboolean('general', 'nonexistent_bool', fallback=True)

        assert value is True

    def test_getint_with_fallback(self, test_config_file):
        """Test getint method with fallback."""
        config = ConfigurationManager(test_config_file)

        value = config.getint('general', 'nonexistent_int', fallback=42)

        assert value == 42

    def test_getfloat_with_fallback(self, test_config_file):
        """Test getfloat method with fallback."""
        config = ConfigurationManager(test_config_file)

        value = config.getfloat('general', 'nonexistent_float', fallback=3.14)

        assert value == 3.14


class TestPathResolution:
    """Test path resolution and directory creation."""

    def test_resolve_relative_project_root(self, test_config_file):
        """Test resolution of relative project_root path."""
        config = ConfigurationManager(test_config_file)

        project_root = config.get('general', 'project_root')

        # Should be absolute path
        assert os.path.isabs(project_root)

    def test_resolve_output_dir(self, test_config_file):
        """Test resolution of output_dir path."""
        config = ConfigurationManager(test_config_file)

        output_dir = config.get('general', 'output_dir')

        # Should be absolute path
        assert os.path.isabs(output_dir)

    def test_create_output_directory(self, test_config_file):
        """Test that output directory is created."""
        config = ConfigurationManager(test_config_file)

        output_dir = config.get('general', 'output_dir')

        # Directory should exist
        assert os.path.exists(output_dir)

    def test_resolve_subdirectories(self, test_config_file):
        """Test resolution of subdirectories in paths section."""
        config = ConfigurationManager(test_config_file)

        log_dir = config.get('paths', 'log_dir')
        extracted_dir = config.get('paths', 'extracted_dir')
        graphs_dir = config.get('paths', 'graphs_dir')

        # All should be absolute paths
        assert os.path.isabs(log_dir)
        assert os.path.isabs(extracted_dir)
        assert os.path.isabs(graphs_dir)

    def test_create_subdirectories(self, test_config_file):
        """Test that subdirectories are created."""
        config = ConfigurationManager(test_config_file)

        log_dir = config.get('paths', 'log_dir')

        # Subdirectories should be created
        assert os.path.exists(log_dir)

    def test_handle_absolute_paths(self, temp_dir):
        """Test handling of absolute paths in configuration."""
        abs_output_dir = os.path.join(temp_dir, "absolute_output")

        config_file = os.path.join(temp_dir, "absolute_paths.ini")
        with open(config_file, 'w') as f:
            f.write(f"""
[general]
project_root = .
output_dir = {abs_output_dir}
log_level = INFO

[paths]
log_dir_name = logs

[pe_analyzer]
enabled = True

[code_analyzer]
enabled = True

[obfuscation_analyzer]
enabled = True
""")

        config = ConfigurationManager(config_file)

        # Should use the absolute path as-is
        assert config.get('general', 'output_dir') == abs_output_dir


class TestGetMethods:
    """Test various get methods."""

    def test_get_string_value(self, test_config_file):
        """Test retrieving string values."""
        config = ConfigurationManager(test_config_file)

        log_level = config.get('general', 'log_level')

        assert log_level == 'DEBUG'
        assert isinstance(log_level, str)

    def test_get_boolean_value_true(self, test_config_file):
        """Test retrieving boolean True value."""
        config = ConfigurationManager(test_config_file)

        verbose = config.getboolean('general', 'verbose')

        assert verbose is True

    def test_get_boolean_value_false(self, temp_dir):
        """Test retrieving boolean False value."""
        config_file = os.path.join(temp_dir, "bool_false.ini")
        with open(config_file, 'w') as f:
            f.write("""
[general]
project_root = .
output_dir = test
verbose = False

[paths]
log_dir_name = logs

[pe_analyzer]
enabled = False

[code_analyzer]
enabled = True

[obfuscation_analyzer]
enabled = True
""")

        config = ConfigurationManager(config_file)

        enabled = config.getboolean('pe_analyzer', 'enabled')

        assert enabled is False

    def test_get_int_value(self, test_config_file):
        """Test retrieving integer values."""
        config = ConfigurationManager(test_config_file)

        max_depth = config.getint('code_analyzer', 'max_recursion_depth')

        assert max_depth == 5
        assert isinstance(max_depth, int)

    def test_get_float_value(self, test_config_file):
        """Test retrieving float values."""
        config = ConfigurationManager(test_config_file)

        threshold = config.getfloat('obfuscation_analyzer', 'string_entropy_threshold')

        assert threshold == 4.5
        assert isinstance(threshold, float)

    def test_get_section(self, test_config_file):
        """Test retrieving entire section."""
        config = ConfigurationManager(test_config_file)

        pe_section = config.get_section('pe_analyzer')

        assert isinstance(pe_section, dict)
        assert 'enabled' in pe_section
        assert 'max_file_size_mb' in pe_section

    def test_get_section_nonexistent(self, test_config_file):
        """Test retrieving non-existent section returns fallback."""
        config = ConfigurationManager(test_config_file)

        section = config.get_section('nonexistent_section', fallback={})

        assert section == {}


class TestBooleanParsing:
    """Test boolean value parsing variations."""

    @pytest.mark.parametrize("bool_value,expected", [
        ("True", True),
        ("true", True),
        ("TRUE", True),
        ("Yes", True),
        ("yes", True),
        ("On", True),
        ("on", True),
        ("1", True),
        ("False", False),
        ("false", False),
        ("FALSE", False),
        ("No", False),
        ("no", False),
        ("Off", False),
        ("off", False),
        ("0", False),
    ])
    def test_boolean_variations(self, temp_dir, bool_value, expected):
        """Test various boolean value formats."""
        config_file = os.path.join(temp_dir, f"bool_{bool_value}.ini")
        with open(config_file, 'w') as f:
            f.write(f"""
[general]
project_root = .
output_dir = test
verbose = {bool_value}

[paths]
log_dir_name = logs

[pe_analyzer]
enabled = True

[code_analyzer]
enabled = True

[obfuscation_analyzer]
enabled = True
""")

        config = ConfigurationManager(config_file)

        result = config.getboolean('general', 'verbose')

        assert result == expected


class TestErrorContextPreservation:
    """Test error context is preserved in exceptions."""

    def test_error_includes_file_path(self, temp_dir):
        """Test error includes configuration file path."""
        missing_file = os.path.join(temp_dir, "missing.ini")

        with pytest.raises(ConfigurationError) as exc_info:
            ConfigurationManager(missing_file)

        error = exc_info.value
        assert hasattr(error, 'context')
        assert 'settings_path' in error.context

    def test_error_includes_config_key(self, temp_dir):
        """Test error includes configuration key causing error."""
        invalid_file = os.path.join(temp_dir, "invalid.ini")
        with open(invalid_file, 'w') as f:
            f.write("""
[general]
project_root = .
output_dir = test

[paths]
log_dir_name = logs

[pe_analyzer]
enabled = True
max_file_size_mb = invalid_int

[code_analyzer]
enabled = True

[obfuscation_analyzer]
enabled = True
""")

        with pytest.raises(ConfigurationError) as exc_info:
            ConfigurationManager(invalid_file)

        error = exc_info.value
        assert hasattr(error, 'config_key')
        assert 'max_file_size_mb' in str(error.config_key)


class TestConfigSchema:
    """Test configuration schema definition."""

    def test_schema_has_general_section(self):
        """Test schema includes general section."""
        assert 'general' in CONFIG_SCHEMA

    def test_schema_has_required_fields(self):
        """Test schema marks required fields correctly."""
        # project_root should be required
        assert CONFIG_SCHEMA['general']['project_root'][1] is True

    def test_schema_has_correct_types(self):
        """Test schema specifies correct types."""
        # log_level should be string
        assert CONFIG_SCHEMA['general']['log_level'][0] == str

        # verbose should be bool
        assert CONFIG_SCHEMA['general']['verbose'][0] == bool

        # max_file_size_mb should be int
        assert CONFIG_SCHEMA['pe_analyzer']['max_file_size_mb'][0] == int

        # string_entropy_threshold should be float
        assert CONFIG_SCHEMA['obfuscation_analyzer']['string_entropy_threshold'][0] == float


class TestEdgeCases:
    """Test edge cases and unusual configurations."""

    def test_empty_section(self, temp_dir):
        """Test handling of empty sections."""
        config_file = os.path.join(temp_dir, "empty_section.ini")
        with open(config_file, 'w') as f:
            f.write("""
[general]
project_root = .
output_dir = test

[paths]

[pe_analyzer]

[code_analyzer]

[obfuscation_analyzer]
""")

        config = ConfigurationManager(config_file)

        # Should use defaults for missing values
        assert config.get('paths', 'log_dir_name', 'logs') is not None

    def test_extra_sections_ignored(self, test_config_file):
        """Test that extra sections not in schema are ignored."""
        # Add extra section to file
        with open(test_config_file, 'a') as f:
            f.write("\n[custom_section]\ncustom_option = value\n")

        config = ConfigurationManager(test_config_file)

        # Should load successfully, extra section ignored
        assert config is not None

    def test_whitespace_in_values(self, temp_dir):
        """Test handling of whitespace in configuration values."""
        config_file = os.path.join(temp_dir, "whitespace.ini")
        with open(config_file, 'w') as f:
            f.write("""
[general]
project_root = .
output_dir =   test_output_with_spaces
log_level = INFO

[paths]
log_dir_name = logs

[pe_analyzer]
enabled = True

[code_analyzer]
enabled = True

[obfuscation_analyzer]
enabled = True
""")

        config = ConfigurationManager(config_file)

        # Whitespace should be stripped
        output_dir = config.get('general', 'output_dir')
        assert output_dir.strip() == output_dir


@pytest.mark.parametrize("log_level", ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
def test_valid_log_levels(temp_dir, log_level):
    """Test all valid log levels are accepted."""
    config_file = os.path.join(temp_dir, f"log_level_{log_level}.ini")
    with open(config_file, 'w') as f:
        f.write(f"""
[general]
project_root = .
output_dir = test
log_level = {log_level}

[paths]
log_dir_name = logs

[pe_analyzer]
enabled = True

[code_analyzer]
enabled = True

[obfuscation_analyzer]
enabled = True
""")

    config = ConfigurationManager(config_file)

    assert config.get('general', 'log_level') == log_level
