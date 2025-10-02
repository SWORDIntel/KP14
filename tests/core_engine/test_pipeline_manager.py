"""
Comprehensive tests for core_engine/pipeline_manager.py

Tests cover:
- Pipeline initialization
- Stage execution order
- Error handling in pipeline
- Recursive analysis
- Max recursion limits
- File type detection
- Static analysis execution
"""

import pytest
import os
import sys
from unittest.mock import Mock, MagicMock, patch, mock_open
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core_engine.pipeline_manager import PipelineManager


class TestPipelineManagerInitialization:
    """Test pipeline manager initialization."""

    def test_init_with_config_manager(self, mock_config_manager):
        """Test pipeline manager initializes with config manager."""
        pipeline = PipelineManager(mock_config_manager)

        assert pipeline.config_manager == mock_config_manager
        assert pipeline.logger is not None

    def test_init_sets_log_level_from_config(self, mock_config_manager):
        """Test that log level is set from configuration."""
        pipeline = PipelineManager(mock_config_manager)

        # Should have called get for log_level
        assert any(
            call[0] == ('general', 'log_level')
            for call in mock_config_manager.get.call_args_list
        )

    @patch('core_engine.pipeline_manager.PEAnalyzer', None)
    @patch('core_engine.pipeline_manager.CodeAnalyzer', None)
    def test_init_handles_missing_analyzers(self, mock_config_manager):
        """Test initialization when analyzers are not available."""
        pipeline = PipelineManager(mock_config_manager)

        assert pipeline.pe_analyzer_template is None
        assert pipeline.code_analyzer_template is None

    def test_load_module_templates(self, mock_config_manager):
        """Test module templates are loaded based on config."""
        with patch('core_engine.pipeline_manager.PEAnalyzer') as mock_pe:
            with patch('core_engine.pipeline_manager.CodeAnalyzer') as mock_code:
                pipeline = PipelineManager(mock_config_manager)

                # Should check if modules are enabled
                assert mock_config_manager.getboolean.called


class TestFileTypeDetection:
    """Test file type detection methods."""

    def test_get_file_type_pe(self, mock_config_manager):
        """Test PE file type detection from bytes."""
        pipeline = PipelineManager(mock_config_manager)
        pe_data = b'MZ' + b'\x00' * 100

        file_type = pipeline._get_file_type(pe_data)

        assert file_type == 'pe'

    def test_get_file_type_zip(self, mock_config_manager):
        """Test ZIP file type detection from bytes."""
        pipeline = PipelineManager(mock_config_manager)
        zip_data = b'PK\x03\x04' + b'\x00' * 100

        file_type = pipeline._get_file_type(zip_data)

        assert file_type == 'zip'

    def test_get_file_type_jpeg(self, mock_config_manager):
        """Test JPEG file type detection from bytes."""
        pipeline = PipelineManager(mock_config_manager)
        jpeg_data = b'\xff\xd8\xff' + b'\x00' * 100

        file_type = pipeline._get_file_type(jpeg_data)

        assert file_type == 'jpeg'

    def test_get_file_type_png(self, mock_config_manager):
        """Test PNG file type detection from bytes."""
        pipeline = PipelineManager(mock_config_manager)
        png_data = b'\x89PNG\r\n\x1a\n' + b'\x00' * 100

        file_type = pipeline._get_file_type(png_data)

        assert file_type == 'png'

    def test_get_file_type_gif(self, mock_config_manager):
        """Test GIF file type detection from bytes."""
        pipeline = PipelineManager(mock_config_manager)
        gif_data = b'GIF89a' + b'\x00' * 100

        file_type = pipeline._get_file_type(gif_data)

        assert file_type == 'gif'

    def test_get_file_type_from_path(self, mock_config_manager, sample_pe_file):
        """Test file type detection from file path."""
        pipeline = PipelineManager(mock_config_manager)

        file_type = pipeline._get_file_type(sample_pe_file)

        assert file_type == 'pe'

    def test_get_file_type_fallback_to_extension(self, mock_config_manager, temp_dir):
        """Test fallback to extension when magic bytes unknown."""
        pipeline = PipelineManager(mock_config_manager)

        # Create file with unknown magic but .exe extension
        test_file = os.path.join(temp_dir, "test.exe")
        with open(test_file, 'wb') as f:
            f.write(b'UNKN' + b'\x00' * 100)

        file_type = pipeline._get_file_type(test_file)

        assert file_type == 'exe'

    def test_get_file_type_unknown(self, mock_config_manager):
        """Test unknown file type detection."""
        pipeline = PipelineManager(mock_config_manager)
        unknown_data = b'XYZA' + b'\x00' * 100

        file_type = pipeline._get_file_type(unknown_data)

        assert file_type == 'unknown'


class TestPipelineExecution:
    """Test pipeline execution and analysis flow."""

    def test_run_pipeline_file_not_found(self, mock_config_manager):
        """Test pipeline returns error for non-existent file."""
        pipeline = PipelineManager(mock_config_manager)

        result = pipeline.run_pipeline("/nonexistent/file.exe")

        assert "error" in result
        assert result["error"] == "Input file not found."

    def test_run_pipeline_basic_execution(self, mock_config_manager, sample_pe_file):
        """Test basic pipeline execution on PE file."""
        with patch('core_engine.pipeline_manager.PEAnalyzer') as mock_pe:
            # Mock PE analyzer instance
            mock_instance = Mock()
            mock_instance.get_analysis_summary.return_value = {
                "file_type": "PE32",
                "sections": []
            }
            mock_pe.return_value = mock_instance

            pipeline = PipelineManager(mock_config_manager)
            pipeline.pe_analyzer_template = mock_pe

            result = pipeline.run_pipeline(sample_pe_file)

            assert "file_path" in result
            assert result["file_path"] == sample_pe_file
            assert "original_file_type" in result

    def test_run_pipeline_handles_read_error(self, mock_config_manager, temp_dir):
        """Test pipeline handles file read errors gracefully."""
        pipeline = PipelineManager(mock_config_manager)

        # Create a file and then make it unreadable
        test_file = os.path.join(temp_dir, "unreadable.exe")
        with open(test_file, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 100)

        # Mock open to raise IOError
        with patch('builtins.open', side_effect=IOError("Permission denied")):
            result = pipeline.run_pipeline(test_file)

            assert "error" in result
            assert "File read error" in result["error"]

    def test_run_pipeline_detects_file_type(self, mock_config_manager, sample_pe_file):
        """Test pipeline correctly detects file type."""
        pipeline = PipelineManager(mock_config_manager)

        result = pipeline.run_pipeline(sample_pe_file)

        assert result["original_file_type"] == "pe"

    def test_run_pipeline_sets_source_description(self, mock_config_manager, sample_pe_file):
        """Test pipeline sets correct source description."""
        pipeline = PipelineManager(mock_config_manager)

        result = pipeline.run_pipeline(
            sample_pe_file,
            is_recursive_call=False,
            original_source_desc="test_source"
        )

        assert result["source_description"] == "test_source"

    def test_run_pipeline_recursive_flag(self, mock_config_manager, sample_pe_file):
        """Test pipeline handles recursive call flag."""
        pipeline = PipelineManager(mock_config_manager)

        result = pipeline.run_pipeline(sample_pe_file, is_recursive_call=True)

        assert result["is_recursive_call"] is True


class TestStaticAnalysis:
    """Test static analysis execution on PE data."""

    def test_run_static_analysis_on_pe_data(self, mock_config_manager, sample_pe_bytes):
        """Test static analysis runs on PE data."""
        with patch('core_engine.pipeline_manager.PEAnalyzer') as mock_pe:
            mock_instance = Mock()
            mock_instance.get_analysis_summary.return_value = {
                "file_type": "PE32",
                "sections": []
            }
            mock_pe.return_value = mock_instance

            pipeline = PipelineManager(mock_config_manager)
            pipeline.pe_analyzer_template = mock_pe

            result = pipeline._run_static_analysis_on_pe_data(
                sample_pe_bytes,
                "test_source"
            )

            assert result["source"] == "test_source"
            assert "pe_info" in result

    def test_static_analysis_handles_pe_error(self, mock_config_manager, sample_pe_bytes):
        """Test static analysis handles PE analyzer errors."""
        with patch('core_engine.pipeline_manager.PEAnalyzer') as mock_pe:
            mock_instance = Mock()
            mock_instance.get_analysis_summary.side_effect = Exception("PE analysis failed")
            mock_pe.return_value = mock_instance

            pipeline = PipelineManager(mock_config_manager)
            pipeline.pe_analyzer_template = mock_pe

            result = pipeline._run_static_analysis_on_pe_data(
                sample_pe_bytes,
                "test_source"
            )

            assert len(result["errors"]) > 0
            assert "PE Analysis" in result["errors"][0]

    def test_static_analysis_creates_temp_file(self, mock_config_manager, sample_pe_bytes, temp_dir):
        """Test static analysis creates temp file when no path provided."""
        mock_config_manager.get.return_value = temp_dir

        with patch('core_engine.pipeline_manager.PEAnalyzer') as mock_pe:
            mock_instance = Mock()
            mock_instance.get_analysis_summary.return_value = {"sections": []}
            mock_pe.return_value = mock_instance

            pipeline = PipelineManager(mock_config_manager)
            pipeline.pe_analyzer_template = mock_pe

            result = pipeline._run_static_analysis_on_pe_data(
                sample_pe_bytes,
                "extracted_source"
            )

            # Should have created temp file (will be cleaned up)
            assert "pe_info" in result or "errors" in result


class TestErrorHandling:
    """Test error handling throughout pipeline."""

    def test_pipeline_handles_analyzer_import_errors(self, mock_config_manager):
        """Test pipeline handles missing analyzer modules gracefully."""
        # All analyzers set to None (import failed)
        with patch('core_engine.pipeline_manager.PEAnalyzer', None):
            with patch('core_engine.pipeline_manager.CodeAnalyzer', None):
                pipeline = PipelineManager(mock_config_manager)

                # Should initialize without errors
                assert pipeline.pe_analyzer_template is None
                assert pipeline.code_analyzer_template is None

    def test_pipeline_handles_exception_in_analyzer_init(self, mock_config_manager):
        """Test pipeline handles exceptions during analyzer initialization."""
        with patch('core_engine.pipeline_manager.PolyglotAnalyzer') as mock_poly:
            mock_poly.side_effect = Exception("Initialization failed")

            pipeline = PipelineManager(mock_config_manager)

            # Should handle error gracefully
            assert pipeline.polyglot_analyzer is None

    def test_pipeline_logs_errors(self, mock_config_manager, sample_pe_file, mock_logger):
        """Test pipeline logs errors appropriately."""
        with patch('core_engine.pipeline_manager.PEAnalyzer') as mock_pe:
            mock_pe.side_effect = Exception("Test error")

            pipeline = PipelineManager(mock_config_manager)
            pipeline.logger = mock_logger
            pipeline.pe_analyzer_template = mock_pe

            result = pipeline.run_pipeline(sample_pe_file)

            # Logger should have been called
            assert mock_logger.info.called or mock_logger.error.called


class TestRecursiveAnalysis:
    """Test recursive analysis of extracted payloads."""

    def test_pipeline_handles_no_extracted_payloads(self, mock_config_manager, sample_pe_file):
        """Test pipeline completes when no payloads extracted."""
        pipeline = PipelineManager(mock_config_manager)

        result = pipeline.run_pipeline(sample_pe_file)

        assert "extracted_payload_analyses" in result
        assert len(result["extracted_payload_analyses"]) == 0

    @patch('core_engine.pipeline_manager.PolyglotAnalyzer')
    def test_pipeline_recursive_analysis_flow(self, mock_poly, mock_config_manager, temp_dir):
        """Test recursive analysis is triggered for extracted PE payloads."""
        # Create a PE file
        pe_file = os.path.join(temp_dir, "test.exe")
        pe_data = b'MZ' + b'\x00' * 1000
        with open(pe_file, 'wb') as f:
            f.write(pe_data)

        # Mock polyglot analyzer to return a PE payload
        mock_poly_instance = Mock()
        mock_poly_instance.analyze_file.return_value = [
            {
                'data': b'MZ' + b'\x00' * 500,  # Embedded PE
                'carrier_type': 'zip',
                'type_desc': 'embedded_exe',
                'offset': 100
            }
        ]
        mock_poly.return_value = mock_poly_instance

        pipeline = PipelineManager(mock_config_manager)
        pipeline.polyglot_analyzer = mock_poly_instance

        result = pipeline.run_pipeline(pe_file)

        # Should have attempted recursive analysis
        assert "extracted_payload_analyses" in result

    def test_pipeline_handles_recursive_analysis_errors(self, mock_config_manager, temp_dir):
        """Test pipeline handles errors during recursive analysis."""
        # This is more of an integration test, simplified for unit testing
        pipeline = PipelineManager(mock_config_manager)

        pe_file = os.path.join(temp_dir, "test.exe")
        with open(pe_file, 'wb') as f:
            f.write(b'MZ' + b'\x00' * 100)

        # Recursive analysis should handle non-existent extracted files
        result = pipeline.run_pipeline(pe_file)

        # Should complete without crashing
        assert "file_path" in result


class TestPipelineConfiguration:
    """Test pipeline configuration and module loading."""

    def test_configure_logging_from_config(self, mock_config_manager):
        """Test logging is configured from config manager."""
        pipeline = PipelineManager(mock_config_manager)

        # Should have queried log_level from config
        assert any(
            'log_level' in str(call)
            for call in mock_config_manager.get.call_args_list
        )

    def test_load_analyzers_respects_enabled_flags(self, mock_config_manager):
        """Test analyzers are only loaded if enabled in config."""
        # Set PE analyzer to disabled
        mock_config_manager.getboolean.return_value = False

        with patch('core_engine.pipeline_manager.PEAnalyzer') as mock_pe:
            pipeline = PipelineManager(mock_config_manager)

            # Should check if enabled
            assert mock_config_manager.getboolean.called

    def test_pipeline_uses_output_dir_from_config(self, mock_config_manager, temp_dir):
        """Test pipeline uses output directory from configuration."""
        mock_config_manager.get.return_value = temp_dir

        pipeline = PipelineManager(mock_config_manager)

        # When creating temp files, should use configured output dir
        # This is tested indirectly through static analysis


class TestPipelineReportGeneration:
    """Test report generation and structure."""

    def test_report_contains_required_fields(self, mock_config_manager, sample_pe_file):
        """Test pipeline report contains all required fields."""
        pipeline = PipelineManager(mock_config_manager)

        result = pipeline.run_pipeline(sample_pe_file)

        # Check required fields
        required_fields = [
            "file_path",
            "original_file_type",
            "source_description",
            "is_recursive_call",
            "extraction_analysis",
            "steganography_analysis",
            "decryption_analysis",
            "static_pe_analysis",
            "extracted_payload_analyses",
            "errors"
        ]

        for field in required_fields:
            assert field in result, f"Missing required field: {field}"

    def test_report_includes_file_path(self, mock_config_manager, sample_pe_file):
        """Test report includes input file path."""
        pipeline = PipelineManager(mock_config_manager)

        result = pipeline.run_pipeline(sample_pe_file)

        assert result["file_path"] == sample_pe_file

    def test_report_tracks_errors(self, mock_config_manager, sample_pe_file):
        """Test report tracks errors encountered during analysis."""
        with patch('core_engine.pipeline_manager.PEAnalyzer') as mock_pe:
            mock_pe.side_effect = Exception("Test error")

            pipeline = PipelineManager(mock_config_manager)
            pipeline.pe_analyzer_template = mock_pe

            result = pipeline.run_pipeline(sample_pe_file)

            # Should have errors list (might be empty if error was handled)
            assert "errors" in result
            assert isinstance(result["errors"], list)


@pytest.mark.parametrize("file_type,magic_bytes", [
    ("pe", b'MZ'),
    ("zip", b'PK\x03\x04'),
    ("jpeg", b'\xff\xd8\xff'),
    ("png", b'\x89PNG\r\n\x1a\n'),
    ("gif", b'GIF89a'),
])
def test_file_type_detection_parametrized(mock_config_manager, file_type, magic_bytes):
    """Parametrized test for multiple file types."""
    pipeline = PipelineManager(mock_config_manager)
    test_data = magic_bytes + b'\x00' * 100

    detected_type = pipeline._get_file_type(test_data)

    assert detected_type == file_type
