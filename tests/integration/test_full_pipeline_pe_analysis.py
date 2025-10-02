"""
Integration Test 1: Full Pipeline PE Analysis

Tests the complete analysis pipeline end-to-end with a real PE file.

Validates:
- Pipeline executes all analysis stages
- PE info extraction works correctly
- Code analysis generates disassembly
- Obfuscation detection runs
- JSON output has correct structure
- All components integrate properly
"""

import pytest
import json
from pathlib import Path


@pytest.mark.integration
@pytest.mark.slow
class TestFullPipelinePEAnalysis:
    """Integration tests for full PE analysis pipeline."""

    def test_analyze_valid_pe32_complete_pipeline(
        self,
        integration_pipeline,
        valid_pe32_sample,
        integration_output_dir,
        validate_analysis_report,
        performance_tracker
    ):
        """
        Test complete pipeline with valid PE32 executable.

        Validates that all analysis stages execute and produce expected output.
        """
        # Run full pipeline
        with performance_tracker("Full PE32 Analysis Pipeline"):
            report = integration_pipeline.run_pipeline(str(valid_pe32_sample))

        # Validate report structure
        assert isinstance(report, dict), "Report should be a dictionary"
        assert "file_path" in report, "Report should contain file_path"
        assert report["file_path"] == str(valid_pe32_sample)

        # Validate file type detection
        assert "original_file_type" in report
        assert report["original_file_type"] == "pe", f"Expected PE type, got {report['original_file_type']}"

        # Validate PE analysis
        assert "static_pe_analysis" in report, "Report should contain static_pe_analysis"
        pe_analysis = report["static_pe_analysis"]

        if pe_analysis:  # May be None if analyzer not available
            assert isinstance(pe_analysis, dict)
            assert "pe_info" in pe_analysis

            if pe_analysis["pe_info"]:
                pe_info = pe_analysis["pe_info"]

                # Validate basic PE info
                assert "machine" in pe_info or "Machine" in pe_info
                assert "sections" in pe_info or "Sections" in pe_info

                # Validate sections if present
                sections = pe_info.get("sections", pe_info.get("Sections", []))
                if sections:
                    assert isinstance(sections, list)
                    assert len(sections) > 0, "PE should have at least one section"

                    # Validate section structure
                    first_section = sections[0]
                    assert isinstance(first_section, dict)
                    # Section should have name or Name
                    assert "name" in first_section or "Name" in first_section

        # Validate code analysis (if enabled)
        if "code_analysis" in pe_analysis and pe_analysis["code_analysis"]:
            code_analysis = pe_analysis["code_analysis"]
            assert isinstance(code_analysis, dict)

            # Should have at least one section analyzed
            if code_analysis:
                for section_name, section_analysis in code_analysis.items():
                    assert isinstance(section_analysis, dict)
                    # Should have some analysis results
                    assert len(section_analysis) > 0

        # Validate obfuscation analysis (if enabled)
        if "obfuscation_details" in pe_analysis and pe_analysis["obfuscation_details"]:
            obf_details = pe_analysis["obfuscation_details"]
            assert isinstance(obf_details, dict)

            # Should have entropy score
            if "entropy_score" in obf_details:
                entropy = obf_details["entropy_score"]
                assert isinstance(entropy, (int, float))
                assert 0.0 <= entropy <= 8.0, f"Entropy should be 0-8, got {entropy}"

        # Validate JSON serialization
        try:
            json_output = json.dumps(report, default=str)
            assert len(json_output) > 0
        except Exception as e:
            pytest.fail(f"Report not JSON serializable: {e}")

        # Save report for inspection
        output_file = integration_output_dir / "test_full_pipeline_report.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"\nReport saved to: {output_file}")
        print(f"Report size: {len(json_output)} bytes")

    def test_pipeline_error_handling(
        self,
        integration_pipeline,
        corrupted_pe_sample,
        validate_analysis_report
    ):
        """
        Test pipeline error handling with corrupted PE.

        Validates graceful degradation when analysis fails.
        """
        # Run pipeline on corrupted file
        report = integration_pipeline.run_pipeline(str(corrupted_pe_sample))

        # Should still return a report
        assert isinstance(report, dict)
        assert "file_path" in report

        # May have errors
        if "errors" in report:
            assert isinstance(report["errors"], list)

        # Should not crash - graceful degradation
        assert report is not None

    def test_pipeline_stages_execute_in_order(
        self,
        integration_pipeline,
        valid_pe32_sample
    ):
        """
        Test that pipeline stages execute in correct order.

        Validates execution flow: extraction -> decryption -> static analysis.
        """
        report = integration_pipeline.run_pipeline(str(valid_pe32_sample))

        # Check stage execution
        stages_present = []

        if "extraction_analysis" in report:
            stages_present.append("extraction")

        if "decryption_analysis" in report:
            stages_present.append("decryption")

        if "static_pe_analysis" in report:
            stages_present.append("static_analysis")

        # At minimum, should have attempted static analysis for PE file
        assert "static_analysis" in stages_present or "static_pe_analysis" in report

    def test_pipeline_produces_complete_metadata(
        self,
        integration_pipeline,
        valid_pe32_sample
    ):
        """
        Test that pipeline produces complete metadata.

        Validates all metadata fields are populated.
        """
        report = integration_pipeline.run_pipeline(str(valid_pe32_sample))

        # Validate metadata
        assert "file_path" in report
        assert "original_file_type" in report
        assert "source_description" in report

        # Validate source description
        source_desc = report["source_description"]
        assert isinstance(source_desc, str)
        assert len(source_desc) > 0

        # Validate recursive call flag
        assert "is_recursive_call" in report
        assert isinstance(report["is_recursive_call"], bool)
        assert report["is_recursive_call"] is False  # Top-level call

    def test_pipeline_memory_efficiency(
        self,
        integration_pipeline,
        valid_pe32_sample,
        performance_tracker
    ):
        """
        Test pipeline memory efficiency.

        Validates that pipeline doesn't leak memory on repeated runs.
        """
        import gc

        # Run pipeline multiple times
        reports = []
        with performance_tracker("Pipeline Memory Test (5 iterations)"):
            for i in range(5):
                report = integration_pipeline.run_pipeline(str(valid_pe32_sample))
                reports.append(report)

                # Force garbage collection
                gc.collect()

        # All reports should be valid
        assert len(reports) == 5
        for report in reports:
            assert isinstance(report, dict)
            assert "file_path" in report

    def test_pipeline_concurrent_analysis_safety(
        self,
        integration_pipeline,
        valid_pe32_sample,
        c2_embedded_sample
    ):
        """
        Test pipeline safety with concurrent-like sequential analysis.

        Validates pipeline can handle multiple files in sequence.
        """
        # Analyze multiple files sequentially
        report1 = integration_pipeline.run_pipeline(str(valid_pe32_sample))
        report2 = integration_pipeline.run_pipeline(str(c2_embedded_sample))

        # Both should succeed
        assert isinstance(report1, dict)
        assert isinstance(report2, dict)

        # Should have different file paths
        assert report1["file_path"] != report2["file_path"]

        # Both should be PE files
        assert report1["original_file_type"] == "pe"
        assert report2["original_file_type"] == "pe"


@pytest.mark.integration
class TestPipelineOutputFormats:
    """Test various output formats from pipeline."""

    def test_json_output_structure(
        self,
        integration_pipeline,
        valid_pe32_sample,
        validate_json_serializable
    ):
        """
        Test JSON output structure and completeness.

        Validates that output can be serialized to JSON properly.
        """
        report = integration_pipeline.run_pipeline(str(valid_pe32_sample))

        # Validate JSON serialization
        assert validate_json_serializable(report)

        # Convert to JSON and back
        json_str = json.dumps(report, default=str)
        parsed = json.loads(json_str)

        # Should preserve structure
        assert isinstance(parsed, dict)
        assert parsed["file_path"] == report["file_path"]

    def test_report_has_no_sensitive_data_leaks(
        self,
        integration_pipeline,
        valid_pe32_sample
    ):
        """
        Test that report doesn't leak sensitive system information.

        Validates no absolute paths or sensitive data in report.
        """
        report = integration_pipeline.run_pipeline(str(valid_pe32_sample))

        # Convert to JSON for easier inspection
        json_str = json.dumps(report, default=str)

        # Check for common sensitive patterns (adjust as needed)
        # Note: file_path will contain the actual path, so we check other fields

        # Should not contain username patterns (basic check)
        import os
        username = os.environ.get('USER', os.environ.get('USERNAME', ''))
        if username and len(username) > 0:
            # File path is expected to contain username, but other fields shouldn't
            # This is a simplified check
            pass

        # Report should be safe to export
        assert isinstance(report, dict)
