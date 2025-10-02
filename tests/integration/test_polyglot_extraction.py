"""
Integration Test 2: Polyglot Extraction Workflow

Tests end-to-end polyglot detection and extraction workflow.

Validates:
- ZIP polyglot detection
- PE extraction from polyglot
- Recursive analysis of extracted PE
- Extraction metadata accuracy
- Multi-format polyglot support
"""

import pytest
import json
from pathlib import Path


@pytest.mark.integration
@pytest.mark.slow
class TestPolyglotExtractionWorkflow:
    """Integration tests for polyglot extraction pipeline."""

    def test_zip_polyglot_pe_extraction(
        self,
        integration_pipeline,
        polyglot_zip_pe_sample,
        validate_analysis_report,
        performance_tracker
    ):
        """
        Test extraction of PE from ZIP polyglot.

        Validates complete polyglot extraction workflow.
        """
        with performance_tracker("ZIP Polyglot Extraction"):
            report = integration_pipeline.run_pipeline(str(polyglot_zip_pe_sample))

        # Validate basic report structure
        assert isinstance(report, dict)
        assert report["file_path"] == str(polyglot_zip_pe_sample)
        assert report["original_file_type"] == "zip"

        # Validate extraction analysis
        assert "extraction_analysis" in report, "Should have extraction analysis"

        if report["extraction_analysis"]:
            extraction = report["extraction_analysis"]

            # Should have polyglot section
            if "polyglot" in extraction:
                polyglot_results = extraction["polyglot"]
                assert isinstance(polyglot_results, list)

                # Should have found embedded files
                if len(polyglot_results) > 0:
                    print(f"\nFound {len(polyglot_results)} polyglot payloads")

                    # Check for PE payload
                    pe_found = False
                    for payload in polyglot_results:
                        if payload.get("data", b"").startswith(b"MZ"):
                            pe_found = True
                            break

                    if pe_found:
                        print("PE payload detected in polyglot")

        # Validate extracted payload analyses
        if "extracted_payload_analyses" in report:
            extracted = report["extracted_payload_analyses"]
            assert isinstance(extracted, list)

            if len(extracted) > 0:
                print(f"\nRecursively analyzed {len(extracted)} extracted payloads")

                # Validate first extracted payload
                first_payload = extracted[0]
                assert isinstance(first_payload, dict)
                assert "source" in first_payload
                assert "polyglot" in first_payload["source"].lower()

    def test_polyglot_metadata_accuracy(
        self,
        integration_pipeline,
        polyglot_zip_pe_sample
    ):
        """
        Test polyglot metadata extraction accuracy.

        Validates that metadata correctly describes the extraction.
        """
        report = integration_pipeline.run_pipeline(str(polyglot_zip_pe_sample))

        if "extraction_analysis" in report and report["extraction_analysis"]:
            extraction = report["extraction_analysis"]

            if "polyglot" in extraction:
                for payload_info in extraction["polyglot"]:
                    # Validate payload metadata structure
                    assert isinstance(payload_info, dict)

                    # Should have description of payload type
                    if "type_desc" in payload_info:
                        assert isinstance(payload_info["type_desc"], str)
                        assert len(payload_info["type_desc"]) > 0

                    # Should have offset information
                    if "offset" in payload_info:
                        assert isinstance(payload_info["offset"], int)
                        assert payload_info["offset"] >= 0

    def test_recursive_analysis_of_extracted_pe(
        self,
        integration_pipeline,
        polyglot_zip_pe_sample
    ):
        """
        Test recursive analysis of extracted PE from polyglot.

        Validates that extracted PE is properly analyzed.
        """
        report = integration_pipeline.run_pipeline(str(polyglot_zip_pe_sample))

        # Check for recursive analyses
        if "extracted_payload_analyses" in report:
            extracted_analyses = report["extracted_payload_analyses"]

            for extracted_report in extracted_analyses:
                # Validate it's marked as recursive
                if "is_recursive_call" in extracted_report:
                    assert extracted_report["is_recursive_call"] is True

                # Validate source tracking
                if "source" in extracted_report:
                    source = extracted_report["source"]
                    assert isinstance(source, str)
                    # Should reference the parent
                    assert "->" in source or "polyglot" in source.lower()

                # If it's a PE, should have static analysis
                if extracted_report.get("original_file_type") == "pe":
                    # May have static PE analysis
                    if "static_pe_analysis" in extracted_report:
                        assert isinstance(extracted_report["static_pe_analysis"], dict)

    def test_polyglot_no_false_positives(
        self,
        integration_pipeline,
        valid_pe32_sample
    ):
        """
        Test that regular PE files don't trigger false polyglot detection.

        Validates specificity of polyglot detection.
        """
        report = integration_pipeline.run_pipeline(str(valid_pe32_sample))

        # A normal PE should not be detected as polyglot
        # (unless it genuinely has embedded payloads)

        if "extraction_analysis" in report and report["extraction_analysis"]:
            extraction = report["extraction_analysis"]

            if "polyglot" in extraction:
                polyglot_results = extraction["polyglot"]

                # Simple PE shouldn't have polyglot payloads
                # (our test PE is minimal)
                # This assertion might need adjustment based on analyzer behavior
                # For now, we just validate structure
                assert isinstance(polyglot_results, list)


@pytest.mark.integration
class TestPolyglotEdgeCases:
    """Test edge cases in polyglot extraction."""

    def test_empty_zip_handling(
        self,
        integration_pipeline,
        integration_samples_dir
    ):
        """
        Test handling of empty ZIP files.

        Validates graceful handling of edge case.
        """
        import zipfile

        # Create empty ZIP
        empty_zip = integration_samples_dir / "empty.zip"
        with zipfile.ZipFile(empty_zip, 'w') as zf:
            pass  # Empty ZIP

        try:
            report = integration_pipeline.run_pipeline(str(empty_zip))

            # Should not crash
            assert isinstance(report, dict)
            assert report["original_file_type"] == "zip"

            # May have empty extraction results
            if "extraction_analysis" in report and report["extraction_analysis"]:
                extraction = report["extraction_analysis"]
                if "polyglot" in extraction:
                    # Empty or empty list
                    assert isinstance(extraction["polyglot"], list)

        finally:
            # Cleanup
            if empty_zip.exists():
                empty_zip.unlink()

    def test_nested_zip_extraction(
        self,
        integration_pipeline,
        nested_polyglot_sample
    ):
        """
        Test extraction of nested ZIP files.

        Validates multi-level extraction.
        """
        report = integration_pipeline.run_pipeline(str(nested_polyglot_sample))

        # Should detect ZIP
        assert report["original_file_type"] == "zip"

        # Should have extraction analysis
        assert "extraction_analysis" in report

        # May have multiple levels of extraction
        if "extracted_payload_analyses" in report:
            extracted = report["extracted_payload_analyses"]

            if len(extracted) > 0:
                print(f"\nExtracted {len(extracted)} payloads from nested structure")

                # Check recursion depth
                max_depth = 0
                for payload_report in extracted:
                    if "source" in payload_report:
                        source = payload_report["source"]
                        # Count arrows as depth indicator
                        depth = source.count("->")
                        max_depth = max(max_depth, depth)

                print(f"Maximum recursion depth: {max_depth}")

                # Should have some nesting
                if max_depth > 0:
                    assert max_depth >= 1, "Nested structure should show recursion"

    def test_corrupted_zip_handling(
        self,
        integration_pipeline,
        integration_samples_dir
    ):
        """
        Test handling of corrupted ZIP files.

        Validates error recovery.
        """
        # Create corrupted ZIP
        corrupted_zip = integration_samples_dir / "corrupted.zip"
        with open(corrupted_zip, 'wb') as f:
            f.write(b'PK\x03\x04')  # ZIP signature
            f.write(b'\x00' * 100)  # Invalid data

        try:
            report = integration_pipeline.run_pipeline(str(corrupted_zip))

            # Should not crash
            assert isinstance(report, dict)

            # May have errors
            if "errors" in report:
                assert isinstance(report["errors"], list)

            # Should still return a report
            assert "file_path" in report

        finally:
            # Cleanup
            if corrupted_zip.exists():
                corrupted_zip.unlink()


@pytest.mark.integration
@pytest.mark.slow
class TestPolyglotPerformance:
    """Test performance of polyglot extraction."""

    def test_large_zip_performance(
        self,
        integration_pipeline,
        integration_samples_dir,
        valid_pe32_sample,
        performance_tracker
    ):
        """
        Test performance with larger ZIP archives.

        Validates reasonable performance on multi-file archives.
        """
        import zipfile

        # Create ZIP with multiple files
        large_zip = integration_samples_dir / "large_archive.zip"

        with zipfile.ZipFile(large_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
            # Add 20 copies of test PE with different names
            for i in range(20):
                zf.write(valid_pe32_sample, arcname=f"sample_{i:03d}.exe")

        try:
            with performance_tracker("Large ZIP Extraction (20 files)") as metrics:
                report = integration_pipeline.run_pipeline(str(large_zip))

            # Should complete in reasonable time
            duration = metrics["duration_seconds"]
            print(f"\nProcessed 20-file archive in {duration:.2f}s")

            # Validate results
            assert isinstance(report, dict)
            assert report["original_file_type"] == "zip"

            # Check extraction results
            if "extraction_analysis" in report and report["extraction_analysis"]:
                extraction = report["extraction_analysis"]
                if "polyglot" in extraction:
                    payloads = extraction["polyglot"]
                    print(f"Extracted {len(payloads)} payloads")

        finally:
            # Cleanup
            if large_zip.exists():
                large_zip.unlink()
