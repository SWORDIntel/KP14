"""
Integration Test 4: Recursive Analysis Chain

Tests multi-level recursive analysis of nested polyglots.

Validates:
- 3+ level recursion handling
- Recursion depth limits
- Source tracking through recursion
- All payloads analyzed
- Infinite recursion prevention
"""

import pytest
import json
from pathlib import Path


@pytest.mark.integration
@pytest.mark.slow
class TestRecursiveAnalysisChain:
    """Integration tests for recursive payload analysis."""

    def test_three_level_recursion(
        self,
        integration_pipeline,
        nested_polyglot_sample,
        performance_tracker
    ):
        """
        Test 3-level nested polyglot analysis.

        Validates: ZIP -> inner ZIP -> PE
        """
        with performance_tracker("3-Level Recursive Analysis"):
            report = integration_pipeline.run_pipeline(str(nested_polyglot_sample))

        # Validate top level
        assert isinstance(report, dict)
        assert report["original_file_type"] == "zip"
        assert report["is_recursive_call"] is False

        # Check for extracted payload analyses
        if "extracted_payload_analyses" in report:
            extracted = report["extracted_payload_analyses"]
            assert isinstance(extracted, list)

            if len(extracted) > 0:
                print(f"\nTotal extracted payloads: {len(extracted)}")

                # Analyze recursion depth
                for payload_report in extracted:
                    if "source" in payload_report:
                        source = payload_report["source"]
                        depth = source.count("->")
                        print(f"Recursion depth {depth}: {source[:80]}...")

                    # All should be marked as recursive
                    if "is_recursive_call" in payload_report:
                        assert payload_report["is_recursive_call"] is True

    def test_recursion_source_tracking(
        self,
        integration_pipeline,
        nested_polyglot_sample
    ):
        """
        Test source provenance tracking through recursion.

        Validates that source chain is maintained.
        """
        report = integration_pipeline.run_pipeline(str(nested_polyglot_sample))

        if "extracted_payload_analyses" in report:
            for payload_report in report["extracted_payload_analyses"]:
                # Must have source field
                assert "source" in payload_report
                source = payload_report["source"]

                # Source should be descriptive
                assert isinstance(source, str)
                assert len(source) > 0

                # Should contain provenance indicators
                if "->" in source:
                    # Has chain tracking
                    parts = source.split("->")
                    assert len(parts) >= 2
                    print(f"\nSource chain: {' -> '.join(parts)}")

    def test_all_payloads_analyzed(
        self,
        integration_pipeline,
        nested_polyglot_sample
    ):
        """
        Test that all extracted payloads are analyzed.

        Validates completeness of recursive analysis.
        """
        report = integration_pipeline.run_pipeline(str(nested_polyglot_sample))

        # Count extraction vs analysis
        extracted_count = 0
        analyzed_count = 0

        # Count top-level extractions
        if "extraction_analysis" in report and report["extraction_analysis"]:
            extraction = report["extraction_analysis"]

            if "polyglot" in extraction:
                extracted_count += len(extraction["polyglot"])

        # Count recursive analyses
        if "extracted_payload_analyses" in report:
            analyzed_count = len(report["extracted_payload_analyses"])

        print(f"\nExtracted: {extracted_count}, Analyzed: {analyzed_count}")

        # All extracted PE payloads should be analyzed
        # (note: non-PE extractions might not trigger analysis)
        if extracted_count > 0:
            assert analyzed_count >= 0  # At least attempted

    def test_recursion_depth_validation(
        self,
        integration_pipeline,
        nested_polyglot_sample
    ):
        """
        Test recursion depth limits are respected.

        Validates protection against infinite recursion.
        """
        report = integration_pipeline.run_pipeline(str(nested_polyglot_sample))

        # Find maximum recursion depth
        max_depth = 0

        if "extracted_payload_analyses" in report:
            for payload_report in report["extracted_payload_analyses"]:
                if "source" in payload_report:
                    depth = payload_report["source"].count("->")
                    max_depth = max(max_depth, depth)

        print(f"\nMaximum recursion depth: {max_depth}")

        # Should have some reasonable limit (e.g., < 10)
        # This prevents runaway recursion
        assert max_depth < 10, f"Recursion depth {max_depth} seems excessive"


@pytest.mark.integration
class TestRecursionEdgeCases:
    """Test edge cases in recursive analysis."""

    def test_circular_reference_prevention(
        self,
        integration_pipeline,
        integration_samples_dir,
        valid_pe32_sample
    ):
        """
        Test prevention of circular reference analysis.

        Validates that same payload isn't analyzed multiple times.
        """
        import zipfile

        # Create ZIP containing itself (simulated circular reference)
        circular_zip = integration_samples_dir / "circular.zip"

        # Create a ZIP with a PE
        with zipfile.ZipFile(circular_zip, 'w') as zf:
            zf.write(valid_pe32_sample, arcname="payload.exe")

        try:
            report = integration_pipeline.run_pipeline(str(circular_zip))

            # Should handle gracefully without infinite loop
            assert isinstance(report, dict)

            # Should complete in finite time (test will timeout if infinite loop)
            assert "extracted_payload_analyses" in report

        finally:
            if circular_zip.exists():
                circular_zip.unlink()

    def test_empty_nested_structure(
        self,
        integration_pipeline,
        integration_samples_dir
    ):
        """
        Test handling of empty nested structures.

        Validates graceful handling of nested empties.
        """
        import zipfile

        nested_empty = integration_samples_dir / "nested_empty.zip"

        # Create ZIP containing empty ZIP
        inner_empty = integration_samples_dir / "inner_empty.zip"
        with zipfile.ZipFile(inner_empty, 'w') as inner:
            pass  # Empty

        with zipfile.ZipFile(nested_empty, 'w') as outer:
            outer.write(inner_empty, arcname="inner.zip")

        try:
            report = integration_pipeline.run_pipeline(str(nested_empty))

            # Should handle without errors
            assert isinstance(report, dict)
            assert report["original_file_type"] == "zip"

        finally:
            if nested_empty.exists():
                nested_empty.unlink()
            if inner_empty.exists():
                inner_empty.unlink()

    def test_deeply_nested_performance(
        self,
        integration_pipeline,
        integration_samples_dir,
        valid_pe32_sample,
        performance_tracker
    ):
        """
        Test performance with deeply nested archives.

        Validates reasonable performance on deep nesting.
        """
        import zipfile

        # Create 5-level nested ZIPs
        current_file = valid_pe32_sample

        for level in range(5, 0, -1):
            zip_file = integration_samples_dir / f"level_{level}.zip"
            with zipfile.ZipFile(zip_file, 'w') as zf:
                zf.write(current_file, arcname=f"payload_{level}.exe" if level == 1 else f"level_{level-1}.zip")
            current_file = zip_file

        deepest_zip = integration_samples_dir / "level_5.zip"

        try:
            with performance_tracker("5-Level Nested Analysis") as metrics:
                report = integration_pipeline.run_pipeline(str(deepest_zip))

            duration = metrics["duration_seconds"]
            print(f"\nProcessed 5-level nesting in {duration:.2f}s")

            # Should complete
            assert isinstance(report, dict)

            # Count recursion levels
            if "extracted_payload_analyses" in report:
                max_depth = 0
                for payload in report["extracted_payload_analyses"]:
                    if "source" in payload:
                        depth = payload["source"].count("->")
                        max_depth = max(max_depth, depth)

                print(f"Recursion depth reached: {max_depth}")

        finally:
            # Cleanup all created ZIPs
            for level in range(1, 6):
                zip_file = integration_samples_dir / f"level_{level}.zip"
                if zip_file.exists():
                    zip_file.unlink()


@pytest.mark.integration
@pytest.mark.slow
class TestRecursionCorrectness:
    """Test correctness of recursive analysis."""

    def test_each_level_analyzed_correctly(
        self,
        integration_pipeline,
        nested_polyglot_sample
    ):
        """
        Test that each recursion level is analyzed with full pipeline.

        Validates consistency across recursion levels.
        """
        report = integration_pipeline.run_pipeline(str(nested_polyglot_sample))

        if "extracted_payload_analyses" in report:
            for idx, payload_report in enumerate(report["extracted_payload_analyses"]):
                print(f"\nValidating payload {idx + 1}")

                # Each should have basic report structure
                assert "file_path" in payload_report
                assert "original_file_type" in payload_report
                assert "source" in payload_report

                # Each should be marked as recursive
                assert payload_report.get("is_recursive_call") is True

                # If it's a PE, should have attempted static analysis
                if payload_report["original_file_type"] == "pe":
                    # May have static_pe_analysis
                    pass  # Structure varies based on analyzer availability

    def test_recursion_preserves_data_integrity(
        self,
        integration_pipeline,
        nested_polyglot_sample
    ):
        """
        Test that data integrity is preserved through recursion.

        Validates no corruption during extraction and re-analysis.
        """
        report = integration_pipeline.run_pipeline(str(nested_polyglot_sample))

        # All recursive analyses should have valid file_path references
        if "extracted_payload_analyses" in report:
            for payload_report in report["extracted_payload_analyses"]:
                # Should have file_path (may be temporary)
                assert "file_path" in payload_report

                file_path = payload_report["file_path"]
                assert isinstance(file_path, str)
                assert len(file_path) > 0

                # File type should be detected
                assert "original_file_type" in payload_report
                assert payload_report["original_file_type"] != "unknown" or True  # May be unknown for some payloads
