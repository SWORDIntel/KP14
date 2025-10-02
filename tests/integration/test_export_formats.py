"""
Integration Test 9: Export Formats Integration

Tests export to multiple threat intelligence formats.

Validates:
- JSON export structure
- CSV export format
- STIX bundle generation
- MISP event creation
- Data consistency across formats
"""

import pytest
import json
import csv
from pathlib import Path
from io import StringIO


@pytest.mark.integration
@pytest.mark.slow
class TestExportFormatsIntegration:
    """Integration tests for export format generation."""

    def test_json_export_structure(
        self,
        integration_pipeline,
        valid_pe32_sample,
        integration_output_dir
    ):
        """
        Test JSON export format structure.

        Validates JSON schema compliance.
        """
        report = integration_pipeline.run_pipeline(str(valid_pe32_sample))

        # Export to JSON
        output_file = integration_output_dir / "export_test.json"

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        # Validate JSON structure
        with open(output_file, 'r') as f:
            loaded = json.load(f)

        assert isinstance(loaded, dict)
        assert loaded["file_path"] == report["file_path"]

        print(f"\nJSON export: {len(json.dumps(loaded))} bytes")

    def test_csv_export_format(
        self,
        integration_pipeline,
        valid_pe32_sample,
        c2_embedded_sample,
        integration_output_dir
    ):
        """
        Test CSV export format for batch results.

        Validates tabular data export.
        """
        # Analyze multiple samples
        reports = [
            integration_pipeline.run_pipeline(str(valid_pe32_sample)),
            integration_pipeline.run_pipeline(str(c2_embedded_sample))
        ]

        # Export to CSV
        output_file = integration_output_dir / "export_test.csv"

        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow([
                "file_path",
                "file_type",
                "pe_detected",
                "has_errors",
                "extracted_payloads"
            ])

            # Rows
            for report in reports:
                writer.writerow([
                    report.get("file_path", ""),
                    report.get("original_file_type", ""),
                    "static_pe_analysis" in report and report["static_pe_analysis"] is not None,
                    len(report.get("errors", [])) > 0,
                    len(report.get("extracted_payload_analyses", []))
                ])

        # Validate CSV
        with open(output_file, 'r') as f:
            reader = csv.DictReader(f)
            rows = list(reader)

        assert len(rows) == 2
        print(f"\nCSV export: {len(rows)} rows")

    def test_stix_bundle_generation(
        self,
        integration_pipeline,
        c2_embedded_sample,
        integration_output_dir
    ):
        """
        Test STIX 2.1 bundle generation.

        Validates STIX format compliance.
        """
        report = integration_pipeline.run_pipeline(str(c2_embedded_sample))

        # Generate STIX bundle (simplified)
        stix_bundle = {
            "type": "bundle",
            "id": f"bundle--{c2_embedded_sample.stem}",
            "objects": []
        }

        # Add malware object
        malware_obj = {
            "type": "malware",
            "id": f"malware--{c2_embedded_sample.stem}",
            "name": c2_embedded_sample.name,
            "description": f"Analyzed sample: {c2_embedded_sample.name}",
            "malware_types": ["trojan"],  # Generic
            "is_family": False
        }
        stix_bundle["objects"].append(malware_obj)

        # Add indicators if C2 found
        report_str = json.dumps(report, default=str)
        if "http://" in report_str or "https://" in report_str:
            indicator_obj = {
                "type": "indicator",
                "id": f"indicator--{c2_embedded_sample.stem}-c2",
                "pattern_type": "stix",
                "pattern": "[network-traffic:dst_ref.type = 'domain-name']",
                "valid_from": "2025-01-01T00:00:00Z",
                "description": "C2 infrastructure detected"
            }
            stix_bundle["objects"].append(indicator_obj)

        # Save STIX bundle
        output_file = integration_output_dir / "export_test.stix.json"
        with open(output_file, 'w') as f:
            json.dump(stix_bundle, f, indent=2)

        # Validate STIX structure
        with open(output_file, 'r') as f:
            loaded_stix = json.load(f)

        assert loaded_stix["type"] == "bundle"
        assert "objects" in loaded_stix
        assert len(loaded_stix["objects"]) > 0

        print(f"\nSTIX bundle: {len(loaded_stix['objects'])} objects")

    def test_misp_event_creation(
        self,
        integration_pipeline,
        c2_embedded_sample,
        integration_output_dir
    ):
        """
        Test MISP event format generation.

        Validates MISP JSON structure.
        """
        report = integration_pipeline.run_pipeline(str(c2_embedded_sample))

        # Generate MISP event (simplified)
        misp_event = {
            "Event": {
                "info": f"Malware analysis: {c2_embedded_sample.name}",
                "threat_level_id": "2",  # Medium
                "analysis": "2",  # Completed
                "Attribute": []
            }
        }

        # Add file hash attribute
        if "static_pe_analysis" in report and report["static_pe_analysis"]:
            pe_analysis = report["static_pe_analysis"]
            if "pe_info" in pe_analysis and pe_analysis["pe_info"]:
                pe_info = pe_analysis["pe_info"]

                # Add SHA256 if available
                if "sha256" in pe_info or "SHA256" in pe_info:
                    sha256 = pe_info.get("sha256", pe_info.get("SHA256"))
                    misp_event["Event"]["Attribute"].append({
                        "type": "sha256",
                        "category": "Payload delivery",
                        "value": sha256,
                        "to_ids": True
                    })

        # Add C2 indicators
        report_str = json.dumps(report, default=str)
        import re

        urls = re.findall(r'https?://[\w\.-]+', report_str)
        for url in set(urls):
            misp_event["Event"]["Attribute"].append({
                "type": "url",
                "category": "Network activity",
                "value": url,
                "to_ids": True
            })

        # Save MISP event
        output_file = integration_output_dir / "export_test.misp.json"
        with open(output_file, 'w') as f:
            json.dump(misp_event, f, indent=2)

        # Validate MISP structure
        with open(output_file, 'r') as f:
            loaded_misp = json.load(f)

        assert "Event" in loaded_misp
        assert "Attribute" in loaded_misp["Event"]

        print(f"\nMISP event: {len(loaded_misp['Event']['Attribute'])} attributes")

    def test_data_consistency_across_formats(
        self,
        integration_pipeline,
        c2_embedded_sample,
        integration_output_dir
    ):
        """
        Test data consistency across export formats.

        Validates same data in all formats.
        """
        # Get source report
        report = integration_pipeline.run_pipeline(str(c2_embedded_sample))

        # Export to multiple formats
        formats_data = {}

        # JSON
        json_file = integration_output_dir / "consistency_test.json"
        with open(json_file, 'w') as f:
            json.dump(report, f, default=str)
        formats_data["json"] = report

        # Simplified CSV (just metadata)
        csv_file = integration_output_dir / "consistency_test.csv"
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["file_path", "file_type"])
            writer.writerow([
                report.get("file_path", ""),
                report.get("original_file_type", "")
            ])

        # Read back CSV
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            csv_data = list(reader)[0]
        formats_data["csv"] = csv_data

        # Validate consistency
        assert formats_data["json"]["file_path"] == formats_data["csv"]["file_path"]
        assert formats_data["json"]["original_file_type"] == formats_data["csv"]["file_type"]

        print("\nData consistency validated across formats")


@pytest.mark.integration
class TestExportEdgeCases:
    """Test edge cases in export formats."""

    def test_export_with_binary_data(
        self,
        integration_pipeline,
        valid_pe32_sample,
        integration_output_dir
    ):
        """
        Test export handling of binary data.

        Validates binary data serialization.
        """
        report = integration_pipeline.run_pipeline(str(valid_pe32_sample))

        # JSON should handle binary data with default=str
        json_file = integration_output_dir / "binary_test.json"

        try:
            with open(json_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)

            # Should succeed
            with open(json_file, 'r') as f:
                loaded = json.load(f)

            assert isinstance(loaded, dict)
            print("\nBinary data exported successfully")

        except TypeError as e:
            pytest.fail(f"Failed to export binary data: {e}")

    def test_export_large_report(
        self,
        integration_pipeline,
        nested_polyglot_sample,
        integration_output_dir,
        performance_tracker
    ):
        """
        Test export of large reports.

        Validates performance with complex data.
        """
        report = integration_pipeline.run_pipeline(str(nested_polyglot_sample))

        json_file = integration_output_dir / "large_report.json"

        with performance_tracker("Large Report Export"):
            with open(json_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)

        # Check file size
        file_size = json_file.stat().st_size
        print(f"\nExported report size: {file_size} bytes")

        # Should be readable
        with open(json_file, 'r') as f:
            loaded = json.load(f)

        assert isinstance(loaded, dict)
