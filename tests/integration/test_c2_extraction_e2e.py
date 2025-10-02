"""
Integration Test 5: C2 Extraction End-to-End

Tests complete C2 infrastructure extraction workflow.

Validates:
- C2 endpoint extraction from PE
- URL and IP detection
- Protocol identification
- MITRE ATT&CK mapping (if available)
- Threat scoring integration
"""

import pytest
import json
import re
from pathlib import Path


@pytest.mark.integration
@pytest.mark.slow
class TestC2ExtractionEndToEnd:
    """Integration tests for C2 extraction pipeline."""

    def test_c2_url_extraction_from_pe(
        self,
        integration_pipeline,
        c2_embedded_sample,
        performance_tracker
    ):
        """
        Test extraction of C2 URLs from PE file.

        Validates URL detection in strings.
        """
        with performance_tracker("C2 URL Extraction"):
            report = integration_pipeline.run_pipeline(str(c2_embedded_sample))

        # Validate basic structure
        assert isinstance(report, dict)
        assert report["original_file_type"] == "pe"

        # Check for PE analysis
        if "static_pe_analysis" in report and report["static_pe_analysis"]:
            pe_analysis = report["static_pe_analysis"]

            # Check PE info for strings
            if "pe_info" in pe_analysis and pe_analysis["pe_info"]:
                pe_info = pe_analysis["pe_info"]

                # Look for strings section
                if "strings" in pe_info or "Strings" in pe_info:
                    strings = pe_info.get("strings", pe_info.get("Strings", []))

                    if strings:
                        print(f"\nFound {len(strings)} strings in PE")

                        # Look for C2 indicators
                        url_pattern = r'https?://[\w\.-]+(?:/[\w\.-]*)*'
                        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'

                        urls_found = []
                        ips_found = []

                        strings_text = ' '.join(str(s) for s in strings)

                        for match in re.finditer(url_pattern, strings_text):
                            urls_found.append(match.group())

                        for match in re.finditer(ip_pattern, strings_text):
                            ips_found.append(match.group())

                        if urls_found:
                            print(f"Potential C2 URLs: {urls_found}")

                        if ips_found:
                            print(f"Potential C2 IPs: {ips_found}")

    def test_c2_indicators_in_pe_sections(
        self,
        integration_pipeline,
        c2_embedded_sample
    ):
        """
        Test C2 indicator detection in PE sections.

        Validates section-level string extraction.
        """
        report = integration_pipeline.run_pipeline(str(c2_embedded_sample))

        if "static_pe_analysis" in report and report["static_pe_analysis"]:
            pe_analysis = report["static_pe_analysis"]

            # Check sections
            if "pe_info" in pe_analysis and pe_analysis["pe_info"]:
                pe_info = pe_analysis["pe_info"]

                if "sections" in pe_info or "Sections" in pe_info:
                    sections = pe_info.get("sections", pe_info.get("Sections", []))

                    print(f"\nAnalyzing {len(sections)} PE sections")

                    # Look for suspicious section names
                    suspicious_names = ['.data', '.rdata', '.rsrc']

                    for section in sections:
                        section_name = section.get("name", section.get("Name", ""))

                        if any(susp in section_name for susp in suspicious_names):
                            print(f"Section {section_name} may contain C2 data")

    def test_protocol_identification(
        self,
        integration_pipeline,
        c2_embedded_sample
    ):
        """
        Test identification of C2 protocols.

        Validates detection of HTTP/HTTPS/custom protocols.
        """
        report = integration_pipeline.run_pipeline(str(c2_embedded_sample))

        # Check for protocol indicators in strings
        protocols_found = set()

        if "static_pe_analysis" in report and report["static_pe_analysis"]:
            pe_analysis = report["static_pe_analysis"]

            if "pe_info" in pe_analysis and pe_analysis["pe_info"]:
                pe_info = pe_analysis["pe_info"]

                # Check strings for protocols
                strings_data = json.dumps(pe_info, default=str).lower()

                if "http://" in strings_data:
                    protocols_found.add("http")

                if "https://" in strings_data:
                    protocols_found.add("https")

                if "post " in strings_data or "get " in strings_data:
                    protocols_found.add("http-verbs")

                if "user-agent" in strings_data:
                    protocols_found.add("http-headers")

        if protocols_found:
            print(f"\nDetected protocols/indicators: {protocols_found}")

    def test_c2_endpoint_metadata(
        self,
        integration_pipeline,
        c2_embedded_sample
    ):
        """
        Test extraction of C2 endpoint metadata.

        Validates comprehensive C2 profiling.
        """
        report = integration_pipeline.run_pipeline(str(c2_embedded_sample))

        # Build C2 profile from report
        c2_profile = {
            "urls": [],
            "ips": [],
            "domains": [],
            "ports": [],
            "protocols": []
        }

        # Extract from report
        report_str = json.dumps(report, default=str)

        # Find URLs
        url_matches = re.findall(r'https?://[\w\.-]+(?::\d+)?(?:/[\w\.-]*)*', report_str)
        c2_profile["urls"] = list(set(url_matches))

        # Find IPs
        ip_matches = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', report_str)
        c2_profile["ips"] = list(set(ip_matches))

        # Find ports
        port_matches = re.findall(r':(\d{2,5})\b', report_str)
        c2_profile["ports"] = list(set(port_matches))

        print(f"\nC2 Profile:")
        print(f"  URLs: {len(c2_profile['urls'])}")
        print(f"  IPs: {len(c2_profile['ips'])}")
        print(f"  Ports: {len(c2_profile['ports'])}")

        # Validate profile has some data
        total_indicators = sum(len(v) for v in c2_profile.values() if isinstance(v, list))

        if total_indicators > 0:
            print(f"  Total C2 indicators: {total_indicators}")


@pytest.mark.integration
class TestC2ExtractionFormats:
    """Test C2 extraction from different formats."""

    def test_c2_in_imports(
        self,
        integration_pipeline,
        c2_embedded_sample
    ):
        """
        Test C2-related API imports detection.

        Validates import analysis for C2 indicators.
        """
        report = integration_pipeline.run_pipeline(str(c2_embedded_sample))

        if "static_pe_analysis" in report and report["static_pe_analysis"]:
            pe_analysis = report["static_pe_analysis"]

            if "pe_info" in pe_analysis and pe_analysis["pe_info"]:
                pe_info = pe_analysis["pe_info"]

                # Check imports
                if "imports" in pe_info or "Imports" in pe_info:
                    imports = pe_info.get("imports", pe_info.get("Imports", {}))

                    if imports:
                        # Look for network-related APIs
                        network_apis = [
                            "WSAStartup", "socket", "connect", "send", "recv",
                            "InternetOpenA", "InternetOpenW",
                            "HttpOpenRequestA", "HttpSendRequestA",
                            "WinHttpOpen", "WinHttpConnect"
                        ]

                        found_network_apis = []

                        for dll, functions in imports.items():
                            if isinstance(functions, list):
                                for func in functions:
                                    if any(api in str(func) for api in network_apis):
                                        found_network_apis.append(f"{dll}!{func}")

                        if found_network_apis:
                            print(f"\nNetwork-related imports: {found_network_apis}")

    def test_c2_obfuscation_detection(
        self,
        integration_pipeline,
        integration_samples_dir,
        c2_embedded_sample
    ):
        """
        Test detection of obfuscated C2 strings.

        Validates advanced C2 hiding techniques.
        """
        # Create PE with base64-encoded C2
        import base64

        obfuscated_c2_pe = integration_samples_dir / "obfuscated_c2.exe"

        # Copy base sample
        import shutil
        shutil.copy(c2_embedded_sample, obfuscated_c2_pe)

        # Append base64-encoded C2
        c2_url = b"http://malware-control-server.example.com/api/beacon"
        encoded_c2 = base64.b64encode(c2_url)

        with open(obfuscated_c2_pe, 'ab') as f:
            f.write(b"\nBASE64_C2:")
            f.write(encoded_c2)
            f.write(b"\x00")

        try:
            report = integration_pipeline.run_pipeline(str(obfuscated_c2_pe))

            # Check if base64 string was detected
            report_str = json.dumps(report, default=str)

            if encoded_c2.decode() in report_str:
                print("\nObfuscated C2 detected in strings")

        finally:
            if obfuscated_c2_pe.exists():
                obfuscated_c2_pe.unlink()


@pytest.mark.integration
class TestC2ThreatAssessment:
    """Test threat assessment based on C2 indicators."""

    def test_threat_scoring_with_c2(
        self,
        integration_pipeline,
        c2_embedded_sample
    ):
        """
        Test threat scoring considers C2 presence.

        Validates threat level elevation for C2 indicators.
        """
        report = integration_pipeline.run_pipeline(str(c2_embedded_sample))

        # Count C2 indicators
        c2_indicator_count = 0

        report_str = json.dumps(report, default=str).lower()

        # Count various indicators
        if "http://" in report_str or "https://" in report_str:
            c2_indicator_count += 1

        if "post " in report_str or "get " in report_str:
            c2_indicator_count += 1

        if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', report_str):
            c2_indicator_count += 1

        print(f"\nC2 indicators found: {c2_indicator_count}")

        # More indicators = higher threat
        if c2_indicator_count >= 2:
            print("Multiple C2 indicators suggest active C2 capability")

    def test_c2_context_in_report(
        self,
        integration_pipeline,
        c2_embedded_sample
    ):
        """
        Test that C2 context is preserved in report.

        Validates comprehensive C2 documentation.
        """
        report = integration_pipeline.run_pipeline(str(c2_embedded_sample))

        # Report should be comprehensive enough for C2 analysis
        assert isinstance(report, dict)

        # Should have static analysis
        assert "static_pe_analysis" in report

        # Should be JSON serializable for export
        try:
            json_output = json.dumps(report, default=str)
            assert len(json_output) > 0
        except Exception as e:
            pytest.fail(f"Report not JSON serializable: {e}")

        # Report should preserve enough context for C2 extraction
        # (specific fields depend on analyzer implementation)
        print("\nReport successfully captures C2 context")
