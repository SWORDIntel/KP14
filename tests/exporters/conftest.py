"""
Shared fixtures for exporter module tests
"""

import pytest
from typing import Dict, Any


@pytest.fixture
def sample_analysis_result():
    """Complete analysis result for export testing."""
    return {
        "file_path": "/path/to/malware.exe",
        "file_name": "malware.exe",
        "analysis_timestamp": "2024-01-01T00:00:00Z",
        "static_pe_analysis": {
            "pe_info": {
                "hashes": {
                    "md5": "d41d8cd98f00b204e9800998ecf8427e",
                    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                },
                "file_size": 102400,
                "compile_time": "2023-01-15T00:00:00Z",
                "machine": "AMD64",
                "imphash": "a1b2c3d4e5f6",
                "sections": [
                    {"name": ".text", "entropy": 6.2, "size": 40960},
                    {"name": ".data", "entropy": 4.8, "size": 20480}
                ],
                "imports": ["kernel32.dll", "ws2_32.dll"],
                "exports": []
            }
        },
        "threat_assessment": {
            "level": "malware",
            "threat_score": 85,
            "severity": "high",
            "confidence": 90
        },
        "intelligence": {
            "malware_family": "KEYPLUG",
            "apt_group": "APT41",
            "c2_endpoints": [
                {
                    "endpoint_type": "domain",
                    "value": "malicious-c2.com",
                    "confidence": 90,
                    "protocol": "https"
                },
                {
                    "endpoint_type": "ip",
                    "value": "45.67.89.123",
                    "confidence": 85,
                    "protocol": "tcp"
                }
            ],
            "ttps": [
                {
                    "technique_id": "T1071.001",
                    "tactic": "Command and Control",
                    "technique_name": "Application Layer Protocol: Web Protocols"
                },
                {
                    "technique_id": "T1547.001",
                    "tactic": "Persistence",
                    "technique_name": "Registry Run Keys"
                }
            ],
            "iocs": [
                {"type": "domain", "value": "malicious-c2.com"},
                {"type": "ip", "value": "45.67.89.123"},
                {"type": "md5", "value": "d41d8cd98f00b204e9800998ecf8427e"}
            ]
        },
        "strings": ["malware", "backdoor", "KEYPLUG"],
        "behaviors": ["persistence", "c2_communication", "credential_theft"]
    }


@pytest.fixture
def batch_analysis_results(sample_analysis_result):
    """Multiple analysis results for batch export testing."""
    results = []
    for i in range(3):
        result = sample_analysis_result.copy()
        result['file_name'] = f'malware_{i}.exe'
        result['file_path'] = f'/path/to/malware_{i}.exe'
        results.append(result)
    return results
