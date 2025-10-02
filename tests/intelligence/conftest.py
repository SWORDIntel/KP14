"""
Shared fixtures for intelligence module tests
"""

import pytest
from typing import Dict, List, Any


@pytest.fixture
def sample_strings():
    """Sample extracted strings from malware."""
    return [
        "http://malicious-c2.example.com:8080/beacon",
        "192.168.1.100",
        "45.67.89.123",
        "evil-domain.tk",
        "abcdef1234567890.onion",
        "mimikatz",
        "KEYPLUG",
        "winnti",
        "password",
        "credential_dump",
        "CreateRemoteThread",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "powershell.exe -enc",
        "admin@evil.com",
        "0123456789ABCDEF0123456789ABCDEF",  # AES-128 key
    ]


@pytest.fixture
def sample_binary_data():
    """Sample binary data for testing extraction."""
    # Include some packed IPs and encoded data
    data = b"KEYP" + b"\x00" * 100  # KEYPLUG magic
    data += b"http://c2server.com" + b"\x00" * 50
    # Packed IP: 45.67.89.123
    data += b"\x2d\x43\x59\x7b"
    data += b"some random binary data here"
    return data


@pytest.fixture
def sample_pe_info():
    """Sample PE file metadata."""
    return {
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "imphash": "a1b2c3d4e5f6",
        "file_size": 102400,
        "machine": "AMD64",
        "compile_time": "2023-01-15",
        "sections": [
            {"name": ".text", "entropy": 6.2},
            {"name": ".data", "entropy": 4.8}
        ]
    }


@pytest.fixture
def sample_c2_endpoints():
    """Sample C2 endpoint extraction results."""
    return [
        {
            "endpoint_type": "ip",
            "value": "45.67.89.123",
            "confidence": 85,
            "location": "string_table",
            "protocol": "tcp",
            "port": 8080
        },
        {
            "endpoint_type": "domain",
            "value": "evil-c2.tk",
            "confidence": 90,
            "location": "string_table",
            "protocol": "https"
        },
        {
            "endpoint_type": "url",
            "value": "https://malware-beacon.com/gate.php",
            "confidence": 95,
            "location": "string_table",
            "protocol": "https"
        },
        {
            "endpoint_type": "onion",
            "value": "abcdef1234567890.onion",
            "confidence": 95,
            "location": "string_table",
            "protocol": "tor"
        }
    ]


@pytest.fixture
def sample_behaviors():
    """Sample behavioral indicators."""
    return [
        "backdoor",
        "persistence",
        "c2_communication",
        "credential_dumping",
        "obfuscation",
        "lateral_movement"
    ]


@pytest.fixture
def sample_analysis_data(sample_strings, sample_c2_endpoints, sample_pe_info, sample_behaviors):
    """Complete sample analysis data."""
    return {
        "strings": sample_strings,
        "c2_endpoints": sample_c2_endpoints,
        "pe_info": sample_pe_info,
        "behaviors": sample_behaviors,
        "metadata": {
            "file_path": "/path/to/malware.exe",
            "family": "KEYPLUG",
            "timestamp": "2024-01-01T00:00:00Z"
        }
    }


@pytest.fixture
def keyplug_sample_data():
    """KEYPLUG-specific test data."""
    return {
        "strings": ["KEYPLUG", "winnti", "barium", "backdoor"],
        "behaviors": ["backdoor", "persistence", "c2_communication"],
        "c2_endpoints": [
            {"endpoint_type": "domain", "value": "apt41-c2.com", "confidence": 90, "protocol": "https"}
        ],
        "pe_info": {"md5": "keyplug_sample_hash"},
        "metadata": {"family": "KEYPLUG"}
    }


@pytest.fixture
def threat_assessment_result():
    """Sample threat assessment result."""
    return {
        "threat_score": 85,
        "severity": "high",
        "family": "KEYPLUG",
        "family_confidence": 90,
        "mitre_techniques": [
            {
                "technique_id": "T1071.001",
                "tactic": "Command and Control",
                "technique_name": "Application Layer Protocol: Web Protocols",
                "confidence": 90,
                "evidence": ["HTTPS beacon detected"]
            }
        ],
        "capabilities": [
            {
                "capability": "Persistence",
                "category": "persistence",
                "severity": "high",
                "description": "Registry run key modification",
                "indicators": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
            }
        ],
        "target_profile": {
            "platform": "windows",
            "architecture": "AMD64",
            "privileges_required": "admin"
        },
        "attribution": {
            "apt_group": "APT41",
            "confidence": 85,
            "indicators": ["KEYPLUG family detection"]
        },
        "risk_factors": ["Critical capabilities detected", "APT attribution: APT41"]
    }
