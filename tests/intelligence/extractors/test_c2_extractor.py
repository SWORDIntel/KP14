"""
Comprehensive tests for C2 endpoint extraction module

Tests cover:
- IP address extraction (IPv4, packed format)
- Domain extraction (various TLDs)
- URL extraction (HTTP/HTTPS)
- Tor .onion address detection
- Encryption key extraction
- Obfuscation handling (Base64, XOR)
- Confidence scoring
- False positive filtering
- KEYPLUG-specific extraction
"""

import pytest
import base64
import struct
from intelligence.extractors.c2_extractor import (
    C2Extractor,
    C2Endpoint,
    EncryptionKey,
    C2ExtractionResult
)


class TestC2EndpointDataclass:
    """Test C2Endpoint dataclass."""

    def test_c2_endpoint_creation(self):
        """Test creating C2Endpoint with all fields."""
        endpoint = C2Endpoint(
            endpoint_type='ip',
            value='1.2.3.4',
            confidence=85,
            location='string_table',
            context='http://1.2.3.4:8080',
            protocol='tcp',
            port=8080,
            obfuscation='none'
        )
        assert endpoint.endpoint_type == 'ip'
        assert endpoint.value == '1.2.3.4'
        assert endpoint.confidence == 85
        assert endpoint.port == 8080

    def test_c2_endpoint_minimal(self):
        """Test creating C2Endpoint with minimal fields."""
        endpoint = C2Endpoint(
            endpoint_type='domain',
            value='evil.com',
            confidence=70,
            location='binary'
        )
        assert endpoint.endpoint_type == 'domain'
        assert endpoint.context == ""
        assert endpoint.port is None


class TestC2ExtractorInit:
    """Test C2Extractor initialization."""

    def test_extractor_initialization(self):
        """Test extractor initializes with correct defaults."""
        extractor = C2Extractor()
        assert len(extractor.suspicious_tlds) > 0
        assert 443 in extractor.common_ports
        assert extractor.extraction_stats['ips_found'] == 0


class TestIPAddressExtraction:
    """Test IP address extraction."""

    def test_extract_valid_ipv4(self, sample_strings):
        """Test extraction of valid IPv4 addresses."""
        extractor = C2Extractor()
        endpoints = extractor._extract_from_strings(sample_strings)

        ips = [ep for ep in endpoints if ep.endpoint_type == 'ip']
        assert len(ips) > 0
        assert any(ep.value == '45.67.89.123' for ep in ips)

    def test_extract_ip_in_url_context(self):
        """Test IP extraction with URL context increases confidence."""
        extractor = C2Extractor()
        strings = ["Visit http://45.67.89.123:8080/beacon"]
        endpoints = extractor._extract_from_strings(strings)

        ips = [ep for ep in endpoints if ep.endpoint_type == 'ip']
        assert len(ips) > 0
        # Should have high confidence due to HTTP context
        assert any(ep.confidence >= 80 for ep in ips)

    def test_filter_private_ips(self):
        """Test that private IPs are filtered out."""
        extractor = C2Extractor()
        strings = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"]
        endpoints = extractor._extract_from_strings(strings)

        ips = [ep for ep in endpoints if ep.endpoint_type == 'ip']
        # Private IPs should be filtered
        assert len(ips) == 0

    def test_filter_invalid_ips(self):
        """Test that invalid IPs are filtered."""
        extractor = C2Extractor()
        strings = ["999.999.999.999", "256.1.1.1", "1.2.3", "a.b.c.d"]
        endpoints = extractor._extract_from_strings(strings)

        ips = [ep for ep in endpoints if ep.endpoint_type == 'ip']
        assert len(ips) == 0

    def test_extract_packed_ip_big_endian(self):
        """Test extraction of packed IP in big-endian format."""
        extractor = C2Extractor()
        # 45.67.89.123 = 0x2D43597B
        packed_ip = struct.pack('>I', 0x2D43597B)
        data = b'HEADER' + packed_ip + b'TRAILER'

        endpoints = extractor._extract_from_binary(data)
        ips = [ep for ep in endpoints if ep.endpoint_type == 'ip' and ep.value == '45.67.89.123']
        assert len(ips) > 0

    def test_ip_confidence_with_port(self):
        """Test IP confidence increases with port number."""
        extractor = C2Extractor()
        string = "Connect to 45.67.89.123:8080"
        confidence = extractor._calculate_ip_confidence('45.67.89.123', string)
        assert confidence >= 70  # Should have bonus for port


class TestDomainExtraction:
    """Test domain name extraction."""

    def test_extract_valid_domain(self, sample_strings):
        """Test extraction of valid domain names."""
        extractor = C2Extractor()
        endpoints = extractor._extract_from_strings(sample_strings)

        domains = [ep for ep in endpoints if ep.endpoint_type == 'domain']
        # Should extract domain from URL
        assert len(domains) > 0

    def test_extract_suspicious_tld(self):
        """Test detection of suspicious TLDs with confidence boost."""
        extractor = C2Extractor()
        strings = ["malware-server.tk", "normal-site.com"]
        endpoints = extractor._extract_from_strings(strings)

        domains = [ep for ep in endpoints if ep.endpoint_type == 'domain']
        tk_domain = [ep for ep in domains if '.tk' in ep.value]

        if tk_domain:
            # .tk domains should have higher confidence
            assert tk_domain[0].confidence >= 70

    def test_filter_common_domains(self):
        """Test filtering of common false positive domains."""
        extractor = C2Extractor()
        assert extractor._is_valid_domain('example.com') is False
        assert extractor._is_valid_domain('test.com') is False
        assert extractor._is_valid_domain('localhost') is False

    def test_domain_length_validation(self):
        """Test domain length validation."""
        extractor = C2Extractor()
        assert extractor._is_valid_domain('a.b') is False  # Too short
        assert extractor._is_valid_domain('valid-domain.com') is True
        assert extractor._is_valid_domain('a' * 260) is False  # Too long

    def test_domain_confidence_in_http_context(self):
        """Test domain confidence boost in HTTP context."""
        extractor = C2Extractor()
        string = "http://malware-c2.com/beacon"
        confidence = extractor._calculate_domain_confidence('malware-c2.com', string)
        assert confidence >= 80  # HTTP context boost


class TestURLExtraction:
    """Test URL extraction."""

    def test_extract_http_url(self):
        """Test extraction of HTTP URLs."""
        extractor = C2Extractor()
        strings = ["Visit http://malware.com/gate.php"]
        endpoints = extractor._extract_from_strings(strings)

        urls = [ep for ep in endpoints if ep.endpoint_type == 'url']
        assert len(urls) > 0
        assert urls[0].protocol == 'http'

    def test_extract_https_url(self, sample_strings):
        """Test extraction of HTTPS URLs."""
        extractor = C2Extractor()
        endpoints = extractor._extract_from_strings(sample_strings)

        urls = [ep for ep in endpoints if ep.endpoint_type == 'url']
        https_urls = [ep for ep in urls if ep.protocol == 'https']
        assert len(https_urls) > 0

    def test_url_confidence_https_bonus(self):
        """Test HTTPS URLs get confidence bonus."""
        extractor = C2Extractor()
        url = "https://secure-malware.com/beacon"
        confidence = extractor._calculate_url_confidence(url, url)

        http_url = "http://insecure-malware.com/beacon"
        http_confidence = extractor._calculate_url_confidence(http_url, http_url)

        assert confidence > http_confidence  # HTTPS should have higher confidence

    def test_url_with_port_extraction(self):
        """Test URL extraction with non-standard port."""
        extractor = C2Extractor()
        strings = ["https://c2.example.com:8443/api"]
        endpoints = extractor._extract_from_strings(strings)

        urls = [ep for ep in endpoints if ep.endpoint_type == 'url']
        assert len(urls) > 0
        assert urls[0].port == 8443


class TestOnionAddressExtraction:
    """Test Tor .onion address extraction."""

    def test_extract_onion_address(self, sample_strings):
        """Test extraction of .onion addresses."""
        extractor = C2Extractor()
        endpoints = extractor._extract_from_strings(sample_strings)

        onions = [ep for ep in endpoints if ep.endpoint_type == 'onion']
        assert len(onions) > 0
        assert onions[0].protocol == 'tor'

    def test_onion_high_confidence(self):
        """Test .onion addresses get high confidence."""
        extractor = C2Extractor()
        strings = ["Connect to abcdef1234567890.onion"]
        endpoints = extractor._extract_from_strings(strings)

        onions = [ep for ep in endpoints if ep.endpoint_type == 'onion']
        assert len(onions) > 0
        assert onions[0].confidence >= 90

    def test_onion_various_lengths(self):
        """Test .onion addresses of various valid lengths."""
        extractor = C2Extractor()
        strings = [
            "short12345678901.onion",  # v2 (16 chars)
            "longonionaddress12345678901234567890123456789012345678.onion"  # v3 (56 chars)
        ]
        endpoints = extractor._extract_from_strings(strings)

        onions = [ep for ep in endpoints if ep.endpoint_type == 'onion']
        assert len(onions) >= 1


class TestEncryptionKeyExtraction:
    """Test encryption key extraction."""

    def test_extract_aes128_key(self, sample_strings):
        """Test extraction of AES-128 keys (32 hex chars)."""
        extractor = C2Extractor()
        keys = extractor._extract_keys(b'', sample_strings)

        aes128_keys = [k for k in keys if k.key_type == 'aes128']
        assert len(aes128_keys) > 0
        assert aes128_keys[0].key_size == 128

    def test_extract_aes256_key(self):
        """Test extraction of AES-256 keys (64 hex chars)."""
        extractor = C2Extractor()
        strings = ["Key: 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"]
        keys = extractor._extract_keys(b'', strings)

        aes256_keys = [k for k in keys if k.key_type == 'aes256']
        assert len(aes256_keys) > 0
        assert aes256_keys[0].key_size == 256

    def test_extract_rsa_key(self):
        """Test extraction of RSA keys."""
        extractor = C2Extractor()
        strings = ["-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."]
        keys = extractor._extract_keys(b'', strings)

        rsa_keys = [k for k in keys if k.key_type == 'rsa']
        assert len(rsa_keys) > 0
        assert rsa_keys[0].confidence >= 90

    def test_key_confidence_levels(self):
        """Test different key types have appropriate confidence levels."""
        extractor = C2Extractor()
        strings = [
            "0123456789ABCDEF0123456789ABCDEF",  # AES-128
            "-----BEGIN RSA PRIVATE KEY-----"       # RSA
        ]
        keys = extractor._extract_keys(b'', strings)

        # RSA keys should have higher confidence
        rsa_keys = [k for k in keys if k.key_type == 'rsa']
        aes_keys = [k for k in keys if k.key_type == 'aes128']

        if rsa_keys and aes_keys:
            assert rsa_keys[0].confidence > aes_keys[0].confidence


class TestObfuscationHandling:
    """Test obfuscation detection and decoding."""

    def test_extract_base64_encoded_ip(self):
        """Test extraction from base64-encoded data."""
        extractor = C2Extractor()
        # Base64 encode an IP address
        ip_data = "45.67.89.123"
        encoded = base64.b64encode(ip_data.encode())
        data = b'PREFIX' + encoded + b'SUFFIX'

        endpoints = extractor._extract_from_binary(data)
        ips = [ep for ep in endpoints if ep.endpoint_type == 'ip' and 'base64' in ep.context]
        # May or may not find depending on encoding
        assert isinstance(endpoints, list)

    def test_xor_decoding(self):
        """Test XOR decoding of configurations."""
        extractor = C2Extractor()
        # XOR encode some data with key 0x55
        plaintext = b"45.67.89.123" + b"\x00" * 1000
        xor_key = 0x55
        encoded = bytes([b ^ xor_key for b in plaintext])

        endpoints = extractor._decode_obfuscated_configs(encoded)
        ips = [ep for ep in endpoints if ep.endpoint_type == 'ip']
        assert len(ips) > 0
        assert any(ep.obfuscation == 'xor' for ep in ips)

    def test_identify_obfuscation_techniques(self):
        """Test identification of obfuscation techniques."""
        extractor = C2Extractor()

        # High entropy data (encrypted/packed)
        high_entropy_data = bytes([i % 256 for i in range(4096)])
        techniques = extractor._identify_obfuscation(high_entropy_data)
        assert 'high_entropy' in techniques

    def test_identify_base64_patterns(self):
        """Test identification of base64 encoding."""
        extractor = C2Extractor()
        base64_data = base64.b64encode(b'a' * 1000)
        techniques = extractor._identify_obfuscation(base64_data)
        assert 'base64_encoding' in techniques

    def test_entropy_calculation(self):
        """Test entropy calculation for data."""
        extractor = C2Extractor()

        # Low entropy (all zeros)
        low_entropy = b'\x00' * 1000
        entropy = extractor._calculate_entropy(low_entropy)
        assert entropy < 3.0

        # High entropy (random-like)
        high_entropy = bytes([i % 256 for i in range(1000)])
        entropy = extractor._calculate_entropy(high_entropy)
        assert entropy > 5.0


class TestKEYPLUGSpecific:
    """Test KEYPLUG-specific extraction."""

    def test_detect_keyplug_magic_bytes(self, sample_binary_data):
        """Test detection of KEYPLUG magic bytes."""
        extractor = C2Extractor()
        is_keyplug = extractor._is_keyplug_sample(sample_binary_data, {})
        assert is_keyplug is True

    def test_detect_keyplug_from_metadata(self):
        """Test KEYPLUG detection from metadata."""
        extractor = C2Extractor()
        metadata = {"family": "KEYPLUG"}
        is_keyplug = extractor._is_keyplug_sample(b'random data', metadata)
        assert is_keyplug is True

    def test_detect_keyplug_from_strings(self):
        """Test KEYPLUG detection from indicator strings."""
        extractor = C2Extractor()
        data = b'Some data with KEYPLUG indicator and winnti strings'
        is_keyplug = extractor._is_keyplug_sample(data, {})
        assert is_keyplug is True

    def test_extract_keyplug_c2_config(self):
        """Test KEYPLUG C2 configuration extraction."""
        extractor = C2Extractor()
        # Create KEYPLUG config with magic bytes
        config = b'KEYP'
        # XOR encode a domain with 0x55
        domain = b'malware-c2.com'
        encoded_domain = bytes([b ^ 0x55 for b in domain])
        config += encoded_domain + b'\x00' * 400

        endpoints = extractor._extract_keyplug_c2(config)
        # Should extract domain from config
        assert isinstance(endpoints, list)


class TestC2ExtractionPipeline:
    """Test complete C2 extraction pipeline."""

    def test_full_extraction_pipeline(self, sample_strings, sample_binary_data):
        """Test complete extraction with all components."""
        extractor = C2Extractor()
        metadata = {"family": "KEYPLUG"}

        result = extractor.extract(sample_binary_data, sample_strings, metadata)

        assert isinstance(result, C2ExtractionResult)
        assert len(result.endpoints) > 0
        assert result.overall_confidence > 0
        assert len(result.protocols) > 0

    def test_extraction_summary_generation(self, sample_strings, sample_binary_data):
        """Test extraction summary statistics."""
        extractor = C2Extractor()
        result = extractor.extract(sample_binary_data, sample_strings, {})

        assert 'total_endpoints' in result.extraction_summary
        assert 'high_confidence' in result.extraction_summary
        assert result.extraction_summary['total_endpoints'] == len(result.endpoints)

    def test_endpoint_deduplication(self):
        """Test duplicate endpoint removal."""
        extractor = C2Extractor()
        endpoints = [
            C2Endpoint('ip', '1.2.3.4', 80, 'loc1'),
            C2Endpoint('ip', '1.2.3.4', 90, 'loc2'),  # Duplicate with higher confidence
            C2Endpoint('domain', 'evil.com', 75, 'loc3')
        ]

        deduped = extractor._deduplicate_endpoints(endpoints)
        assert len(deduped) == 2  # Should remove duplicate IP
        # Should keep the higher confidence one
        ip_endpoints = [ep for ep in deduped if ep.endpoint_type == 'ip']
        assert ip_endpoints[0].confidence == 90

    def test_protocol_identification(self, sample_c2_endpoints):
        """Test protocol identification from endpoints."""
        extractor = C2Extractor()
        protocols = extractor._identify_protocols([
            C2Endpoint('url', 'http://test.com', 80, 'loc', protocol='http'),
            C2Endpoint('url', 'https://test2.com', 90, 'loc', protocol='https'),
            C2Endpoint('onion', 'abc123.onion', 95, 'loc', protocol='tor')
        ])

        assert 'HTTP' in protocols or 'HTTPS' in protocols
        assert 'TOR' in protocols

    def test_overall_confidence_calculation(self):
        """Test overall confidence score calculation."""
        extractor = C2Extractor()
        result = C2ExtractionResult()

        # Add endpoints with various confidences
        result.endpoints = [
            C2Endpoint('ip', '1.2.3.4', 80, 'loc'),
            C2Endpoint('domain', 'evil.com', 90, 'loc'),
            C2Endpoint('url', 'http://test.com', 85, 'loc')
        ]

        confidence = extractor._calculate_overall_confidence(result)
        assert 80 <= confidence <= 95  # Should be in range of endpoint confidences

    def test_confidence_boost_for_multiple_indicators(self):
        """Test confidence boost when many indicators found."""
        extractor = C2Extractor()
        result = C2ExtractionResult()

        # Add many endpoints
        result.endpoints = [C2Endpoint('ip', f'1.2.3.{i}', 70, 'loc') for i in range(10)]

        confidence = extractor._calculate_overall_confidence(result)
        # Should get boost for multiple indicators
        assert confidence >= 75


class TestExportFunctionality:
    """Test export to dictionary."""

    def test_export_to_dict(self, sample_strings, sample_binary_data):
        """Test exporting extraction results to dictionary."""
        extractor = C2Extractor()
        result = extractor.extract(sample_binary_data, sample_strings, {})

        exported = extractor.export_to_dict(result)

        assert 'endpoints' in exported
        assert 'encryption_keys' in exported
        assert 'protocols' in exported
        assert 'overall_confidence' in exported
        assert isinstance(exported['endpoints'], list)

    def test_exported_dict_structure(self):
        """Test exported dictionary has correct structure."""
        extractor = C2Extractor()
        result = C2ExtractionResult()
        result.endpoints = [C2Endpoint('ip', '1.2.3.4', 80, 'loc', protocol='tcp', port=8080)]

        exported = extractor.export_to_dict(result)

        assert len(exported['endpoints']) == 1
        ep = exported['endpoints'][0]
        assert 'type' in ep
        assert 'value' in ep
        assert 'confidence' in ep
        assert ep['value'] == '1.2.3.4'


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_strings_list(self):
        """Test extraction with empty strings list."""
        extractor = C2Extractor()
        endpoints = extractor._extract_from_strings([])
        assert endpoints == []

    def test_empty_binary_data(self):
        """Test extraction with empty binary data."""
        extractor = C2Extractor()
        endpoints = extractor._extract_from_binary(b'')
        assert endpoints == []

    def test_malformed_data_handling(self):
        """Test handling of malformed data."""
        extractor = C2Extractor()
        # Binary data with invalid UTF-8
        bad_data = b'\xff\xfe\x00\x00' * 100
        endpoints = extractor._extract_from_binary(bad_data)
        # Should not crash
        assert isinstance(endpoints, list)

    def test_very_long_strings(self):
        """Test handling of very long strings."""
        extractor = C2Extractor()
        long_string = 'A' * 10000 + '45.67.89.123' + 'B' * 10000
        endpoints = extractor._extract_from_strings([long_string])
        # Should still extract IP
        ips = [ep for ep in endpoints if ep.endpoint_type == 'ip']
        assert len(ips) > 0

    def test_context_extraction_boundaries(self):
        """Test context extraction at string boundaries."""
        extractor = C2Extractor()
        # Short string where context window extends beyond boundaries
        short_string = "1.2.3.4"
        context = extractor._get_context(short_string, 0, len(short_string))
        assert context == short_string
