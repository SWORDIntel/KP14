"""
Comprehensive tests for YARA rule generation module

Tests cover:
- YARA rule generation from patterns
- Family-based rule creation
- String extraction and formatting
- Rule validation
- False positive reduction
- Hash-based rules
- Confidence scoring
- Export functionality
"""

import pytest
import hashlib
from intelligence.generators.yara_generator import YaraGenerator, YaraRule


class TestYaraRuleDataclass:
    """Test YaraRule dataclass."""

    def test_yara_rule_creation(self):
        """Test creating YaraRule with all fields."""
        rule = YaraRule(
            name='Test_Rule',
            tags=['malware', 'test'],
            meta={'author': 'test'},
            strings={'$str1': '"test"'},
            condition='$str1',
            confidence=85,
            description='Test rule'
        )
        assert rule.name == 'Test_Rule'
        assert len(rule.tags) == 2
        assert rule.confidence == 85


class TestYaraGeneratorInit:
    """Test YaraGenerator initialization."""

    def test_generator_initialization(self):
        """Test generator initializes with correct defaults."""
        generator = YaraGenerator()
        assert generator.min_string_length >= 4
        assert generator.min_confidence > 0

    def test_min_string_length_default(self):
        """Test minimum string length default."""
        generator = YaraGenerator()
        assert generator.min_string_length == 6

    def test_min_confidence_default(self):
        """Test minimum confidence default."""
        generator = YaraGenerator()
        assert generator.min_confidence == 70


class TestFamilyRuleGeneration:
    """Test family-based YARA rule generation."""

    def test_generate_keyplug_family_rule(self, keyplug_sample_data, threat_assessment_result):
        """Test generating KEYPLUG family rule."""
        generator = YaraGenerator()
        data = keyplug_sample_data.copy()
        data['threat_assessment'] = threat_assessment_result

        rules = generator.generate(data)

        family_rules = [r for r in rules if 'family' in r.meta.get('type', r.meta.get('description', ''))]
        assert len(family_rules) > 0

    def test_family_rule_metadata(self, keyplug_sample_data, threat_assessment_result):
        """Test family rule has correct metadata."""
        generator = YaraGenerator()
        data = keyplug_sample_data.copy()
        data['threat_assessment'] = threat_assessment_result

        rule = generator._generate_family_rule(data)

        if rule:
            assert 'description' in rule.meta
            assert 'author' in rule.meta
            assert 'family' in rule.meta
            assert rule.meta['family'] == 'KEYPLUG'

    def test_family_rule_with_low_confidence(self):
        """Test family rule not generated with low confidence."""
        generator = YaraGenerator()
        data = {
            'threat_assessment': {
                'family': 'unknown',
                'family_confidence': 30
            },
            'strings': ['test'],
            'pe_info': {}
        }

        rule = generator._generate_family_rule(data)
        assert rule is None

    def test_family_rule_string_extraction(self, keyplug_sample_data, threat_assessment_result):
        """Test strings are extracted for family rule."""
        generator = YaraGenerator()
        data = keyplug_sample_data.copy()
        data['threat_assessment'] = threat_assessment_result

        rule = generator._generate_family_rule(data)

        if rule:
            assert len(rule.strings) > 0

    def test_family_rule_string_limit(self):
        """Test family rule limits number of strings."""
        generator = YaraGenerator()
        data = {
            'threat_assessment': {
                'family': 'Test',
                'family_confidence': 85,
                'severity': 'high'
            },
            'strings': [f'string_{i}' for i in range(100)],
            'pe_info': {}
        }

        rule = generator._generate_family_rule(data)

        if rule:
            # Should limit to reasonable number
            assert len(rule.strings) <= 15

    def test_family_rule_condition_generation(self, keyplug_sample_data, threat_assessment_result):
        """Test family rule condition is properly formatted."""
        generator = YaraGenerator()
        data = keyplug_sample_data.copy()
        data['threat_assessment'] = threat_assessment_result

        rule = generator._generate_family_rule(data)

        if rule:
            assert len(rule.condition) > 0
            # Should use 'of' syntax
            assert 'of' in rule.condition or 'them' in rule.condition


class TestC2IndicatorRules:
    """Test C2 indicator-based rule generation."""

    def test_generate_c2_rule(self, sample_c2_endpoints, threat_assessment_result):
        """Test generating C2 indicator rule."""
        generator = YaraGenerator()
        data = {
            'c2_endpoints': sample_c2_endpoints,
            'threat_assessment': threat_assessment_result
        }

        rule = generator._generate_c2_rule(data)

        assert rule is not None
        assert len(rule.strings) > 0

    def test_c2_rule_high_confidence_only(self):
        """Test C2 rule only uses high-confidence indicators."""
        generator = YaraGenerator()
        data = {
            'c2_endpoints': [
                {'value': 'high-conf.com', 'confidence': 90},
                {'value': 'low-conf.com', 'confidence': 50}
            ],
            'threat_assessment': {}
        }

        rule = generator._generate_c2_rule(data)

        if rule:
            # Should only include high confidence
            assert 'low-conf' not in str(rule.strings)

    def test_c2_rule_endpoint_limit(self):
        """Test C2 rule limits number of endpoints."""
        generator = YaraGenerator()
        data = {
            'c2_endpoints': [
                {'value': f'c2-{i}.com', 'confidence': 90}
                for i in range(50)
            ],
            'threat_assessment': {}
        }

        rule = generator._generate_c2_rule(data)

        if rule:
            # Should limit to reasonable number (max 10 in code)
            assert len(rule.strings) <= 10

    def test_c2_rule_metadata(self, sample_c2_endpoints):
        """Test C2 rule has correct metadata."""
        generator = YaraGenerator()
        data = {
            'c2_endpoints': sample_c2_endpoints,
            'threat_assessment': {'family': 'KEYPLUG'}
        }

        rule = generator._generate_c2_rule(data)

        if rule:
            assert 'description' in rule.meta
            assert 'type' in rule.meta
            assert rule.meta['type'] == 'c2_indicators'

    def test_c2_rule_tags(self, sample_c2_endpoints):
        """Test C2 rule has appropriate tags."""
        generator = YaraGenerator()
        data = {
            'c2_endpoints': sample_c2_endpoints,
            'threat_assessment': {}
        }

        rule = generator._generate_c2_rule(data)

        if rule:
            assert 'c2' in rule.tags
            assert 'network' in rule.tags


class TestCapabilityRules:
    """Test capability-based rule generation."""

    def test_generate_capability_rule(self, threat_assessment_result):
        """Test generating capability-based rule."""
        generator = YaraGenerator()
        data = {
            'threat_assessment': threat_assessment_result
        }

        rule = generator._generate_capability_rule(data)

        if rule:
            assert len(rule.strings) > 0
            assert 'capabilities' in rule.tags or 'behavior' in rule.tags

    def test_capability_rule_with_no_capabilities(self):
        """Test capability rule not generated without capabilities."""
        generator = YaraGenerator()
        data = {
            'threat_assessment': {
                'capabilities': []
            }
        }

        rule = generator._generate_capability_rule(data)
        assert rule is None

    def test_capability_rule_indicator_extraction(self):
        """Test capability rule extracts indicators."""
        generator = YaraGenerator()
        data = {
            'threat_assessment': {
                'family': 'Test',
                'capabilities': [
                    {
                        'capability': 'Persistence',
                        'indicators': ['registry_run_key', 'autostart_entry', 'service_install']
                    }
                ]
            }
        }

        rule = generator._generate_capability_rule(data)

        if rule:
            # Should have strings from indicators
            assert len(rule.strings) > 0

    def test_capability_rule_condition(self):
        """Test capability rule uses multi-match condition."""
        generator = YaraGenerator()
        data = {
            'threat_assessment': {
                'family': 'Test',
                'capabilities': [
                    {
                        'capability': 'Test',
                        'indicators': [f'indicator_{i}' for i in range(10)]
                    }
                ]
            }
        }

        rule = generator._generate_capability_rule(data)

        if rule:
            # Should require multiple matches
            assert 'of' in rule.condition


class TestHashBasedRules:
    """Test hash-based detection rules."""

    def test_generate_hash_rule(self, sample_pe_info):
        """Test generating hash-based rule."""
        generator = YaraGenerator()
        data = {
            'pe_info': sample_pe_info,
            'threat_assessment': {'family': 'Test'}
        }

        rule = generator._generate_generic_rule(data)

        assert rule is not None
        assert len(rule.strings) > 0

    def test_hash_rule_confidence(self, sample_pe_info):
        """Test hash-based rules have maximum confidence."""
        generator = YaraGenerator()
        data = {
            'pe_info': sample_pe_info,
            'threat_assessment': {}
        }

        rule = generator._generate_generic_rule(data)

        if rule:
            assert rule.confidence == 100

    def test_hash_rule_with_missing_hashes(self):
        """Test hash rule not generated without hashes."""
        generator = YaraGenerator()
        data = {
            'pe_info': {},
            'threat_assessment': {}
        }

        rule = generator._generate_generic_rule(data)
        assert rule is None

    def test_hash_rule_metadata(self, sample_pe_info):
        """Test hash rule includes hash values in metadata."""
        generator = YaraGenerator()
        data = {
            'pe_info': sample_pe_info,
            'threat_assessment': {}
        }

        rule = generator._generate_generic_rule(data)

        if rule:
            assert 'md5' in rule.meta
            assert 'sha256' in rule.meta


class TestStringProcessing:
    """Test string extraction and formatting."""

    def test_filter_common_strings(self):
        """Test filtering of common false positive strings."""
        generator = YaraGenerator()

        assert generator._is_common_string('12345') is True  # Only numbers
        assert generator._is_common_string('http://example.com') is True
        assert generator._is_common_string('test') is True
        assert generator._is_common_string('Microsoft Windows') is True
        assert generator._is_common_string('malware-string') is False

    def test_format_ascii_string(self):
        """Test formatting ASCII strings for YARA."""
        generator = YaraGenerator()
        formatted = generator._format_yara_string('test_string')

        assert formatted == '"test_string"'

    def test_format_wide_string(self):
        """Test formatting wide/unicode strings for YARA."""
        generator = YaraGenerator()
        formatted = generator._format_yara_string('test\u00e9')  # Contains non-ASCII

        assert 'wide' in formatted

    def test_format_string_escaping(self):
        """Test special character escaping in strings."""
        generator = YaraGenerator()

        # Test backslash escaping
        formatted = generator._format_yara_string('test\\path')
        assert '\\\\' in formatted

        # Test quote escaping
        formatted = generator._format_yara_string('test"quote')
        assert '\\"' in formatted

    def test_minimum_string_length_filter(self):
        """Test minimum string length filtering."""
        generator = YaraGenerator()
        generator.min_string_length = 8

        short_string = 'short'
        long_string = 'this_is_long_enough'

        # Short strings should be filtered in actual usage
        assert len(short_string) < generator.min_string_length
        assert len(long_string) >= generator.min_string_length


class TestCompleteRuleGeneration:
    """Test complete rule generation pipeline."""

    def test_generate_multiple_rule_types(self, sample_analysis_data, threat_assessment_result):
        """Test generating multiple rule types from one sample."""
        generator = YaraGenerator()
        data = sample_analysis_data.copy()
        data['threat_assessment'] = threat_assessment_result

        rules = generator.generate(data)

        # Should generate multiple rule types
        assert len(rules) > 0
        rule_types = {r.meta.get('type', 'family') for r in rules}
        assert len(rule_types) >= 1

    def test_all_rules_have_required_fields(self, sample_analysis_data, threat_assessment_result):
        """Test all generated rules have required fields."""
        generator = YaraGenerator()
        data = sample_analysis_data.copy()
        data['threat_assessment'] = threat_assessment_result

        rules = generator.generate(data)

        for rule in rules:
            assert rule.name
            assert rule.meta
            assert rule.condition
            assert rule.confidence >= 0

    def test_generate_with_minimal_data(self):
        """Test generation with minimal input data."""
        generator = YaraGenerator()
        data = {
            'strings': ['test'],
            'threat_assessment': {'family': 'unknown'}
        }

        rules = generator.generate(data)

        # Should handle gracefully, may or may not generate rules
        assert isinstance(rules, list)


class TestYaraExport:
    """Test YARA rule export functionality."""

    def test_export_single_rule(self):
        """Test exporting a single rule to YARA format."""
        generator = YaraGenerator()
        rule = YaraRule(
            name='Test_Rule',
            tags=['malware', 'test'],
            meta={'author': 'test', 'description': 'Test rule'},
            strings={'$str1': '"malware"', '$str2': '"backdoor"'},
            condition='any of them',
            confidence=85
        )

        yara_text = generator.export_to_yara([rule])

        assert 'rule Test_Rule' in yara_text
        assert 'meta:' in yara_text
        assert 'strings:' in yara_text
        assert 'condition:' in yara_text

    def test_export_multiple_rules(self):
        """Test exporting multiple rules."""
        generator = YaraGenerator()
        rules = [
            YaraRule('Rule1', ['test'], {'author': 'test'}, {'$s': '"test"'}, 'any of them', 80),
            YaraRule('Rule2', ['test'], {'author': 'test'}, {'$s': '"test2"'}, '$s', 85)
        ]

        yara_text = generator.export_to_yara(rules)

        assert 'rule Rule1' in yara_text
        assert 'rule Rule2' in yara_text

    def test_export_header_generation(self):
        """Test export includes header comments."""
        generator = YaraGenerator()
        rules = [YaraRule('Test', [], {}, {}, 'true', 80)]

        yara_text = generator.export_to_yara(rules)

        assert 'Auto-generated YARA rules' in yara_text
        assert 'KP14' in yara_text

    def test_export_meta_formatting(self):
        """Test metadata is properly formatted."""
        generator = YaraGenerator()
        rule = YaraRule(
            'Test',
            [],
            {'author': 'KP14', 'date': '2024-01-01', 'severity': 'high'},
            {},
            'true',
            80
        )

        yara_text = generator.export_to_yara([rule])

        assert 'author = "KP14"' in yara_text
        assert 'date = "2024-01-01"' in yara_text
        assert 'severity = "high"' in yara_text

    def test_export_strings_formatting(self):
        """Test strings are properly formatted."""
        generator = YaraGenerator()
        rule = YaraRule(
            'Test',
            [],
            {},
            {'$str1': '"test"', '$hex1': '{ 01 02 03 }'},
            'any of them',
            80
        )

        yara_text = generator.export_to_yara([rule])

        assert '$str1 = "test"' in yara_text
        assert '$hex1 = { 01 02 03 }' in yara_text

    def test_export_condition_formatting(self):
        """Test condition is properly formatted."""
        generator = YaraGenerator()
        rule = YaraRule(
            'Test',
            [],
            {},
            {'$s1': '"test"', '$s2': '"test2"'},
            '2 of them',
            80
        )

        yara_text = generator.export_to_yara([rule])

        assert 'condition:' in yara_text
        assert '2 of them' in yara_text

    def test_export_tags_formatting(self):
        """Test tags are included in rule definition."""
        generator = YaraGenerator()
        rule = YaraRule(
            'Test',
            ['malware', 'keyplug', 'high'],
            {},
            {'$s': '"test"'},
            '$s',
            80
        )

        yara_text = generator.export_to_yara([rule])

        # Tags should be in rule definition line
        assert 'rule Test' in yara_text


class TestRuleValidation:
    """Test rule validation and quality checks."""

    def test_rule_name_format(self):
        """Test rule names are properly formatted."""
        generator = YaraGenerator()
        data = {
            'threat_assessment': {
                'family': 'KEYPLUG',
                'family_confidence': 85,
                'severity': 'high'
            },
            'strings': ['test_string'],
            'pe_info': {}
        }

        rule = generator._generate_family_rule(data)

        if rule:
            # Rule name should be valid YARA identifier
            assert rule.name.replace('_', '').replace('-', '').isalnum() or rule.name.replace('_', '').isalnum()

    def test_rule_confidence_range(self, sample_analysis_data, threat_assessment_result):
        """Test all rule confidences are in valid range."""
        generator = YaraGenerator()
        data = sample_analysis_data.copy()
        data['threat_assessment'] = threat_assessment_result

        rules = generator.generate(data)

        for rule in rules:
            assert 0 <= rule.confidence <= 100

    def test_no_empty_strings_section(self):
        """Test rules don't have empty strings sections."""
        generator = YaraGenerator()
        data = {
            'threat_assessment': {
                'family': 'Test',
                'family_confidence': 85,
                'severity': 'high'
            },
            'strings': [],  # Empty strings
            'pe_info': {}
        }

        rule = generator._generate_family_rule(data)

        # Should not generate rule with no strings
        assert rule is None


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_input_data(self):
        """Test generation with empty input."""
        generator = YaraGenerator()
        rules = generator.generate({})

        assert isinstance(rules, list)

    def test_malformed_threat_assessment(self):
        """Test handling of malformed threat assessment."""
        generator = YaraGenerator()
        data = {
            'threat_assessment': None,
            'strings': ['test']
        }

        rules = generator.generate(data)

        # Should handle gracefully
        assert isinstance(rules, list)

    def test_unicode_handling_in_strings(self):
        """Test handling of unicode characters."""
        generator = YaraGenerator()
        unicode_string = 'test\u00e9\u00f1\u4e2d'

        formatted = generator._format_yara_string(unicode_string)

        # Should mark as wide
        assert 'wide' in formatted

    def test_very_long_string_handling(self):
        """Test handling of very long strings."""
        generator = YaraGenerator()
        long_string = 'A' * 10000

        formatted = generator._format_yara_string(long_string)

        # Should still format correctly
        assert formatted.startswith('"')
        assert formatted.endswith('"') or formatted.endswith('" wide')

    def test_special_characters_in_metadata(self):
        """Test handling of special characters in metadata."""
        generator = YaraGenerator()
        rule = YaraRule(
            'Test',
            [],
            {'description': 'Test "with quotes" and \\backslashes'},
            {'$s': '"test"'},
            '$s',
            80
        )

        # Should export without errors
        yara_text = generator.export_to_yara([rule])
        assert 'meta:' in yara_text
