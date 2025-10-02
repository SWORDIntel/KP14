"""
Comprehensive tests for threat assessment and scoring module

Tests cover:
- Threat score calculation (0-100 scale)
- Malware family classification
- MITRE ATT&CK technique mapping
- Capability analysis
- Severity rating
- Confidence metrics
- Attribution analysis
- Target profiling
"""

import pytest
from intelligence.scorers.threat_scorer import (
    ThreatScorer,
    ThreatAssessment,
    MitreTechnique,
    ThreatCapability
)


class TestMitreTechniqueDataclass:
    """Test MitreTechnique dataclass."""

    def test_mitre_technique_creation(self):
        """Test creating MitreTechnique with all fields."""
        tech = MitreTechnique(
            technique_id='T1071.001',
            tactic='Command and Control',
            technique_name='Application Layer Protocol: Web Protocols',
            confidence=90,
            evidence=['HTTPS beacon detected']
        )
        assert tech.technique_id == 'T1071.001'
        assert tech.confidence == 90
        assert len(tech.evidence) == 1


class TestThreatScorerInit:
    """Test ThreatScorer initialization."""

    def test_scorer_initialization(self):
        """Test scorer initializes with correct defaults."""
        scorer = ThreatScorer()
        assert 'network_indicators' in scorer.scoring_weights
        assert sum(scorer.scoring_weights.values()) <= 1.01  # Allow rounding
        assert len(scorer.FAMILY_SIGNATURES) > 0
        assert 'KEYPLUG' in scorer.FAMILY_SIGNATURES

    def test_family_signatures_structure(self):
        """Test family signatures have required fields."""
        scorer = ThreatScorer()
        for family, sig in scorer.FAMILY_SIGNATURES.items():
            assert 'base_score' in sig
            assert 'strings' in sig
            assert 'behavior' in sig

    def test_mitre_mappings_completeness(self):
        """Test MITRE mappings cover key tactics."""
        scorer = ThreatScorer()
        tactics = {tech.tactic for tech in scorer.MITRE_MAPPINGS.values()}
        assert 'Command and Control' in tactics
        assert 'Persistence' in tactics
        assert 'Defense Evasion' in tactics


class TestFamilyClassification:
    """Test malware family classification."""

    def test_classify_keyplug_family(self, keyplug_sample_data):
        """Test KEYPLUG family classification."""
        scorer = ThreatScorer()
        family, confidence = scorer._classify_family(keyplug_sample_data)

        assert family == 'KEYPLUG'
        assert confidence > 0

    def test_classify_unknown_family(self):
        """Test classification when no family matches."""
        scorer = ThreatScorer()
        data = {
            'strings': ['generic', 'strings'],
            'behaviors': [],
            'c2_endpoints': []
        }
        family, confidence = scorer._classify_family(data)

        assert family == 'unknown'
        assert confidence == 0

    def test_family_confidence_with_multiple_indicators(self):
        """Test confidence increases with multiple matching indicators."""
        scorer = ThreatScorer()
        data = {
            'strings': ['KEYPLUG', 'winnti', 'barium'],
            'behaviors': ['backdoor', 'persistence'],
            'c2_endpoints': [{'protocol': 'tor'}]
        }
        family, confidence = scorer._classify_family(data)

        assert confidence > 50  # Multiple indicators should boost confidence

    def test_family_string_matching_case_insensitive(self):
        """Test family detection is case-insensitive."""
        scorer = ThreatScorer()
        data_upper = {'strings': ['KEYPLUG'], 'behaviors': [], 'c2_endpoints': []}
        data_lower = {'strings': ['keyplug'], 'behaviors': [], 'c2_endpoints': []}

        family_upper, conf_upper = scorer._classify_family(data_upper)
        family_lower, conf_lower = scorer._classify_family(data_lower)

        assert family_upper == family_lower


class TestMitreTechniqueMapping:
    """Test MITRE ATT&CK technique mapping."""

    def test_map_https_c2_technique(self):
        """Test mapping HTTPS C2 to MITRE technique."""
        scorer = ThreatScorer()
        data = {
            'strings': [],
            'behaviors': [],
            'c2_endpoints': [
                {'protocol': 'https', 'value': 'c2.example.com'}
            ]
        }
        techniques = scorer._map_mitre_techniques(data)

        https_techs = [t for t in techniques if 'T1071' in t.technique_id]
        assert len(https_techs) > 0
        assert https_techs[0].tactic == 'Command and Control'

    def test_map_tor_usage_technique(self):
        """Test mapping Tor usage to MITRE technique."""
        scorer = ThreatScorer()
        data = {
            'strings': [],
            'behaviors': [],
            'c2_endpoints': [
                {'protocol': 'tor', 'value': 'abc123.onion'}
            ]
        }
        techniques = scorer._map_mitre_techniques(data)

        tor_techs = [t for t in techniques if 'tor' in t.technique_name.lower()]
        assert len(tor_techs) > 0

    def test_map_persistence_techniques(self):
        """Test mapping persistence mechanisms."""
        scorer = ThreatScorer()
        data = {
            'strings': ['HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'],
            'behaviors': [],
            'c2_endpoints': []
        }
        techniques = scorer._map_mitre_techniques(data)

        persistence_techs = [t for t in techniques if t.tactic == 'Persistence']
        assert len(persistence_techs) > 0

    def test_map_credential_dumping(self):
        """Test mapping credential access techniques."""
        scorer = ThreatScorer()
        data = {
            'strings': ['mimikatz', 'lsass', 'credential_dump'],
            'behaviors': [],
            'c2_endpoints': []
        }
        techniques = scorer._map_mitre_techniques(data)

        cred_techs = [t for t in techniques if 'credential' in t.technique_name.lower()]
        assert len(cred_techs) > 0

    def test_map_obfuscation_technique(self):
        """Test mapping obfuscation to defense evasion."""
        scorer = ThreatScorer()
        data = {
            'strings': ['encrypted payload', 'base64 encode'],
            'behaviors': ['obfuscation'],
            'c2_endpoints': []
        }
        techniques = scorer._map_mitre_techniques(data)

        evasion_techs = [t for t in techniques if t.tactic == 'Defense Evasion']
        assert len(evasion_techs) > 0

    def test_map_powershell_execution(self):
        """Test mapping PowerShell execution technique."""
        scorer = ThreatScorer()
        data = {
            'strings': ['powershell.exe -enc', 'Invoke-Expression'],
            'behaviors': [],
            'c2_endpoints': []
        }
        techniques = scorer._map_mitre_techniques(data)

        ps_techs = [t for t in techniques if 'powershell' in t.technique_name.lower()]
        assert len(ps_techs) > 0

    def test_technique_deduplication(self):
        """Test that duplicate techniques are deduplicated."""
        scorer = ThreatScorer()
        data = {
            'strings': ['powershell', 'powershell.exe', 'PowerShell'],
            'behaviors': [],
            'c2_endpoints': []
        }
        techniques = scorer._map_mitre_techniques(data)

        # Should not have duplicate PowerShell techniques
        ps_ids = [t.technique_id for t in techniques if 'powershell' in t.technique_name.lower()]
        assert len(ps_ids) == len(set(ps_ids))

    def test_technique_evidence_collection(self):
        """Test that evidence is collected for techniques."""
        scorer = ThreatScorer()
        data = {
            'strings': ['registry autostart key'],
            'behaviors': [],
            'c2_endpoints': []
        }
        techniques = scorer._map_mitre_techniques(data)

        for tech in techniques:
            if tech.tactic == 'Persistence':
                assert len(tech.evidence) > 0


class TestCapabilityIdentification:
    """Test malware capability identification."""

    def test_identify_persistence_capability(self):
        """Test identification of persistence capability."""
        scorer = ThreatScorer()
        data = {
            'strings': ['registry run key', 'autostart', 'service install'],
            'behaviors': []
        }
        capabilities = scorer._identify_capabilities(data)

        persistence_caps = [c for c in capabilities if 'persistence' in c.capability.lower()]
        assert len(persistence_caps) > 0
        assert persistence_caps[0].severity in ['high', 'critical']

    def test_identify_credential_theft_capability(self):
        """Test identification of credential theft."""
        scorer = ThreatScorer()
        data = {
            'strings': ['password', 'credential', 'mimikatz'],
            'behaviors': []
        }
        capabilities = scorer._identify_capabilities(data)

        cred_caps = [c for c in capabilities if 'credential' in c.capability.lower()]
        assert len(cred_caps) > 0
        assert cred_caps[0].severity == 'critical'

    def test_identify_lateral_movement_capability(self):
        """Test identification of lateral movement."""
        scorer = ThreatScorer()
        data = {
            'strings': ['psexec', 'wmi remote', 'admin share'],
            'behaviors': ['lateral_movement']
        }
        capabilities = scorer._identify_capabilities(data)

        lateral_caps = [c for c in capabilities if 'lateral' in c.capability.lower()]
        assert len(lateral_caps) > 0

    def test_identify_multiple_capabilities(self):
        """Test identification of multiple capabilities."""
        scorer = ThreatScorer()
        data = {
            'strings': ['password', 'persistence', 'execute', 'upload'],
            'behaviors': ['credential_theft', 'persistence', 'execution']
        }
        capabilities = scorer._identify_capabilities(data)

        assert len(capabilities) >= 2
        categories = {c.category for c in capabilities}
        assert len(categories) > 1

    def test_capability_indicator_limits(self):
        """Test that capability indicators are limited."""
        scorer = ThreatScorer()
        # Create many matching strings
        data = {
            'strings': ['password'] * 20,
            'behaviors': []
        }
        capabilities = scorer._identify_capabilities(data)

        if capabilities:
            # Should limit indicators to prevent bloat
            assert len(capabilities[0].indicators) <= 5


class TestTargetProfiling:
    """Test target profile building."""

    def test_build_windows_profile(self, sample_analysis_data):
        """Test building Windows platform profile."""
        scorer = ThreatScorer()
        profile = scorer._build_target_profile(sample_analysis_data)

        assert profile['platform'] == 'windows'
        assert profile['architecture'] != 'unknown'

    def test_determine_privilege_requirements(self):
        """Test determination of privilege requirements."""
        scorer = ThreatScorer()
        data = {
            'strings': ['SYSTEM', 'administrator', 'elevation required'],
            'pe_info': {}
        }
        profile = scorer._build_target_profile(data)

        # Should detect admin/system privilege requirement
        assert profile['privileges_required'] in ['admin', 'system']

    def test_identify_targeted_sectors(self):
        """Test identification of targeted sectors."""
        scorer = ThreatScorer()
        data = {
            'strings': ['bank account', 'financial', 'credit card'],
            'pe_info': {}
        }
        profile = scorer._build_target_profile(data)

        assert 'financial' in profile['targeted_sectors']

    def test_multiple_targeted_sectors(self):
        """Test detection of multiple targeted sectors."""
        scorer = ThreatScorer()
        data = {
            'strings': ['banking', 'healthcare', 'government classified'],
            'pe_info': {}
        }
        profile = scorer._build_target_profile(data)

        sectors = profile['targeted_sectors']
        assert len(sectors) >= 2


class TestAttribution:
    """Test attribution analysis."""

    def test_attribution_from_family(self):
        """Test attribution derived from family classification."""
        scorer = ThreatScorer()
        data = {'strings': [], 'c2_endpoints': []}

        attribution = scorer._perform_attribution(data, 'KEYPLUG')

        assert attribution['apt_group'] == 'APT41'
        assert attribution['confidence'] > 0

    def test_attribution_from_indicators(self):
        """Test attribution from specific indicators."""
        scorer = ThreatScorer()
        data = {
            'strings': ['winnti group', 'apt41 operation', 'barium campaign']
        }

        attribution = scorer._perform_attribution(data, 'unknown')

        assert attribution['apt_group'] == 'APT41'
        assert attribution['confidence'] > 0

    def test_attribution_confidence_accumulation(self):
        """Test attribution confidence increases with multiple indicators."""
        scorer = ThreatScorer()
        data = {
            'strings': ['winnti', 'apt41', 'keyplug', 'shadowpad']
        }

        attribution = scorer._perform_attribution(data, 'KEYPLUG')

        # Multiple indicators should boost confidence
        assert attribution['confidence'] >= 70

    def test_unknown_attribution(self):
        """Test handling of unknown attribution."""
        scorer = ThreatScorer()
        data = {'strings': []}

        attribution = scorer._perform_attribution(data, 'unknown')

        assert attribution['apt_group'] == 'unknown'
        assert attribution['confidence'] == 0


class TestRiskFactors:
    """Test risk factor identification."""

    def test_identify_critical_capability_risk(self):
        """Test identification of critical capability risk."""
        scorer = ThreatScorer()
        assessment = ThreatAssessment(
            threat_score=0,
            severity='high',
            family='test',
            family_confidence=80
        )
        assessment.capabilities = [
            ThreatCapability(
                capability='Credential Theft',
                category='credential_access',
                severity='critical',
                description='Test',
                indicators=[]
            )
        ]

        data = {'c2_endpoints': [], 'behaviors': []}
        risks = scorer._identify_risk_factors(data, assessment)

        assert any('critical' in r.lower() for r in risks)

    def test_identify_multiple_c2_risk(self):
        """Test identification of multiple C2 channels risk."""
        scorer = ThreatScorer()
        assessment = ThreatAssessment(
            threat_score=0,
            severity='high',
            family='test',
            family_confidence=80
        )

        data = {
            'c2_endpoints': [{'value': f'c2-{i}.com'} for i in range(5)],
            'behaviors': []
        }
        risks = scorer._identify_risk_factors(data, assessment)

        assert any('multiple c2' in r.lower() for r in risks)

    def test_identify_tor_usage_risk(self):
        """Test identification of Tor usage risk."""
        scorer = ThreatScorer()
        assessment = ThreatAssessment(
            threat_score=0,
            severity='high',
            family='test',
            family_confidence=80
        )

        data = {
            'c2_endpoints': [{'protocol': 'tor', 'value': 'abc.onion'}],
            'behaviors': []
        }
        risks = scorer._identify_risk_factors(data, assessment)

        assert any('tor' in r.lower() for r in risks)

    def test_identify_apt_attribution_risk(self):
        """Test identification of APT attribution risk."""
        scorer = ThreatScorer()
        assessment = ThreatAssessment(
            threat_score=0,
            severity='high',
            family='test',
            family_confidence=80
        )
        assessment.attribution = {'apt_group': 'APT41', 'confidence': 85}

        data = {'c2_endpoints': [], 'behaviors': []}
        risks = scorer._identify_risk_factors(data, assessment)

        assert any('apt' in r.lower() for r in risks)


class TestThreatScoreCalculation:
    """Test threat score calculation."""

    def test_score_range_validity(self, sample_analysis_data):
        """Test threat score is within valid range (0-100)."""
        scorer = ThreatScorer()
        assessment = ThreatAssessment(
            threat_score=0,
            severity='medium',
            family='KEYPLUG',
            family_confidence=80
        )

        score = scorer._calculate_threat_score(sample_analysis_data, assessment)

        assert 0 <= score <= 100

    def test_score_increases_with_capabilities(self):
        """Test score increases with critical capabilities."""
        scorer = ThreatScorer()

        assessment_few = ThreatAssessment(
            threat_score=0,
            severity='medium',
            family='test',
            family_confidence=50
        )
        assessment_few.capabilities = [
            ThreatCapability('test', 'test', 'medium', 'test')
        ]

        assessment_many = ThreatAssessment(
            threat_score=0,
            severity='medium',
            family='test',
            family_confidence=50
        )
        assessment_many.capabilities = [
            ThreatCapability('cred', 'cred', 'critical', 'test'),
            ThreatCapability('persist', 'persist', 'critical', 'test'),
            ThreatCapability('lateral', 'lateral', 'high', 'test')
        ]

        data = {'c2_endpoints': [], 'behaviors': []}

        score_few = scorer._calculate_threat_score(data, assessment_few)
        score_many = scorer._calculate_threat_score(data, assessment_many)

        assert score_many > score_few

    def test_score_increases_with_c2_channels(self):
        """Test score increases with multiple C2 channels."""
        scorer = ThreatScorer()
        assessment = ThreatAssessment(
            threat_score=0,
            severity='medium',
            family='test',
            family_confidence=50
        )

        data_few = {'c2_endpoints': [{}], 'behaviors': []}
        data_many = {'c2_endpoints': [{} for _ in range(10)], 'behaviors': []}

        score_few = scorer._calculate_threat_score(data_few, assessment)
        score_many = scorer._calculate_threat_score(data_many, assessment)

        assert score_many > score_few

    def test_score_bonus_for_family_match(self):
        """Test score bonus for high-confidence family match."""
        scorer = ThreatScorer()

        assessment_low = ThreatAssessment(
            threat_score=0,
            severity='medium',
            family='unknown',
            family_confidence=0
        )

        assessment_high = ThreatAssessment(
            threat_score=0,
            severity='medium',
            family='KEYPLUG',
            family_confidence=95
        )

        data = {'c2_endpoints': [], 'behaviors': []}

        score_low = scorer._calculate_threat_score(data, assessment_low)
        score_high = scorer._calculate_threat_score(data, assessment_high)

        assert score_high > score_low


class TestSeverityDetermination:
    """Test severity level determination."""

    def test_critical_severity(self):
        """Test critical severity for high scores."""
        scorer = ThreatScorer()
        severity = scorer._determine_severity(90)
        assert severity == 'critical'

    def test_high_severity(self):
        """Test high severity for medium-high scores."""
        scorer = ThreatScorer()
        severity = scorer._determine_severity(75)
        assert severity == 'high'

    def test_medium_severity(self):
        """Test medium severity for moderate scores."""
        scorer = ThreatScorer()
        severity = scorer._determine_severity(55)
        assert severity == 'medium'

    def test_low_severity(self):
        """Test low severity for low scores."""
        scorer = ThreatScorer()
        severity = scorer._determine_severity(30)
        assert severity == 'low'

    def test_severity_thresholds(self):
        """Test severity boundary thresholds."""
        scorer = ThreatScorer()

        assert scorer._determine_severity(84) == 'high'
        assert scorer._determine_severity(85) == 'critical'
        assert scorer._determine_severity(69) == 'medium'
        assert scorer._determine_severity(70) == 'high'


class TestCompleteAssessment:
    """Test complete threat assessment pipeline."""

    def test_full_assessment_pipeline(self, sample_analysis_data):
        """Test complete assessment workflow."""
        scorer = ThreatScorer()
        assessment = scorer.assess(sample_analysis_data)

        assert isinstance(assessment, ThreatAssessment)
        assert assessment.threat_score > 0
        assert assessment.severity in ['low', 'medium', 'high', 'critical']
        assert assessment.family != ''
        assert len(assessment.assessment_summary) > 0

    def test_assessment_timestamp(self, sample_analysis_data):
        """Test assessment includes timestamp."""
        scorer = ThreatScorer()
        assessment = scorer.assess(sample_analysis_data)

        assert assessment.timestamp != ''
        assert 'T' in assessment.timestamp  # ISO format

    def test_assessment_summary_generation(self, sample_analysis_data):
        """Test assessment summary is generated."""
        scorer = ThreatScorer()
        assessment = scorer.assess(sample_analysis_data)

        summary = assessment.assessment_summary
        assert 'Threat Score' in summary
        assert assessment.family in summary

    def test_assessment_with_minimal_data(self):
        """Test assessment with minimal input data."""
        scorer = ThreatScorer()
        minimal_data = {
            'strings': ['test'],
            'c2_endpoints': [],
            'behaviors': [],
            'pe_info': {}
        }

        assessment = scorer.assess(minimal_data)

        # Should complete without errors
        assert isinstance(assessment, ThreatAssessment)
        assert assessment.threat_score >= 0


class TestExportFunctionality:
    """Test export to dictionary."""

    def test_export_to_dict(self, sample_analysis_data):
        """Test exporting assessment to dictionary."""
        scorer = ThreatScorer()
        assessment = scorer.assess(sample_analysis_data)

        exported = scorer.export_to_dict(assessment)

        assert 'threat_score' in exported
        assert 'severity' in exported
        assert 'family' in exported
        assert 'mitre_techniques' in exported
        assert 'capabilities' in exported

    def test_exported_dict_structure(self):
        """Test exported dictionary has correct structure."""
        scorer = ThreatScorer()
        assessment = ThreatAssessment(
            threat_score=85,
            severity='high',
            family='KEYPLUG',
            family_confidence=90
        )

        exported = scorer.export_to_dict(assessment)

        assert exported['threat_score'] == 85
        assert exported['severity'] == 'high'
        assert exported['family'] == 'KEYPLUG'
        assert isinstance(exported['mitre_techniques'], list)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_analysis_data(self):
        """Test assessment with empty data."""
        scorer = ThreatScorer()
        empty_data = {}

        assessment = scorer.assess(empty_data)

        # Should handle gracefully
        assert isinstance(assessment, ThreatAssessment)

    def test_malformed_c2_endpoints(self):
        """Test handling of malformed C2 endpoint data."""
        scorer = ThreatScorer()
        data = {
            'strings': [],
            'c2_endpoints': ['string instead of dict', None, {}],
            'behaviors': []
        }

        techniques = scorer._map_mitre_techniques(data)

        # Should not crash
        assert isinstance(techniques, list)

    def test_none_values_in_data(self):
        """Test handling of None values in data."""
        scorer = ThreatScorer()
        data = {
            'strings': None,
            'c2_endpoints': None,
            'behaviors': None,
            'pe_info': None
        }

        # Should handle None gracefully
        family, conf = scorer._classify_family(data)
        assert family == 'unknown'
