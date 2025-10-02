"""
Threat Assessment and Scoring Module

Provides automated threat scoring and classification:
- Threat score calculation (0-100)
- MITRE ATT&CK technique mapping
- Malware family classification
- Severity rating
- Capability analysis
- Target profiling
- Attribution indicators
"""

from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import hashlib


@dataclass
class MitreTechnique:
    """MITRE ATT&CK technique mapping."""
    technique_id: str
    tactic: str
    technique_name: str
    confidence: int
    evidence: List[str] = field(default_factory=list)


@dataclass
class ThreatCapability:
    """Malware capability description."""
    capability: str
    category: str  # persistence, evasion, collection, etc.
    severity: str  # low, medium, high, critical
    description: str
    indicators: List[str] = field(default_factory=list)


@dataclass
class ThreatAssessment:
    """Complete threat assessment results."""
    threat_score: int  # 0-100
    severity: str  # low, medium, high, critical
    family: str
    family_confidence: int
    mitre_techniques: List[MitreTechnique] = field(default_factory=list)
    capabilities: List[ThreatCapability] = field(default_factory=list)
    target_profile: Dict[str, Any] = field(default_factory=dict)
    attribution: Dict[str, Any] = field(default_factory=dict)
    risk_factors: List[str] = field(default_factory=list)
    assessment_summary: str = ""
    timestamp: str = ""


class ThreatScorer:
    """
    Advanced threat assessment and scoring engine.

    Features:
    - Multi-factor threat scoring
    - MITRE ATT&CK mapping
    - Family classification
    - Capability detection
    - Attribution analysis
    """

    # Malware family signatures
    FAMILY_SIGNATURES = {
        'KEYPLUG': {
            'strings': ['KEYPLUG', 'winnti', 'barium'],
            'behavior': ['backdoor', 'persistence', 'c2_communication'],
            'file_patterns': ['.plug', 'key.dat'],
            'network_patterns': ['tor', 'https_beacon'],
            'apt_group': 'APT41',
            'base_score': 85
        },
        'COBALT_STRIKE': {
            'strings': ['cobaltstrike', 'beacon', 'malleable'],
            'behavior': ['post_exploitation', 'lateral_movement'],
            'file_patterns': ['.beacon', 'artifact.exe'],
            'network_patterns': ['https_beacon', 'dns_beacon'],
            'base_score': 80
        },
        'MIMIKATZ': {
            'strings': ['mimikatz', 'gentilkiwi', 'sekurlsa'],
            'behavior': ['credential_dumping', 'privilege_escalation'],
            'file_patterns': ['mimikatz.exe'],
            'network_patterns': [],
            'base_score': 75
        },
        'GENERIC_BACKDOOR': {
            'strings': ['backdoor', 'remote', 'shell'],
            'behavior': ['backdoor', 'c2_communication'],
            'base_score': 60
        }
    }

    # MITRE ATT&CK technique mappings
    MITRE_MAPPINGS = {
        # Command and Control
        'c2_http': MitreTechnique('T1071.001', 'Command and Control', 'Application Layer Protocol: Web Protocols', 0, []),
        'c2_https': MitreTechnique('T1071.001', 'Command and Control', 'Application Layer Protocol: Web Protocols', 0, []),
        'c2_dns': MitreTechnique('T1071.004', 'Command and Control', 'Application Layer Protocol: DNS', 0, []),
        'tor_usage': MitreTechnique('T1090.003', 'Command and Control', 'Proxy: Multi-hop Proxy', 0, []),

        # Persistence
        'registry_run': MitreTechnique('T1547.001', 'Persistence', 'Boot or Logon Autostart: Registry Run Keys', 0, []),
        'service_install': MitreTechnique('T1543.003', 'Persistence', 'Create or Modify System Process: Windows Service', 0, []),
        'scheduled_task': MitreTechnique('T1053.005', 'Persistence', 'Scheduled Task/Job: Scheduled Task', 0, []),

        # Defense Evasion
        'obfuscation': MitreTechnique('T1027', 'Defense Evasion', 'Obfuscated Files or Information', 0, []),
        'process_injection': MitreTechnique('T1055', 'Defense Evasion', 'Process Injection', 0, []),
        'masquerading': MitreTechnique('T1036', 'Defense Evasion', 'Masquerading', 0, []),

        # Credential Access
        'credential_dumping': MitreTechnique('T1003', 'Credential Access', 'OS Credential Dumping', 0, []),
        'input_capture': MitreTechnique('T1056', 'Credential Access', 'Input Capture', 0, []),

        # Discovery
        'system_info': MitreTechnique('T1082', 'Discovery', 'System Information Discovery', 0, []),
        'network_info': MitreTechnique('T1016', 'Discovery', 'System Network Configuration Discovery', 0, []),
        'process_discovery': MitreTechnique('T1057', 'Discovery', 'Process Discovery', 0, []),

        # Collection
        'data_staging': MitreTechnique('T1074', 'Collection', 'Data Staged', 0, []),
        'screen_capture': MitreTechnique('T1113', 'Collection', 'Screen Capture', 0, []),
        'keylogging': MitreTechnique('T1056.001', 'Collection', 'Input Capture: Keylogging', 0, []),

        # Exfiltration
        'exfil_c2': MitreTechnique('T1041', 'Exfiltration', 'Exfiltration Over C2 Channel', 0, []),
        'exfil_web': MitreTechnique('T1567', 'Exfiltration', 'Exfiltration Over Web Service', 0, []),

        # Execution
        'command_shell': MitreTechnique('T1059', 'Execution', 'Command and Scripting Interpreter', 0, []),
        'powershell': MitreTechnique('T1059.001', 'Execution', 'PowerShell', 0, []),
    }

    # Capability definitions
    CAPABILITY_PATTERNS = {
        'persistence': {
            'patterns': ['autostart', 'registry', 'service', 'scheduled', 'startup'],
            'severity': 'high',
            'category': 'persistence'
        },
        'evasion': {
            'patterns': ['obfuscate', 'encrypt', 'hide', 'stealth', 'anti'],
            'severity': 'high',
            'category': 'defense_evasion'
        },
        'credential_theft': {
            'patterns': ['password', 'credential', 'lsass', 'sam', 'mimikatz'],
            'severity': 'critical',
            'category': 'credential_access'
        },
        'lateral_movement': {
            'patterns': ['psexec', 'wmi', 'remote', 'share', 'smb'],
            'severity': 'critical',
            'category': 'lateral_movement'
        },
        'data_exfiltration': {
            'patterns': ['upload', 'exfil', 'send', 'post', 'transfer'],
            'severity': 'critical',
            'category': 'exfiltration'
        },
        'reconnaissance': {
            'patterns': ['enumerate', 'scan', 'discover', 'list', 'query'],
            'severity': 'medium',
            'category': 'discovery'
        },
        'execution': {
            'patterns': ['execute', 'run', 'spawn', 'create', 'shell'],
            'severity': 'high',
            'category': 'execution'
        }
    }

    def __init__(self):
        """Initialize threat scorer."""
        self.scoring_weights = {
            'network_indicators': 0.20,
            'capabilities': 0.25,
            'obfuscation': 0.15,
            'persistence': 0.20,
            'family_match': 0.20
        }

    def assess(self, analysis_data: Dict[str, Any]) -> ThreatAssessment:
        """
        Perform complete threat assessment.

        Args:
            analysis_data: Dictionary containing:
                - strings: List of extracted strings
                - c2_endpoints: List of C2 endpoints
                - pe_info: PE file metadata
                - behaviors: List of observed behaviors
                - metadata: Additional metadata

        Returns:
            ThreatAssessment with scoring and classification
        """
        assessment = ThreatAssessment(
            threat_score=0,
            severity='low',
            family='unknown',
            family_confidence=0,
            timestamp=datetime.utcnow().isoformat()
        )

        # Classify malware family
        assessment.family, assessment.family_confidence = self._classify_family(analysis_data)

        # Map MITRE ATT&CK techniques
        assessment.mitre_techniques = self._map_mitre_techniques(analysis_data)

        # Identify capabilities
        assessment.capabilities = self._identify_capabilities(analysis_data)

        # Build target profile
        assessment.target_profile = self._build_target_profile(analysis_data)

        # Perform attribution analysis
        assessment.attribution = self._perform_attribution(analysis_data, assessment.family)

        # Identify risk factors
        assessment.risk_factors = self._identify_risk_factors(analysis_data, assessment)

        # Calculate threat score
        assessment.threat_score = self._calculate_threat_score(analysis_data, assessment)

        # Determine severity
        assessment.severity = self._determine_severity(assessment.threat_score)

        # Generate summary
        assessment.assessment_summary = self._generate_summary(assessment)

        return assessment

    def _classify_family(self, data: Dict[str, Any]) -> Tuple[str, int]:
        """Classify malware family with confidence score."""
        strings = data.get('strings', [])
        behaviors = data.get('behaviors', [])
        c2_data = data.get('c2_endpoints', [])

        best_match = ('unknown', 0)

        for family, signature in self.FAMILY_SIGNATURES.items():
            score = 0
            matches = 0

            # Check string signatures
            for sig_string in signature.get('strings', []):
                for sample_string in strings:
                    if sig_string.lower() in sample_string.lower():
                        score += 25
                        matches += 1
                        break

            # Check behavioral signatures
            for sig_behavior in signature.get('behavior', []):
                if sig_behavior in behaviors:
                    score += 20
                    matches += 1

            # Check network patterns
            for pattern in signature.get('network_patterns', []):
                for endpoint in c2_data:
                    if isinstance(endpoint, dict) and pattern in str(endpoint.get('protocol', '')).lower():
                        score += 15
                        matches += 1

            # Normalize score
            if matches > 0:
                confidence = min(100, score)
                if confidence > best_match[1]:
                    best_match = (family, confidence)

        return best_match

    def _map_mitre_techniques(self, data: Dict[str, Any]) -> List[MitreTechnique]:
        """Map observed behaviors to MITRE ATT&CK techniques."""
        techniques = []
        strings = data.get('strings', [])
        behaviors = data.get('behaviors', [])
        c2_data = data.get('c2_endpoints', [])

        # Check C2 protocols
        for endpoint in c2_data:
            if isinstance(endpoint, dict):
                protocol = str(endpoint.get('protocol', '')).lower()
                if 'http' in protocol:
                    tech = self._clone_technique('c2_https' if 'https' in protocol else 'c2_http')
                    tech.confidence = 90
                    tech.evidence = [f"C2 endpoint: {endpoint.get('value')}"]
                    techniques.append(tech)
                elif 'dns' in protocol:
                    tech = self._clone_technique('c2_dns')
                    tech.confidence = 85
                    tech.evidence = [f"DNS C2: {endpoint.get('value')}"]
                    techniques.append(tech)
                elif 'tor' in protocol:
                    tech = self._clone_technique('tor_usage')
                    tech.confidence = 95
                    tech.evidence = [f"Tor endpoint: {endpoint.get('value')}"]
                    techniques.append(tech)

        # Check for persistence mechanisms
        persistence_keywords = ['registry', 'autostart', 'run key', 'service', 'scheduled task']
        for keyword in persistence_keywords:
            for string in strings:
                if keyword in string.lower():
                    if 'registry' in keyword or 'run' in keyword:
                        tech = self._clone_technique('registry_run')
                        tech.confidence = 80
                        tech.evidence = [string]
                        techniques.append(tech)
                    elif 'service' in keyword:
                        tech = self._clone_technique('service_install')
                        tech.confidence = 75
                        tech.evidence = [string]
                        techniques.append(tech)
                    elif 'scheduled' in keyword:
                        tech = self._clone_technique('scheduled_task')
                        tech.confidence = 75
                        tech.evidence = [string]
                        techniques.append(tech)
                    break

        # Check for evasion techniques
        if 'obfuscation' in behaviors or any('encrypt' in s.lower() or 'encode' in s.lower() for s in strings):
            tech = self._clone_technique('obfuscation')
            tech.confidence = 85
            tech.evidence = ['Obfuscation detected']
            techniques.append(tech)

        # Check for credential access
        cred_keywords = ['password', 'credential', 'lsass', 'mimikatz', 'sam']
        for keyword in cred_keywords:
            for string in strings:
                if keyword in string.lower():
                    tech = self._clone_technique('credential_dumping')
                    tech.confidence = 90
                    tech.evidence = [string]
                    techniques.append(tech)
                    break

        # Check for keylogging
        if any('keylog' in s.lower() or 'keystroke' in s.lower() for s in strings):
            tech = self._clone_technique('keylogging')
            tech.confidence = 85
            tech.evidence = ['Keylogging indicators found']
            techniques.append(tech)

        # Check for execution
        if any('powershell' in s.lower() for s in strings):
            tech = self._clone_technique('powershell')
            tech.confidence = 80
            tech.evidence = ['PowerShell execution detected']
            techniques.append(tech)

        # Deduplicate by technique_id
        unique_techniques = {}
        for tech in techniques:
            if tech.technique_id not in unique_techniques:
                unique_techniques[tech.technique_id] = tech
            else:
                # Merge evidence
                unique_techniques[tech.technique_id].evidence.extend(tech.evidence)

        return list(unique_techniques.values())

    def _identify_capabilities(self, data: Dict[str, Any]) -> List[ThreatCapability]:
        """Identify malware capabilities."""
        capabilities = []
        strings = data.get('strings', [])
        behaviors = data.get('behaviors', [])

        for cap_name, cap_def in self.CAPABILITY_PATTERNS.items():
            patterns = cap_def['patterns']
            indicators = []

            # Check strings
            for pattern in patterns:
                for string in strings:
                    if pattern in string.lower():
                        indicators.append(string)

            # Check behaviors
            for behavior in behaviors:
                for pattern in patterns:
                    if pattern in behavior.lower():
                        indicators.append(behavior)

            if indicators:
                capabilities.append(ThreatCapability(
                    capability=cap_name.replace('_', ' ').title(),
                    category=cap_def['category'],
                    severity=cap_def['severity'],
                    description=f"Detected {cap_name.replace('_', ' ')} capabilities",
                    indicators=indicators[:5]  # Limit to 5 indicators
                ))

        return capabilities

    def _build_target_profile(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Build target profile based on indicators."""
        profile = {
            'platform': 'unknown',
            'architecture': 'unknown',
            'privileges_required': 'unknown',
            'targeted_sectors': []
        }

        pe_info = data.get('pe_info', {})
        strings = data.get('strings', [])

        # Determine platform
        if pe_info:
            profile['platform'] = 'windows'
            profile['architecture'] = pe_info.get('machine', 'unknown')

        # Determine privilege requirements
        privilege_indicators = {
            'user': ['user', 'appdata', 'temp'],
            'admin': ['system32', 'program files', 'administrator'],
            'system': ['system', 'kernel', 'driver']
        }

        for priv_level, indicators in privilege_indicators.items():
            for indicator in indicators:
                if any(indicator in s.lower() for s in strings):
                    profile['privileges_required'] = priv_level
                    break

        # Identify targeted sectors
        sector_keywords = {
            'financial': ['bank', 'finance', 'payment', 'credit'],
            'healthcare': ['medical', 'health', 'patient', 'hospital'],
            'government': ['gov', 'military', 'defense', 'classified'],
            'technology': ['tech', 'software', 'development', 'engineering'],
            'energy': ['energy', 'power', 'utility', 'scada']
        }

        for sector, keywords in sector_keywords.items():
            for keyword in keywords:
                if any(keyword in s.lower() for s in strings):
                    if sector not in profile['targeted_sectors']:
                        profile['targeted_sectors'].append(sector)

        return profile

    def _perform_attribution(self, data: Dict[str, Any], family: str) -> Dict[str, Any]:
        """Perform attribution analysis."""
        attribution = {
            'apt_group': 'unknown',
            'confidence': 0,
            'indicators': [],
            'ttps_match': []
        }

        # Check if family has known APT association
        if family in self.FAMILY_SIGNATURES:
            apt_group = self.FAMILY_SIGNATURES[family].get('apt_group')
            if apt_group:
                attribution['apt_group'] = apt_group
                attribution['confidence'] = 70
                attribution['indicators'].append(f"Family {family} associated with {apt_group}")

        # APT41/KEYPLUG specific indicators
        apt41_indicators = ['winnti', 'barium', 'apt41', 'keyplug', 'shadowpad']
        strings = data.get('strings', [])

        for indicator in apt41_indicators:
            for string in strings:
                if indicator in string.lower():
                    attribution['apt_group'] = 'APT41'
                    attribution['confidence'] = min(100, attribution['confidence'] + 15)
                    attribution['indicators'].append(string)

        return attribution

    def _identify_risk_factors(self, data: Dict[str, Any], assessment: ThreatAssessment) -> List[str]:
        """Identify risk factors."""
        risks = []

        # High severity capabilities
        critical_caps = [cap for cap in assessment.capabilities if cap.severity == 'critical']
        if critical_caps:
            risks.append(f"Critical capabilities detected: {len(critical_caps)}")

        # Multiple C2 channels
        c2_count = len(data.get('c2_endpoints', []))
        if c2_count > 3:
            risks.append(f"Multiple C2 channels: {c2_count}")

        # Tor usage
        if any(endpoint.get('protocol') == 'tor' for endpoint in data.get('c2_endpoints', [])):
            risks.append("Tor anonymization network usage")

        # Advanced evasion
        if 'obfuscation' in data.get('behaviors', []):
            risks.append("Advanced obfuscation techniques")

        # Credential theft
        if any(cap.capability == 'Credential Theft' for cap in assessment.capabilities):
            risks.append("Credential theft capability")

        # APT attribution
        if assessment.attribution.get('apt_group') != 'unknown':
            risks.append(f"APT attribution: {assessment.attribution['apt_group']}")

        return risks

    def _calculate_threat_score(self, data: Dict[str, Any], assessment: ThreatAssessment) -> int:
        """Calculate overall threat score (0-100)."""
        score = 0

        # Base score from family
        if assessment.family in self.FAMILY_SIGNATURES:
            score += self.FAMILY_SIGNATURES[assessment.family].get('base_score', 50)
        else:
            score += 40  # Unknown family base

        # Network indicators (max 20 points)
        c2_count = len(data.get('c2_endpoints', []))
        network_score = min(20, c2_count * 5)
        score += int(network_score * self.scoring_weights['network_indicators'])

        # Capabilities (max 25 points)
        critical_caps = sum(1 for cap in assessment.capabilities if cap.severity == 'critical')
        high_caps = sum(1 for cap in assessment.capabilities if cap.severity == 'high')
        cap_score = min(25, critical_caps * 10 + high_caps * 5)
        score += int(cap_score * self.scoring_weights['capabilities'])

        # Obfuscation (max 15 points)
        if 'obfuscation' in data.get('behaviors', []):
            score += int(15 * self.scoring_weights['obfuscation'])

        # Persistence (max 20 points)
        persistence_techniques = sum(1 for tech in assessment.mitre_techniques if tech.tactic == 'Persistence')
        persist_score = min(20, persistence_techniques * 10)
        score += int(persist_score * self.scoring_weights['persistence'])

        # Family match bonus (max 20 points)
        family_bonus = int((assessment.family_confidence / 100) * 20)
        score += int(family_bonus * self.scoring_weights['family_match'])

        # Cap at 100
        return min(100, int(score))

    def _determine_severity(self, threat_score: int) -> str:
        """Determine severity level from threat score."""
        if threat_score >= 85:
            return 'critical'
        elif threat_score >= 70:
            return 'high'
        elif threat_score >= 50:
            return 'medium'
        else:
            return 'low'

    def _generate_summary(self, assessment: ThreatAssessment) -> str:
        """Generate human-readable assessment summary."""
        summary_parts = []

        summary_parts.append(f"Threat Score: {assessment.threat_score}/100 ({assessment.severity.upper()})")
        summary_parts.append(f"Family: {assessment.family} (confidence: {assessment.family_confidence}%)")

        if assessment.mitre_techniques:
            summary_parts.append(f"MITRE Techniques: {len(assessment.mitre_techniques)} identified")

        if assessment.capabilities:
            critical = sum(1 for c in assessment.capabilities if c.severity == 'critical')
            if critical > 0:
                summary_parts.append(f"Critical Capabilities: {critical}")

        if assessment.attribution.get('apt_group') != 'unknown':
            summary_parts.append(f"Attribution: {assessment.attribution['apt_group']}")

        return " | ".join(summary_parts)

    def _clone_technique(self, technique_key: str) -> MitreTechnique:
        """Create a copy of a MITRE technique template."""
        template = self.MITRE_MAPPINGS[technique_key]
        return MitreTechnique(
            technique_id=template.technique_id,
            tactic=template.tactic,
            technique_name=template.technique_name,
            confidence=0,
            evidence=[]
        )

    def export_to_dict(self, assessment: ThreatAssessment) -> Dict[str, Any]:
        """Export assessment to dictionary."""
        return {
            'threat_score': assessment.threat_score,
            'severity': assessment.severity,
            'family': assessment.family,
            'family_confidence': assessment.family_confidence,
            'mitre_techniques': [
                {
                    'id': tech.technique_id,
                    'tactic': tech.tactic,
                    'name': tech.technique_name,
                    'confidence': tech.confidence,
                    'evidence': tech.evidence
                }
                for tech in assessment.mitre_techniques
            ],
            'capabilities': [
                {
                    'capability': cap.capability,
                    'category': cap.category,
                    'severity': cap.severity,
                    'description': cap.description,
                    'indicators': cap.indicators
                }
                for cap in assessment.capabilities
            ],
            'target_profile': assessment.target_profile,
            'attribution': assessment.attribution,
            'risk_factors': assessment.risk_factors,
            'summary': assessment.assessment_summary,
            'timestamp': assessment.timestamp
        }
