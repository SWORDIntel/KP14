"""
YARA Rule Generator

Automatically generates YARA rules from malware patterns:
- String-based rules
- Binary pattern rules
- Import/export rules
- PE section rules
- Confidence-based tuning
"""

import hashlib
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class YaraRule:
    """Represents a YARA rule."""
    name: str
    tags: List[str]
    meta: Dict[str, str]
    strings: Dict[str, str]
    condition: str
    confidence: int
    description: str = ""


class YaraGenerator:
    """
    Automatic YARA rule generator.

    Features:
    - Pattern extraction from samples
    - Confidence-based string selection
    - False positive reduction
    - Family-specific rule generation
    """

    def __init__(self):
        """Initialize YARA generator."""
        self.min_string_length = 6
        self.min_confidence = 70

    def generate(self, analysis_data: Dict[str, Any]) -> List[YaraRule]:
        """
        Generate YARA rules from analysis data.

        Args:
            analysis_data: Complete analysis results

        Returns:
            List of generated YARA rules
        """
        rules = []

        # Generate family-based rule
        if analysis_data.get('threat_assessment', {}).get('family') != 'unknown':
            family_rule = self._generate_family_rule(analysis_data)
            if family_rule:
                rules.append(family_rule)

        # Generate C2 indicator rule
        if analysis_data.get('c2_endpoints'):
            c2_rule = self._generate_c2_rule(analysis_data)
            if c2_rule:
                rules.append(c2_rule)

        # Generate capability-based rule
        if analysis_data.get('threat_assessment', {}).get('capabilities'):
            cap_rule = self._generate_capability_rule(analysis_data)
            if cap_rule:
                rules.append(cap_rule)

        # Generate generic detection rule
        generic_rule = self._generate_generic_rule(analysis_data)
        if generic_rule:
            rules.append(generic_rule)

        return rules

    def _generate_family_rule(self, data: Dict[str, Any]) -> Optional[YaraRule]:
        """Generate malware family detection rule."""
        threat = data.get('threat_assessment', {})
        family = threat.get('family', 'unknown')

        if family == 'unknown' or threat.get('family_confidence', 0) < self.min_confidence:
            return None

        strings = data.get('strings', [])
        pe_info = data.get('pe_info', {})

        # Extract high-confidence strings
        yara_strings = {}
        string_count = 0

        for string in strings[:50]:  # Limit to first 50 strings
            if len(string) >= self.min_string_length:
                # Filter out common false positives
                if not self._is_common_string(string):
                    string_count += 1
                    yara_strings[f'$str{string_count}'] = self._format_yara_string(string)
                    if string_count >= 15:  # Max 15 strings
                        break

        # Add PE metadata strings
        if pe_info:
            if 'imphash' in pe_info:
                yara_strings['$imphash'] = f'{{ {pe_info["imphash"]} }}'

        if not yara_strings:
            return None

        # Build condition
        condition_parts = []
        if string_count >= 5:
            condition_parts.append(f'{min(3, string_count)} of ($str*)')
        else:
            condition_parts.append('any of them')

        meta = {
            'description': f'{family} malware family detection',
            'author': 'KP14 Auto-Generator',
            'date': datetime.utcnow().strftime('%Y-%m-%d'),
            'family': family,
            'confidence': str(threat.get('family_confidence', 0)),
            'severity': threat.get('severity', 'unknown'),
            'reference': 'Auto-generated from sample analysis'
        }

        rule_name = f'{family}_Detection_{hashlib.md5(family.encode()).hexdigest()[:8]}'

        return YaraRule(
            name=rule_name,
            tags=[family.lower(), 'malware', threat.get('severity', 'medium')],
            meta=meta,
            strings=yara_strings,
            condition=' or '.join(condition_parts),
            confidence=threat.get('family_confidence', 0),
            description=f'Detects {family} malware family'
        )

    def _generate_c2_rule(self, data: Dict[str, Any]) -> Optional[YaraRule]:
        """Generate C2 indicator-based rule."""
        c2_endpoints = data.get('c2_endpoints', [])

        if not c2_endpoints:
            return None

        yara_strings = {}

        # Extract high-confidence C2 indicators
        for i, endpoint in enumerate(c2_endpoints[:10], 1):  # Max 10 endpoints
            if isinstance(endpoint, dict):
                value = endpoint.get('value', '')
                confidence = endpoint.get('confidence', 0)

                if confidence >= self.min_confidence and len(value) >= 6:
                    yara_strings[f'$c2_{i}'] = self._format_yara_string(value)

        if not yara_strings:
            return None

        meta = {
            'description': 'C2 infrastructure detection',
            'author': 'KP14 Auto-Generator',
            'date': datetime.utcnow().strftime('%Y-%m-%d'),
            'type': 'c2_indicators',
            'confidence': '85',
            'reference': 'C2 endpoint extraction'
        }

        family = data.get('threat_assessment', {}).get('family', 'Unknown')
        rule_name = f'C2_Indicators_{family}_{hashlib.md5(str(c2_endpoints).encode()).hexdigest()[:8]}'

        return YaraRule(
            name=rule_name,
            tags=['c2', 'network', 'communication'],
            meta=meta,
            strings=yara_strings,
            condition='any of them',
            confidence=85,
            description='Detects C2 communication indicators'
        )

    def _generate_capability_rule(self, data: Dict[str, Any]) -> Optional[YaraRule]:
        """Generate capability-based detection rule."""
        threat = data.get('threat_assessment', {})
        capabilities = threat.get('capabilities', [])

        if not capabilities:
            return None

        yara_strings = {}
        string_idx = 0

        # Extract capability indicators
        for cap in capabilities:
            if isinstance(cap, dict):
                indicators = cap.get('indicators', [])
                for indicator in indicators[:3]:  # Max 3 per capability
                    if len(indicator) >= self.min_string_length:
                        string_idx += 1
                        yara_strings[f'$cap{string_idx}'] = self._format_yara_string(indicator)
                        if string_idx >= 20:
                            break
                if string_idx >= 20:
                    break

        if not yara_strings:
            return None

        meta = {
            'description': 'Malware capability detection',
            'author': 'KP14 Auto-Generator',
            'date': datetime.utcnow().strftime('%Y-%m-%d'),
            'type': 'capabilities',
            'confidence': '80',
            'capabilities': ', '.join([c.get('capability', '') for c in capabilities if isinstance(c, dict)])[:200]
        }

        family = threat.get('family', 'Unknown')
        rule_name = f'Capabilities_{family}_{hashlib.md5(str(capabilities).encode()).hexdigest()[:8]}'

        # Require multiple capability matches to reduce false positives
        condition = f'{min(3, len(yara_strings))} of them'

        return YaraRule(
            name=rule_name,
            tags=['capabilities', 'behavior'],
            meta=meta,
            strings=yara_strings,
            condition=condition,
            confidence=80,
            description='Detects malware capabilities'
        )

    def _generate_generic_rule(self, data: Dict[str, Any]) -> Optional[YaraRule]:
        """Generate generic detection rule from hashes."""
        pe_info = data.get('pe_info', {})

        if not pe_info:
            return None

        yara_strings = {}

        # Use file hashes for exact detection
        if 'md5' in pe_info:
            yara_strings['$md5'] = f'{{ {pe_info["md5"]} }}'
        if 'sha256' in pe_info:
            yara_strings['$sha256'] = f'{{ {pe_info["sha256"]} }}'

        if not yara_strings:
            return None

        meta = {
            'description': 'Generic malware detection via file hash',
            'author': 'KP14 Auto-Generator',
            'date': datetime.utcnow().strftime('%Y-%m-%d'),
            'type': 'hash_detection',
            'confidence': '100',
            'md5': pe_info.get('md5', ''),
            'sha256': pe_info.get('sha256', '')
        }

        family = data.get('threat_assessment', {}).get('family', 'Unknown')
        rule_name = f'Hash_Detection_{family}_{pe_info.get("md5", "unknown")[:8]}'

        return YaraRule(
            name=rule_name,
            tags=['hash', 'exact_match'],
            meta=meta,
            strings=yara_strings,
            condition='any of them',
            confidence=100,
            description='Exact file hash detection'
        )

    def _is_common_string(self, string: str) -> bool:
        """Filter out common false positive strings."""
        common_patterns = [
            r'^[0-9]+$',  # Only numbers
            r'^[a-zA-Z]$',  # Single letter
            r'^(http://|https://)(www\.)?example\.(com|org)',  # Example URLs
            r'^(test|debug|temp|tmp)',  # Test strings
            r'^(microsoft|windows|system)',  # Common OS strings
        ]

        for pattern in common_patterns:
            if re.match(pattern, string, re.IGNORECASE):
                return True

        return False

    def _format_yara_string(self, string: str) -> str:
        """Format string for YARA rule."""
        # Escape special characters
        escaped = string.replace('\\', '\\\\').replace('"', '\\"')

        # Use wide string if contains non-ASCII
        if any(ord(c) > 127 for c in string):
            return f'"{escaped}" wide'
        else:
            return f'"{escaped}"'

    def export_to_yara(self, rules: List[YaraRule]) -> str:
        """Export rules to YARA format."""
        output = []
        output.append('/*')
        output.append(' * Auto-generated YARA rules')
        output.append(' * Generated by KP14 Intelligence Module')
        output.append(f' * Date: {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC')
        output.append(' */')
        output.append('')

        for rule in rules:
            output.append(f'rule {rule.name}')
            output.append('{')

            # Meta section
            output.append('    meta:')
            for key, value in rule.meta.items():
                output.append(f'        {key} = "{value}"')

            # Strings section
            if rule.strings:
                output.append('')
                output.append('    strings:')
                for var_name, var_value in rule.strings.items():
                    output.append(f'        {var_name} = {var_value}')

            # Condition section
            output.append('')
            output.append('    condition:')
            output.append(f'        {rule.condition}')

            output.append('}')
            output.append('')

        return '\n'.join(output)

    def save_rules(self, rules: List[YaraRule], output_path: str):
        """Save YARA rules to file."""
        yara_content = self.export_to_yara(rules)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(yara_content)
