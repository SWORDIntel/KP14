"""
Sigma Rule Generator

Generates Sigma rules for log detection:
- Windows Event Log detection
- Process execution patterns
- Network connection logs
- Registry modifications
"""

from typing import Dict, List, Any
from datetime import datetime
import yaml


class SigmaGenerator:
    """Generate Sigma rules for SIEM platforms."""

    def generate(self, threat_data: Dict[str, Any], capabilities: List[Dict]) -> List[Dict[str, Any]]:
        """Generate Sigma rules from threat data."""
        rules = []

        family = threat_data.get('family', 'Unknown')
        techniques = threat_data.get('mitre_techniques', [])

        # Process execution rule
        if any(cap.get('category') == 'execution' for cap in capabilities):
            rules.append(self._generate_process_rule(family, capabilities))

        # Network connection rule
        if threat_data.get('c2_endpoints'):
            rules.append(self._generate_network_rule(family, threat_data))

        # Registry modification rule
        if any(cap.get('category') == 'persistence' for cap in capabilities):
            rules.append(self._generate_registry_rule(family, capabilities))

        return rules

    def _generate_process_rule(self, family: str, capabilities: List[Dict]) -> Dict[str, Any]:
        """Generate process execution detection rule."""
        indicators = []
        for cap in capabilities:
            if cap.get('category') == 'execution':
                indicators.extend(cap.get('indicators', [])[:5])

        return {
            'title': f'{family} Malware Process Execution',
            'id': self._generate_uuid(f'{family}_process'),
            'status': 'experimental',
            'description': f'Detects {family} malware process execution patterns',
            'author': 'KP14 Auto-Generator',
            'date': datetime.utcnow().strftime('%Y/%m/%d'),
            'tags': [f'attack.{family.lower()}', 'attack.execution'],
            'logsource': {
                'category': 'process_creation',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'CommandLine|contains': indicators[:10]
                },
                'condition': 'selection'
            },
            'falsepositives': ['Unknown'],
            'level': 'high'
        }

    def _generate_network_rule(self, family: str, threat_data: Dict) -> Dict[str, Any]:
        """Generate network connection detection rule."""
        c2_list = [ep.get('value') for ep in threat_data.get('c2_endpoints', [])[:10] if isinstance(ep, dict)]

        return {
            'title': f'{family} C2 Network Communication',
            'id': self._generate_uuid(f'{family}_network'),
            'status': 'experimental',
            'description': f'Detects {family} C2 communication',
            'author': 'KP14 Auto-Generator',
            'date': datetime.utcnow().strftime('%Y/%m/%d'),
            'tags': [f'attack.{family.lower()}', 'attack.command_and_control'],
            'logsource': {
                'category': 'network_connection',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'DestinationHostname|contains': c2_list
                },
                'condition': 'selection'
            },
            'falsepositives': ['Unknown'],
            'level': 'critical'
        }

    def _generate_registry_rule(self, family: str, capabilities: List[Dict]) -> Dict[str, Any]:
        """Generate registry modification detection rule."""
        return {
            'title': f'{family} Registry Persistence',
            'id': self._generate_uuid(f'{family}_registry'),
            'status': 'experimental',
            'description': f'Detects {family} registry persistence mechanisms',
            'author': 'KP14 Auto-Generator',
            'date': datetime.utcnow().strftime('%Y/%m/%d'),
            'tags': [f'attack.{family.lower()}', 'attack.persistence'],
            'logsource': {
                'category': 'registry_event',
                'product': 'windows'
            },
            'detection': {
                'selection': {
                    'TargetObject|contains': [
                        '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                        '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
                    ]
                },
                'condition': 'selection'
            },
            'falsepositives': ['Legitimate software installation'],
            'level': 'high'
        }

    def _generate_uuid(self, seed: str) -> str:
        """Generate deterministic UUID."""
        import hashlib
        import uuid
        hash_obj = hashlib.md5(seed.encode())
        return str(uuid.UUID(hash_obj.hexdigest()))

    def export_to_yaml(self, rules: List[Dict[str, Any]]) -> List[str]:
        """Export rules to YAML format."""
        return [yaml.dump(rule, default_flow_style=False) for rule in rules]

    def save_rules(self, rules: List[Dict[str, Any]], output_dir: str):
        """Save Sigma rules to files."""
        import os
        for i, rule in enumerate(rules, 1):
            filename = f'sigma_rule_{i}_{rule.get("id", "unknown")[:8]}.yml'
            filepath = os.path.join(output_dir, filename)
            with open(filepath, 'w') as f:
                yaml.dump(rule, f, default_flow_style=False)
