"""
STIX 2.1 Exporter

Exports threat intelligence in STIX 2.1 format:
- Indicator objects
- Malware objects
- Attack patterns (MITRE ATT&CK)
- Relationships
- Bundle creation
"""

from typing import Dict, List, Any
from datetime import datetime
import uuid
import hashlib


class StixExporter:
    """Export intelligence to STIX 2.1 format."""

    def __init__(self):
        """Initialize STIX exporter."""
        self.stix_version = "2.1"
        self.namespace = "kp14"

    def export(self, intelligence_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Export complete intelligence to STIX bundle.

        Args:
            intelligence_data: Complete intelligence analysis results

        Returns:
            STIX 2.1 bundle
        """
        objects = []

        # Create identity (analyst/organization)
        identity = self._create_identity()
        objects.append(identity)

        # Create malware object
        malware = self._create_malware(intelligence_data, identity)
        objects.append(malware)

        # Create indicators from C2 endpoints
        indicators = self._create_indicators(intelligence_data, identity)
        objects.extend(indicators)

        # Create attack patterns from MITRE techniques
        attack_patterns = self._create_attack_patterns(intelligence_data, identity)
        objects.extend(attack_patterns)

        # Create relationships
        relationships = self._create_relationships(malware, indicators, attack_patterns)
        objects.extend(relationships)

        # Create bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{self._generate_uuid()}",
            "objects": objects
        }

        return bundle

    def _create_identity(self) -> Dict[str, Any]:
        """Create STIX identity object."""
        return {
            "type": "identity",
            "spec_version": self.stix_version,
            "id": f"identity--{self._generate_uuid('kp14-intelligence')}",
            "created": self._get_timestamp(),
            "modified": self._get_timestamp(),
            "name": "KP14 Intelligence Module",
            "identity_class": "system",
            "description": "Automated malware intelligence extraction system"
        }

    def _create_malware(self, data: Dict[str, Any], identity: Dict) -> Dict[str, Any]:
        """Create STIX malware object."""
        threat = data.get('threat_assessment', {})
        family = threat.get('family', 'unknown')

        malware_obj = {
            "type": "malware",
            "spec_version": self.stix_version,
            "id": f"malware--{self._generate_uuid(family)}",
            "created": self._get_timestamp(),
            "modified": self._get_timestamp(),
            "name": family,
            "is_family": True,
            "malware_types": self._get_malware_types(threat),
            "created_by_ref": identity["id"]
        }

        # Add optional fields
        if threat.get('description'):
            malware_obj["description"] = threat["description"]

        # Add capabilities
        capabilities = threat.get('capabilities', [])
        if capabilities:
            cap_names = [c.get('capability', '') for c in capabilities if isinstance(c, dict)]
            malware_obj["capabilities"] = cap_names[:10]

        return malware_obj

    def _create_indicators(self, data: Dict[str, Any], identity: Dict) -> List[Dict[str, Any]]:
        """Create STIX indicator objects from C2 endpoints."""
        indicators = []
        c2_endpoints = data.get('c2_endpoints', [])

        for endpoint in c2_endpoints[:50]:  # Limit to 50 indicators
            if not isinstance(endpoint, dict):
                continue

            ep_type = endpoint.get('endpoint_type', '')
            value = endpoint.get('value', '')
            confidence = endpoint.get('confidence', 0)

            # Map to STIX pattern
            pattern = self._create_stix_pattern(ep_type, value)
            if not pattern:
                continue

            indicator = {
                "type": "indicator",
                "spec_version": self.stix_version,
                "id": f"indicator--{self._generate_uuid(value)}",
                "created": self._get_timestamp(),
                "modified": self._get_timestamp(),
                "name": f"{ep_type.upper()}: {value}",
                "description": f"C2 endpoint detected in malware analysis",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": self._get_timestamp(),
                "indicator_types": ["malicious-activity"],
                "confidence": confidence,
                "created_by_ref": identity["id"]
            }

            indicators.append(indicator)

        return indicators

    def _create_attack_patterns(self, data: Dict[str, Any], identity: Dict) -> List[Dict[str, Any]]:
        """Create STIX attack pattern objects from MITRE techniques."""
        patterns = []
        threat = data.get('threat_assessment', {})
        techniques = threat.get('mitre_techniques', [])

        for technique in techniques[:30]:  # Limit to 30 techniques
            if not isinstance(technique, dict):
                continue

            pattern = {
                "type": "attack-pattern",
                "spec_version": self.stix_version,
                "id": f"attack-pattern--{self._generate_uuid(technique.get('technique_id', ''))}",
                "created": self._get_timestamp(),
                "modified": self._get_timestamp(),
                "name": technique.get('technique_name', 'Unknown'),
                "description": f"MITRE ATT&CK Technique: {technique.get('technique_id', '')}",
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique.get('technique_id', ''),
                        "url": f"https://attack.mitre.org/techniques/{technique.get('technique_id', '').replace('.', '/')}"
                    }
                ],
                "kill_chain_phases": [
                    {
                        "kill_chain_name": "mitre-attack",
                        "phase_name": technique.get('tactic', 'unknown').lower().replace(' ', '-')
                    }
                ],
                "created_by_ref": identity["id"]
            }

            patterns.append(pattern)

        return patterns

    def _create_relationships(self, malware: Dict, indicators: List[Dict],
                            attack_patterns: List[Dict]) -> List[Dict[str, Any]]:
        """Create STIX relationship objects."""
        relationships = []

        # Malware uses attack patterns
        for pattern in attack_patterns:
            rel = {
                "type": "relationship",
                "spec_version": self.stix_version,
                "id": f"relationship--{self._generate_uuid()}",
                "created": self._get_timestamp(),
                "modified": self._get_timestamp(),
                "relationship_type": "uses",
                "source_ref": malware["id"],
                "target_ref": pattern["id"]
            }
            relationships.append(rel)

        # Indicators indicate malware
        for indicator in indicators:
            rel = {
                "type": "relationship",
                "spec_version": self.stix_version,
                "id": f"relationship--{self._generate_uuid()}",
                "created": self._get_timestamp(),
                "modified": self._get_timestamp(),
                "relationship_type": "indicates",
                "source_ref": indicator["id"],
                "target_ref": malware["id"]
            }
            relationships.append(rel)

        return relationships

    def _create_stix_pattern(self, endpoint_type: str, value: str) -> str:
        """Create STIX pattern from endpoint."""
        if endpoint_type == 'ip':
            return f"[ipv4-addr:value = '{value}']"
        elif endpoint_type == 'domain':
            return f"[domain-name:value = '{value}']"
        elif endpoint_type == 'url':
            return f"[url:value = '{value}']"
        elif endpoint_type == 'onion':
            return f"[domain-name:value = '{value}']"
        return None

    def _get_malware_types(self, threat: Dict) -> List[str]:
        """Determine STIX malware types."""
        types = []
        capabilities = threat.get('capabilities', [])

        for cap in capabilities:
            if isinstance(cap, dict):
                category = cap.get('category', '').lower()
                if 'backdoor' in category:
                    types.append('backdoor')
                elif 'trojan' in category:
                    types.append('trojan')
                elif 'downloader' in category:
                    types.append('downloader')
                elif 'ransomware' in category:
                    types.append('ransomware')

        if not types:
            types = ['unknown']

        return list(set(types))[:5]  # Deduplicate and limit

    def _generate_uuid(self, seed: str = None) -> str:
        """Generate UUID (deterministic if seed provided)."""
        if seed:
            hash_obj = hashlib.md5(seed.encode())
            return str(uuid.UUID(hash_obj.hexdigest()))
        return str(uuid.uuid4())

    def _get_timestamp(self) -> str:
        """Get current timestamp in STIX format."""
        return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')

    def save_bundle(self, bundle: Dict[str, Any], output_path: str):
        """Save STIX bundle to file."""
        import json
        with open(output_path, 'w') as f:
            json.dump(bundle, f, indent=2)
