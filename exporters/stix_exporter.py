"""STIX Export Module - Convert analysis results to STIX 2.1 bundles"""

import json
import uuid
from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime


class STIXExporter:
    """Export analysis results as STIX 2.1 bundles"""

    STIX_VERSION = "2.1"

    def __init__(self):
        """Initialize STIX exporter"""
        pass

    def export(self, result: Dict[str, Any], output_path: str = None) -> Dict[str, Any]:
        """
        Export analysis result as STIX bundle

        Args:
            result: Analysis result dictionary
            output_path: Optional file path to write JSON

        Returns:
            STIX bundle dictionary
        """
        bundle = self._create_stix_bundle(result)

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                json.dump(bundle, f, indent=2)

        return bundle

    def export_batch(self, results: List[Dict[str, Any]], output_path: str) -> Dict[str, Any]:
        """
        Export multiple results as single STIX bundle

        Args:
            results: List of analysis results
            output_path: File path to write JSON

        Returns:
            STIX bundle with all results
        """
        all_objects = []

        for result in results:
            bundle = self._create_stix_bundle(result)
            all_objects.extend(bundle['objects'])

        # Create combined bundle
        combined_bundle = {
            "type": "bundle",
            "id": f"bundle--{self._generate_uuid()}",
            "spec_version": self.STIX_VERSION,
            "objects": all_objects
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(combined_bundle, f, indent=2)

        return combined_bundle

    def _create_stix_bundle(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Create STIX bundle structure from analysis result"""
        pe_info = result.get('static_pe_analysis', {}).get('pe_info', {})
        threat = result.get('threat_assessment', {})
        intelligence = result.get('intelligence', {})

        timestamp = datetime.utcnow().isoformat() + "Z"
        objects = []

        # Create file object
        file_obj = self._create_file_object(result, pe_info, timestamp)
        objects.append(file_obj)

        # Create indicator if malicious
        if threat.get('level') in ['suspicious', 'malware']:
            indicator = self._create_indicator(result, pe_info, threat, timestamp)
            objects.append(indicator)

        # Create malware object if detected
        if intelligence.get('malware_family'):
            malware = self._create_malware_object(intelligence, timestamp)
            objects.append(malware)

            # Create relationship between indicator and malware
            if len(objects) >= 2:
                relationship = self._create_relationship(
                    objects[1]['id'],  # indicator
                    objects[2]['id'],  # malware
                    "indicates",
                    timestamp
                )
                objects.append(relationship)

        # Create network traffic objects for C2
        for c2 in intelligence.get('c2_endpoints', [])[:10]:
            network_obj = self._create_network_traffic(c2, timestamp)
            if network_obj:
                objects.append(network_obj)

        # Create MITRE ATT&CK objects
        for technique in intelligence.get('mitre_attack', []):
            attack_pattern = self._create_attack_pattern(technique, timestamp)
            objects.append(attack_pattern)

        # Create bundle
        bundle = {
            "type": "bundle",
            "id": f"bundle--{self._generate_uuid()}",
            "spec_version": self.STIX_VERSION,
            "objects": objects
        }

        return bundle

    def _create_file_object(self, result: Dict[str, Any], pe_info: Dict[str, Any],
                           timestamp: str) -> Dict[str, Any]:
        """Create STIX file object"""
        hashes = pe_info.get('hashes', {})

        file_obj = {
            "type": "file",
            "spec_version": self.STIX_VERSION,
            "id": f"file--{self._generate_uuid()}",
            "name": Path(result.get('file_path', 'unknown')).name,
            "hashes": {}
        }

        # Add hashes
        if isinstance(hashes, dict):
            for hash_type, hash_value in hashes.items():
                if hash_value:
                    file_obj["hashes"][hash_type.upper()] = hash_value

        # Add size
        if pe_info.get('file_size'):
            file_obj["size"] = pe_info['file_size']

        return file_obj

    def _create_indicator(self, result: Dict[str, Any], pe_info: Dict[str, Any],
                         threat: Dict[str, Any], timestamp: str) -> Dict[str, Any]:
        """Create STIX indicator object"""
        hashes = pe_info.get('hashes', {})
        md5_hash = hashes.get('md5', 'unknown') if isinstance(hashes, dict) else 'unknown'

        # Create pattern
        pattern = f"[file:hashes.MD5 = '{md5_hash}']"

        # Add additional patterns if available
        if hashes.get('sha256'):
            pattern = f"[file:hashes.'SHA-256' = '{hashes['sha256']}']"

        indicator = {
            "type": "indicator",
            "spec_version": self.STIX_VERSION,
            "id": f"indicator--{self._generate_uuid()}",
            "created": timestamp,
            "modified": timestamp,
            "name": f"KP14 Detection: {Path(result.get('file_path', 'unknown')).name}",
            "description": f"Threat Level: {threat.get('level', 'unknown')}. " +
                          f"Indicators: {', '.join(threat.get('indicators', [])[:3])}",
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": timestamp,
            "labels": [threat.get('level', 'unknown')]
        }

        # Add confidence
        confidence = threat.get('confidence', 0.5)
        indicator["confidence"] = int(confidence * 100)

        return indicator

    def _create_malware_object(self, intelligence: Dict[str, Any], timestamp: str) -> Dict[str, Any]:
        """Create STIX malware object"""
        family = intelligence.get('malware_family', 'Unknown')

        malware = {
            "type": "malware",
            "spec_version": self.STIX_VERSION,
            "id": f"malware--{self._generate_uuid()}",
            "created": timestamp,
            "modified": timestamp,
            "name": family,
            "is_family": True,
            "malware_types": ["backdoor", "remote-access-trojan"]
        }

        # Add description if available
        if family.lower() == 'keyplug':
            malware["description"] = "APT41 KEYPLUG backdoor with steganographic capabilities"
            malware["aliases"] = ["KeyPlug", "KEYPLUG"]

        return malware

    def _create_network_traffic(self, c2_endpoint: str, timestamp: str) -> Dict[str, Any]:
        """Create STIX network traffic or URL object"""
        if c2_endpoint.startswith('http'):
            # Create URL object
            return {
                "type": "url",
                "spec_version": self.STIX_VERSION,
                "id": f"url--{self._generate_uuid()}",
                "value": c2_endpoint
            }
        elif '.' in c2_endpoint:
            # Create domain or IPv4 object
            if any(c.isalpha() for c in c2_endpoint.split(':')[0]):
                return {
                    "type": "domain-name",
                    "spec_version": self.STIX_VERSION,
                    "id": f"domain-name--{self._generate_uuid()}",
                    "value": c2_endpoint.split(':')[0]
                }
            else:
                return {
                    "type": "ipv4-addr",
                    "spec_version": self.STIX_VERSION,
                    "id": f"ipv4-addr--{self._generate_uuid()}",
                    "value": c2_endpoint.split(':')[0]
                }

        return None

    def _create_attack_pattern(self, technique_id: str, timestamp: str) -> Dict[str, Any]:
        """Create STIX attack pattern object"""
        return {
            "type": "attack-pattern",
            "spec_version": self.STIX_VERSION,
            "id": f"attack-pattern--{self._generate_uuid()}",
            "created": timestamp,
            "modified": timestamp,
            "name": technique_id,
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}"
                }
            ]
        }

    def _create_relationship(self, source_ref: str, target_ref: str,
                           relationship_type: str, timestamp: str) -> Dict[str, Any]:
        """Create STIX relationship object"""
        return {
            "type": "relationship",
            "spec_version": self.STIX_VERSION,
            "id": f"relationship--{self._generate_uuid()}",
            "created": timestamp,
            "modified": timestamp,
            "relationship_type": relationship_type,
            "source_ref": source_ref,
            "target_ref": target_ref
        }

    def _generate_uuid(self) -> str:
        """Generate UUID for STIX objects"""
        return str(uuid.uuid4())
