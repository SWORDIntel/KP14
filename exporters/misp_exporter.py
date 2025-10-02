"""MISP Export Module - Convert analysis results to MISP event format"""

import json
import uuid
from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime


class MISPExporter:
    """Export analysis results as MISP events"""

    def __init__(self):
        """Initialize MISP exporter"""
        pass

    def export(self, result: Dict[str, Any], output_path: str = None) -> Dict[str, Any]:
        """
        Export analysis result as MISP event

        Args:
            result: Analysis result dictionary
            output_path: Optional file path to write JSON

        Returns:
            MISP event dictionary
        """
        event = self._create_misp_event(result)

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                json.dump(event, f, indent=2)

        return event

    def export_batch(self, results: List[Dict[str, Any]], output_path: str) -> List[Dict[str, Any]]:
        """
        Export multiple results as MISP events

        Args:
            results: List of analysis results
            output_path: File path to write JSON array

        Returns:
            List of MISP events
        """
        events = [self._create_misp_event(result) for result in results]

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(events, f, indent=2)

        return events

    def _create_misp_event(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Create MISP event structure from analysis result"""
        pe_info = result.get('static_pe_analysis', {}).get('pe_info', {})
        threat = result.get('threat_assessment', {})
        intelligence = result.get('intelligence', {})

        # Event metadata
        event_uuid = str(uuid.uuid4())
        timestamp = datetime.utcnow().strftime('%Y-%m-%d')

        event = {
            "Event": {
                "uuid": event_uuid,
                "info": f"KP14 Analysis: {Path(result.get('file_path', 'unknown')).name}",
                "date": timestamp,
                "threat_level_id": self._map_threat_level(threat.get('level', 'unknown')),
                "analysis": "2",  # Completed
                "distribution": "3",  # All communities
                "publish_timestamp": str(int(datetime.utcnow().timestamp())),
                "published": False,
                "Attribute": [],
                "Tag": []
            }
        }

        attributes = event["Event"]["Attribute"]
        tags = event["Event"]["Tag"]

        # Add file hashes
        hashes = pe_info.get('hashes', {})
        if isinstance(hashes, dict):
            for hash_type, hash_value in hashes.items():
                if hash_value:
                    attributes.append({
                        "type": hash_type.lower(),
                        "category": "Payload delivery",
                        "value": hash_value,
                        "to_ids": True,
                        "comment": f"File hash from KP14 analysis"
                    })

        # Add file size
        if pe_info.get('file_size'):
            attributes.append({
                "type": "size-in-bytes",
                "category": "Other",
                "value": str(pe_info['file_size']),
                "to_ids": False
            })

        # Add filename
        if result.get('file_path'):
            filename = Path(result['file_path']).name
            attributes.append({
                "type": "filename",
                "category": "Payload delivery",
                "value": filename,
                "to_ids": False
            })

        # Add malware family
        if intelligence.get('malware_family'):
            attributes.append({
                "type": "text",
                "category": "Attribution",
                "value": f"Malware Family: {intelligence['malware_family']}",
                "to_ids": False
            })

            tags.append({
                "name": f"malware:{intelligence['malware_family'].lower()}"
            })

        # Add C2 endpoints
        for c2 in intelligence.get('c2_endpoints', [])[:10]:  # Limit to 10
            # Determine type
            if c2.startswith('http'):
                attr_type = "url"
            elif ':' in c2:
                attr_type = "ip-dst|port"
            else:
                attr_type = "domain"

            attributes.append({
                "type": attr_type,
                "category": "Network activity",
                "value": c2,
                "to_ids": True,
                "comment": "C2 endpoint extracted by KP14"
            })

        # Add MITRE ATT&CK techniques
        for technique in intelligence.get('mitre_attack', []):
            attributes.append({
                "type": "text",
                "category": "External analysis",
                "value": f"MITRE ATT&CK: {technique}",
                "to_ids": False
            })

        # Add threat indicators
        for indicator in threat.get('indicators', []):
            attributes.append({
                "type": "text",
                "category": "External analysis",
                "value": f"KP14 Indicator: {indicator}",
                "to_ids": False
            })

        # Add tags based on characteristics
        if pe_info.get('is_pe'):
            tags.append({"name": "file-type:pe"})

        obf = result.get('static_pe_analysis', {}).get('obfuscation_details', {})
        if obf.get('packed'):
            tags.append({"name": "analysis:packed"})
        if obf.get('anti_debug'):
            tags.append({"name": "analysis:anti-debug"})

        if result.get('steganography_analysis'):
            tags.append({"name": "analysis:steganography"})

        # Add threat level tag
        if threat.get('level') == 'malware':
            tags.append({"name": "threat-level:high"})
        elif threat.get('level') == 'suspicious':
            tags.append({"name": "threat-level:medium"})

        # Add APT41 tag if KeyPlug detected
        if intelligence.get('malware_family', '').lower() == 'keyplug':
            tags.append({"name": "threat-actor:apt41"})

        return event

    def _map_threat_level(self, level: str) -> str:
        """Map KP14 threat level to MISP threat level ID"""
        mapping = {
            'clean': '4',       # Undefined
            'suspicious': '3',  # Low
            'malware': '1',     # High
            'error': '4'        # Undefined
        }
        return mapping.get(level, '4')
