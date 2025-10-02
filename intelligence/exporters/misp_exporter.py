"""MISP Event Exporter - Creates MISP-compatible JSON events."""

from typing import Dict, List, Any
from datetime import datetime
import uuid


class MispExporter:
    """Export intelligence to MISP event format."""

    def export(self, intelligence_data: Dict[str, Any]) -> Dict[str, Any]:
        """Export to MISP event format."""
        threat = intelligence_data.get('threat_assessment', {})
        c2_endpoints = intelligence_data.get('c2_endpoints', [])
        pe_info = intelligence_data.get('pe_info', {})

        event = {
            "Event": {
                "uuid": str(uuid.uuid4()),
                "info": f"{threat.get('family', 'Unknown')} Malware Analysis",
                "threat_level_id": self._map_threat_level(threat.get('severity', 'medium')),
                "analysis": "2",  # Completed
                "date": datetime.utcnow().strftime('%Y-%m-%d'),
                "published": False,
                "Attribute": []
            }
        }

        # Add file hashes
        if pe_info:
            for hash_type in ['md5', 'sha1', 'sha256']:
                if hash_type in pe_info:
                    event["Event"]["Attribute"].append({
                        "type": hash_type,
                        "category": "Payload delivery",
                        "value": pe_info[hash_type],
                        "to_ids": True
                    })

        # Add C2 indicators
        for endpoint in c2_endpoints[:50]:
            if isinstance(endpoint, dict):
                attr_type = self._map_endpoint_type(endpoint.get('endpoint_type'))
                if attr_type:
                    event["Event"]["Attribute"].append({
                        "type": attr_type,
                        "category": "Network activity",
                        "value": endpoint.get('value', ''),
                        "to_ids": True,
                        "comment": f"Confidence: {endpoint.get('confidence', 0)}"
                    })

        return event

    def _map_threat_level(self, severity: str) -> str:
        """Map severity to MISP threat level."""
        mapping = {'low': '3', 'medium': '2', 'high': '1', 'critical': '1'}
        return mapping.get(severity.lower(), '2')

    def _map_endpoint_type(self, ep_type: str) -> str:
        """Map endpoint type to MISP attribute type."""
        mapping = {'ip': 'ip-dst', 'domain': 'domain', 'url': 'url', 'onion': 'hostname'}
        return mapping.get(ep_type, None)

    def save_event(self, event: Dict[str, Any], output_path: str):
        """Save MISP event to file."""
        import json
        with open(output_path, 'w') as f:
            json.dump(event, f, indent=2)
