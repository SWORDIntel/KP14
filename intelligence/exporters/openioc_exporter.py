"""OpenIOC Exporter - Creates OpenIOC XML format."""

from typing import Dict, List, Any
from datetime import datetime
import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom
import uuid


class OpenIOCExporter:
    """Export intelligence to OpenIOC XML format."""

    def export(self, intelligence_data: Dict[str, Any]) -> str:
        """Export to OpenIOC XML format."""
        threat = intelligence_data.get('threat_assessment', {})
        c2_endpoints = intelligence_data.get('c2_endpoints', [])
        pe_info = intelligence_data.get('pe_info', {})

        # Create root IOC element
        ioc = ET.Element('ioc', {
            'id': str(uuid.uuid4()),
            'last-modified': datetime.utcnow().isoformat(),
            'xmlns': 'http://schemas.mandiant.com/2010/ioc'
        })

        # Metadata
        metadata = ET.SubElement(ioc, 'metadata')
        ET.SubElement(metadata, 'short_description').text = f"{threat.get('family', 'Unknown')} Indicators"
        ET.SubElement(metadata, 'description').text = threat.get('assessment_summary', '')
        ET.SubElement(metadata, 'authored_by').text = 'KP14 Intelligence'
        ET.SubElement(metadata, 'authored_date').text = datetime.utcnow().isoformat()

        # Definition (indicator logic)
        definition = ET.SubElement(ioc, 'definition')
        indicator_node = ET.SubElement(definition, 'Indicator', {'operator': 'OR'})

        # Add file hash indicators
        if pe_info:
            for hash_type in ['md5', 'sha256']:
                if hash_type in pe_info:
                    item = ET.SubElement(indicator_node, 'IndicatorItem', {'condition': 'is'})
                    ET.SubElement(item, 'Context', {'document': 'FileItem', 'search': f'FileItem/Md5sum' if hash_type == 'md5' else 'FileItem/Sha256sum'})
                    ET.SubElement(item, 'Content', {'type': 'string'}).text = pe_info[hash_type]

        # Add network indicators
        for endpoint in c2_endpoints[:20]:
            if isinstance(endpoint, dict):
                ep_type = endpoint.get('endpoint_type')
                if ep_type in ['ip', 'domain']:
                    item = ET.SubElement(indicator_node, 'IndicatorItem', {'condition': 'contains'})
                    context = 'PortItem/remoteIP' if ep_type == 'ip' else 'DnsEntryItem/Host'
                    ET.SubElement(item, 'Context', {'document': 'Network', 'search': context})
                    ET.SubElement(item, 'Content', {'type': 'string'}).text = endpoint.get('value', '')

        # Convert to pretty XML string
        return self._prettify_xml(ioc)

    def _prettify_xml(self, elem: ET.Element) -> str:
        """Return a pretty-printed XML string."""
        rough_string = ET.tostring(elem, encoding='unicode')
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ")

    def save_ioc(self, ioc_xml: str, output_path: str):
        """Save OpenIOC to file."""
        with open(output_path, 'w') as f:
            f.write(ioc_xml)
