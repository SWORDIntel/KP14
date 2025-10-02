"""
External API Integrations

Integrates with external threat intelligence platforms:
- VirusTotal API (enrichment)
- MISP API (sharing)
- Shodan/Censys (infrastructure research)
- Custom threat feeds
"""

from typing import Dict, List, Any, Optional
import requests
import json


class APIIntegrations:
    """
    External API integrations for threat intelligence enrichment.

    Supported platforms:
    - VirusTotal
    - MISP
    - Shodan
    - Censys
    """

    def __init__(self, config: Dict[str, str] = None):
        """
        Initialize API integrations.

        Args:
            config: Dictionary with API keys:
                {
                    'virustotal_api_key': 'key',
                    'misp_url': 'url',
                    'misp_key': 'key',
                    'shodan_api_key': 'key',
                    'censys_api_id': 'id',
                    'censys_api_secret': 'secret'
                }
        """
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'KP14-Intelligence/1.0'})

    def enrich_with_virustotal(self, file_hash: str) -> Dict[str, Any]:
        """
        Enrich analysis with VirusTotal data.

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            VirusTotal report data
        """
        api_key = self.config.get('virustotal_api_key')
        if not api_key:
            return {'error': 'VirusTotal API key not configured'}

        try:
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            headers = {'x-apikey': api_key}
            response = self.session.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                return {
                    'detections': data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}),
                    'names': data.get('data', {}).get('attributes', {}).get('names', []),
                    'tags': data.get('data', {}).get('attributes', {}).get('tags', []),
                    'first_seen': data.get('data', {}).get('attributes', {}).get('first_submission_date'),
                    'sandbox_verdicts': data.get('data', {}).get('attributes', {}).get('sandbox_verdicts', {})
                }
            elif response.status_code == 404:
                return {'error': 'Hash not found in VirusTotal'}
            else:
                return {'error': f'VirusTotal API error: {response.status_code}'}

        except Exception as e:
            return {'error': f'VirusTotal request failed: {str(e)}'}

    def submit_to_misp(self, intelligence_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Submit intelligence to MISP instance.

        Args:
            intelligence_data: Intelligence data to submit

        Returns:
            MISP submission result
        """
        misp_url = self.config.get('misp_url')
        misp_key = self.config.get('misp_key')

        if not misp_url or not misp_key:
            return {'error': 'MISP URL or API key not configured'}

        try:
            from .misp_exporter import MispExporter
            exporter = MispExporter()
            misp_event = exporter.export(intelligence_data)

            headers = {
                'Authorization': misp_key,
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }

            response = self.session.post(
                f'{misp_url}/events/add',
                headers=headers,
                json=misp_event,
                timeout=30
            )

            if response.status_code == 200:
                return {'success': True, 'event_id': response.json().get('Event', {}).get('id')}
            else:
                return {'error': f'MISP submission failed: {response.status_code}'}

        except Exception as e:
            return {'error': f'MISP submission error: {str(e)}'}

    def lookup_shodan(self, ip_address: str) -> Dict[str, Any]:
        """
        Lookup IP address on Shodan.

        Args:
            ip_address: IP address to lookup

        Returns:
            Shodan data
        """
        api_key = self.config.get('shodan_api_key')
        if not api_key:
            return {'error': 'Shodan API key not configured'}

        try:
            url = f'https://api.shodan.io/shodan/host/{ip_address}'
            params = {'key': api_key}
            response = self.session.get(url, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json()
                return {
                    'ports': data.get('ports', []),
                    'hostnames': data.get('hostnames', []),
                    'country': data.get('country_name'),
                    'org': data.get('org'),
                    'asn': data.get('asn'),
                    'tags': data.get('tags', [])
                }
            else:
                return {'error': f'Shodan lookup failed: {response.status_code}'}

        except Exception as e:
            return {'error': f'Shodan request error: {str(e)}'}

    def lookup_censys(self, ip_address: str) -> Dict[str, Any]:
        """
        Lookup IP address on Censys.

        Args:
            ip_address: IP address to lookup

        Returns:
            Censys data
        """
        api_id = self.config.get('censys_api_id')
        api_secret = self.config.get('censys_api_secret')

        if not api_id or not api_secret:
            return {'error': 'Censys API credentials not configured'}

        try:
            url = f'https://search.censys.io/api/v2/hosts/{ip_address}'
            response = self.session.get(url, auth=(api_id, api_secret), timeout=30)

            if response.status_code == 200:
                data = response.json()
                return {
                    'services': data.get('result', {}).get('services', []),
                    'autonomous_system': data.get('result', {}).get('autonomous_system', {}),
                    'location': data.get('result', {}).get('location', {}),
                    'protocols': data.get('result', {}).get('protocols', [])
                }
            else:
                return {'error': f'Censys lookup failed: {response.status_code}'}

        except Exception as e:
            return {'error': f'Censys request error: {str(e)}'}

    def enrich_c2_infrastructure(self, c2_endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Enrich C2 endpoints with threat intelligence.

        Args:
            c2_endpoints: List of C2 endpoint dictionaries

        Returns:
            Enriched infrastructure data
        """
        enriched = {}

        for endpoint in c2_endpoints[:10]:  # Limit to 10 lookups
            if not isinstance(endpoint, dict):
                continue

            ep_type = endpoint.get('endpoint_type')
            value = endpoint.get('value')

            if ep_type == 'ip':
                # Lookup on Shodan and Censys
                shodan_data = self.lookup_shodan(value)
                censys_data = self.lookup_censys(value)

                enriched[value] = {
                    'type': 'ip',
                    'shodan': shodan_data,
                    'censys': censys_data
                }

        return enriched

    def check_threat_feeds(self, indicators: List[str]) -> Dict[str, Any]:
        """
        Check indicators against threat feeds.

        Args:
            indicators: List of indicators (IPs, domains, hashes)

        Returns:
            Threat feed matches
        """
        # Placeholder for custom threat feed integration
        # In production, this would query various threat feeds
        matches = {}

        for indicator in indicators:
            matches[indicator] = {
                'found_in_feeds': [],
                'confidence': 0,
                'last_seen': None
            }

        return matches

    def export_to_tip(self, intelligence_data: Dict[str, Any],  platform: str = 'misp') -> Dict[str, Any]:
        """
        Export intelligence to Threat Intelligence Platform.

        Args:
            intelligence_data: Intelligence to export
            platform: Platform name ('misp', 'opencti', etc.)

        Returns:
            Export result
        """
        if platform.lower() == 'misp':
            return self.submit_to_misp(intelligence_data)
        else:
            return {'error': f'Unsupported platform: {platform}'}

    def bulk_enrich(self, intelligence_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform bulk enrichment using all available APIs.

        Args:
            intelligence_data: Intelligence data to enrich

        Returns:
            Enriched intelligence data
        """
        enrichment = {}

        # Enrich with VirusTotal
        pe_info = intelligence_data.get('pe_info', {})
        if pe_info.get('sha256'):
            enrichment['virustotal'] = self.enrich_with_virustotal(pe_info['sha256'])

        # Enrich C2 infrastructure
        c2_endpoints = intelligence_data.get('c2_endpoints', [])
        if c2_endpoints:
            enrichment['infrastructure'] = self.enrich_c2_infrastructure(c2_endpoints)

        return enrichment
