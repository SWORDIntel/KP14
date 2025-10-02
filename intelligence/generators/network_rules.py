"""
Network Rule Generator (Suricata/Snort)

Generates network detection rules from C2 indicators:
- Suricata IDS rules
- Snort signatures
- HTTP/HTTPS/DNS traffic patterns
- Tor detection rules
"""

from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class NetworkRule:
    """Represents a network detection rule."""
    rule_type: str  # 'suricata' or 'snort'
    action: str  # 'alert', 'drop', 'reject'
    protocol: str  # 'tcp', 'udp', 'http', etc.
    source: str
    destination: str
    rule_options: List[str]
    sid: int
    message: str
    confidence: int
    metadata: Dict[str, str]


class NetworkRuleGenerator:
    """
    Automatic network rule generator for IDS/IPS systems.

    Supports:
    - Suricata rules
    - Snort rules
    - Protocol-specific detection
    """

    def __init__(self, start_sid: int = 5000000):
        """Initialize with starting SID."""
        self.current_sid = start_sid

    def generate(self, c2_data: List[Dict[str, Any]], threat_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Generate network rules from C2 indicators.

        Returns:
            Dictionary with 'suricata' and 'snort' rule lists
        """
        rules = {'suricata': [], 'snort': []}

        for endpoint in c2_data:
            if not isinstance(endpoint, dict):
                continue

            ep_type = endpoint.get('endpoint_type', '')
            value = endpoint.get('value', '')
            protocol = endpoint.get('protocol', '').lower()
            confidence = endpoint.get('confidence', 0)

            if confidence < 70:  # Only high confidence indicators
                continue

            # Generate rules based on type
            if ep_type == 'ip':
                rules['suricata'].extend(self._generate_ip_rules(value, endpoint, threat_data))
                rules['snort'].extend(self._generate_ip_rules(value, endpoint, threat_data, format='snort'))

            elif ep_type == 'domain':
                rules['suricata'].extend(self._generate_domain_rules(value, endpoint, threat_data))
                rules['snort'].extend(self._generate_domain_rules(value, endpoint, threat_data, format='snort'))

            elif ep_type == 'url':
                rules['suricata'].extend(self._generate_url_rules(value, endpoint, threat_data))
                rules['snort'].extend(self._generate_url_rules(value, endpoint, threat_data, format='snort'))

            elif ep_type == 'onion':
                rules['suricata'].extend(self._generate_tor_rules(value, endpoint, threat_data))

        return rules

    def _generate_ip_rules(self, ip: str, endpoint: Dict, threat: Dict, format: str = 'suricata') -> List[str]:
        """Generate IP-based detection rules."""
        rules = []
        family = threat.get('family', 'Unknown')
        severity = threat.get('severity', 'medium')

        # HTTP traffic to C2 IP
        rule = self._format_rule(
            format=format,
            action='alert',
            protocol='tcp',
            source='$HOME_NET',
            destination=ip,
            dest_port='any',
            options=[
                f'msg:"Potential {family} C2 Communication to {ip}"',
                f'flow:to_server,established',
                f'threshold:type limit,track by_src,count 1,seconds 3600',
                f'classtype:trojan-activity',
                f'sid:{self._get_next_sid()}',
                'rev:1'
            ]
        )
        rules.append(rule)

        # DNS queries for IP (reverse lookup)
        if format == 'suricata':
            rule = self._format_rule(
                format=format,
                action='alert',
                protocol='dns',
                source='$HOME_NET',
                destination='any',
                dest_port='53',
                options=[
                    f'msg:"DNS Query for {family} C2 IP {ip}"',
                    f'dns.query; content:"{ip}"; nocase',
                    f'classtype:trojan-activity',
                    f'sid:{self._get_next_sid()}',
                    'rev:1'
                ]
            )
            rules.append(rule)

        return rules

    def _generate_domain_rules(self, domain: str, endpoint: Dict, threat: Dict, format: str = 'suricata') -> List[str]:
        """Generate domain-based detection rules."""
        rules = []
        family = threat.get('family', 'Unknown')

        # DNS query detection
        if format == 'suricata':
            rule = self._format_rule(
                format='suricata',
                action='alert',
                protocol='dns',
                source='$HOME_NET',
                destination='any',
                dest_port='53',
                options=[
                    f'msg:"{family} C2 Domain Query - {domain}"',
                    f'dns.query; content:"{domain}"; nocase; endswith',
                    f'classtype:trojan-activity',
                    f'sid:{self._get_next_sid()}',
                    'rev:1'
                ]
            )
            rules.append(rule)
        else:
            # Snort DNS detection
            rule = self._format_rule(
                format='snort',
                action='alert',
                protocol='udp',
                source='$HOME_NET',
                destination='any',
                dest_port='53',
                options=[
                    f'msg:"{family} C2 Domain Query - {domain}"',
                    f'content:"|01 00 00 01|"; offset:2; depth:4',
                    f'content:"{self._encode_domain(domain)}"; nocase',
                    f'classtype:trojan-activity',
                    f'sid:{self._get_next_sid()}',
                    'rev:1'
                ]
            )
            rules.append(rule)

        # HTTP Host header detection
        if format == 'suricata':
            rule = self._format_rule(
                format='suricata',
                action='alert',
                protocol='http',
                source='$HOME_NET',
                destination='any',
                dest_port='any',
                options=[
                    f'msg:"{family} C2 HTTP Communication - {domain}"',
                    f'http.host; content:"{domain}"; nocase; endswith',
                    f'flow:to_server,established',
                    f'classtype:trojan-activity',
                    f'sid:{self._get_next_sid()}',
                    'rev:1'
                ]
            )
            rules.append(rule)

        return rules

    def _generate_url_rules(self, url: str, endpoint: Dict, threat: Dict, format: str = 'suricata') -> List[str]:
        """Generate URL-based detection rules."""
        rules = []
        family = threat.get('family', 'Unknown')

        # Parse URL components
        if '://' in url:
            protocol, rest = url.split('://', 1)
            if '/' in rest:
                host, uri = rest.split('/', 1)
                uri = '/' + uri
            else:
                host = rest
                uri = '/'
        else:
            return rules

        if format == 'suricata':
            rule = self._format_rule(
                format='suricata',
                action='alert',
                protocol='http',
                source='$HOME_NET',
                destination='any',
                dest_port='any',
                options=[
                    f'msg:"{family} C2 URL Access - {url}"',
                    f'http.host; content:"{host}"; nocase',
                    f'http.uri; content:"{uri}"; startswith',
                    f'flow:to_server,established',
                    f'classtype:trojan-activity',
                    f'sid:{self._get_next_sid()}',
                    'rev:1'
                ]
            )
            rules.append(rule)

        return rules

    def _generate_tor_rules(self, onion: str, endpoint: Dict, threat: Dict) -> List[str]:
        """Generate Tor .onion detection rules."""
        rules = []
        family = threat.get('family', 'Unknown')

        # Detect .onion in traffic (Suricata only)
        rule = self._format_rule(
            format='suricata',
            action='alert',
            protocol='tls',
            source='$HOME_NET',
            destination='any',
            dest_port='any',
            options=[
                f'msg:"{family} Tor Hidden Service Access - {onion}"',
                f'tls.sni; content:"{onion}"; nocase; endswith',
                f'flow:to_server,established',
                f'classtype:trojan-activity',
                f'sid:{self._get_next_sid()}',
                'rev:1'
            ]
        )
        rules.append(rule)

        return rules

    def _format_rule(self, format: str, action: str, protocol: str, source: str,
                     destination: str, dest_port: str, options: List[str]) -> str:
        """Format rule in Suricata or Snort syntax."""
        if format == 'suricata':
            rule_parts = [
                action,
                protocol,
                source,
                'any',
                '->',
                destination,
                dest_port,
                f'({"; ".join(options)};)'
            ]
        else:  # snort
            rule_parts = [
                action,
                protocol,
                source,
                'any',
                '->',
                destination,
                dest_port,
                f'({"; ".join(options)};)'
            ]

        return ' '.join(rule_parts)

    def _encode_domain(self, domain: str) -> str:
        """Encode domain for DNS packet matching (Snort format)."""
        # Simple encoding: length-prefixed labels
        parts = domain.split('.')
        encoded_parts = [f"|{len(part):02x}|{part}" for part in parts]
        return ''.join(encoded_parts)

    def _get_next_sid(self) -> int:
        """Get next SID and increment."""
        sid = self.current_sid
        self.current_sid += 1
        return sid

    def export_to_file(self, rules: Dict[str, List[str]], output_dir: str):
        """Export rules to separate files."""
        import os

        # Export Suricata rules
        suricata_path = os.path.join(output_dir, 'kp14_generated.rules')
        with open(suricata_path, 'w') as f:
            f.write('# Auto-generated Suricata rules\n')
            f.write(f'# Generated by KP14 at {datetime.utcnow().isoformat()}\n\n')
            for rule in rules.get('suricata', []):
                f.write(rule + '\n')

        # Export Snort rules
        snort_path = os.path.join(output_dir, 'kp14_generated_snort.rules')
        with open(snort_path, 'w') as f:
            f.write('# Auto-generated Snort rules\n')
            f.write(f'# Generated by KP14 at {datetime.utcnow().isoformat()}\n\n')
            for rule in rules.get('snort', []):
                f.write(rule + '\n')
