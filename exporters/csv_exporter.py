"""CSV Export Module - Convert analysis results to spreadsheet format"""

import csv
from typing import Dict, Any, List
from pathlib import Path
from datetime import datetime


class CSVExporter:
    """Export analysis results as CSV"""

    DEFAULT_FIELDS = [
        'file_path',
        'file_type',
        'file_size',
        'md5',
        'sha1',
        'sha256',
        'threat_level',
        'threat_score',
        'malware_family',
        'is_packed',
        'has_anti_debug',
        'entropy',
        'suspicious_imports',
        'c2_endpoints',
        'embedded_payloads',
        'has_steganography',
        'analysis_timestamp',
        'errors'
    ]

    def __init__(self, fields: List[str] = None):
        """
        Initialize CSV exporter

        Args:
            fields: List of field names to export (default: DEFAULT_FIELDS)
        """
        self.fields = fields or self.DEFAULT_FIELDS

    def export(self, results: List[Dict[str, Any]], output_path: str) -> None:
        """
        Export results as CSV

        Args:
            results: List of analysis results dictionaries
            output_path: File path to write CSV
        """
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.fields, extrasaction='ignore')

            # Write header
            writer.writeheader()

            # Write data rows
            for result in results:
                row = self._flatten_result(result)
                writer.writerow(row)

    def export_single(self, result: Dict[str, Any], output_path: str) -> None:
        """
        Export single result as CSV

        Args:
            result: Analysis result dictionary
            output_path: File path to write CSV
        """
        self.export([result], output_path)

    def _flatten_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Flatten nested result structure for CSV

        Args:
            result: Nested analysis result

        Returns:
            Flattened dictionary matching CSV fields
        """
        pe_info = result.get('static_pe_analysis', {}).get('pe_info', {})
        obf_details = result.get('static_pe_analysis', {}).get('obfuscation_details', {})
        threat = result.get('threat_assessment', {})
        intelligence = result.get('intelligence', {})

        # Extract file hashes
        hashes = pe_info.get('hashes', {}) if isinstance(pe_info.get('hashes'), dict) else {}

        # Extract suspicious imports
        suspicious_imports = []
        if pe_info.get('imports'):
            suspicious_keywords = ['virtual', 'thread', 'process', 'hook', 'inject']
            for dll, funcs in pe_info['imports'].items():
                for func in funcs:
                    if any(kw in func.lower() for kw in suspicious_keywords):
                        suspicious_imports.append(f"{dll}:{func}")

        # Extract C2 endpoints
        c2_endpoints = intelligence.get('c2_endpoints', [])
        c2_str = '; '.join(c2_endpoints[:5]) if c2_endpoints else ''

        return {
            'file_path': result.get('file_path', ''),
            'file_type': result.get('original_file_type', ''),
            'file_size': pe_info.get('file_size', ''),
            'md5': hashes.get('md5', ''),
            'sha1': hashes.get('sha1', ''),
            'sha256': hashes.get('sha256', ''),
            'threat_level': threat.get('level', 'unknown'),
            'threat_score': intelligence.get('threat_score', 0),
            'malware_family': intelligence.get('malware_family', ''),
            'is_packed': obf_details.get('packed', False),
            'has_anti_debug': obf_details.get('anti_debug', False),
            'entropy': round(obf_details.get('entropy_score', 0.0), 2),
            'suspicious_imports': '; '.join(suspicious_imports[:10]),
            'c2_endpoints': c2_str,
            'embedded_payloads': len(result.get('extracted_payload_analyses', [])),
            'has_steganography': bool(result.get('steganography_analysis')),
            'analysis_timestamp': datetime.utcnow().isoformat(),
            'errors': '; '.join(result.get('errors', []))
        }


class CSVBatchExporter:
    """Export batch analysis results with aggregation"""

    def export_summary(self, results: List[Dict[str, Any]], output_path: str) -> None:
        """
        Export aggregated summary of batch analysis

        Args:
            results: List of analysis results
            output_path: File path to write CSV
        """
        # Calculate statistics
        stats = {
            'total_files': len(results),
            'clean': 0,
            'suspicious': 0,
            'malware': 0,
            'errors': 0,
            'total_size': 0,
            'packed_count': 0,
            'anti_debug_count': 0,
            'c2_count': 0,
            'unique_families': set()
        }

        for result in results:
            threat = result.get('threat_assessment', {})
            level = threat.get('level', 'unknown')

            if level == 'clean':
                stats['clean'] += 1
            elif level == 'suspicious':
                stats['suspicious'] += 1
            elif level == 'malware':
                stats['malware'] += 1
            else:
                stats['errors'] += 1

            pe_info = result.get('static_pe_analysis', {}).get('pe_info', {})
            stats['total_size'] += pe_info.get('file_size', 0)

            obf = result.get('static_pe_analysis', {}).get('obfuscation_details', {})
            if obf.get('packed'):
                stats['packed_count'] += 1
            if obf.get('anti_debug'):
                stats['anti_debug_count'] += 1

            intel = result.get('intelligence', {})
            if intel.get('c2_endpoints'):
                stats['c2_count'] += 1
            if intel.get('malware_family'):
                stats['unique_families'].add(intel['malware_family'])

        # Write summary CSV
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Metric', 'Value'])
            writer.writerow(['Total Files', stats['total_files']])
            writer.writerow(['Clean', stats['clean']])
            writer.writerow(['Suspicious', stats['suspicious']])
            writer.writerow(['Malware', stats['malware']])
            writer.writerow(['Errors', stats['errors']])
            writer.writerow(['Total Size (bytes)', stats['total_size']])
            writer.writerow(['Packed Files', stats['packed_count']])
            writer.writerow(['Anti-Debug Files', stats['anti_debug_count']])
            writer.writerow(['Files with C2', stats['c2_count']])
            writer.writerow(['Unique Malware Families', len(stats['unique_families'])])
            writer.writerow(['Families', ', '.join(sorted(stats['unique_families']))])
