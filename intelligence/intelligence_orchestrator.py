"""
Intelligence Orchestrator

Main orchestration module that coordinates all intelligence components:
- C2 extraction
- Threat assessment
- Rule generation
- Export to TI platforms
- Correlation analysis
"""

from typing import Dict, List, Any, Optional
from datetime import datetime
import os
import json

from .extractors.c2_extractor import C2Extractor
from .scorers.threat_scorer import ThreatScorer
from .generators.yara_generator import YaraGenerator
from .generators.network_rules import NetworkRuleGenerator
from .generators.sigma_generator import SigmaGenerator
from .exporters.stix_exporter import StixExporter
from .exporters.misp_exporter import MispExporter
from .exporters.openioc_exporter import OpenIOCExporter
from .database.pattern_db import PatternDatabase
from .correlation.correlator import CorrelationEngine
from .integrations.api_integrations import APIIntegrations


class IntelligenceOrchestrator:
    """
    Main intelligence orchestrator.

    Coordinates all intelligence extraction, analysis, and export operations.
    """

    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize intelligence orchestrator.

        Args:
            config: Configuration dictionary with settings
        """
        self.config = config or {}

        # Initialize components
        self.c2_extractor = C2Extractor()
        self.threat_scorer = ThreatScorer()
        self.yara_generator = YaraGenerator()
        self.network_rule_generator = NetworkRuleGenerator()
        self.sigma_generator = SigmaGenerator()
        self.stix_exporter = StixExporter()
        self.misp_exporter = MispExporter()
        self.openioc_exporter = OpenIOCExporter()
        self.pattern_db = PatternDatabase()
        self.correlation_engine = CorrelationEngine()
        self.api_integrations = APIIntegrations(config.get('api_keys', {}))

        # Output directory
        self.output_dir = config.get('output_dir', 'intelligence_output')
        os.makedirs(self.output_dir, exist_ok=True)

    def analyze(self, sample_data: Dict[str, Any], sample_id: str = None) -> Dict[str, Any]:
        """
        Perform complete intelligence analysis.

        Args:
            sample_data: Analysis data from KP14 pipeline containing:
                - strings: List of extracted strings
                - pe_info: PE file information
                - behaviors: List of detected behaviors
                - metadata: Additional metadata
            sample_id: Optional sample identifier

        Returns:
            Complete intelligence report
        """
        print("[*] Starting intelligence analysis...")

        # Generate sample ID if not provided
        if not sample_id:
            sample_id = sample_data.get('pe_info', {}).get('sha256', 'unknown')[:16]

        intelligence_report = {
            'sample_id': sample_id,
            'timestamp': datetime.utcnow().isoformat(),
            'analysis_version': '1.0.0'
        }

        # Step 1: Extract C2 endpoints
        print("[*] Extracting C2 endpoints...")
        c2_result = self.c2_extractor.extract(
            data=sample_data.get('raw_data', b''),
            strings=sample_data.get('strings', []),
            metadata=sample_data.get('pe_info', {})
        )
        intelligence_report['c2_extraction'] = self.c2_extractor.export_to_dict(c2_result)

        # Step 2: Perform threat assessment
        print("[*] Performing threat assessment...")
        analysis_data = {
            'strings': sample_data.get('strings', []),
            'c2_endpoints': c2_result.endpoints,
            'pe_info': sample_data.get('pe_info', {}),
            'behaviors': sample_data.get('behaviors', []),
            'metadata': sample_data.get('metadata', {})
        }
        threat_assessment = self.threat_scorer.assess(analysis_data)
        intelligence_report['threat_assessment'] = self.threat_scorer.export_to_dict(threat_assessment)

        # Step 3: Check against pattern database
        print("[*] Checking pattern database...")
        pattern_matches = self.pattern_db.match_patterns(analysis_data)
        intelligence_report['pattern_matches'] = pattern_matches

        # Step 4: Generate YARA rules
        print("[*] Generating YARA rules...")
        full_data = {**analysis_data, 'threat_assessment': threat_assessment.__dict__}
        yara_rules = self.yara_generator.generate(full_data)
        intelligence_report['yara_rules'] = [
            {'name': rule.name, 'confidence': rule.confidence}
            for rule in yara_rules
        ]

        # Save YARA rules
        if yara_rules:
            yara_path = os.path.join(self.output_dir, f'{sample_id}_rules.yar')
            self.yara_generator.save_rules(yara_rules, yara_path)
            print(f"[+] YARA rules saved to: {yara_path}")

        # Step 5: Generate network rules
        print("[*] Generating network detection rules...")
        network_rules = self.network_rule_generator.generate(
            [self.c2_extractor.export_to_dict(c2_result)['endpoints'][i]
             for i in range(len(c2_result.endpoints))],
            self.threat_scorer.export_to_dict(threat_assessment)
        )
        intelligence_report['network_rules'] = {
            'suricata_count': len(network_rules.get('suricata', [])),
            'snort_count': len(network_rules.get('snort', []))
        }

        # Save network rules
        if network_rules.get('suricata') or network_rules.get('snort'):
            self.network_rule_generator.export_to_file(network_rules, self.output_dir)
            print(f"[+] Network rules saved to: {self.output_dir}")

        # Step 6: Generate Sigma rules
        print("[*] Generating Sigma rules...")
        sigma_rules = self.sigma_generator.generate(
            self.threat_scorer.export_to_dict(threat_assessment),
            [cap.__dict__ if hasattr(cap, '__dict__') else cap
             for cap in threat_assessment.capabilities]
        )
        intelligence_report['sigma_rules'] = {'count': len(sigma_rules)}

        # Save Sigma rules
        if sigma_rules:
            self.sigma_generator.save_rules(sigma_rules, self.output_dir)
            print(f"[+] Sigma rules saved to: {self.output_dir}")

        # Step 7: Export to STIX 2.1
        print("[*] Generating STIX 2.1 bundle...")
        intel_data = {
            'c2_endpoints': [ep.__dict__ if hasattr(ep, '__dict__') else ep
                           for ep in c2_result.endpoints],
            'threat_assessment': self.threat_scorer.export_to_dict(threat_assessment),
            'pe_info': sample_data.get('pe_info', {})
        }
        stix_bundle = self.stix_exporter.export(intel_data)
        intelligence_report['stix_bundle'] = {
            'object_count': len(stix_bundle.get('objects', []))
        }

        # Save STIX bundle
        stix_path = os.path.join(self.output_dir, f'{sample_id}_stix.json')
        self.stix_exporter.save_bundle(stix_bundle, stix_path)
        print(f"[+] STIX bundle saved to: {stix_path}")

        # Step 8: Export to MISP
        print("[*] Generating MISP event...")
        misp_event = self.misp_exporter.export(intel_data)
        intelligence_report['misp_event'] = {
            'attribute_count': len(misp_event.get('Event', {}).get('Attribute', []))
        }

        # Save MISP event
        misp_path = os.path.join(self.output_dir, f'{sample_id}_misp.json')
        self.misp_exporter.save_event(misp_event, misp_path)
        print(f"[+] MISP event saved to: {misp_path}")

        # Step 9: Export to OpenIOC
        print("[*] Generating OpenIOC...")
        openioc_xml = self.openioc_exporter.export(intel_data)
        intelligence_report['openioc'] = {'generated': True}

        # Save OpenIOC
        openioc_path = os.path.join(self.output_dir, f'{sample_id}_openioc.xml')
        self.openioc_exporter.save_ioc(openioc_xml, openioc_path)
        print(f"[+] OpenIOC saved to: {openioc_path}")

        # Step 10: Correlation analysis
        print("[*] Performing correlation analysis...")
        self.correlation_engine.add_sample(sample_id, intel_data)
        correlations = self.correlation_engine.correlate_sample(sample_id)
        intelligence_report['correlations'] = correlations

        # Step 11: External enrichment (if configured)
        if self.config.get('enable_enrichment', False):
            print("[*] Enriching with external APIs...")
            enrichment = self.api_integrations.bulk_enrich(intel_data)
            intelligence_report['enrichment'] = enrichment

        # Generate final summary
        intelligence_report['summary'] = self._generate_summary(intelligence_report)

        # Save complete intelligence report
        report_path = os.path.join(self.output_dir, f'{sample_id}_intelligence.json')
        with open(report_path, 'w') as f:
            json.dump(intelligence_report, f, indent=2, default=str)
        print(f"[+] Intelligence report saved to: {report_path}")

        print("[+] Intelligence analysis complete!")
        return intelligence_report

    def _generate_summary(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of intelligence analysis."""
        threat = report.get('threat_assessment', {})

        summary = {
            'threat_score': threat.get('threat_score', 0),
            'severity': threat.get('severity', 'unknown'),
            'family': threat.get('family', 'unknown'),
            'family_confidence': threat.get('family_confidence', 0),
            'c2_endpoints_found': len(report.get('c2_extraction', {}).get('endpoints', [])),
            'mitre_techniques': len(threat.get('mitre_techniques', [])),
            'yara_rules_generated': len(report.get('yara_rules', [])),
            'network_rules_generated': (
                report.get('network_rules', {}).get('suricata_count', 0) +
                report.get('network_rules', {}).get('snort_count', 0)
            ),
            'sigma_rules_generated': report.get('sigma_rules', {}).get('count', 0),
            'stix_objects': report.get('stix_bundle', {}).get('object_count', 0),
            'similar_samples': len(report.get('correlations', {}).get('similar_samples', [])),
            'assessment': threat.get('summary', 'No assessment available')
        }

        return summary

    def batch_analyze(self, samples: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze multiple samples in batch.

        Args:
            samples: List of sample data dictionaries

        Returns:
            List of intelligence reports
        """
        results = []

        for i, sample_data in enumerate(samples, 1):
            print(f"\n[*] Analyzing sample {i}/{len(samples)}...")
            try:
                result = self.analyze(sample_data)
                results.append(result)
            except Exception as e:
                print(f"[!] Error analyzing sample {i}: {e}")
                results.append({'error': str(e)})

        # Generate batch summary
        batch_summary = self._generate_batch_summary(results)

        # Save batch report
        batch_path = os.path.join(self.output_dir, 'batch_intelligence_report.json')
        with open(batch_path, 'w') as f:
            json.dump({
                'samples_analyzed': len(samples),
                'successful': sum(1 for r in results if 'error' not in r),
                'failed': sum(1 for r in results if 'error' in r),
                'summary': batch_summary,
                'reports': results
            }, f, indent=2, default=str)

        print(f"\n[+] Batch analysis complete! Report saved to: {batch_path}")
        return results

    def _generate_batch_summary(self, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary for batch analysis."""
        successful_reports = [r for r in reports if 'error' not in r]

        if not successful_reports:
            return {'error': 'No successful analyses'}

        return {
            'total_samples': len(reports),
            'successful': len(successful_reports),
            'average_threat_score': sum(
                r.get('summary', {}).get('threat_score', 0)
                for r in successful_reports
            ) / len(successful_reports),
            'families_detected': list(set(
                r.get('summary', {}).get('family', 'unknown')
                for r in successful_reports
            )),
            'total_c2_endpoints': sum(
                r.get('summary', {}).get('c2_endpoints_found', 0)
                for r in successful_reports
            ),
            'total_rules_generated': sum(
                r.get('summary', {}).get('yara_rules_generated', 0) +
                r.get('summary', {}).get('network_rules_generated', 0) +
                r.get('summary', {}).get('sigma_rules_generated', 0)
                for r in successful_reports
            )
        }

    def export_campaign_report(self, campaign_name: str, sample_ids: List[str]) -> str:
        """
        Create campaign report from multiple samples.

        Args:
            campaign_name: Name of the campaign
            sample_ids: List of sample IDs to include

        Returns:
            Path to campaign report
        """
        campaign_id = self.correlation_engine.create_campaign(campaign_name, sample_ids)
        campaign_data = self.correlation_engine.campaigns.get(campaign_id, {})

        # Save campaign report
        report_path = os.path.join(self.output_dir, f'campaign_{campaign_id}.json')
        with open(report_path, 'w') as f:
            json.dump(campaign_data, f, indent=2, default=str)

        print(f"[+] Campaign report saved to: {report_path}")
        return report_path

    def get_correlation_timeline(self) -> List[Dict[str, Any]]:
        """Get infrastructure usage timeline."""
        return self.correlation_engine.get_infrastructure_timeline()
