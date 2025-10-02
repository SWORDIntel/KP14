"""
KP14 Intelligence Enhancement Module

Advanced threat intelligence capabilities for malware analysis:
- C2 endpoint extraction
- Threat scoring and assessment
- Automated rule generation (YARA, Suricata, Snort, Sigma)
- Intelligence export (STIX 2.1, MISP, OpenIOC)
- Pattern correlation and campaign tracking
"""

__version__ = "1.0.0"
__author__ = "KP14 Intelligence Team"

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
from .intelligence_orchestrator import IntelligenceOrchestrator

__all__ = [
    'C2Extractor',
    'ThreatScorer',
    'YaraGenerator',
    'NetworkRuleGenerator',
    'SigmaGenerator',
    'StixExporter',
    'MispExporter',
    'OpenIOCExporter',
    'PatternDatabase',
    'CorrelationEngine',
    'APIIntegrations',
    'IntelligenceOrchestrator'
]
