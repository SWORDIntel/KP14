# KP14 Intelligence Enhancement Module

Advanced threat intelligence capabilities for malware analysis with automated C2 extraction, threat scoring, rule generation, and TI platform integration.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Components](#components)
- [Usage Examples](#usage-examples)
- [API Reference](#api-reference)
- [Output Formats](#output-formats)
- [Configuration](#configuration)
- [Integration Guide](#integration-guide)

---

## Overview

The KP14 Intelligence Module transforms raw malware analysis data into actionable threat intelligence. It automatically extracts C2 endpoints, scores threats, maps to MITRE ATT&CK, generates detection rules, and exports to all major TI platforms.

**Key Capabilities:**

- **C2 Extraction**: Automatic discovery of IP addresses, domains, .onion addresses, encryption keys
- **Threat Scoring**: Automated 0-100 threat scoring with severity classification
- **MITRE Mapping**: ATT&CK technique identification and classification
- **Rule Generation**: Auto-generate YARA, Suricata, Snort, and Sigma rules
- **TI Export**: STIX 2.1 bundles, MISP events, OpenIOC XML
- **Correlation**: Link related samples, track campaigns, identify infrastructure reuse
- **External Integration**: VirusTotal, MISP, Shodan, Censys API integration

---

## Features

### C2 Endpoint Extraction (`c2_extractor.py`)

Extracts all network indicators from malware samples:

- **IP Addresses**: IPv4 detection with validation and confidence scoring
- **Domains**: FQDN extraction with TLD analysis
- **URLs**: Full URL parsing with protocol and port extraction
- **Tor .onion**: Hidden service detection
- **Encryption Keys**: AES, RSA, RC4 key extraction
- **Obfuscation Handling**: XOR, Base64, custom encoding detection
- **Confidence Scoring**: 0-100 confidence for each indicator

**Example Output:**
```json
{
  "endpoints": [
    {
      "type": "ip",
      "value": "185.220.101.23",
      "confidence": 90,
      "location": "string_table",
      "protocol": "https",
      "port": 8080
    },
    {
      "type": "onion",
      "value": "example3fah3jk2l4.onion",
      "confidence": 95,
      "protocol": "tor"
    }
  ],
  "encryption_keys": [
    {
      "type": "aes256",
      "value": "a1b2c3d4e5f6...",
      "size": 256,
      "confidence": 80
    }
  ]
}
```

### Threat Assessment (`threat_scorer.py`)

Multi-factor threat scoring and classification:

- **Threat Score**: 0-100 automated scoring
- **Severity Rating**: Low, Medium, High, Critical
- **Family Classification**: Malware family identification with confidence
- **MITRE ATT&CK Mapping**: Technique and tactic identification
- **Capability Analysis**: Detection of persistence, evasion, credential theft, etc.
- **Target Profiling**: Platform, architecture, privilege requirements
- **Attribution**: APT group identification with confidence

**Example Output:**
```json
{
  "threat_score": 87,
  "severity": "critical",
  "family": "KEYPLUG",
  "family_confidence": 85,
  "mitre_techniques": [
    {
      "id": "T1071.001",
      "tactic": "Command and Control",
      "name": "Application Layer Protocol: Web Protocols",
      "confidence": 90
    }
  ],
  "capabilities": [
    {
      "capability": "Credential Theft",
      "category": "credential_access",
      "severity": "critical"
    }
  ]
}
```

### Rule Generation

Automated detection rule creation:

**YARA Rules** (`yara_generator.py`):
- Family-based detection rules
- C2 indicator rules
- Capability-based rules
- Hash-based exact detection
- False positive reduction

**Network Rules** (`network_rules.py`):
- Suricata IDS rules
- Snort signatures
- DNS query detection
- HTTP/HTTPS traffic patterns
- Tor detection rules

**Sigma Rules** (`sigma_generator.py`):
- Process execution detection
- Network connection logging
- Registry modification detection
- Windows Event Log correlation

### Intelligence Export

**STIX 2.1** (`stix_exporter.py`):
- Complete STIX bundles with indicators, malware objects, attack patterns
- Proper relationships between objects
- MITRE ATT&CK external references
- Full spec compliance

**MISP Events** (`misp_exporter.py`):
- MISP-compatible JSON events
- Attribute categorization
- Threat level mapping
- Direct MISP API submission

**OpenIOC** (`openioc_exporter.py`):
- OpenIOC 1.1 XML format
- File hash indicators
- Network indicators
- Mandiant-compatible output

### Pattern Database (`pattern_db.py`)

APT41/KEYPLUG-specific signatures:

- String signatures
- Binary patterns
- Network patterns
- Behavioral signatures
- Memory patterns
- Cryptographic patterns
- File artifacts
- Registry keys
- Mutex patterns

**Included Patterns:**
- KEYPLUG malware family
- APT41 general TTPs
- Generic backdoor signatures
- Extensible JSON database

### Correlation Engine (`correlator.py`)

Link related samples and track campaigns:

- **Sample Similarity**: Multi-factor similarity scoring
- **Infrastructure Clustering**: Shared C2 detection
- **TTP Clustering**: Technique-based grouping
- **Campaign Tracking**: Campaign creation and management
- **Timeline Analysis**: Infrastructure usage timeline

### API Integrations (`api_integrations.py`)

External threat intelligence enrichment:

- **VirusTotal**: Hash lookup and enrichment
- **MISP**: Event submission and retrieval
- **Shodan**: IP infrastructure research
- **Censys**: Network exposure analysis
- **Custom Feeds**: Extensible feed integration

---

## Architecture

```
intelligence/
├── extractors/
│   ├── __init__.py
│   └── c2_extractor.py          # C2 endpoint extraction
├── scorers/
│   ├── __init__.py
│   └── threat_scorer.py          # Threat assessment & scoring
├── generators/
│   ├── __init__.py
│   ├── yara_generator.py         # YARA rule generation
│   ├── network_rules.py          # Suricata/Snort rules
│   └── sigma_generator.py        # Sigma rule generation
├── exporters/
│   ├── __init__.py
│   ├── stix_exporter.py          # STIX 2.1 export
│   ├── misp_exporter.py          # MISP event export
│   └── openioc_exporter.py       # OpenIOC export
├── database/
│   ├── __init__.py
│   └── pattern_db.py             # Pattern database
├── correlation/
│   ├── __init__.py
│   └── correlator.py             # Correlation engine
├── integrations/
│   ├── __init__.py
│   └── api_integrations.py       # External API integrations
├── __init__.py
├── intelligence_orchestrator.py  # Main orchestrator
└── README.md
```

---

## Installation

### Prerequisites

```bash
# Core dependencies (already in KP14 requirements.txt)
pip install pyyaml requests

# Optional: For MISP integration
pip install pymisp

# Optional: For STIX validation
pip install stix2-validator
```

### Verify Installation

```python
from intelligence import IntelligenceOrchestrator

orchestrator = IntelligenceOrchestrator()
print("Intelligence module loaded successfully!")
```

---

## Quick Start

### Basic Usage

```python
from intelligence import IntelligenceOrchestrator

# Initialize orchestrator
orchestrator = IntelligenceOrchestrator({
    'output_dir': 'intelligence_output',
    'enable_enrichment': False  # Set True for API enrichment
})

# Prepare sample data from KP14 analysis
sample_data = {
    'strings': ['http://example.com/c2', 'KEYPLUG', ...],
    'pe_info': {'sha256': '...', 'md5': '...', ...},
    'behaviors': ['persistence_registry_run', ...],
    'raw_data': b'...'  # Raw file bytes
}

# Run intelligence analysis
intelligence_report = orchestrator.analyze(sample_data, sample_id='sample_001')

# Access results
print(f"Threat Score: {intelligence_report['summary']['threat_score']}")
print(f"Severity: {intelligence_report['summary']['severity']}")
print(f"Family: {intelligence_report['summary']['family']}")
print(f"C2 Endpoints Found: {intelligence_report['summary']['c2_endpoints_found']}")
```

### Integration with KP14 Pipeline

```python
from core_engine.pipeline_manager import PipelineManager
from intelligence import IntelligenceOrchestrator

# Run KP14 analysis
pipeline = PipelineManager(config_manager)
kp14_report = pipeline.run_pipeline('malware.exe')

# Extract intelligence
orchestrator = IntelligenceOrchestrator()
intelligence = orchestrator.analyze({
    'strings': kp14_report.get('extracted_strings', []),
    'pe_info': kp14_report.get('static_pe_analysis', {}).get('pe_info', {}),
    'behaviors': kp14_report.get('behaviors', []),
    'raw_data': open('malware.exe', 'rb').read()
})

# Export to STIX
stix_bundle = intelligence['stix_bundle']
# Export to MISP
misp_event = intelligence['misp_event']
```

---

## Components

### 1. C2 Extractor

```python
from intelligence.extractors.c2_extractor import C2Extractor

extractor = C2Extractor()
result = extractor.extract(
    data=file_bytes,
    strings=string_list,
    metadata={'family': 'KEYPLUG'}
)

# Access results
for endpoint in result.endpoints:
    print(f"{endpoint.endpoint_type}: {endpoint.value} (confidence: {endpoint.confidence})")

for key in result.encryption_keys:
    print(f"{key.key_type} key: {key.key_value[:16]}...")
```

### 2. Threat Scorer

```python
from intelligence.scorers.threat_scorer import ThreatScorer

scorer = ThreatScorer()
assessment = scorer.assess({
    'strings': [...],
    'c2_endpoints': [...],
    'pe_info': {...},
    'behaviors': [...]
})

print(f"Threat Score: {assessment.threat_score}")
print(f"Malware Family: {assessment.family}")
print(f"MITRE Techniques: {len(assessment.mitre_techniques)}")
```

### 3. YARA Generator

```python
from intelligence.generators.yara_generator import YaraGenerator

generator = YaraGenerator()
rules = generator.generate(intelligence_data)

# Export to file
generator.save_rules(rules, 'output/rules.yar')

# Or get YARA text
yara_text = generator.export_to_yara(rules)
print(yara_text)
```

### 4. Network Rules

```python
from intelligence.generators.network_rules import NetworkRuleGenerator

generator = NetworkRuleGenerator(start_sid=5000000)
rules = generator.generate(c2_endpoints, threat_data)

# Export to files
generator.export_to_file(rules, 'output/')
# Creates: kp14_generated.rules (Suricata)
#          kp14_generated_snort.rules (Snort)
```

### 5. STIX Exporter

```python
from intelligence.exporters.stix_exporter import StixExporter

exporter = StixExporter()
bundle = exporter.export(intelligence_data)

# Save to file
exporter.save_bundle(bundle, 'output/stix_bundle.json')

# Or integrate with TAXII server
# upload_to_taxii(bundle)
```

### 6. Pattern Database

```python
from intelligence.database.pattern_db import PatternDatabase

db = PatternDatabase()

# Match against patterns
matches = db.match_patterns(sample_data)
for family, score in matches.items():
    print(f"{family}: {score}% match")

# Get family info
keyplug_info = db.get_family_info('apt41_keyplug')

# Add custom pattern
db.add_pattern('custom_family', {
    'string_signatures': ['custom_malware', 'evil_backdoor'],
    'behavioral_signatures': ['persistence', 'c2_communication']
})
db.save_database('custom_patterns.json')
```

### 7. Correlation Engine

```python
from intelligence.correlation.correlator import CorrelationEngine

correlator = CorrelationEngine()

# Add samples
correlator.add_sample('sample1', intelligence_data_1)
correlator.add_sample('sample2', intelligence_data_2)

# Find correlations
correlations = correlator.correlate_sample('sample1')
print(f"Similar samples: {len(correlations['similar_samples'])}")
print(f"Shared C2: {len(correlations['shared_infrastructure'])}")

# Create campaign
campaign_id = correlator.create_campaign('Operation XYZ', ['sample1', 'sample2', 'sample3'])

# Get timeline
timeline = correlator.get_infrastructure_timeline()
```

### 8. API Integrations

```python
from intelligence.integrations.api_integrations import APIIntegrations

integrations = APIIntegrations({
    'virustotal_api_key': 'your_vt_key',
    'shodan_api_key': 'your_shodan_key',
    'misp_url': 'https://misp.example.com',
    'misp_key': 'your_misp_key'
})

# Enrich with VirusTotal
vt_data = integrations.enrich_with_virustotal(file_hash)

# Lookup IP on Shodan
shodan_data = integrations.lookup_shodan('185.220.101.23')

# Submit to MISP
result = integrations.submit_to_misp(intelligence_data)
```

---

## Usage Examples

### Complete Analysis Workflow

```python
from intelligence import IntelligenceOrchestrator

# Configure with API keys for enrichment
config = {
    'output_dir': 'intel_output',
    'enable_enrichment': True,
    'api_keys': {
        'virustotal_api_key': 'VT_API_KEY',
        'shodan_api_key': 'SHODAN_KEY'
    }
}

orchestrator = IntelligenceOrchestrator(config)

# Analyze sample
report = orchestrator.analyze(sample_data, 'malware_sample_001')

# Results automatically saved to intel_output/:
# - malware_sample_001_rules.yar
# - malware_sample_001_stix.json
# - malware_sample_001_misp.json
# - malware_sample_001_openioc.xml
# - malware_sample_001_intelligence.json
# - kp14_generated.rules (Suricata)
# - kp14_generated_snort.rules
# - sigma_rule_*.yml

print(f"Analysis complete! Output in {config['output_dir']}/")
```

### Batch Analysis

```python
samples = [
    {'strings': [...], 'pe_info': {...}, 'behaviors': [...]},
    {'strings': [...], 'pe_info': {...}, 'behaviors': [...]},
    # ... more samples
]

results = orchestrator.batch_analyze(samples)

# Batch report saved to: batch_intelligence_report.json
print(f"Analyzed {len(results)} samples")
print(f"Average threat score: {results[0]['summary']['average_threat_score']}")
```

### Campaign Tracking

```python
# Add samples to correlation engine
orchestrator.correlation_engine.add_sample('sample1', intel_data1)
orchestrator.correlation_engine.add_sample('sample2', intel_data2)
orchestrator.correlation_engine.add_sample('sample3', intel_data3)

# Create campaign
campaign_report = orchestrator.export_campaign_report(
    'APT41_Operation_2025',
    ['sample1', 'sample2', 'sample3']
)

# Campaign report includes:
# - Aggregated families
# - APT groups
# - Common techniques
# - Shared infrastructure
```

### Custom Rule Generation

```python
from intelligence.generators.yara_generator import YaraGenerator

# Generate custom rules
generator = YaraGenerator()
generator.min_string_length = 8  # More specific strings
generator.min_confidence = 80    # Higher confidence threshold

rules = generator.generate(intelligence_data)

# Customize rule before export
for rule in rules:
    rule.tags.append('custom_tag')
    rule.meta['custom_field'] = 'value'

yara_text = generator.export_to_yara(rules)
```

---

## Output Formats

### Intelligence Report JSON

```json
{
  "sample_id": "a1b2c3d4e5f6g7h8",
  "timestamp": "2025-10-02T12:34:56.789Z",
  "c2_extraction": {
    "endpoints": [...],
    "encryption_keys": [...],
    "overall_confidence": 85
  },
  "threat_assessment": {
    "threat_score": 87,
    "severity": "critical",
    "family": "KEYPLUG",
    "mitre_techniques": [...],
    "capabilities": [...]
  },
  "yara_rules": [{"name": "KEYPLUG_Detection_a1b2c3d4", "confidence": 85}],
  "network_rules": {"suricata_count": 12, "snort_count": 12},
  "sigma_rules": {"count": 3},
  "stix_bundle": {"object_count": 45},
  "misp_event": {"attribute_count": 23},
  "correlations": {
    "similar_samples": [],
    "shared_infrastructure": [],
    "ttp_clusters": []
  },
  "summary": {
    "threat_score": 87,
    "severity": "critical",
    "family": "KEYPLUG",
    "c2_endpoints_found": 5,
    "assessment": "Threat Score: 87/100 (CRITICAL) | Family: KEYPLUG..."
  }
}
```

---

## Configuration

### Basic Configuration

```python
config = {
    # Output settings
    'output_dir': 'intelligence_output',

    # API keys for enrichment
    'api_keys': {
        'virustotal_api_key': 'YOUR_VT_KEY',
        'shodan_api_key': 'YOUR_SHODAN_KEY',
        'censys_api_id': 'YOUR_CENSYS_ID',
        'censys_api_secret': 'YOUR_CENSYS_SECRET',
        'misp_url': 'https://misp.example.com',
        'misp_key': 'YOUR_MISP_KEY'
    },

    # Feature toggles
    'enable_enrichment': True,
    'enable_correlation': True,
    'generate_rules': True,
    'export_stix': True,
    'export_misp': True,
    'export_openioc': True
}

orchestrator = IntelligenceOrchestrator(config)
```

---

## Integration Guide

### MISP Integration

```python
# Submit event to MISP
integrations = APIIntegrations({
    'misp_url': 'https://misp.example.com',
    'misp_key': 'YOUR_API_KEY'
})

result = integrations.submit_to_misp(intelligence_data)
if result.get('success'):
    print(f"Event created: {result['event_id']}")
```

### SIEM Integration (Sigma Rules)

```python
# Generate Sigma rules for SIEM
from intelligence.generators.sigma_generator import SigmaGenerator

generator = SigmaGenerator()
rules = generator.generate(threat_data, capabilities)

# Rules saved in output_dir/
# Import to: Elastic, Splunk, QRadar, etc.
```

### IDS/IPS Integration (Suricata/Snort)

```bash
# Generated rules in output_dir/kp14_generated.rules

# For Suricata:
sudo cp intelligence_output/kp14_generated.rules /etc/suricata/rules/
sudo suricata-update  # Or edit suricata.yaml to include rules
sudo systemctl restart suricata

# For Snort:
sudo cp intelligence_output/kp14_generated_snort.rules /etc/snort/rules/
# Add to snort.conf: include $RULE_PATH/kp14_generated_snort.rules
sudo systemctl restart snort
```

---

## Advanced Features

### Custom Pattern Database

```python
# Create custom patterns
custom_patterns = {
    "custom_malware": {
        "family": "CustomMalware",
        "string_signatures": ["evil_string_1", "backdoor_init"],
        "behavioral_signatures": ["persistence", "c2_communication"],
        "network_patterns": {
            "c2_protocols": ["https"],
            "suspicious_ports": [4444, 5555]
        }
    }
}

# Load custom database
db = PatternDatabase('custom_patterns.json')
db.add_pattern('custom_malware', custom_patterns['custom_malware'])
db.save_database()
```

### Infrastructure Timeline Analysis

```python
# Get timeline of C2 infrastructure usage
timeline = orchestrator.get_correlation_timeline()

for entry in timeline:
    print(f"{entry['endpoint']} - First: {entry['first_seen']}, Last: {entry['last_seen']}")
    print(f"  Used by {entry['sample_count']} samples")
```

---

## API Reference

See individual module docstrings for detailed API documentation:

```python
from intelligence import C2Extractor
help(C2Extractor)

from intelligence import ThreatScorer
help(ThreatScorer)
```

---

## Troubleshooting

### Common Issues

**Issue: No C2 endpoints extracted**
- Ensure sample has network indicators in strings
- Check if data is obfuscated (XOR keys may need adjustment)
- Verify `raw_data` parameter contains actual file bytes

**Issue: Low threat scores**
- May indicate unknown malware family
- Add custom patterns to pattern database
- Check if behavioral signatures are provided

**Issue: API enrichment fails**
- Verify API keys are valid
- Check network connectivity
- Some APIs have rate limits (VirusTotal: 4 req/min on free tier)

**Issue: Rule generation produces no rules**
- Requires minimum confidence threshold (default 70)
- Need sufficient high-quality indicators
- Check if sample has unique strings

---

## Performance Notes

- **C2 Extraction**: ~0.1-0.5 seconds per sample
- **Threat Assessment**: ~0.1-0.2 seconds per sample
- **Rule Generation**: ~0.2-1.0 seconds per sample
- **STIX Export**: ~0.1-0.3 seconds per sample
- **API Enrichment**: 1-5 seconds per API call (network dependent)

**Batch Processing**: Near-linear scaling for correlation analysis

---

## Security Considerations

1. **API Keys**: Never commit API keys to version control
2. **Sample Handling**: Assume all samples are malicious
3. **Network Isolation**: Run enrichment in controlled environment
4. **Data Sanitization**: All exports sanitize potentially malicious content
5. **Rate Limiting**: Respect API rate limits to avoid bans

---

## License

MIT License - See KP14 main LICENSE file

---

## Support

For issues, feature requests, or questions:

- GitHub Issues: https://github.com/yourusername/kp14/issues
- Documentation: KP14 main README.md
- Email: security@kp14.dev

---

**Built with care by the KP14 Intelligence Team**

Transform raw malware analysis into actionable threat intelligence.
