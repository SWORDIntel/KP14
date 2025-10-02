# KP14 Intelligence Module - Quick Start Guide

## 5-Minute Quick Start

### Installation

```python
# Already installed with KP14!
from intelligence import IntelligenceOrchestrator
```

### Basic Usage

```python
from intelligence import IntelligenceOrchestrator

# 1. Initialize
orchestrator = IntelligenceOrchestrator({
    'output_dir': 'intelligence_output'
})

# 2. Prepare sample data (from KP14 analysis)
sample_data = {
    'strings': ['http://evil.com/c2', 'backdoor', 'KEYPLUG'],
    'pe_info': {
        'sha256': 'a1b2c3d4...',
        'md5': 'e5f6g7h8...',
        'file_size': 524288
    },
    'behaviors': ['persistence_registry_run', 'c2_communication'],
    'raw_data': open('malware.exe', 'rb').read()
}

# 3. Run analysis
report = orchestrator.analyze(sample_data, 'malware_001')

# 4. View results
print(f"Threat Score: {report['summary']['threat_score']}/100")
print(f"Severity: {report['summary']['severity']}")
print(f"Family: {report['summary']['family']}")
print(f"C2 Endpoints: {report['summary']['c2_endpoints_found']}")

# 5. Check output directory
# intelligence_output/
#   - malware_001_intelligence.json    (Complete report)
#   - malware_001_rules.yar            (YARA rules)
#   - malware_001_stix.json            (STIX bundle)
#   - malware_001_misp.json            (MISP event)
#   - malware_001_openioc.xml          (OpenIOC)
#   - kp14_generated.rules             (Suricata)
#   - kp14_generated_snort.rules       (Snort)
#   - sigma_rule_*.yml                 (Sigma rules)
```

## Common Workflows

### Workflow 1: Quick Threat Assessment

```python
from intelligence import ThreatScorer

scorer = ThreatScorer()
assessment = scorer.assess({
    'strings': [...],
    'c2_endpoints': [...],
    'behaviors': [...]
})

print(f"Score: {assessment.threat_score}")
print(f"Family: {assessment.family}")
print(f"MITRE Techniques: {len(assessment.mitre_techniques)}")
```

### Workflow 2: Extract C2 Only

```python
from intelligence import C2Extractor

extractor = C2Extractor()
result = extractor.extract(
    data=file_bytes,
    strings=string_list,
    metadata={}
)

for ep in result.endpoints:
    print(f"{ep.endpoint_type}: {ep.value} (confidence: {ep.confidence})")
```

### Workflow 3: Generate YARA Rules

```python
from intelligence import YaraGenerator

generator = YaraGenerator()
rules = generator.generate(intelligence_data)
generator.save_rules(rules, 'my_rules.yar')
```

### Workflow 4: Export to STIX

```python
from intelligence import StixExporter

exporter = StixExporter()
bundle = exporter.export(intelligence_data)
exporter.save_bundle(bundle, 'threat_intel.json')
```

### Workflow 5: Batch Processing

```python
samples = [sample1, sample2, sample3, ...]
results = orchestrator.batch_analyze(samples)
# Check: intelligence_output/batch_intelligence_report.json
```

## Integration with KP14

### Method 1: Post-Processing

```python
from core_engine.pipeline_manager import PipelineManager
from intelligence import IntelligenceOrchestrator

# Run KP14
pipeline = PipelineManager(config)
kp14_report = pipeline.run_pipeline('sample.exe')

# Extract intelligence
intel = IntelligenceOrchestrator()
intelligence_report = intel.analyze({
    'strings': kp14_report.get('extracted_strings', []),
    'pe_info': kp14_report.get('static_pe_analysis', {}).get('pe_info', {}),
    'behaviors': [],  # Add if available
    'raw_data': open('sample.exe', 'rb').read()
})
```

### Method 2: Direct Integration

```python
# Add to pipeline_manager.py after analysis completes:

from intelligence import IntelligenceOrchestrator

def run_pipeline(self, input_file):
    # ... existing analysis ...

    # Add intelligence extraction
    intel = IntelligenceOrchestrator()
    intel_report = intel.analyze({
        'strings': report.get('strings', []),
        'pe_info': report.get('pe_info', {}),
        'behaviors': report.get('behaviors', []),
        'raw_data': open(input_file, 'rb').read()
    })

    report['intelligence'] = intel_report
    return report
```

## Output Examples

### Intelligence Report Summary

```json
{
  "summary": {
    "threat_score": 87,
    "severity": "critical",
    "family": "KEYPLUG",
    "family_confidence": 85,
    "c2_endpoints_found": 5,
    "mitre_techniques": 12,
    "yara_rules_generated": 4,
    "network_rules_generated": 24,
    "sigma_rules_generated": 3
  }
}
```

### YARA Rule Output

```yara
rule KEYPLUG_Detection_a1b2c3d4 {
    meta:
        description = "KEYPLUG malware family detection"
        author = "KP14 Auto-Generator"
        family = "KEYPLUG"
        confidence = "85"

    strings:
        $str1 = "KEYPLUG"
        $str2 = "http://evil.com"

    condition:
        2 of them
}
```

### Suricata Rule Output

```
alert dns $HOME_NET any -> any 53 (msg:"KEYPLUG C2 Domain Query"; dns.query; content:"evil.com"; classtype:trojan-activity; sid:5000001; rev:1;)
```

## Configuration

### Basic Config

```python
config = {
    'output_dir': 'intelligence_output'
}
```

### Advanced Config with API Keys

```python
config = {
    'output_dir': 'intelligence_output',
    'enable_enrichment': True,
    'api_keys': {
        'virustotal_api_key': 'YOUR_VT_KEY',
        'shodan_api_key': 'YOUR_SHODAN_KEY',
        'misp_url': 'https://misp.example.com',
        'misp_key': 'YOUR_MISP_KEY'
    }
}
```

## Troubleshooting

### Issue: No C2 endpoints found
**Solution**: Ensure strings list contains network indicators. Check if data is obfuscated.

### Issue: Low threat score
**Solution**: Unknown malware family. Add custom patterns to pattern database.

### Issue: API enrichment fails
**Solution**: Verify API keys are valid and network connectivity is working.

### Issue: No rules generated
**Solution**: Need higher confidence indicators (default min: 70%). Lower threshold or provide better data.

## Next Steps

1. **Read Full Documentation**: `/run/media/john/DATA/Active Measures/c2-enum-toolkit/kp14/intelligence/README.md`
2. **Explore Examples**: See README.md "Usage Examples" section
3. **Custom Patterns**: Add to `pattern_db.py` for your specific threats
4. **API Integration**: Configure VirusTotal, Shodan for enrichment
5. **SIEM Integration**: Deploy Sigma rules to your SIEM
6. **IDS Integration**: Deploy Suricata/Snort rules to network sensors

## Support

- **Full Documentation**: `intelligence/README.md`
- **Implementation Summary**: `/run/media/john/DATA/Active Measures/c2-enum-toolkit/kp14/INTELLIGENCE-SUMMARY.md`
- **Module Source**: `/run/media/john/DATA/Active Measures/c2-enum-toolkit/kp14/intelligence/`

---

**Ready to transform malware analysis into actionable intelligence!**
