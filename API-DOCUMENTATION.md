# KP14 Automation & API Documentation

## Overview

KP14 provides comprehensive automation support for integration into malware analysis workflows, CI/CD pipelines, and threat intelligence platforms.

**Key Features:**
- Command-line JSON/CSV API
- Batch processing with multiprocessing
- REST API server (FastAPI)
- Multiple export formats (JSON, CSV, MISP, STIX, YARA, Suricata)
- CI/CD templates (GitHub Actions, Jenkins, GitLab CI)
- Example automation scripts

---

## Table of Contents

1. [CLI API](#cli-api)
2. [Batch Processing](#batch-processing)
3. [REST API](#rest-api)
4. [Export Formats](#export-formats)
5. [CI/CD Integration](#cicd-integration)
6. [Example Scripts](#example-scripts)
7. [Integration Patterns](#integration-patterns)

---

## CLI API

### kp14-cli.py

Clean command-line interface for automation and scripting.

**Features:**
- JSON/CSV output to stdout only
- Errors to stderr
- Proper exit codes
- Pipeable design
- Quiet mode

**Exit Codes:**
- `0` = Success, clean file
- `1` = Error (invalid arguments, file not found)
- `2` = Malware detected (high confidence)
- `3` = Suspicious activity detected
- `4` = Analysis completed with warnings

### Usage Examples

**Analyze single file (JSON output):**
```bash
python kp14-cli.py analyze --file sample.exe --format json
```

**Analyze with CSV output:**
```bash
python kp14-cli.py analyze --file sample.exe --format csv > results.csv
```

**Quiet mode for automation:**
```bash
python kp14-cli.py analyze --file sample.exe --quiet --format json | jq '.threat_assessment'
```

**Export to MISP:**
```bash
python kp14-cli.py analyze --file sample.exe --format misp > misp_event.json
```

**Export to STIX:**
```bash
python kp14-cli.py analyze --file sample.exe --format stix > stix_bundle.json
```

**Check exit code:**
```bash
python kp14-cli.py analyze --file sample.exe --format json
EXIT_CODE=$?

if [ $EXIT_CODE -eq 2 ]; then
    echo "Malware detected!"
elif [ $EXIT_CODE -eq 3 ]; then
    echo "Suspicious file!"
fi
```

---

## Batch Processing

### batch_analyzer.py

Parallel analysis of multiple samples with worker pool management.

**Features:**
- Multiprocessing for speed
- Progress tracking to stderr
- Result aggregation
- Resume capability
- JSONL streaming output

### Usage Examples

**Analyze directory:**
```bash
python batch_analyzer.py --dir samples/ --output results/
```

**Parallel processing (8 workers):**
```bash
python batch_analyzer.py --dir samples/ --workers 8
```

**Recursive scan:**
```bash
python batch_analyzer.py --dir samples/ --recursive
```

**Filter by extensions:**
```bash
python batch_analyzer.py --dir samples/ --extensions .exe .dll
```

**Resume interrupted batch:**
```bash
python batch_analyzer.py --dir samples/ --resume
```

**Quiet mode:**
```bash
python batch_analyzer.py --dir samples/ --quiet > summary.json
```

### Output Files

- `batch_results.jsonl` - JSONL file with all results
- `summary.json` - Statistics summary
- `batch_state.json` - State for resume capability

---

## REST API

### api_server.py

FastAPI-based REST API for HTTP access.

**Requirements:**
```bash
pip install fastapi uvicorn python-multipart
```

**Start server:**
```bash
python api_server.py --host 0.0.0.0 --port 8000
```

**With auto-reload (development):**
```bash
python api_server.py --reload
```

### API Endpoints

#### Health Check
```bash
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-10-02T12:00:00",
  "components": {
    "config_manager": true,
    "pipeline_manager": true
  }
}
```

#### Analyze Single File
```bash
POST /api/v1/analyze
Content-Type: multipart/form-data

file: <binary data>
format: json|csv|misp|stix
```

**Example (curl):**
```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -F "file=@sample.exe" \
  -F "format=json"
```

**Response:**
```json
{
  "file_path": "/tmp/sample.exe",
  "original_file_type": "pe",
  "threat_assessment": {
    "level": "suspicious",
    "exit_code": 3,
    "indicators": ["High entropy: 7.8"],
    "confidence": 0.65
  },
  "static_pe_analysis": {...},
  "api_metadata": {
    "filename": "sample.exe",
    "size": 524288,
    "analyzed_at": "2025-10-02T12:00:00"
  }
}
```

#### Batch Analysis
```bash
POST /api/v1/analyze/batch
Content-Type: multipart/form-data

files[]: <binary data>
files[]: <binary data>
```

**Example:**
```bash
curl -X POST http://localhost:8000/api/v1/analyze/batch \
  -F "files=@sample1.exe" \
  -F "files=@sample2.dll"
```

#### Export Result
```bash
GET /api/v1/export/{result_id}?format=misp
```

**Formats:** json, csv, misp, stix, yara, suricata

#### List Results
```bash
GET /api/v1/results
```

**Response:**
```json
{
  "total": 5,
  "results": [
    {
      "id": "sample1.exe_1234567890.123",
      "filename": "sample1.exe",
      "analyzed_at": "2025-10-02T12:00:00"
    }
  ]
}
```

#### Webhook Registration
```bash
POST /api/v1/webhook?event=malware_detected&url=https://example.com/webhook
```

---

## Export Formats

### JSON Exporter

**Compact JSON:**
```python
from exporters.json_exporter import JSONExporter

exporter = JSONExporter()
json_str = exporter.export(result)
```

**Pretty JSON:**
```python
exporter = JSONExporter(pretty=True, indent=2)
json_str = exporter.export(result, output_path="result.json")
```

### CSV Exporter

```python
from exporters.csv_exporter import CSVExporter

exporter = CSVExporter()
exporter.export([result1, result2], "results.csv")
```

**Custom fields:**
```python
exporter = CSVExporter(fields=['file_path', 'threat_level', 'malware_family'])
```

### MISP Exporter

```python
from exporters.misp_exporter import MISPExporter

exporter = MISPExporter()
misp_event = exporter.export(result, "misp_event.json")
```

**Batch export:**
```python
events = exporter.export_batch([result1, result2], "misp_events.json")
```

### STIX Exporter

```python
from exporters.stix_exporter import STIXExporter

exporter = STIXExporter()
stix_bundle = exporter.export(result, "stix_bundle.json")
```

### YARA Rule Exporter

```python
from exporters.rule_exporter import YARAExporter

exporter = YARAExporter()
yara_rule = exporter.export(result, "detection.yar")
```

### Suricata Rule Exporter

```python
from exporters.rule_exporter import SuricataExporter

exporter = SuricataExporter()
rules = exporter.export(result, "detection.rules")
```

---

## CI/CD Integration

### GitHub Actions

**.github/workflows/kp14-analysis.yml** is included.

**Usage:**
```yaml
on:
  push:
    paths:
      - 'samples/**'

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Analyze samples
        run: |
          python batch_analyzer.py --dir samples/ --output ci_results
```

### Jenkins

**Jenkinsfile** is included.

**Usage:**
```groovy
pipeline {
    agent any
    parameters {
        string(name: 'SAMPLE_DIR', defaultValue: 'samples/')
    }
    stages {
        stage('Analyze') {
            steps {
                sh 'python batch_analyzer.py --dir ${SAMPLE_DIR}'
            }
        }
    }
}
```

### GitLab CI

**.gitlab-ci.yml** is included.

**Usage:**
```yaml
stages:
  - analyze

analyze:batch:
  stage: analyze
  script:
    - python batch_analyzer.py --dir samples/
  artifacts:
    paths:
      - results/
```

### Docker Integration

**Build container:**
```bash
docker build -t kp14:latest .
```

**Run analysis:**
```bash
docker run --rm \
  -v $(pwd)/samples:/samples:ro \
  -v $(pwd)/results:/output \
  kp14:latest python batch_analyzer.py --dir /samples --output /output
```

---

## Example Scripts

### 1. analyze-dir.sh

Bash wrapper for batch analysis with nice output.

```bash
./examples/analyze-dir.sh samples/ --workers 4 --format json
```

### 2. export-to-misp.py

Export results to MISP format.

```bash
python examples/export-to-misp.py \
  --input results/batch_results.jsonl \
  --output misp_events.json
```

**Filter by threat level:**
```bash
python examples/export-to-misp.py \
  --input results/batch_results.jsonl \
  --output misp_malware.json \
  --filter-level malware
```

### 3. export-to-stix.py

Export results to STIX 2.1 format.

```bash
python examples/export-to-stix.py \
  --input results/batch_results.jsonl \
  --output stix_bundle.json
```

**Separate bundles:**
```bash
python examples/export-to-stix.py \
  --input results/batch_results.jsonl \
  --output stix/ \
  --separate
```

### 4. watch-folder.py

Continuously monitor folder for new samples.

**Requirements:**
```bash
pip install watchdog
```

**Usage:**
```bash
python examples/watch-folder.py \
  --dir /path/to/watch \
  --output watch_results/ \
  --extensions .exe .dll
```

**Features:**
- Auto-analysis of new files
- Alert files for malware detection
- JSONL result streaming

### 5. generate-report.py

Generate HTML/Markdown reports.

**HTML report:**
```bash
python examples/generate-report.py \
  --input results/batch_results.jsonl \
  --output report.html \
  --format html
```

**Markdown report:**
```bash
python examples/generate-report.py \
  --input results/batch_results.jsonl \
  --output report.md \
  --format markdown
```

---

## Integration Patterns

### Pattern 1: Pipeline Integration

**Example: Jenkins Pipeline**
```groovy
pipeline {
    stages {
        stage('Fetch Samples') {
            steps {
                sh 'wget https://samples.example.com/daily.zip'
                sh 'unzip daily.zip -d samples/'
            }
        }
        stage('Analyze') {
            steps {
                sh 'python batch_analyzer.py --dir samples/ --output results/'
            }
        }
        stage('Export to MISP') {
            steps {
                sh 'python examples/export-to-misp.py --input results/batch_results.jsonl --output misp.json'
                sh 'curl -X POST https://misp.local/events/add -d @misp.json'
            }
        }
    }
}
```

### Pattern 2: Webhook Integration

**Example: Slack notifications**
```python
import requests
import json

# Analyze file
result = pipeline_manager.run_pipeline("sample.exe")

# Send to Slack if malware detected
if result.get('threat_assessment', {}).get('level') == 'malware':
    webhook_url = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

    message = {
        "text": f"⚠️ Malware detected: {result['file_path']}",
        "attachments": [{
            "color": "danger",
            "fields": [
                {"title": "Threat Level", "value": "Malware", "short": True},
                {"title": "Family", "value": result.get('intelligence', {}).get('malware_family', 'Unknown'), "short": True}
            ]
        }]
    }

    requests.post(webhook_url, json=message)
```

### Pattern 3: Database Integration

**Example: SQLite storage**
```python
import sqlite3
import json

# Analyze file
result = pipeline_manager.run_pipeline("sample.exe")

# Store in database
conn = sqlite3.connect('kp14_results.db')
cursor = conn.cursor()

cursor.execute('''
    INSERT INTO analysis_results (file_path, threat_level, result_json, analyzed_at)
    VALUES (?, ?, ?, datetime('now'))
''', (
    result['file_path'],
    result.get('threat_assessment', {}).get('level', 'unknown'),
    json.dumps(result)
))

conn.commit()
conn.close()
```

### Pattern 4: Message Queue Integration

**Example: RabbitMQ**
```python
import pika
import json

# Analyze file
result = pipeline_manager.run_pipeline("sample.exe")

# Send to RabbitMQ
connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
channel = connection.channel()

channel.queue_declare(queue='kp14_results')

channel.basic_publish(
    exchange='',
    routing_key='kp14_results',
    body=json.dumps(result)
)

connection.close()
```

---

## Exit Codes Reference

| Code | Meaning | CLI | Batch | Description |
|------|---------|-----|-------|-------------|
| 0 | Success | ✓ | ✓ | All files clean, no errors |
| 1 | Error | ✓ | ✓ | Analysis errors, invalid input |
| 2 | Malware | ✓ | ✓ | Malware detected with high confidence |
| 3 | Suspicious | ✓ | ✓ | Suspicious activity detected |
| 4 | Warnings | ✓ | ✓ | Completed with warnings |

---

## Output Schema Reference

### Threat Assessment Object

```json
{
  "level": "malware|suspicious|clean|error",
  "exit_code": 0-4,
  "indicators": ["list", "of", "indicators"],
  "confidence": 0.0-1.0
}
```

### Intelligence Object

```json
{
  "threat_score": 0-100,
  "malware_family": "KeyPlug|Unknown",
  "c2_endpoints": ["http://example.com"],
  "mitre_attack": ["T1071.001"]
}
```

### Static PE Analysis Object

```json
{
  "source": "original_file",
  "pe_info": {
    "hashes": {
      "md5": "...",
      "sha1": "...",
      "sha256": "..."
    },
    "file_size": 524288,
    "is_pe": true,
    "architecture": "x86|x64",
    "sections": [...],
    "imports": {...}
  },
  "code_analysis": {...},
  "obfuscation_details": {...}
}
```

---

## Best Practices

1. **Use quiet mode in automation:** `--quiet` flag suppresses progress to stdout
2. **Parse exit codes:** Check exit codes for workflow decisions
3. **Stream large batches:** Use JSONL format for memory efficiency
4. **Resume interrupted jobs:** Use `--resume` flag for batch processing
5. **Export for TI platforms:** Use MISP/STIX for integration
6. **Monitor with webhooks:** Set up alerts for malware detection
7. **Version your configs:** Keep settings.ini in version control
8. **Log everything:** Enable comprehensive logging for debugging
9. **Use containers:** Docker provides isolation and consistency
10. **Rate limit API:** Implement rate limiting for production REST API

---

## Troubleshooting

**Q: "ModuleNotFoundError: No module named 'fastapi'"**
```bash
pip install fastapi uvicorn python-multipart
```

**Q: Batch processing is slow**
```bash
# Increase workers
python batch_analyzer.py --workers 8
```

**Q: Out of memory during batch processing**
```bash
# Reduce workers or use resume capability
python batch_analyzer.py --workers 2 --resume
```

**Q: API server not accessible**
```bash
# Bind to all interfaces
python api_server.py --host 0.0.0.0 --port 8000
```

---

## Additional Resources

- [CLI Reference](docs/CLI-GUIDE.md)
- [REST API Specification](docs/API-REFERENCE.md)
- [Docker Deployment](docs/DOCKER.md)
- [CI/CD Integration](docs/CICD-INTEGRATION.md)
- [Output Format Schemas](docs/OUTPUT-FORMATS.md)

---

**Support:** For issues and questions, see [GitHub Issues](https://github.com/yourusername/kp14/issues)
