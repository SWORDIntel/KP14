"""
Comprehensive tests for MISP export module

Tests cover:
- MISP event creation
- Attribute generation
- Object relationships
- Tag assignment
- Threat level mapping
- JSON format validation
- Batch export
"""

import pytest
import json
import tempfile
from pathlib import Path
from exporters.misp_exporter import MISPExporter


class TestMISPExporterInit:
    """Test MISPExporter initialization."""

    def test_exporter_initialization(self):
        """Test exporter initializes correctly."""
        exporter = MISPExporter()
        assert exporter is not None


class TestMISPEventCreation:
    """Test MISP event creation."""

    def test_create_basic_event(self, sample_analysis_result):
        """Test creating a basic MISP event."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        assert event is not None
        assert 'Event' in event
        assert 'uuid' in event['Event']
        assert 'info' in event['Event']

    def test_event_info_field(self, sample_analysis_result):
        """Test event info field contains filename."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        assert 'malware.exe' in event['Event']['info']

    def test_event_has_attributes(self, sample_analysis_result):
        """Test event contains attributes."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        assert 'Attribute' in event['Event']
        assert isinstance(event['Event']['Attribute'], list)
        assert len(event['Event']['Attribute']) > 0

    def test_event_has_tags(self, sample_analysis_result):
        """Test event contains tags."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        assert 'Tag' in event['Event']
        assert isinstance(event['Event']['Tag'], list)

    def test_event_date_format(self, sample_analysis_result):
        """Test event date is in correct format."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        date = event['Event']['date']
        # Should be YYYY-MM-DD format
        assert len(date) == 10
        assert date[4] == '-'
        assert date[7] == '-'


class TestAttributeGeneration:
    """Test MISP attribute generation."""

    def test_hash_attributes(self, sample_analysis_result):
        """Test hash attributes are generated."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        attributes = event['Event']['Attribute']
        hash_attrs = [a for a in attributes if a['type'] in ['md5', 'sha1', 'sha256']]

        assert len(hash_attrs) > 0

    def test_hash_attribute_structure(self, sample_analysis_result):
        """Test hash attributes have correct structure."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        attributes = event['Event']['Attribute']
        hash_attrs = [a for a in attributes if a['type'] == 'md5']

        if hash_attrs:
            attr = hash_attrs[0]
            assert 'type' in attr
            assert 'category' in attr
            assert 'value' in attr
            assert 'to_ids' in attr

    def test_file_size_attribute(self, sample_analysis_result):
        """Test file size attribute is generated."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        attributes = event['Event']['Attribute']
        size_attrs = [a for a in attributes if a['type'] == 'size-in-bytes']

        assert len(size_attrs) > 0

    def test_network_attributes(self, sample_analysis_result):
        """Test network attributes for C2 endpoints."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        attributes = event['Event']['Attribute']
        network_attrs = [a for a in attributes if a['category'] == 'Network activity']

        # Should have C2 endpoints as network attributes
        if sample_analysis_result.get('intelligence', {}).get('c2_endpoints'):
            assert len(network_attrs) > 0

    def test_domain_attributes(self, sample_analysis_result):
        """Test domain attributes are created."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        attributes = event['Event']['Attribute']
        domain_attrs = [a for a in attributes if a['type'] == 'domain']

        # Should have domain from C2 endpoints
        if any(ep.get('endpoint_type') == 'domain'
               for ep in sample_analysis_result.get('intelligence', {}).get('c2_endpoints', [])):
            assert len(domain_attrs) > 0

    def test_ip_attributes(self, sample_analysis_result):
        """Test IP address attributes are created."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        attributes = event['Event']['Attribute']
        ip_attrs = [a for a in attributes if a['type'] == 'ip-dst']

        # Should have IP from C2 endpoints
        if any(ep.get('endpoint_type') == 'ip'
               for ep in sample_analysis_result.get('intelligence', {}).get('c2_endpoints', [])):
            assert len(ip_attrs) > 0

    def test_to_ids_flag(self, sample_analysis_result):
        """Test to_ids flag is set appropriately."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        attributes = event['Event']['Attribute']

        # Hash attributes should have to_ids=True
        hash_attrs = [a for a in attributes if a['type'] in ['md5', 'sha256']]
        if hash_attrs:
            assert hash_attrs[0]['to_ids'] is True


class TestThreatLevelMapping:
    """Test threat level mapping."""

    def test_threat_level_malware(self, sample_analysis_result):
        """Test threat level for malware."""
        exporter = MISPExporter()
        sample_analysis_result['threat_assessment']['level'] = 'malware'

        event = exporter.export(sample_analysis_result)

        threat_level = event['Event']['threat_level_id']
        # Malware should be high threat
        assert threat_level in ['1', '2']  # High or Medium

    def test_threat_level_suspicious(self, sample_analysis_result):
        """Test threat level for suspicious files."""
        exporter = MISPExporter()
        sample_analysis_result['threat_assessment']['level'] = 'suspicious'

        event = exporter.export(sample_analysis_result)

        threat_level = event['Event']['threat_level_id']
        # Suspicious should be medium threat
        assert threat_level in ['2', '3']

    def test_threat_level_clean(self, sample_analysis_result):
        """Test threat level for clean files."""
        exporter = MISPExporter()
        sample_analysis_result['threat_assessment']['level'] = 'clean'

        event = exporter.export(sample_analysis_result)

        threat_level = event['Event']['threat_level_id']
        # Clean should be low threat
        assert threat_level in ['3', '4']


class TestTagAssignment:
    """Test tag assignment."""

    def test_malware_family_tag(self, sample_analysis_result):
        """Test malware family tag is added."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        tags = event['Event']['Tag']

        # Should have family tag
        family_tags = [t for t in tags if 'KEYPLUG' in str(t)]
        if sample_analysis_result.get('intelligence', {}).get('malware_family'):
            assert len(family_tags) > 0

    def test_mitre_attack_tags(self, sample_analysis_result):
        """Test MITRE ATT&CK tags are added."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        tags = event['Event']['Tag']

        # Should have MITRE tags
        mitre_tags = [t for t in tags if 'mitre' in str(t).lower() or 'T' in str(t)]
        if sample_analysis_result.get('intelligence', {}).get('ttps'):
            assert len(mitre_tags) > 0

    def test_tag_structure(self, sample_analysis_result):
        """Test tag structure is correct."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        tags = event['Event']['Tag']

        if tags:
            tag = tags[0]
            # Tags should have name field
            assert 'name' in tag or isinstance(tag, str)


class TestFileExport:
    """Test exporting to file."""

    def test_export_to_file(self, sample_analysis_result):
        """Test exporting event to JSON file."""
        exporter = MISPExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "event.json"
            event = exporter.export(sample_analysis_result, str(output_path))

            assert output_path.exists()

            # Verify JSON is valid
            with open(output_path) as f:
                loaded = json.load(f)
                assert 'Event' in loaded

    def test_export_creates_parent_dirs(self, sample_analysis_result):
        """Test export creates parent directories."""
        exporter = MISPExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "subdir" / "event.json"
            exporter.export(sample_analysis_result, str(output_path))

            assert output_path.exists()

    def test_export_without_output_path(self, sample_analysis_result):
        """Test export without writing to file."""
        exporter = MISPExporter()

        event = exporter.export(sample_analysis_result, output_path=None)

        # Should return event without writing
        assert event is not None
        assert 'Event' in event


class TestBatchExport:
    """Test batch export functionality."""

    def test_batch_export_multiple_events(self, batch_analysis_results):
        """Test exporting multiple events."""
        exporter = MISPExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "events.json"
            events = exporter.export_batch(batch_analysis_results, str(output_path))

            assert len(events) == len(batch_analysis_results)

    def test_batch_export_writes_file(self, batch_analysis_results):
        """Test batch export writes to file."""
        exporter = MISPExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "events.json"
            exporter.export_batch(batch_analysis_results, str(output_path))

            assert output_path.exists()

            with open(output_path) as f:
                loaded = json.load(f)
                assert isinstance(loaded, list)

    def test_batch_export_event_count(self, batch_analysis_results):
        """Test batch export creates correct number of events."""
        exporter = MISPExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "events.json"
            events = exporter.export_batch(batch_analysis_results, str(output_path))

            assert len(events) == 3


class TestEventMetadata:
    """Test event metadata fields."""

    def test_event_uuid_format(self, sample_analysis_result):
        """Test event UUID is valid format."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        uuid = event['Event']['uuid']
        assert len(uuid) == 36  # UUID format length
        assert uuid.count('-') == 4

    def test_event_distribution(self, sample_analysis_result):
        """Test event has distribution setting."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        assert 'distribution' in event['Event']

    def test_event_analysis_status(self, sample_analysis_result):
        """Test event has analysis status."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        assert 'analysis' in event['Event']

    def test_event_published_status(self, sample_analysis_result):
        """Test event has published status."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        assert 'published' in event['Event']
        # Should default to not published
        assert event['Event']['published'] is False


class TestAttributeCategories:
    """Test attribute category assignment."""

    def test_payload_delivery_category(self, sample_analysis_result):
        """Test file attributes use payload delivery category."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        attributes = event['Event']['Attribute']
        hash_attrs = [a for a in attributes if a['type'] == 'md5']

        if hash_attrs:
            assert hash_attrs[0]['category'] == 'Payload delivery'

    def test_network_activity_category(self, sample_analysis_result):
        """Test network attributes use correct category."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        attributes = event['Event']['Attribute']
        network_attrs = [a for a in attributes if a['type'] in ['domain', 'ip-dst']]

        if network_attrs:
            assert network_attrs[0]['category'] == 'Network activity'


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_export_minimal_data(self):
        """Test export with minimal data."""
        exporter = MISPExporter()
        minimal_result = {
            "file_path": "/test.exe",
            "static_pe_analysis": {
                "pe_info": {
                    "hashes": {"md5": "abc123"}
                }
            }
        }

        event = exporter.export(minimal_result)

        # Should create valid event
        assert 'Event' in event

    def test_export_missing_optional_fields(self, sample_analysis_result):
        """Test export with missing optional fields."""
        exporter = MISPExporter()

        # Remove optional intelligence field
        result = sample_analysis_result.copy()
        result.pop('intelligence', None)

        event = exporter.export(result)

        # Should still create event
        assert event is not None

    def test_export_empty_batch(self):
        """Test batch export with empty list."""
        exporter = MISPExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "empty.json"
            events = exporter.export_batch([], str(output_path))

            assert len(events) == 0

    def test_export_missing_hashes(self):
        """Test export when hashes are missing."""
        exporter = MISPExporter()
        result = {
            "file_path": "/test.exe",
            "static_pe_analysis": {
                "pe_info": {}
            }
        }

        event = exporter.export(result)

        # Should handle gracefully
        assert 'Event' in event

    def test_export_malformed_c2_endpoints(self, sample_analysis_result):
        """Test export with malformed C2 endpoint data."""
        exporter = MISPExporter()
        sample_analysis_result['intelligence']['c2_endpoints'] = [
            'not a dict',
            None,
            {}
        ]

        event = exporter.export(sample_analysis_result)

        # Should handle gracefully
        assert 'Event' in event


class TestMISPCompliance:
    """Test MISP format compliance."""

    def test_event_required_fields(self, sample_analysis_result):
        """Test event has all required MISP fields."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        required = ['uuid', 'info', 'date', 'threat_level_id', 'analysis',
                    'distribution', 'Attribute', 'Tag']

        for field in required:
            assert field in event['Event']

    def test_attribute_required_fields(self, sample_analysis_result):
        """Test attributes have required fields."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        attributes = event['Event']['Attribute']

        if attributes:
            attr = attributes[0]
            assert 'type' in attr
            assert 'category' in attr
            assert 'value' in attr

    def test_json_serializable(self, sample_analysis_result):
        """Test event is JSON serializable."""
        exporter = MISPExporter()
        event = exporter.export(sample_analysis_result)

        # Should be able to serialize to JSON
        json_str = json.dumps(event)
        assert len(json_str) > 0
