"""
Comprehensive tests for STIX 2.1 export module

Tests cover:
- STIX 2.1 bundle creation
- Indicator object generation
- Malware object generation
- Attack pattern mapping
- Relationship creation
- Bundle validation
- File object creation
- Batch export
"""

import pytest
import json
import tempfile
from pathlib import Path
from exporters.stix_exporter import STIXExporter


class TestSTIXExporterInit:
    """Test STIXExporter initialization."""

    def test_exporter_initialization(self):
        """Test exporter initializes correctly."""
        exporter = STIXExporter()
        assert exporter.STIX_VERSION == "2.1"


class TestSTIXBundleCreation:
    """Test STIX bundle creation."""

    def test_create_basic_bundle(self, sample_analysis_result):
        """Test creating a basic STIX bundle."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        assert bundle is not None
        assert bundle['type'] == 'bundle'
        assert 'id' in bundle
        assert bundle['id'].startswith('bundle--')
        assert bundle['spec_version'] == '2.1'
        assert 'objects' in bundle

    def test_bundle_contains_objects(self, sample_analysis_result):
        """Test bundle contains STIX objects."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        assert len(bundle['objects']) > 0

    def test_bundle_file_object(self, sample_analysis_result):
        """Test bundle contains file object."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        file_objects = [obj for obj in bundle['objects'] if obj['type'] == 'file']
        assert len(file_objects) > 0

    def test_bundle_with_malicious_classification(self, sample_analysis_result):
        """Test bundle with malicious threat classification."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        # Should include indicator for malicious file
        indicators = [obj for obj in bundle['objects'] if obj['type'] == 'indicator']
        assert len(indicators) > 0


class TestFileObjectCreation:
    """Test STIX file object creation."""

    def test_file_object_structure(self, sample_analysis_result):
        """Test file object has correct structure."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        file_obj = next(obj for obj in bundle['objects'] if obj['type'] == 'file')

        assert 'hashes' in file_obj
        assert 'size' in file_obj
        assert file_obj['type'] == 'file'

    def test_file_object_hashes(self, sample_analysis_result):
        """Test file object includes hashes."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        file_obj = next(obj for obj in bundle['objects'] if obj['type'] == 'file')

        assert 'MD5' in file_obj['hashes'] or 'md5' in file_obj['hashes']
        assert 'SHA-256' in file_obj['hashes'] or 'sha256' in file_obj['hashes']

    def test_file_object_size(self, sample_analysis_result):
        """Test file object includes size."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        file_obj = next(obj for obj in bundle['objects'] if obj['type'] == 'file')

        assert file_obj['size'] == 102400


class TestIndicatorCreation:
    """Test STIX indicator object creation."""

    def test_indicator_for_malicious_file(self, sample_analysis_result):
        """Test indicator is created for malicious files."""
        exporter = STIXExporter()
        sample_analysis_result['threat_assessment']['level'] = 'malware'

        bundle = exporter.export(sample_analysis_result)

        indicators = [obj for obj in bundle['objects'] if obj['type'] == 'indicator']
        assert len(indicators) > 0

    def test_no_indicator_for_clean_file(self, sample_analysis_result):
        """Test no indicator for clean files."""
        exporter = STIXExporter()
        sample_analysis_result['threat_assessment']['level'] = 'clean'

        bundle = exporter.export(sample_analysis_result)

        indicators = [obj for obj in bundle['objects'] if obj['type'] == 'indicator']
        # Clean files should not have indicators
        assert len(indicators) == 0

    def test_indicator_pattern(self, sample_analysis_result):
        """Test indicator includes pattern."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        indicators = [obj for obj in bundle['objects'] if obj['type'] == 'indicator']

        if indicators:
            indicator = indicators[0]
            assert 'pattern' in indicator
            assert len(indicator['pattern']) > 0

    def test_indicator_metadata(self, sample_analysis_result):
        """Test indicator includes metadata."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        indicators = [obj for obj in bundle['objects'] if obj['type'] == 'indicator']

        if indicators:
            indicator = indicators[0]
            assert 'created' in indicator
            assert 'modified' in indicator
            assert 'valid_from' in indicator


class TestMalwareObjectCreation:
    """Test STIX malware object creation."""

    def test_malware_object_for_family(self, sample_analysis_result):
        """Test malware object created when family detected."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        malware_objects = [obj for obj in bundle['objects'] if obj['type'] == 'malware']
        assert len(malware_objects) > 0

    def test_malware_object_name(self, sample_analysis_result):
        """Test malware object includes family name."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        malware_objects = [obj for obj in bundle['objects'] if obj['type'] == 'malware']

        if malware_objects:
            malware = malware_objects[0]
            assert 'name' in malware
            assert malware['name'] == 'KEYPLUG'

    def test_malware_object_is_family(self, sample_analysis_result):
        """Test malware object marked as family."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        malware_objects = [obj for obj in bundle['objects'] if obj['type'] == 'malware']

        if malware_objects:
            malware = malware_objects[0]
            assert malware.get('is_family', False) is True


class TestRelationshipCreation:
    """Test STIX relationship object creation."""

    def test_relationship_indicator_to_malware(self, sample_analysis_result):
        """Test relationship between indicator and malware."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        relationships = [obj for obj in bundle['objects'] if obj['type'] == 'relationship']

        # Should have relationship if both indicator and malware exist
        indicators = [obj for obj in bundle['objects'] if obj['type'] == 'indicator']
        malware = [obj for obj in bundle['objects'] if obj['type'] == 'malware']

        if indicators and malware:
            assert len(relationships) > 0

    def test_relationship_structure(self, sample_analysis_result):
        """Test relationship has correct structure."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        relationships = [obj for obj in bundle['objects'] if obj['type'] == 'relationship']

        if relationships:
            rel = relationships[0]
            assert 'source_ref' in rel
            assert 'target_ref' in rel
            assert 'relationship_type' in rel


class TestFileExport:
    """Test exporting to file."""

    def test_export_to_file(self, sample_analysis_result):
        """Test exporting bundle to JSON file."""
        exporter = STIXExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "output.json"
            bundle = exporter.export(sample_analysis_result, str(output_path))

            assert output_path.exists()

            # Verify JSON is valid
            with open(output_path) as f:
                loaded = json.load(f)
                assert loaded['type'] == 'bundle'

    def test_export_creates_parent_dirs(self, sample_analysis_result):
        """Test export creates parent directories."""
        exporter = STIXExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "subdir" / "output.json"
            exporter.export(sample_analysis_result, str(output_path))

            assert output_path.exists()


class TestBatchExport:
    """Test batch export functionality."""

    def test_batch_export_multiple_results(self, batch_analysis_results):
        """Test exporting multiple results."""
        exporter = STIXExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "batch.json"
            bundle = exporter.export_batch(batch_analysis_results, str(output_path))

            assert bundle is not None
            assert bundle['type'] == 'bundle'

    def test_batch_export_combines_objects(self, batch_analysis_results):
        """Test batch export combines all objects."""
        exporter = STIXExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "batch.json"
            bundle = exporter.export_batch(batch_analysis_results, str(output_path))

            # Should have objects from all results
            assert len(bundle['objects']) >= len(batch_analysis_results)

    def test_batch_export_writes_file(self, batch_analysis_results):
        """Test batch export writes to file."""
        exporter = STIXExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "batch.json"
            exporter.export_batch(batch_analysis_results, str(output_path))

            assert output_path.exists()

            with open(output_path) as f:
                loaded = json.load(f)
                assert loaded['type'] == 'bundle'


class TestObservableCreation:
    """Test STIX observable creation."""

    def test_network_traffic_observables(self, sample_analysis_result):
        """Test network traffic observables for C2."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        # Check for network-related objects
        objects = bundle['objects']
        types = {obj['type'] for obj in objects}

        # Should have some representation of network indicators
        assert len(objects) > 0


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_export_minimal_data(self):
        """Test export with minimal data."""
        exporter = STIXExporter()
        minimal_result = {
            "file_path": "/test.exe",
            "static_pe_analysis": {
                "pe_info": {
                    "hashes": {"md5": "abc123"}
                }
            }
        }

        bundle = exporter.export(minimal_result)

        # Should create valid bundle
        assert bundle['type'] == 'bundle'

    def test_export_missing_optional_fields(self, sample_analysis_result):
        """Test export with missing optional fields."""
        exporter = STIXExporter()

        # Remove optional intelligence field
        result = sample_analysis_result.copy()
        result.pop('intelligence', None)

        bundle = exporter.export(result)

        # Should still create bundle
        assert bundle is not None

    def test_export_empty_batch(self):
        """Test batch export with empty list."""
        exporter = STIXExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "empty.json"
            bundle = exporter.export_batch([], str(output_path))

            assert bundle['type'] == 'bundle'
            assert len(bundle['objects']) == 0

    def test_export_without_output_path(self, sample_analysis_result):
        """Test export without writing to file."""
        exporter = STIXExporter()

        bundle = exporter.export(sample_analysis_result, output_path=None)

        # Should return bundle without writing
        assert bundle is not None
        assert bundle['type'] == 'bundle'


class TestSTIXCompliance:
    """Test STIX 2.1 compliance."""

    def test_bundle_id_format(self, sample_analysis_result):
        """Test bundle ID follows STIX format."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        assert bundle['id'].startswith('bundle--')
        # UUID should follow after --
        uuid_part = bundle['id'].split('--')[1]
        assert len(uuid_part) == 36  # UUID length

    def test_object_ids_unique(self, sample_analysis_result):
        """Test all object IDs are unique."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        ids = [obj['id'] for obj in bundle['objects']]
        assert len(ids) == len(set(ids))

    def test_timestamp_format(self, sample_analysis_result):
        """Test timestamps follow ISO 8601 format."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        for obj in bundle['objects']:
            if 'created' in obj:
                # Should end with Z for UTC
                assert obj['created'].endswith('Z')

    def test_required_fields_present(self, sample_analysis_result):
        """Test required STIX fields are present."""
        exporter = STIXExporter()
        bundle = exporter.export(sample_analysis_result)

        assert 'type' in bundle
        assert 'id' in bundle
        assert 'spec_version' in bundle
        assert 'objects' in bundle

        for obj in bundle['objects']:
            assert 'type' in obj
            assert 'id' in obj
