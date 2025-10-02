# KP14 Test Fixtures

This directory contains test data, configuration files, and expected outputs for the KP14 test suite.

## Directory Structure

```
fixtures/
├── README.md                   # This file
├── samples/                    # Test samples
│   ├── pe/                    # PE executables
│   ├── images/                # Image files (JPEG, PNG)
│   ├── polyglot/              # Polyglot files
│   ├── encrypted/             # Encrypted samples
│   └── malicious/             # Synthetic malware samples
├── configs/                    # Test configuration files
└── expected_outputs/           # Expected analysis results
```

## Test Samples

### PE Samples (`samples/pe/`)

| File | Description | Size | Purpose |
|------|-------------|------|---------|
| `simple_pe32.exe` | Minimal PE32 executable | 1024 bytes | Basic PE analysis tests |
| `simple_pe64.exe` | Minimal PE64 executable | 1024 bytes | x64 architecture tests |
| `packed_upx.exe` | UPX packed sample | 2 KB | Packing detection tests |
| `corrupted.exe` | Invalid PE (broken headers) | 512 bytes | Error handling tests |
| `large_sample.exe` | Large PE file | 10 MB | Size limit tests |

### Image Samples (`samples/images/`)

| File | Description | Size | Purpose |
|------|-------------|------|---------|
| `clean_100x100.jpg` | Clean JPEG image | 5 KB | Baseline tests |
| `clean_100x100.png` | Clean PNG image | 5 KB | Baseline tests |
| `lsb_embedded.png` | PNG with LSB steganography | 10 KB | LSB detection tests |
| `jpeg_appended.jpg` | JPEG with appended data | 8 KB | Appended data detection |
| `corrupt.jpg` | Corrupted JPEG file | 2 KB | Error handling tests |

### Polyglot Samples (`samples/polyglot/`)

| File | Description | Size | Purpose |
|------|-------------|------|---------|
| `jpeg_pe.jpg` | JPEG/PE polyglot | 10 KB | Polyglot detection |
| `zip_pe.zip` | ZIP with embedded PE | 15 KB | Archive extraction |
| `pdf_pe.pdf` | PDF/PE polyglot | 20 KB | Multi-format detection |
| `nested_archive.zip` | ZIP containing ZIP with PE | 12 KB | Recursive extraction |

### Encrypted Samples (`samples/encrypted/`)

| File | Description | Size | Encryption | Purpose |
|------|-------------|------|------------|---------|
| `xor_encrypted.bin` | XOR encrypted PE | 1 KB | XOR (key=0xAB) | XOR decryption tests |
| `aes_cbc.bin` | AES encrypted PE | 2 KB | AES-128-CBC | AES decryption tests |
| `rc4_encrypted.bin` | RC4 encrypted PE | 1 KB | RC4 | RC4 decryption tests |
| `multi_layer.bin` | Multi-layer encrypted | 3 KB | XOR → AES → RC4 | Decryption chain tests |

### Malicious Samples (`samples/malicious/`)

**WARNING:** All samples are SYNTHETIC and contain NO actual malicious code.

| File | Description | Size | Purpose |
|------|-------------|------|---------|
| `keyplug_synthetic.exe` | Synthetic KeyPlug features | 5 KB | KeyPlug detection tests |
| `packed_synthetic.exe` | Synthetic packed malware | 3 KB | Packing detection tests |
| `dropper_synthetic.dll` | Synthetic dropper DLL | 4 KB | Dropper detection tests |

## Configuration Files (`configs/`)

| File | Description | Purpose |
|------|-------------|---------|
| `minimal.ini` | Minimal configuration | Basic functionality tests |
| `full_featured.ini` | All features enabled | Comprehensive tests |
| `hardware_accel.ini` | NPU/GPU acceleration | Hardware tests |
| `invalid.ini` | Invalid configuration | Error handling tests |

## Expected Outputs (`expected_outputs/`)

Contains JSON files with expected analysis results for validation tests.

| File | Description | Purpose |
|------|-------------|---------|
| `simple_pe32_report.json` | Expected report for simple_pe32.exe | Output validation |
| `lsb_embedded_report.json` | Expected report for lsb_embedded.png | Stego detection validation |

## Generating Test Samples

Test samples can be regenerated using the provided script:

```bash
cd tests/fixtures
python generate_samples.py
```

This will create all synthetic test files with deterministic output.

## Sample Provenance

All test samples are:
- **Synthetic:** Created by automated scripts
- **Safe:** Contain no malicious code
- **Deterministic:** Generated with fixed seeds for reproducibility
- **Checksummed:** MD5/SHA256 checksums documented

## Usage in Tests

### Using Sample Fixtures

```python
@pytest.fixture
def simple_pe_sample(samples_dir):
    """Get path to simple PE32 sample."""
    return samples_dir / "pe" / "simple_pe32.exe"

def test_pe_analysis(simple_pe_sample):
    """Test PE analysis with simple sample."""
    result = analyze_pe(simple_pe_sample)
    assert result['is_valid']
```

### Using Configuration Fixtures

```python
@pytest.fixture
def minimal_test_config(configs_dir):
    """Get path to minimal configuration."""
    return configs_dir / "minimal.ini"

def test_config_loading(minimal_test_config):
    """Test configuration loading."""
    config = ConfigurationManager(minimal_test_config)
    assert config.get('general', 'log_level') == 'DEBUG'
```

## Checksums

### PE Samples
```
simple_pe32.exe: MD5=<to be generated>
simple_pe64.exe: MD5=<to be generated>
```

### Image Samples
```
clean_100x100.jpg: MD5=<to be generated>
lsb_embedded.png: MD5=<to be generated>
```

## Maintenance

### Adding New Samples

1. Create the sample file (preferably via script)
2. Document in this README
3. Add checksum to checksums section
4. Create corresponding expected output if needed
5. Write tests using the new sample

### Regenerating Samples

When algorithms or file formats change:

1. Run `python generate_samples.py`
2. Update checksums in this README
3. Update expected outputs if needed
4. Verify all tests still pass

## Security Notice

**All test samples are SYNTHETIC and SAFE:**
- No actual malware code
- No exploits or vulnerabilities
- Safe for analysis in any environment
- Created specifically for testing purposes

Test samples should NOT be submitted to malware databases or analysis services.

## Version Control

Test samples are:
- **Version controlled:** All samples tracked in git
- **Binary files:** Use git-lfs if samples become large
- **Immutable:** Samples should not change without version bump
- **Documented:** All changes logged in git history

## Questions?

For questions about test fixtures, contact the QA team or refer to:
- TEST_STRATEGY.md (comprehensive testing strategy)
- tests/conftest.py (fixture definitions)
- tests/unit/*/conftest.py (module-specific fixtures)
