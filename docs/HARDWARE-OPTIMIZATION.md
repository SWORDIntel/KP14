# KP14 Hardware Acceleration Guide

## Overview

KP14 includes comprehensive hardware acceleration support for Intel NPU, GPU, GNA, and multi-core CPU using OpenVINO runtime. This enables **3-10× performance improvements** for malware analysis workloads.

## Table of Contents

- [Supported Hardware](#supported-hardware)
- [Quick Start](#quick-start)
- [Hardware Detection](#hardware-detection)
- [Device Selection](#device-selection)
- [Performance Optimization](#performance-optimization)
- [Benchmarking](#benchmarking)
- [Troubleshooting](#troubleshooting)
- [API Reference](#api-reference)

---

## Supported Hardware

### Intel NPU (Neural Processing Unit)

**Best for:** Pattern matching, ML inference, sustained workloads

**Supported Processors:**
- Intel Core Ultra (Series 1 and 2)
- Intel Core Ultra processors with AI Boost

**Performance:** 3-10× faster than CPU for ML workloads

**Optimization:**
- INT8 quantization (recommended)
- Sustained inference mode
- Low power consumption

### Intel GPU (Integrated Graphics)

**Best for:** Image processing, batch analysis, parallel workloads

**Supported Hardware:**
- Intel Iris Xe Graphics
- Intel UHD Graphics (Gen 11+)
- Intel Arc Graphics (discrete)

**Performance:** 2-4× faster than CPU for parallel tasks

**Optimization:**
- FP16 precision
- Batch processing (batch size 8-32)
- Throughput mode

### Intel GNA (Gaussian Neural Accelerator)

**Best for:** Low-power signal processing, audio analysis

**Supported Processors:**
- Intel Core 10th Gen and later
- Intel Core with GNA 2.0+

**Performance:** 1.5-2× faster for signal processing

**Optimization:**
- Sequential processing
- Low-power mode
- Fixed-point arithmetic

### Multi-core CPU

**Best for:** General processing, fallback mode, compatibility

**Supported:**
- Any x86-64 processor
- ARM processors (limited support)

**Performance:** Baseline reference

**Optimization:**
- Multi-threading
- NUMA awareness
- Cache optimization

---

## Quick Start

### 1. Install OpenVINO

```bash
# Install OpenVINO (recommended version)
pip install openvino==2025.3.0

# Verify installation
python -c "import openvino; print(openvino.__version__)"
```

### 2. Detect Available Hardware

```bash
# Run hardware detection
python hw_detect.py

# Generate hardware report
python hw_detect.py --output hardware_report.json
```

**Expected Output:**
```
====================================================================
HARDWARE PROFILE
====================================================================

Timestamp: 2025-10-02 14:30:15
OpenVINO Version: 2025.3.0

Platform Information:
  system: Linux
  machine: x86_64
  processor: Intel(R) Core(TM) Ultra 7 155H
  cpu_cores_physical: 16
  cpu_cores_logical: 22
  total_memory_gb: 32.0

Detected Devices:

  [1] NPU (NPU)
      Status: Available
      Score: 130.0
      Latency: 1.23ms
      Throughput: 813.01 FPS
      INT8: Yes
      FP16: No
      Batching: Yes

  [2] GPU.0 (GPU)
      Status: Available
      Score: 115.5
      Latency: 2.45ms
      Throughput: 408.16 FPS
      INT8: Yes
      FP16: Yes
      Batching: Yes

  [3] CPU (CPU)
      Status: Available
      Score: 60.0
      Latency: 5.12ms
      Throughput: 195.31 FPS
      INT8: No
      FP16: No
      Batching: No

Recommended Device: NPU

Optimization Hints:
  - NPU detected - enable INT8 quantization for best performance
  - Use NPU for sustained ML workloads and pattern matching
  - GPU detected - enable batch processing for maximum throughput
  - Use GPU for image processing and parallel analysis tasks
  - Multi-core CPU detected (22 cores) - enable parallel processing
```

### 3. Run Accelerated Analysis

```bash
# Automatic device selection
python -m stego-analyzer.analysis.ml_malware_analyzer_hw sample.exe

# Specify device
python -m stego-analyzer.analysis.ml_malware_analyzer_hw --device NPU sample.exe

# Disable acceleration
python -m stego-analyzer.analysis.ml_malware_analyzer_hw --no-acceleration sample.exe
```

---

## Hardware Detection

### Automatic Detection

KP14 automatically detects available hardware on startup:

```python
from hw_detect import HardwareDetector

# Create detector
detector = HardwareDetector(verbose=True)

# Run detection
profile = detector.run_full_detection()

# Print results
detector.print_profile(profile)

# Export to JSON
detector.export_profile(profile, "hardware.json")
```

### Manual Detection

Check specific hardware capabilities:

```python
from hw_detect import HardwareDetector

detector = HardwareDetector()

# Get available devices
devices = detector.detect_available_devices()
print(f"Available: {devices}")

# Get capabilities
for device in devices:
    caps = detector.get_device_capabilities(device)
    print(f"{device}: INT8={caps.supports_int8}, FP16={caps.supports_fp16}")

# Benchmark device
latency, throughput = detector.benchmark_device("NPU")
print(f"NPU: {latency:.2f}ms latency, {throughput:.2f} FPS")
```

---

## Device Selection

### Automatic Selection

KP14 automatically selects the optimal device based on task type:

```python
from hw_detect import HardwareDetector, DeviceSelector

# Detect hardware
detector = HardwareDetector()
profile = detector.run_full_detection()

# Create selector
selector = DeviceSelector(profile)

# Select device for task
device = selector.select_device("pattern_matching")
print(f"Pattern matching: {device}")

device = selector.select_device("image_processing")
print(f"Image processing: {device}")
```

**Task-to-Device Mapping:**

| Task Type | Preferred Devices |
|-----------|------------------|
| Pattern Matching | NPU → GPU → CPU |
| Image Processing | GPU → NPU → CPU |
| Signal Processing | GNA → NPU → CPU |
| Batch Processing | GPU → NPU → CPU |
| General Tasks | CPU → GPU → NPU |

### Manual Selection

Override automatic selection:

```python
from ml_accelerated import InferenceConfig, HardwareAcceleratedAnalyzer

# Create analyzer with specific device
analyzer = HardwareAcceleratedAnalyzer(
    auto_detect=True,
    prefer_device="NPU"  # Force NPU usage
)

# Or disable auto-detection
analyzer = HardwareAcceleratedAnalyzer(
    auto_detect=False,
    prefer_device="CPU"  # CPU only
)
```

### Load Balancing

Distribute work across multiple devices:

```python
from hw_detect import DeviceSelector

selector = DeviceSelector(profile)

# Select with load balancing
for i in range(10):
    device = selector.select_device("pattern_matching", prefer_idle=True)
    print(f"Task {i}: {device}")

    # Do work...

    # Release device
    selector.release_device(device)

# Check device usage
usage = selector.get_device_usage()
print(f"Device usage: {usage}")
```

---

## Performance Optimization

### NPU Optimization

**Best Practices:**
- Enable INT8 quantization for maximum performance
- Use batch size 4-8 for optimal throughput
- Enable model caching to reduce compilation time
- Use sustained inference mode for continuous workloads

**Configuration:**
```python
from ml_accelerated import InferenceConfig, ModelOptimizer

config = InferenceConfig(
    device="NPU",
    precision="INT8",          # Critical for NPU
    batch_size=8,              # Optimal for NPU
    enable_caching=True,       # Reduce startup time
    performance_mode="LATENCY" # Or "THROUGHPUT" for batch
)

optimizer = ModelOptimizer(config)
```

**Expected Performance:**
- Pattern matching: 8-10× faster than CPU
- ML inference: 5-7× faster than CPU
- Batch processing: 3-5× faster than CPU

### GPU Optimization

**Best Practices:**
- Enable FP16 precision for 2× memory reduction
- Use larger batch sizes (16-32) for maximum throughput
- Enable multiple inference streams
- Use throughput mode for batch processing

**Configuration:**
```python
config = InferenceConfig(
    device="GPU",
    precision="FP16",          # 2× faster than FP32
    batch_size=16,             # Larger batches on GPU
    num_streams=4,             # Parallel inference
    performance_mode="THROUGHPUT"
)
```

**Expected Performance:**
- Image processing: 3-4× faster than CPU
- Batch analysis: 4-6× faster than CPU
- Parallel workloads: 2-3× faster than CPU

### CPU Optimization

**Best Practices:**
- Enable multi-threading (auto-detect cores)
- Use CPU affinity for consistent performance
- Enable NUMA awareness on multi-socket systems
- Use cache-friendly data structures

**Configuration:**
```python
config = InferenceConfig(
    device="CPU",
    num_threads=0,  # Auto-detect (recommended)
    batch_size=4,   # Smaller batches for CPU
)
```

### Memory Optimization

**Reduce Memory Usage:**
```python
# Enable model caching (share models across instances)
config.enable_caching = True
config.cache_dir = "./model_cache"

# Use smaller batch sizes
config.batch_size = 4  # Instead of 16

# Enable precision reduction
config.precision = "FP16"  # Or INT8 on NPU
```

---

## Benchmarking

### Run Comprehensive Benchmark

```bash
# Full benchmark (all devices, 100 iterations)
python hw-benchmark.py

# Quick test (50 iterations)
python hw-benchmark.py --iterations 50

# Generate HTML report
python hw-benchmark.py --html benchmark_report.html

# Export JSON results
python hw-benchmark.py --json results.json

# Test specific devices
python hw-benchmark.py --devices NPU GPU CPU

# Quiet mode
python hw-benchmark.py --quiet --html report.html
```

### Interpret Results

**Example Output:**
```
================================================================================
BENCHMARK RESULTS
================================================================================

PATTERN MATCHING
--------------------------------------------------------------------------------
Device          Avg Latency     Min/Max              Std Dev      Throughput    Status
--------------------------------------------------------------------------------
NPU             1.23ms          1.05/2.31ms          0.18ms       813.01 FPS    ✓ OK
GPU.0           2.45ms          2.12/3.87ms          0.31ms       408.16 FPS    ✓ OK
CPU             5.12ms          4.89/6.23ms          0.42ms       195.31 FPS    ✓ OK

IMAGE PROCESSING
--------------------------------------------------------------------------------
Device          Avg Latency     Min/Max              Std Dev      Throughput    Status
--------------------------------------------------------------------------------
GPU.0           3.21ms          2.98/4.12ms          0.35ms       311.53 FPS    ✓ OK
NPU             4.15ms          3.92/5.01ms          0.29ms       240.96 FPS    ✓ OK
CPU             12.34ms         11.87/14.23ms        0.67ms       81.04 FPS     ✓ OK

================================================================================
PERFORMANCE COMPARISON (vs CPU baseline)
================================================================================
Device          Speedup      Latency Gain       Throughput Gain
--------------------------------------------------------------------------------
NPU             4.16×        75.9%              316.4%
GPU.0           2.09×        52.1%              109.0%

SUMMARY
================================================================================
Best Device: NPU
Max Speedup: 4.16×

Recommendations:
  • Use NPU for 4.2× performance improvement
  • GPU available with 311.5 FPS average - enable batch processing for best results
  • Multi-core CPU detected (22 cores) - enable parallel processing
```

### HTML Report

Generate interactive HTML report with charts:

```bash
python hw-benchmark.py --html report.html
```

**Report includes:**
- Performance comparison bar charts
- Detailed results tables
- Device-specific recommendations
- Speedup visualization

---

## Troubleshooting

### NPU Not Detected

**Problem:** NPU not showing in device list

**Solutions:**

1. **Check Hardware Support:**
   ```bash
   # Linux: Check CPU model
   lscpu | grep "Model name"

   # Windows: Check in Device Manager
   # Look for "Neural Processor" or "AI Accelerator"
   ```

2. **Install NPU Drivers:**
   ```bash
   # Windows: Download from Intel
   # https://www.intel.com/content/www/us/en/download/794734/

   # Linux: Install driver package
   sudo apt install intel-npu-driver

   # Verify installation
   python hw_detect.py
   ```

3. **Update OpenVINO:**
   ```bash
   pip install --upgrade openvino
   ```

### GPU Not Detected

**Problem:** GPU showing as unavailable

**Solutions:**

1. **Install GPU Drivers:**
   ```bash
   # Ubuntu/Debian
   sudo apt install intel-gpu-tools

   # Verify GPU
   intel_gpu_top
   ```

2. **Enable GPU in BIOS:**
   - Reboot and enter BIOS
   - Enable Integrated Graphics
   - Set graphics memory to 512MB or higher

3. **Check OpenCL Support:**
   ```bash
   # Install clinfo
   sudo apt install clinfo

   # Check OpenCL devices
   clinfo
   ```

### Low Performance

**Problem:** Hardware acceleration not providing expected speedup

**Solutions:**

1. **Check Precision Settings:**
   ```python
   # NPU requires INT8
   config.precision = "INT8"  # Not FP32

   # GPU benefits from FP16
   config.precision = "FP16"
   ```

2. **Optimize Batch Size:**
   ```python
   # Too small: underutilizes hardware
   config.batch_size = 1  # Bad for GPU/NPU

   # Optimal: balances throughput and latency
   config.batch_size = 8   # Good for NPU
   config.batch_size = 16  # Good for GPU
   ```

3. **Enable Model Caching:**
   ```python
   config.enable_caching = True
   config.cache_dir = "./model_cache"
   ```

4. **Use Correct Performance Mode:**
   ```python
   # For single samples
   config.performance_mode = "LATENCY"

   # For batch processing
   config.performance_mode = "THROUGHPUT"
   ```

### Memory Issues

**Problem:** Out of memory errors

**Solutions:**

1. **Reduce Batch Size:**
   ```python
   config.batch_size = 4  # Instead of 16
   ```

2. **Enable FP16/INT8:**
   ```python
   config.precision = "FP16"  # 2× memory reduction
   config.precision = "INT8"  # 4× memory reduction
   ```

3. **Clear Model Cache:**
   ```bash
   rm -rf ./model_cache/*
   ```

---

## API Reference

### HardwareDetector

```python
from hw_detect import HardwareDetector

detector = HardwareDetector(verbose=True)
```

**Methods:**
- `detect_available_devices() -> List[str]`: Get list of available devices
- `get_device_capabilities(device: str) -> DeviceCapabilities`: Get device info
- `benchmark_device(device: str, iterations: int) -> Tuple[float, float]`: Benchmark device
- `run_full_detection() -> HardwareProfile`: Complete hardware profiling
- `print_profile(profile: HardwareProfile)`: Print profile
- `export_profile(profile: HardwareProfile, file: str)`: Export to JSON

### DeviceSelector

```python
from hw_detect import DeviceSelector

selector = DeviceSelector(hardware_profile)
```

**Methods:**
- `select_device(task_type: str, prefer_idle: bool) -> str`: Select optimal device
- `release_device(device: str)`: Mark device as available
- `get_device_usage() -> Dict[str, int]`: Get usage statistics

### HardwareAcceleratedAnalyzer

```python
from ml_accelerated import HardwareAcceleratedAnalyzer

analyzer = HardwareAcceleratedAnalyzer(
    auto_detect=True,
    prefer_device="NPU"
)
```

**Methods:**
- `select_device_for_task(task_type: str) -> str`: Select device for task
- `create_optimized_config(task_type: str, batch_mode: bool) -> InferenceConfig`: Create config
- `analyze_with_acceleration(data, task_type, batch_mode) -> Dict`: Run analysis
- `get_performance_stats() -> Dict`: Get statistics
- `print_performance_summary()`: Print performance

### InferenceConfig

```python
from ml_accelerated import InferenceConfig

config = InferenceConfig(
    device="NPU",
    precision="INT8",
    batch_size=8,
    num_streams=1,
    enable_caching=True,
    performance_mode="LATENCY"
)
```

**Attributes:**
- `device`: Target device (CPU, GPU, NPU, GNA)
- `precision`: FP32, FP16, or INT8
- `batch_size`: Batch size (1-32)
- `num_streams`: Parallel streams (1-8)
- `enable_caching`: Enable model caching
- `cache_dir`: Cache directory
- `performance_mode`: LATENCY or THROUGHPUT

---

## Performance Expectations

### Typical Speedups (vs CPU baseline)

| Workload Type | NPU | GPU | GNA | CPU |
|---------------|-----|-----|-----|-----|
| Pattern Matching | **8-10×** | 3-4× | N/A | 1× |
| Image Processing | 4-6× | **6-8×** | N/A | 1× |
| Signal Processing | 3-5× | 2-3× | **5-7×** | 1× |
| Batch Analysis | 5-7× | **7-10×** | N/A | 1× |
| General Tasks | 3-5× | 2-4× | N/A | 1× |

### Hardware Requirements

**Minimum:**
- Python 3.11+
- 8GB RAM
- Intel processor with integrated graphics

**Recommended:**
- Intel Core Ultra processor (with NPU)
- 16GB RAM
- Ubuntu 22.04+ or Windows 11

**Optimal:**
- Intel Core Ultra 7/9 (with NPU + GPU)
- 32GB RAM
- NVMe SSD for model caching
- Ubuntu 22.04 LTS

---

## Additional Resources

- [OpenVINO Documentation](https://docs.openvino.ai/)
- [Intel NPU Developer Guide](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-npu-developer-guide.html)
- [Performance Tuning Guide](PERFORMANCE-TUNING.md)
- [API Reference](API-REFERENCE.md)

---

## Support

For hardware acceleration issues:
- Check [Troubleshooting](#troubleshooting) section
- Run `python hw_detect.py` for diagnostics
- File issue with hardware report attached

---

**Built with Intel OpenVINO for maximum performance**
