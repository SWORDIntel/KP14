# KP14 Hardware Acceleration - Quick Start Guide

## Overview

KP14 now includes advanced hardware acceleration support for Intel NPU, GPU, and GNA devices using OpenVINO. This guide will help you get started quickly.

## Quick Start

### 1. Check Available Hardware

```bash
python hw_detect.py
```

This will show all available accelerators and their capabilities.

### 2. Run Basic Benchmark

```bash
# Quick benchmark
python hw-benchmark.py --iterations 50

# Generate HTML report
python hw-benchmark.py --html benchmark_report.html

# Export JSON results
python hw-benchmark.py --json results.json
```

### 3. Use Hardware-Accelerated Analysis

```python
from ml_accelerated import HardwareAcceleratedAnalyzer
import numpy as np

# Initialize with auto-detection
analyzer = HardwareAcceleratedAnalyzer(auto_detect=True)

# Analyze data
data = np.random.rand(224, 224, 3).astype(np.float32)
results = analyzer.analyze_with_acceleration(data, task_type="image_processing")

print(f"Device used: {results['device_used']}")
print(f"Latency: {results['latency_ms']:.2f}ms")
```

## Common Use Cases

### Pattern Matching (NPU Optimized)

```python
from ml_accelerated import HardwareAcceleratedAnalyzer

analyzer = HardwareAcceleratedAnalyzer(auto_detect=True)
config = analyzer.create_optimized_config("pattern_matching", batch_mode=False)

# Config will use:
# - Device: NPU (if available)
# - Precision: INT8 (75% memory reduction)
# - Batch size: 1 (latency mode)
# - Expected speedup: 8-10×
```

### Batch Image Processing (GPU Optimized)

```python
analyzer = HardwareAcceleratedAnalyzer(auto_detect=True)
config = analyzer.create_optimized_config("image_processing", batch_mode=True)

# Config will use:
# - Device: GPU (if available)
# - Precision: FP16 (50% memory reduction)
# - Batch size: 16 (throughput mode)
# - Streams: 4 (parallel processing)
# - Expected speedup: 5-8×
```

### Malware Analysis with Hardware Acceleration

```python
from stego-analyzer.analysis.ml_malware_analyzer_hw import analyze_with_hw_acceleration

# Analyze malware sample
results = analyze_with_hw_acceleration(
    file_path="/path/to/malware.exe",
    verbose=True
)

print(f"Detection score: {results['ml_analysis']['detection']['score']:.2f}")
print(f"Device used: {results['device_used']}")
```

## Performance Optimization Tips

### For Maximum Speed

1. **Use NPU for sustained workloads**
   - INT8 quantization: 75% memory reduction
   - Best for pattern matching and repetitive tasks
   - 8-10× speedup vs CPU

2. **Use GPU for batch processing**
   - FP16 precision: 50% memory reduction
   - Best for parallel image/signal processing
   - 5-8× speedup vs CPU

3. **Enable model caching**
   ```python
   config = InferenceConfig(
       enable_caching=True,
       cache_dir="./model_cache"
   )
   ```
   - 70-90% reduction in startup time
   - Models compile once, run many times

### For Minimum Memory Usage

1. **Use INT8 quantization (NPU)**
   ```python
   config.precision = "INT8"
   config.device = "NPU"
   ```
   - 75% memory reduction vs FP32
   - Minimal accuracy loss

2. **Enable tensor sharing**
   ```python
   config.use_tensor_sharing = True
   config.memory_mode = "OPTIMIZED"
   ```
   - Reduces peak memory by 15-20%
   - Improves cache performance

3. **Use dynamic batching**
   ```python
   config.enable_dynamic_batching = True
   ```
   - Adapts batch size to available memory
   - Prevents OOM errors

## Device Selection Guide

| Task Type          | Best Device | Precision | Expected Speedup |
|--------------------|-------------|-----------|------------------|
| Pattern Matching   | NPU         | INT8      | 8-10×            |
| Image Processing   | GPU         | FP16      | 5-8×             |
| Signal Processing  | GNA/NPU     | INT8      | 6-8×             |
| Batch Processing   | GPU         | FP16      | 6-10×            |
| General Purpose    | CPU         | FP32      | 1× (baseline)    |

## Benchmark Examples

### Example 1: Compare All Devices

```bash
python hw-benchmark.py \
  --iterations 100 \
  --devices CPU GPU NPU \
  --html comparison.html
```

### Example 2: Quick Test

```bash
python hw-benchmark.py \
  --iterations 50 \
  --quiet \
  --json quick_results.json
```

### Example 3: Custom Baseline

```bash
python hw-benchmark.py \
  --baseline GPU \
  --iterations 100
```

## Memory Profiling

### Check Memory Usage

```python
from ml_accelerated import AsyncInferenceEngine

# Enable profiling
engine = AsyncInferenceEngine(
    compiled_model,
    num_requests=4,
    enable_profiling=True
)

# Run inference
results = engine.infer_async(inputs)

# Check memory stats
print(f"Peak memory: {engine.stats.peak_memory_mb:.1f}MB")
print(f"Average memory: {engine.stats.avg_memory_mb:.1f}MB")
```

## Troubleshooting

### NPU Not Detected

1. Check OpenVINO installation:
   ```bash
   python -c "from openvino.runtime import Core; print(Core().available_devices)"
   ```

2. Verify Intel Core Ultra processor with NPU
3. Update OpenVINO to latest version:
   ```bash
   pip install --upgrade openvino
   ```

### Out of Memory Errors

1. Reduce batch size:
   ```python
   config.batch_size = 4  # or 2, 1
   ```

2. Enable memory optimization:
   ```python
   config.memory_mode = "OPTIMIZED"
   config.use_tensor_sharing = True
   ```

3. Use lower precision:
   ```python
   config.precision = "INT8"  # or "FP16"
   ```

### Slow Compilation

1. Enable caching:
   ```python
   config.enable_caching = True
   config.cache_dir = "./model_cache"
   ```

2. Compilation happens once per model/device/config combination
3. Subsequent runs use cached compiled models (97% faster)

## Advanced Configuration

### Custom Device Selection

```python
from hw_detect import HardwareDetector, DeviceSelector

# Detect hardware
detector = HardwareDetector(verbose=True)
profile = detector.run_full_detection()

# Create selector with load balancing
selector = DeviceSelector(profile)

# Select device for specific task
device = selector.select_device("pattern_matching", prefer_idle=True)
print(f"Selected device: {device}")
```

### Manual Optimization

```python
from ml_accelerated import InferenceConfig, ModelOptimizer

# Create custom config
config = InferenceConfig(
    device="NPU",
    precision="INT8",
    batch_size=8,
    num_streams=2,
    performance_mode="THROUGHPUT",
    enable_caching=True,
    memory_mode="OPTIMIZED",
    use_tensor_sharing=True,
    prefetch_data=True
)

# Compile model with config
optimizer = ModelOptimizer(config)
compiled_model = optimizer.compile_model("model.xml")
```

## Performance Expectations

### NPU (INT8)
- **Latency:** 0.5-2ms per inference
- **Throughput:** 500-2000 FPS (batch mode)
- **Memory:** 75% reduction vs CPU
- **Power:** Lowest power consumption
- **Best for:** Sustained ML workloads, pattern matching

### GPU (FP16)
- **Latency:** 1-3ms per inference
- **Throughput:** 300-1000 FPS (batch mode)
- **Memory:** 50% reduction vs CPU
- **Power:** Moderate power consumption
- **Best for:** Batch processing, parallel tasks

### CPU (FP32)
- **Latency:** 5-20ms per inference
- **Throughput:** 50-200 FPS
- **Memory:** Baseline (no reduction)
- **Power:** Variable
- **Best for:** General purpose, fallback

## Resources

- **Full Report:** `HARDWARE_OPTIMIZATION_REPORT.md`
- **Hardware Detection:** `hw_detect.py`
- **Benchmarking:** `hw-benchmark.py`
- **Acceleration Engine:** `ml_accelerated.py`
- **Example Code:** See `ml_accelerated.py` main function

## Support

For issues or questions:
1. Check hardware compatibility with `hw_detect.py`
2. Run benchmarks to verify performance with `hw-benchmark.py`
3. Review full optimization report in `HARDWARE_OPTIMIZATION_REPORT.md`
4. Enable verbose logging for detailed diagnostics

---

**Last Updated:** 2025-10-02
**Version:** 1.0
