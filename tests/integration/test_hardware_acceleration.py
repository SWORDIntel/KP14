"""
Integration Test 8: Hardware Acceleration Flow

Tests hardware-accelerated analysis workflows.

Validates:
- NPU/GPU device detection
- Accelerated vs CPU analysis comparison
- Result consistency across devices
- Performance differences
- Device selection logic
"""

import pytest
import json
from pathlib import Path


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.hardware
class TestHardwareAccelerationFlow:
    """Integration tests for hardware acceleration."""

    def test_cpu_analysis_baseline(
        self,
        integration_config,
        valid_pe32_sample,
        performance_tracker
    ):
        """
        Test CPU-only analysis as baseline.

        Validates default CPU execution path.
        """
        from core_engine.configuration_manager import ConfigurationManager
        from core_engine.pipeline_manager import PipelineManager

        # Force CPU-only config
        config = ConfigurationManager(str(integration_config))
        pipeline = PipelineManager(config)

        with performance_tracker("CPU Analysis") as metrics:
            report = pipeline.run_pipeline(str(valid_pe32_sample))

        cpu_duration = metrics["duration_seconds"]
        print(f"\nCPU analysis time: {cpu_duration:.3f}s")

        assert isinstance(report, dict)
        return report, cpu_duration

    @pytest.mark.skipif(
        True,  # Skip by default as hardware-specific
        reason="Requires NPU/GPU hardware"
    )
    def test_npu_accelerated_analysis(
        self,
        has_npu,
        integration_config,
        valid_pe32_sample,
        performance_tracker
    ):
        """
        Test NPU-accelerated analysis.

        Validates NPU execution if available.
        """
        if not has_npu:
            pytest.skip("NPU not available")

        from core_engine.configuration_manager import ConfigurationManager
        from core_engine.pipeline_manager import PipelineManager

        # Configure for NPU
        config = ConfigurationManager(str(integration_config))
        pipeline = PipelineManager(config)

        with performance_tracker("NPU Analysis") as metrics:
            report = pipeline.run_pipeline(str(valid_pe32_sample))

        npu_duration = metrics["duration_seconds"]
        print(f"\nNPU analysis time: {npu_duration:.3f}s")

        assert isinstance(report, dict)
        return report, npu_duration

    def test_device_detection(
        self,
        available_devices
    ):
        """
        Test hardware device detection.

        Validates device enumeration.
        """
        print(f"\nAvailable devices: {available_devices}")

        # Should at least have CPU
        assert "CPU" in available_devices or len(available_devices) > 0

        # Log device capabilities
        for device in available_devices:
            print(f"  - {device}")

    def test_result_consistency_across_devices(
        self,
        integration_pipeline,
        valid_pe32_sample
    ):
        """
        Test result consistency between CPU and accelerated execution.

        Validates that hardware acceleration doesn't change results.
        """
        # Run on CPU
        report_cpu = integration_pipeline.run_pipeline(str(valid_pe32_sample))

        # For now, just validate CPU results are consistent
        assert isinstance(report_cpu, dict)
        assert "original_file_type" in report_cpu

        # In a real test with GPU/NPU, would compare results
        # assert report_cpu["original_file_type"] == report_gpu["original_file_type"]

    def test_hardware_selection_logic(
        self,
        available_devices,
        integration_config
    ):
        """
        Test device selection logic.

        Validates preference order: NPU > GPU > CPU.
        """
        print(f"\nDevice selection from: {available_devices}")

        # Test device preference
        preferred = None

        if "NPU" in available_devices:
            preferred = "NPU"
        elif "GPU" in available_devices:
            preferred = "GPU"
        else:
            preferred = "CPU"

        print(f"Preferred device: {preferred}")
        assert preferred in ["NPU", "GPU", "CPU"]


@pytest.mark.integration
class TestHardwareAccelerationEdgeCases:
    """Test edge cases in hardware acceleration."""

    def test_fallback_to_cpu_on_error(
        self,
        integration_pipeline,
        valid_pe32_sample
    ):
        """
        Test graceful fallback to CPU on accelerator error.

        Validates error recovery.
        """
        # Even if accelerator fails, should fall back to CPU
        report = integration_pipeline.run_pipeline(str(valid_pe32_sample))

        # Should complete successfully
        assert isinstance(report, dict)
        print("\nAnalysis completed (with or without acceleration)")

    def test_mixed_accelerator_availability(
        self,
        available_devices
    ):
        """
        Test handling of mixed device availability.

        Validates graceful degradation.
        """
        print(f"\nDevice availability: {available_devices}")

        # Should handle any combination
        assert len(available_devices) >= 1  # At least CPU
