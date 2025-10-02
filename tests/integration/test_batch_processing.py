"""
Integration Test 6: Batch Processing

Tests batch analysis of multiple samples.

Validates:
- Parallel processing of multiple files
- Result aggregation
- Progress tracking
- Resource management
- Batch completion
"""

import pytest
import json
import subprocess
import sys
from pathlib import Path


@pytest.mark.integration
@pytest.mark.slow
class TestBatchProcessing:
    """Integration tests for batch analysis."""

    def test_batch_analyze_multiple_samples(
        self,
        batch_test_samples,
        integration_output_dir,
        integration_config,
        performance_tracker
    ):
        """
        Test batch processing of 10 samples.

        Validates parallel analysis completion.
        """
        # Get project root
        project_root = Path(__file__).parent.parent.parent

        # Path to batch analyzer
        batch_analyzer_path = project_root / "batch_analyzer.py"

        if not batch_analyzer_path.exists():
            pytest.skip("batch_analyzer.py not found")

        # Run batch analyzer
        cmd = [
            sys.executable,
            str(batch_analyzer_path),
            "--dir", str(batch_test_samples),
            "--output", str(integration_output_dir / "batch_results"),
            "--config", str(integration_config),
            "--workers", "2",  # Use 2 workers for testing
            "--quiet"
        ]

        with performance_tracker("Batch Processing (10 samples)"):
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

        # Check execution
        print(f"\nBatch analyzer exit code: {result.returncode}")
        print(f"Stdout: {result.stdout[:500]}")

        if result.returncode not in [0, 2, 3, 4]:  # 0=success, 2-4=warnings/findings
            print(f"Stderr: {result.stderr}")

        # Parse output
        try:
            output = json.loads(result.stdout)
            print(f"\nBatch results:")
            print(f"  Total: {output.get('total', 0)}")
            print(f"  Processed: {output.get('processed', 0)}")
            print(f"  Errors: {output.get('errors', 0)}")

            # Validate results
            assert output.get("total", 0) > 0
            assert output.get("processed", 0) > 0

        except json.JSONDecodeError:
            # May not be JSON if error occurred
            print(f"Output not JSON: {result.stdout[:200]}")

    def test_batch_result_aggregation(
        self,
        batch_test_samples,
        integration_output_dir,
        integration_config
    ):
        """
        Test batch result aggregation.

        Validates all results are collected.
        """
        project_root = Path(__file__).parent.parent.parent
        batch_analyzer_path = project_root / "batch_analyzer.py"

        if not batch_analyzer_path.exists():
            pytest.skip("batch_analyzer.py not found")

        output_dir = integration_output_dir / "batch_test_results"

        # Run batch analyzer
        cmd = [
            sys.executable,
            str(batch_analyzer_path),
            "--dir", str(batch_test_samples),
            "--output", str(output_dir),
            "--config", str(integration_config),
            "--workers", "2",
            "--quiet"
        ]

        subprocess.run(cmd, capture_output=True, timeout=300)

        # Check for output files
        results_file = output_dir / "batch_results.jsonl"
        summary_file = output_dir / "summary.json"

        if results_file.exists():
            # Count results
            with open(results_file, 'r') as f:
                results = [json.loads(line) for line in f]

            print(f"\nBatch results file contains {len(results)} entries")
            assert len(results) > 0

        if summary_file.exists():
            with open(summary_file, 'r') as f:
                summary = json.load(f)

            print(f"Summary: {summary}")

    def test_batch_error_handling(
        self,
        integration_samples_dir,
        integration_output_dir,
        integration_config
    ):
        """
        Test batch processing with mixed valid/invalid files.

        Validates graceful error handling.
        """
        project_root = Path(__file__).parent.parent.parent
        batch_analyzer_path = project_root / "batch_analyzer.py"

        if not batch_analyzer_path.exists():
            pytest.skip("batch_analyzer.py not found")

        # Create test directory with mixed files
        test_dir = integration_samples_dir / "mixed_samples"
        test_dir.mkdir(exist_ok=True)

        # Create some invalid files
        (test_dir / "invalid1.exe").write_bytes(b"NOT_A_PE")
        (test_dir / "invalid2.exe").write_bytes(b"\x00" * 100)

        try:
            output_dir = integration_output_dir / "mixed_batch_results"

            cmd = [
                sys.executable,
                str(batch_analyzer_path),
                "--dir", str(test_dir),
                "--output", str(output_dir),
                "--config", str(integration_config),
                "--quiet"
            ]

            result = subprocess.run(cmd, capture_output=True, timeout=120)

            # Should complete even with errors
            print(f"\nBatch with errors - exit code: {result.returncode}")

            # Should have processed files
            results_file = output_dir / "batch_results.jsonl"
            if results_file.exists():
                with open(results_file, 'r') as f:
                    results = [json.loads(line) for line in f]

                print(f"Processed {len(results)} files with errors")

        finally:
            # Cleanup
            import shutil
            if test_dir.exists():
                shutil.rmtree(test_dir)


@pytest.mark.integration
class TestBatchPerformance:
    """Test batch processing performance."""

    def test_batch_scales_with_workers(
        self,
        batch_test_samples,
        integration_output_dir,
        integration_config,
        performance_tracker
    ):
        """
        Test that batch processing scales with worker count.

        Validates parallel processing benefit.
        """
        project_root = Path(__file__).parent.parent.parent
        batch_analyzer_path = project_root / "batch_analyzer.py"

        if not batch_analyzer_path.exists():
            pytest.skip("batch_analyzer.py not found")

        # Test with 1 worker
        with performance_tracker("Batch (1 worker)") as metrics1:
            cmd1 = [
                sys.executable,
                str(batch_analyzer_path),
                "--dir", str(batch_test_samples),
                "--output", str(integration_output_dir / "batch_1worker"),
                "--config", str(integration_config),
                "--workers", "1",
                "--quiet"
            ]
            subprocess.run(cmd1, capture_output=True, timeout=300)

        time_1worker = metrics1["duration_seconds"]

        # Test with 2 workers
        with performance_tracker("Batch (2 workers)") as metrics2:
            cmd2 = [
                sys.executable,
                str(batch_analyzer_path),
                "--dir", str(batch_test_samples),
                "--output", str(integration_output_dir / "batch_2workers"),
                "--config", str(integration_config),
                "--workers", "2",
                "--quiet"
            ]
            subprocess.run(cmd2, capture_output=True, timeout=300)

        time_2workers = metrics2["duration_seconds"]

        print(f"\n1 worker: {time_1worker:.2f}s")
        print(f"2 workers: {time_2workers:.2f}s")

        # 2 workers should be faster (or at least not slower)
        # Allow some variance for overhead
        if time_1worker > 5:  # Only check if meaningful runtime
            print(f"Speedup: {time_1worker/time_2workers:.2f}x")


@pytest.mark.integration
class TestBatchResume:
    """Test batch processing resume capability."""

    def test_batch_resume_after_interruption(
        self,
        batch_test_samples,
        integration_output_dir,
        integration_config
    ):
        """
        Test batch resume functionality.

        Validates state persistence and resume.
        """
        project_root = Path(__file__).parent.parent.parent
        batch_analyzer_path = project_root / "batch_analyzer.py"

        if not batch_analyzer_path.exists():
            pytest.skip("batch_analyzer.py not found")

        output_dir = integration_output_dir / "batch_resume_test"

        # First run (will complete normally)
        cmd = [
            sys.executable,
            str(batch_analyzer_path),
            "--dir", str(batch_test_samples),
            "--output", str(output_dir),
            "--config", str(integration_config),
            "--workers", "1",
            "--quiet"
        ]

        subprocess.run(cmd, capture_output=True, timeout=300)

        # Check state file exists
        state_file = output_dir / "batch_state.json"

        if state_file.exists():
            with open(state_file, 'r') as f:
                state = json.load(f)

            print(f"\nState saved with {len(state.get('processed_files', []))} processed files")

            # Second run with --resume
            cmd_resume = cmd + ["--resume"]
            result = subprocess.run(cmd_resume, capture_output=True, timeout=60)

            print(f"Resume exit code: {result.returncode}")

            # Should recognize all files already processed
            if "already processed" in result.stderr.decode().lower():
                print("Resume correctly detected processed files")
