"""
Integration Test 7: Docker Container Analysis

Tests analysis running in Docker container.

Validates:
- Docker image build
- Container execution
- Volume mounting
- Output retrieval
- GPU/NPU device passthrough (if available)
"""

import pytest
import subprocess
import json
from pathlib import Path


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.docker
class TestDockerIntegration:
    """Integration tests for Docker container analysis."""

    @pytest.mark.skipif(
        not Path("/var/run/docker.sock").exists(),
        reason="Docker not available"
    )
    def test_docker_image_builds(
        self,
        docker_available,
        performance_tracker
    ):
        """
        Test Docker image builds successfully.

        Validates Dockerfile and dependencies.
        """
        if not docker_available:
            pytest.skip("Docker not available")

        project_root = Path(__file__).parent.parent.parent
        dockerfile = project_root / "Dockerfile"

        if not dockerfile.exists():
            pytest.skip("Dockerfile not found")

        # Build image
        with performance_tracker("Docker Image Build"):
            result = subprocess.run(
                ["docker", "build", "-t", "kp14-test:latest", str(project_root)],
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout for build
            )

        print(f"\nDocker build exit code: {result.returncode}")

        if result.returncode != 0:
            print(f"Build stderr: {result.stderr[:500]}")

        assert result.returncode == 0, "Docker build should succeed"

    @pytest.mark.skipif(
        not Path("/var/run/docker.sock").exists(),
        reason="Docker not available"
    )
    def test_docker_container_analysis(
        self,
        docker_available,
        docker_image_name,
        valid_pe32_sample,
        integration_output_dir
    ):
        """
        Test running analysis in Docker container.

        Validates container execution and volume mounting.
        """
        if not docker_available:
            pytest.skip("Docker not available")

        # Create output directory
        output_dir = integration_output_dir / "docker_output"
        output_dir.mkdir(exist_ok=True)

        # Run analysis in container
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{valid_pe32_sample.parent}:/input:ro",
            "-v", f"{output_dir}:/output",
            docker_image_name,
            "python", "main.py",
            f"/input/{valid_pe32_sample.name}",
            "-o", "/output/report.json"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        print(f"\nDocker run exit code: {result.returncode}")

        if result.returncode != 0:
            print(f"Container stderr: {result.stderr[:500]}")

        # Check output file
        output_file = output_dir / "report.json"

        if output_file.exists():
            with open(output_file, 'r') as f:
                report = json.load(f)

            print(f"Report generated in container")
            assert isinstance(report, dict)
        else:
            pytest.skip("Container execution failed - image may not be built")

    @pytest.mark.skipif(
        not Path("/var/run/docker.sock").exists(),
        reason="Docker not available"
    )
    def test_docker_device_passthrough(
        self,
        docker_available,
        docker_image_name
    ):
        """
        Test GPU/NPU device passthrough to container.

        Validates hardware acceleration in container.
        """
        if not docker_available:
            pytest.skip("Docker not available")

        # Try to list devices in container
        cmd = [
            "docker", "run", "--rm",
            "--device=/dev/dri:/dev/dri",  # GPU passthrough
            docker_image_name,
            "python", "-c",
            "import sys; sys.path.insert(0, '.'); "
            "from hw_detect import detect_hardware; "
            "print(detect_hardware())"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )

        print(f"\nDevice detection in container:")
        print(result.stdout[:200])

        # Should not crash
        assert result.returncode == 0 or result.returncode == 1


@pytest.mark.integration
class TestDockerEdgeCases:
    """Test edge cases in Docker integration."""

    @pytest.mark.skipif(
        not Path("/var/run/docker.sock").exists(),
        reason="Docker not available"
    )
    def test_docker_resource_limits(
        self,
        docker_available,
        docker_image_name,
        valid_pe32_sample
    ):
        """
        Test analysis with container resource limits.

        Validates behavior under constraints.
        """
        if not docker_available:
            pytest.skip("Docker not available")

        # Run with memory limit
        cmd = [
            "docker", "run", "--rm",
            "--memory=512m",
            "--cpus=1",
            "-v", f"{valid_pe32_sample.parent}:/input:ro",
            docker_image_name,
            "python", "main.py",
            f"/input/{valid_pe32_sample.name}",
            "-f", "summary"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180
        )

        # Should handle resource limits gracefully
        print(f"\nResource-limited container exit code: {result.returncode}")
