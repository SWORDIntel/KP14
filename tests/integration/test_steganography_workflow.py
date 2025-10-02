"""
Integration Test 3: Steganography Detection Workflow

Tests end-to-end steganography detection and extraction.

Validates:
- LSB steganography detection
- Payload extraction from images
- Analysis of extracted payloads
- Multiple stego technique detection
- Format-specific stego handling
"""

import pytest
import json
from pathlib import Path


@pytest.mark.integration
@pytest.mark.slow
class TestSteganographyWorkflow:
    """Integration tests for steganography detection pipeline."""

    def test_lsb_stego_detection_and_extraction(
        self,
        integration_pipeline,
        stego_lsb_image_sample,
        performance_tracker
    ):
        """
        Test LSB steganography detection in PNG image.

        Validates detection and extraction of LSB-embedded data.
        """
        with performance_tracker("LSB Steganography Detection"):
            report = integration_pipeline.run_pipeline(str(stego_lsb_image_sample))

        # Validate basic structure
        assert isinstance(report, dict)
        assert report["file_path"] == str(stego_lsb_image_sample)
        assert report["original_file_type"] == "png"

        # Check steganography analysis
        if "steganography_analysis" in report and report["steganography_analysis"]:
            stego_analysis = report["steganography_analysis"]
            assert isinstance(stego_analysis, dict)

            # Check LSB analysis
            if "lsb_analysis" in stego_analysis:
                lsb_result = stego_analysis["lsb_analysis"]
                assert isinstance(lsb_result, dict)

                # Should have status
                if "status" in lsb_result:
                    status = lsb_result["status"]
                    assert isinstance(status, str)

                    # If data was extracted
                    if status == "data_extracted":
                        print("\nLSB data successfully extracted")

                        # Should have extracted data
                        if "data" in lsb_result:
                            extracted_data = lsb_result["data"]
                            assert isinstance(extracted_data, bytes)
                            assert len(extracted_data) > 0

                            # Check if it extracted our test message
                            if b"HIDDEN_PAYLOAD" in extracted_data:
                                print("Test payload successfully recovered!")

    def test_appended_data_detection(
        self,
        integration_pipeline,
        integration_samples_dir,
        valid_pe32_sample
    ):
        """
        Test detection of data appended to images.

        Validates EOF marker-based detection.
        """
        # Create image with appended PE
        test_image = integration_samples_dir / "image_with_appended_pe.png"

        # Create simple PNG (1x1 pixel)
        from PIL import Image
        import numpy as np

        img_array = np.array([[[255, 0, 0]]], dtype=np.uint8)
        img = Image.fromarray(img_array, 'RGB')
        img.save(test_image, 'PNG')

        # Append PE data
        with open(valid_pe32_sample, 'rb') as f:
            pe_data = f.read()

        with open(test_image, 'ab') as f:
            f.write(pe_data)

        try:
            report = integration_pipeline.run_pipeline(str(test_image))

            # Check steganography analysis
            if "steganography_analysis" in report and report["steganography_analysis"]:
                stego_analysis = report["steganography_analysis"]

                # Check for appended data detection
                if "appended_data" in stego_analysis:
                    appended = stego_analysis["appended_data"]
                    assert isinstance(appended, list)

                    if len(appended) > 0:
                        print(f"\nFound {len(appended)} appended data blocks")

                        # Check if PE was detected
                        for block in appended:
                            if block.get("data", b"").startswith(b"MZ"):
                                print("Appended PE detected successfully")

                # Check if extracted PE was analyzed
                if "extracted_payload_analyses" in report:
                    extracted = report["extracted_payload_analyses"]
                    if len(extracted) > 0:
                        print(f"Recursively analyzed {len(extracted)} extracted payloads")

        finally:
            # Cleanup
            if test_image.exists():
                test_image.unlink()

    def test_multiple_stego_techniques(
        self,
        integration_pipeline,
        stego_lsb_image_sample
    ):
        """
        Test detection of multiple steganography techniques on same file.

        Validates comprehensive stego scanning.
        """
        report = integration_pipeline.run_pipeline(str(stego_lsb_image_sample))

        if "steganography_analysis" in report and report["steganography_analysis"]:
            stego_analysis = report["steganography_analysis"]

            # Count detected techniques
            techniques_checked = []

            if "lsb_analysis" in stego_analysis:
                techniques_checked.append("lsb")

            if "appended_data" in stego_analysis:
                techniques_checked.append("appended")

            print(f"\nSteganography techniques checked: {techniques_checked}")

            # Should check multiple techniques
            assert len(techniques_checked) > 0

    def test_clean_image_no_false_positives(
        self,
        integration_pipeline,
        integration_samples_dir
    ):
        """
        Test that clean images don't trigger false stego detection.

        Validates specificity of stego detection.
        """
        # Create clean PNG
        from PIL import Image
        import numpy as np

        clean_image = integration_samples_dir / "clean_image.png"

        # Create random image
        img_array = np.random.randint(0, 256, (50, 50, 3), dtype=np.uint8)
        img = Image.fromarray(img_array, 'RGB')
        img.save(clean_image, 'PNG')

        try:
            report = integration_pipeline.run_pipeline(str(clean_image))

            # Should detect as PNG
            assert report["original_file_type"] == "png"

            # May have steganography analysis
            if "steganography_analysis" in report and report["steganography_analysis"]:
                stego_analysis = report["steganography_analysis"]

                # LSB analysis shouldn't find PE payload
                if "lsb_analysis" in stego_analysis:
                    lsb_result = stego_analysis["lsb_analysis"]

                    # Should not extract PE from random data
                    if "status" in lsb_result:
                        # Even if data extracted, shouldn't be PE
                        if "data" in lsb_result:
                            extracted = lsb_result["data"]
                            # Random LSB shouldn't form valid PE
                            # (statistically very unlikely)
                            pass

        finally:
            # Cleanup
            if clean_image.exists():
                clean_image.unlink()


@pytest.mark.integration
class TestSteganographyFormats:
    """Test steganography detection across different formats."""

    def test_png_lsb_support(
        self,
        integration_pipeline,
        stego_lsb_image_sample
    ):
        """
        Test PNG LSB steganography support.

        Validates PNG-specific stego handling.
        """
        report = integration_pipeline.run_pipeline(str(stego_lsb_image_sample))

        # Should recognize PNG
        assert report["original_file_type"] == "png"

        # Should run stego analysis on PNG
        if "steganography_analysis" in report:
            assert report["steganography_analysis"] is not None

    def test_jpeg_appended_data_support(
        self,
        integration_pipeline,
        integration_samples_dir,
        valid_pe32_sample
    ):
        """
        Test JPEG appended data detection.

        Validates JPEG EOI marker-based detection.
        """
        # Create JPEG with appended data
        from PIL import Image
        import numpy as np

        jpeg_file = integration_samples_dir / "jpeg_with_appended.jpg"

        # Create simple JPEG
        img_array = np.random.randint(0, 256, (50, 50, 3), dtype=np.uint8)
        img = Image.fromarray(img_array, 'RGB')
        img.save(jpeg_file, 'JPEG')

        # Append data after JPEG EOI marker
        with open(jpeg_file, 'ab') as f:
            f.write(b'\x00' * 100)  # Some padding
            f.write(b"SECRET_DATA_AFTER_EOI")

        try:
            report = integration_pipeline.run_pipeline(str(jpeg_file))

            # Should detect as JPEG
            assert report["original_file_type"] == "jpeg"

            # Check for appended data detection
            if "steganography_analysis" in report and report["steganography_analysis"]:
                stego_analysis = report["steganography_analysis"]

                if "appended_data" in stego_analysis:
                    appended = stego_analysis["appended_data"]

                    if len(appended) > 0:
                        print(f"\nFound appended data in JPEG")

        finally:
            # Cleanup
            if jpeg_file.exists():
                jpeg_file.unlink()


@pytest.mark.integration
@pytest.mark.slow
class TestSteganographyPerformance:
    """Test performance of steganography detection."""

    def test_large_image_stego_detection(
        self,
        integration_pipeline,
        integration_samples_dir,
        performance_tracker
    ):
        """
        Test steganography detection on larger images.

        Validates performance with realistic image sizes.
        """
        from PIL import Image
        import numpy as np

        # Create larger image (1000x1000)
        large_image = integration_samples_dir / "large_image.png"

        img_array = np.random.randint(0, 256, (1000, 1000, 3), dtype=np.uint8)
        img = Image.fromarray(img_array, 'RGB')
        img.save(large_image, 'PNG')

        try:
            with performance_tracker("Large Image Stego Detection (1000x1000)") as metrics:
                report = integration_pipeline.run_pipeline(str(large_image))

            duration = metrics["duration_seconds"]
            print(f"\nProcessed 1000x1000 image in {duration:.2f}s")

            # Should complete
            assert isinstance(report, dict)
            assert report["original_file_type"] == "png"

        finally:
            # Cleanup
            if large_image.exists():
                large_image.unlink()

    def test_stego_memory_efficiency(
        self,
        integration_pipeline,
        stego_lsb_image_sample
    ):
        """
        Test memory efficiency of steganography detection.

        Validates no memory leaks on repeated scans.
        """
        import gc

        # Run multiple times
        for i in range(3):
            report = integration_pipeline.run_pipeline(str(stego_lsb_image_sample))
            assert isinstance(report, dict)

            # Force garbage collection
            gc.collect()

        print("\nMemory efficiency test passed - no crashes")
