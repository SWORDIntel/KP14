"""
KEYPLUG Hash Algorithm Detector
-------------------------------
Modular system for detecting API hashing algorithms in multi-layered encrypted malware
using OpenVINO hardware acceleration for maximum performance.
"""

from stego_analyzer.utils.hash_detector.accelerator import OpenVINOAccelerator  # noqa: F401
from stego_analyzer.utils.hash_detector.patterns import HashPatterns  # noqa: F401
from stego_analyzer.utils.hash_detector.algorithms import HashAlgorithms  # noqa: F401
from stego_analyzer.utils.hash_detector.detector import HashDetector  # noqa: F401

__version__ = "0.1.0"
