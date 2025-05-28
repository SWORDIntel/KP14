"""
KEYPLUG Hash Algorithm Detector
-------------------------------
Modular system for detecting API hashing algorithms in multi-layered encrypted malware
using OpenVINO hardware acceleration for maximum performance.
"""

from .accelerator import OpenVINOAccelerator
from .patterns import HashPatterns
from .algorithms import HashAlgorithms
from .detector import HashDetector

__version__ = "0.1.0"
