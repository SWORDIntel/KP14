"""
KEYPLUG String Decoder Module
----------------------------
Advanced system for detecting encoded strings and decoder functions in malware
using statistical analysis and OpenVINO hardware acceleration.
"""

from .string_detector import EncodedStringDetector
from .decoder_identifier import DecoderFunctionIdentifier
from .entropy_analyzer import EntropyAnalyzer

__version__ = "0.1.0"
