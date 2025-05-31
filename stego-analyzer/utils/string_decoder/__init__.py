"""
KEYPLUG String Decoder Module
----------------------------
Advanced system for detecting encoded strings and decoder functions in malware
using statistical analysis and OpenVINO hardware acceleration.
"""

from stego_analyzer.utils.string_decoder.string_detector import EncodedStringDetector
from stego_analyzer.utils.string_decoder.decoder_identifier import DecoderFunctionIdentifier
from stego_analyzer.utils.string_decoder.entropy_analyzer import EntropyAnalyzer

__version__ = "0.1.0"
