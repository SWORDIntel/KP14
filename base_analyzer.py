#!/usr/bin/env python3
"""
Base Analyzer Module - Abstract base class for KP14 analyzer plugins
This module defines the core plugin interface for all analyzer modules.

All analyzer plugins must inherit from BaseAnalyzer and implement the required methods.
This ensures consistent behavior, metadata handling, and result formatting across the platform.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set, Callable
from enum import Enum
import logging
from pathlib import Path


class AnalyzerCategory(Enum):
    """Categories for analyzer classification"""
    FORMAT = "format"              # PE, JPEG, PNG, ZIP, etc.
    CONTENT = "content"            # Steganography, polyglot, code analysis
    INTELLIGENCE = "intelligence"  # C2 extraction, threat scoring, MITRE mapping
    EXPORT = "export"              # STIX, MISP, YARA generators
    BEHAVIORAL = "behavioral"      # Behavioral pattern detection
    CRYPTOGRAPHIC = "cryptographic"  # Encryption/decryption analysis


class AnalysisPhase(Enum):
    """Analysis pipeline phases"""
    PRE_SCAN = "pre_scan"          # Initial file validation
    EXTRACTION = "extraction"      # Payload extraction
    DECRYPTION = "decryption"      # Cryptographic analysis
    STATIC = "static"              # Static code analysis
    INTELLIGENCE = "intelligence"  # Threat intelligence extraction
    EXPORT = "export"              # Report generation
    POST_PROCESS = "post_process"  # Cleanup and aggregation


class FileType(Enum):
    """Supported file types"""
    PE = "pe"
    JPEG = "jpeg"
    PNG = "png"
    BMP = "bmp"
    ZIP = "zip"
    ODG = "odg"
    BINARY = "binary"
    UNKNOWN = "unknown"


@dataclass
class AnalyzerCapabilities:
    """Defines what an analyzer can process and detect"""

    # Basic identification
    name: str
    version: str
    category: AnalyzerCategory

    # File type support
    supported_file_types: Set[FileType] = field(default_factory=set)

    # Phase support
    supported_phases: Set[AnalysisPhase] = field(default_factory=set)

    # Feature flags
    requires_pe_format: bool = False
    can_extract_payloads: bool = False
    can_decrypt: bool = False
    supports_recursive: bool = False
    hardware_accelerated: bool = False

    # Dependencies
    dependencies: Set[str] = field(default_factory=set)  # Other analyzer names
    optional_dependencies: Set[str] = field(default_factory=set)

    # Metadata
    description: str = ""
    author: str = ""
    license: str = "MIT"

    def __post_init__(self):
        """Validate capabilities"""
        if not self.name:
            raise ValueError("Analyzer name cannot be empty")
        if not self.version:
            raise ValueError("Analyzer version cannot be empty")


@dataclass
class AnalysisResult:
    """Standard result format for all analyzers"""

    # Core identification
    analyzer_name: str
    analyzer_version: str

    # Status
    success: bool
    error_message: Optional[str] = None

    # Data
    data: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    execution_time_ms: float = 0.0
    warnings: List[str] = field(default_factory=list)

    # Intelligence
    threat_indicators: List[Dict[str, Any]] = field(default_factory=list)
    confidence_score: float = 0.0  # 0.0 to 1.0

    # Extracted artifacts
    extracted_files: List[Path] = field(default_factory=list)

    def add_warning(self, message: str):
        """Add a warning message"""
        self.warnings.append(message)

    def add_threat_indicator(self, indicator_type: str, value: Any, confidence: float = 1.0):
        """Add a threat indicator"""
        self.threat_indicators.append({
            "type": indicator_type,
            "value": value,
            "confidence": confidence
        })


class BaseAnalyzer(ABC):
    """
    Abstract base class for all KP14 analyzers.

    All analyzer plugins must inherit from this class and implement:
    - get_capabilities(): Return analyzer metadata and capabilities
    - analyze(): Perform the actual analysis
    - get_priority(): Return execution priority (lower = higher priority)

    Optional methods to override:
    - validate_input(): Custom input validation
    - cleanup(): Resource cleanup after analysis
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the analyzer with optional configuration.

        Args:
            config: Configuration dictionary for this analyzer
        """
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self._enabled = self.config.get("enabled", True)

    @abstractmethod
    def get_capabilities(self) -> AnalyzerCapabilities:
        """
        Return the capabilities and metadata of this analyzer.

        This method defines what file types the analyzer can process,
        what phases it participates in, and any dependencies.

        Returns:
            AnalyzerCapabilities object describing this analyzer
        """
        pass

    @abstractmethod
    def analyze(self, file_data: bytes, metadata: Dict[str, Any]) -> AnalysisResult:
        """
        Perform analysis on the provided file data.

        Args:
            file_data: Binary content of the file to analyze
            metadata: Dictionary containing:
                - file_path: Path to the file
                - file_type: Detected file type (FileType enum)
                - file_size: Size in bytes
                - file_hash: SHA256 hash
                - previous_results: Results from earlier analyzers

        Returns:
            AnalysisResult containing the analysis findings
        """
        pass

    @abstractmethod
    def get_priority(self) -> int:
        """
        Return the execution priority for this analyzer.

        Lower numbers = higher priority (executed first).

        Priority ranges:
        - 0-99: Pre-scan and validation analyzers
        - 100-199: Format analyzers (PE, image formats)
        - 200-299: Content analyzers (steganography, polyglot)
        - 300-399: Cryptographic analyzers
        - 400-499: Static code analyzers
        - 500-599: Intelligence extractors
        - 600-699: Export generators
        - 700+: Post-processing

        Returns:
            Integer priority value
        """
        pass

    def is_enabled(self) -> bool:
        """
        Check if this analyzer is enabled.

        Returns:
            True if enabled, False otherwise
        """
        return self._enabled

    def validate_input(self, file_data: bytes, metadata: Dict[str, Any]) -> bool:
        """
        Validate that the input can be processed by this analyzer.

        Override this method to implement custom validation logic.

        Args:
            file_data: Binary content to validate
            metadata: File metadata

        Returns:
            True if input is valid, False otherwise
        """
        # Default implementation - check file type
        capabilities = self.get_capabilities()
        file_type = metadata.get("file_type", FileType.UNKNOWN)

        if capabilities.supported_file_types:
            return file_type in capabilities.supported_file_types

        return True

    def cleanup(self):
        """
        Perform cleanup after analysis.

        Override this method to release resources, close file handles, etc.
        """
        pass

    def can_process_phase(self, phase: AnalysisPhase) -> bool:
        """
        Check if this analyzer supports a specific analysis phase.

        Args:
            phase: The analysis phase to check

        Returns:
            True if this analyzer supports the phase
        """
        capabilities = self.get_capabilities()
        return phase in capabilities.supported_phases

    def get_config(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.

        Args:
            key: Configuration key
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        return self.config.get(key, default)

    def log_info(self, message: str):
        """Log an info message"""
        self.logger.info(f"[{self.__class__.__name__}] {message}")

    def log_warning(self, message: str):
        """Log a warning message"""
        self.logger.warning(f"[{self.__class__.__name__}] {message}")

    def log_error(self, message: str):
        """Log an error message"""
        self.logger.error(f"[{self.__class__.__name__}] {message}")

    def log_debug(self, message: str):
        """Log a debug message"""
        self.logger.debug(f"[{self.__class__.__name__}] {message}")


class HardwareAcceleratedAnalyzer(BaseAnalyzer):
    """
    Base class for analyzers that support hardware acceleration.

    Provides common functionality for OpenVINO integration and device selection.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.use_hardware_acceleration = config.get("use_hardware_acceleration", True)
        self.preferred_device = config.get("preferred_device", "AUTO")
        self._hardware_available = False
        self._init_hardware()

    def _init_hardware(self):
        """Initialize hardware acceleration"""
        if not self.use_hardware_acceleration:
            return

        try:
            from openvino.runtime import Core
            self.ov_core = Core()
            available_devices = self.ov_core.available_devices
            self._hardware_available = len(available_devices) > 0

            if self._hardware_available:
                self.log_info(f"Hardware acceleration available: {available_devices}")
            else:
                self.log_warning("No hardware acceleration devices found")
        except ImportError:
            self.log_warning("OpenVINO not available - hardware acceleration disabled")
            self._hardware_available = False

    def is_hardware_available(self) -> bool:
        """Check if hardware acceleration is available"""
        return self._hardware_available


class ResultAggregator:
    """
    Helper class for aggregating results from multiple analyzers.
    """

    def __init__(self):
        self.results: List[AnalysisResult] = []

    def add_result(self, result: AnalysisResult):
        """Add an analysis result"""
        self.results.append(result)

    def get_results_by_category(self, category: AnalyzerCategory) -> List[AnalysisResult]:
        """Get all results from analyzers of a specific category"""
        # This would require analyzer metadata to be stored with results
        # Implementation depends on how category info is preserved
        return self.results

    def get_all_threat_indicators(self) -> List[Dict[str, Any]]:
        """Collect all threat indicators from all analyzers"""
        all_indicators = []
        for result in self.results:
            all_indicators.extend(result.threat_indicators)
        return all_indicators

    def get_overall_confidence(self) -> float:
        """Calculate overall confidence score across all analyzers"""
        if not self.results:
            return 0.0

        # Average confidence scores
        total = sum(r.confidence_score for r in self.results)
        return total / len(self.results)

    def has_errors(self) -> bool:
        """Check if any analyzer reported errors"""
        return any(not r.success for r in self.results)

    def get_errors(self) -> List[str]:
        """Get all error messages"""
        errors = []
        for result in self.results:
            if not result.success and result.error_message:
                errors.append(f"{result.analyzer_name}: {result.error_message}")
        return errors

    def to_dict(self) -> Dict[str, Any]:
        """Convert aggregated results to dictionary"""
        return {
            "total_analyzers": len(self.results),
            "successful_analyzers": sum(1 for r in self.results if r.success),
            "failed_analyzers": sum(1 for r in self.results if not r.success),
            "overall_confidence": self.get_overall_confidence(),
            "threat_indicators": self.get_all_threat_indicators(),
            "errors": self.get_errors(),
            "results": [
                {
                    "analyzer": r.analyzer_name,
                    "version": r.analyzer_version,
                    "success": r.success,
                    "data": r.data,
                    "confidence": r.confidence_score,
                    "execution_time_ms": r.execution_time_ms
                }
                for r in self.results
            ]
        }
