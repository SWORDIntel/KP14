"""
Pattern Database

APT41/KEYPLUG-specific signatures and patterns:
- Behavioral signatures
- Memory patterns
- Network patterns
- Crypto patterns
- Auto-update mechanism
"""

from typing import Dict, List, Any
import json
import os


class PatternDatabase:
    """
    Pattern database for APT41/KEYPLUG malware detection.

    Contains signatures for:
    - Malware families
    - Behavioral patterns
    - Network indicators
    - Cryptographic patterns
    """

    def __init__(self, db_path: str = None):
        """Initialize pattern database."""
        self.db_path = db_path or os.path.join(os.path.dirname(__file__), 'patterns.json')
        self.patterns = self._load_default_patterns()

        # Try to load custom patterns
        if db_path and os.path.exists(db_path):
            self._load_custom_patterns(db_path)

    def _load_default_patterns(self) -> Dict[str, Any]:
        """Load default APT41/KEYPLUG patterns."""
        return {
            "apt41_keyplug": {
                "family": "KEYPLUG",
                "apt_group": "APT41",
                "aliases": ["winnti", "barium", "wicked panda"],

                "string_signatures": [
                    "KEYPLUG",
                    "winnti",
                    "barium",
                    "APT41",
                    "shadowpad",
                    "keyplug_install",
                    "keyplug_config",
                    "KP_MAGIC"
                ],

                "binary_patterns": [
                    {"name": "keyplug_magic", "pattern": "4B455950", "offset": "any"},
                    {"name": "xor_key_0x55", "pattern": "55555555", "offset": "any"},
                    {"name": "rc4_init", "pattern": "31C08945FC8B4DF8", "offset": ".text"}
                ],

                "network_patterns": {
                    "c2_protocols": ["http", "https", "tor"],
                    "user_agents": [
                        "Mozilla/5.0 (Windows NT 6.1; WOW64)",
                        "Microsoft BITS"
                    ],
                    "uri_patterns": [
                        "/update.php",
                        "/check.asp",
                        "/login.jsp"
                    ],
                    "port_preferences": [80, 443, 8080, 8443]
                },

                "behavioral_signatures": [
                    "persistence_registry_run",
                    "service_installation",
                    "dll_injection",
                    "process_hollowing",
                    "credential_dumping",
                    "lateral_movement_wmi"
                ],

                "memory_patterns": [
                    {"name": "rc4_sbox", "pattern": "000102030405060708090A0B0C0D0E0F", "size": 256},
                    {"name": "aes_key_schedule", "pattern": "52096AD53036A538", "type": "aes"}
                ],

                "crypto_patterns": {
                    "algorithms": ["rc4", "aes128", "aes256", "xor", "custom"],
                    "key_sizes": [128, 256],
                    "xor_keys": [0x55, 0xAA, 0x33, 0x66, 0x99, 0xCC]
                },

                "file_artifacts": [
                    "key.dat",
                    "config.ini",
                    "update.tmp",
                    ".plug"
                ],

                "registry_keys": [
                    "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services"
                ],

                "mutex_patterns": [
                    "Global\\keyplug_",
                    "Local\\{random_guid}",
                    "KP_MUTEX_"
                ],

                "confidence_weights": {
                    "string_match": 25,
                    "binary_pattern": 30,
                    "behavior_match": 20,
                    "network_pattern": 15,
                    "crypto_pattern": 10
                }
            },

            "generic_backdoor": {
                "family": "generic_backdoor",
                "behavioral_signatures": [
                    "c2_communication",
                    "file_upload",
                    "file_download",
                    "command_execution",
                    "screenshot_capture"
                ],
                "network_patterns": {
                    "c2_protocols": ["http", "https", "tcp", "udp"],
                    "suspicious_ports": [4444, 5555, 6666, 7777, 8888, 9999]
                }
            },

            "apt41_general": {
                "family": "APT41",
                "description": "APT41 general TTPs and indicators",
                "tools": [
                    "cobalt_strike",
                    "mimikatz",
                    "plink",
                    "psexec",
                    "winrar"
                ],
                "target_sectors": [
                    "financial",
                    "healthcare",
                    "telecommunications",
                    "gaming",
                    "software"
                ],
                "geographic_focus": [
                    "united_states",
                    "europe",
                    "japan",
                    "southeast_asia"
                ]
            }
        }

    def _load_custom_patterns(self, db_path: str):
        """Load custom patterns from JSON file."""
        try:
            with open(db_path, 'r') as f:
                custom = json.load(f)
                # Merge with default patterns
                for key, value in custom.items():
                    if key in self.patterns:
                        self.patterns[key].update(value)
                    else:
                        self.patterns[key] = value
        except Exception as e:
            print(f"Warning: Could not load custom patterns: {e}")

    def match_patterns(self, data: Dict[str, Any]) -> Dict[str, int]:
        """
        Match sample against pattern database.

        Args:
            data: Sample analysis data

        Returns:
            Dictionary of pattern matches with confidence scores
        """
        matches = {}

        for family_name, family_patterns in self.patterns.items():
            score = self._calculate_family_score(data, family_patterns)
            if score > 0:
                matches[family_name] = score

        return matches

    def _calculate_family_score(self, data: Dict[str, Any], patterns: Dict[str, Any]) -> int:
        """Calculate confidence score for family match."""
        score = 0
        weights = patterns.get('confidence_weights', {})

        # Check string signatures
        strings = data.get('strings', [])
        string_sigs = patterns.get('string_signatures', [])
        string_matches = sum(1 for sig in string_sigs if any(sig.lower() in s.lower() for s in strings))
        if string_matches > 0:
            score += weights.get('string_match', 20) * min(string_matches, 3)

        # Check behavioral signatures
        behaviors = data.get('behaviors', [])
        behavior_sigs = patterns.get('behavioral_signatures', [])
        behavior_matches = sum(1 for sig in behavior_sigs if sig in behaviors)
        if behavior_matches > 0:
            score += weights.get('behavior_match', 15) * min(behavior_matches, 3)

        # Check network patterns
        c2_endpoints = data.get('c2_endpoints', [])
        if c2_endpoints and 'network_patterns' in patterns:
            net_patterns = patterns['network_patterns']
            protocols = [ep.get('protocol', '') for ep in c2_endpoints if isinstance(ep, dict)]
            if any(p in net_patterns.get('c2_protocols', []) for p in protocols):
                score += weights.get('network_pattern', 10)

        return min(100, score)

    def get_family_info(self, family_name: str) -> Dict[str, Any]:
        """Get detailed information about a malware family."""
        return self.patterns.get(family_name, {})

    def add_pattern(self, family_name: str, pattern_data: Dict[str, Any]):
        """Add new pattern to database."""
        if family_name in self.patterns:
            self.patterns[family_name].update(pattern_data)
        else:
            self.patterns[family_name] = pattern_data

    def save_database(self, output_path: str = None):
        """Save pattern database to JSON file."""
        path = output_path or self.db_path
        with open(path, 'w') as f:
            json.dump(self.patterns, f, indent=2)

    def get_all_families(self) -> List[str]:
        """Get list of all malware families in database."""
        return list(self.patterns.keys())

    def search_patterns(self, query: str) -> List[Dict[str, Any]]:
        """Search patterns by keyword."""
        results = []
        query_lower = query.lower()

        for family_name, family_data in self.patterns.items():
            # Search in family name
            if query_lower in family_name.lower():
                results.append({"family": family_name, "data": family_data})
                continue

            # Search in strings
            string_sigs = family_data.get('string_signatures', [])
            if any(query_lower in sig.lower() for sig in string_sigs):
                results.append({"family": family_name, "data": family_data})

        return results
