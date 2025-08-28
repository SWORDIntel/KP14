"""
Hash Algorithms Module
--------------------
Implements common API hashing algorithms used in malware
with OpenVINO acceleration for maximum performance.
"""

import struct
import numpy as np
import concurrent.futures
import os

# Use maximum CPU cores
MAX_WORKERS = os.cpu_count()

class HashAlgorithms:
    """
    Implementation of common API hashing algorithms used in malware
    with methods to identify and reverse engineer custom algorithms.
    """
    
    @staticmethod
    def compute_ror13_hash(api_name):
        """
        Compute ROR-13 hash for an API name (common in many malware families)
        
        Args:
            api_name: API name string
            
        Returns:
            32-bit hash value
        """
        hash_val = 0
        for char in api_name:
            hash_val = ((hash_val >> 13) | (hash_val << 19)) & 0xFFFFFFFF  # ROR 13
            hash_val = (hash_val + ord(char)) & 0xFFFFFFFF
        return hash_val
    
    @staticmethod
    def compute_ror7_hash(api_name):
        """
        Compute ROR-7 hash for an API name (variation seen in some malware)
        
        Args:
            api_name: API name string
            
        Returns:
            32-bit hash value
        """
        hash_val = 0
        for char in api_name:
            hash_val = ((hash_val >> 7) | (hash_val << 25)) & 0xFFFFFFFF  # ROR 7
            hash_val = (hash_val + ord(char)) & 0xFFFFFFFF
        return hash_val
    
    @staticmethod
    def compute_djb2_hash(api_name):
        """
        Compute DJB2 hash for an API name (used in some malware)
        
        Args:
            api_name: API name string
            
        Returns:
            32-bit hash value
        """
        hash_val = 5381
        for char in api_name:
            hash_val = ((hash_val * 33) + ord(char)) & 0xFFFFFFFF
        return hash_val
    
    @staticmethod
    def compute_murmur_hash(api_name, seed=0x9747b28c):
        """
        Compute Murmur3 hash (occasionally used in advanced malware)
        
        Args:
            api_name: API name string
            seed: Hash seed value
            
        Returns:
            32-bit hash value
        """
        c1 = 0xcc9e2d51
        c2 = 0x1b873593
        r1 = 15
        r2 = 13
        m = 5
        n = 0xe6546b64
        
        hash_val = seed
        data = api_name.encode('utf-8')
        
        # Process 4 bytes at a time
        for i in range(0, len(data) - len(data) % 4, 4):
            k = struct.unpack('<I', data[i:i+4])[0]
            k = (k * c1) & 0xFFFFFFFF
            k = ((k << r1) | (k >> (32 - r1))) & 0xFFFFFFFF
            k = (k * c2) & 0xFFFFFFFF
            
            hash_val ^= k
            hash_val = ((hash_val << r2) | (hash_val >> (32 - r2))) & 0xFFFFFFFF
            hash_val = (hash_val * m + n) & 0xFFFFFFFF
        
        # Process remaining bytes
        remaining = len(data) % 4
        if remaining > 0:
            k = 0
            for i in range(remaining):
                k |= data[len(data) - remaining + i] << (8 * i)
            
            k = (k * c1) & 0xFFFFFFFF
            k = ((k << r1) | (k >> (32 - r1))) & 0xFFFFFFFF
            k = (k * c2) & 0xFFFFFFFF
            
            hash_val ^= k
        
        # Finalization
        hash_val ^= len(data)
        hash_val ^= (hash_val >> 16)
        hash_val = (hash_val * 0x85ebca6b) & 0xFFFFFFFF
        hash_val ^= (hash_val >> 13)
        hash_val = (hash_val * 0xc2b2ae35) & 0xFFFFFFFF
        hash_val ^= (hash_val >> 16)
        
        return hash_val
    
    @staticmethod
    def compute_custom_hash(api_name, algorithm_params):
        """
        Compute a custom hash based on specified parameters
        
        Args:
            api_name: API name string
            algorithm_params: Dict with hash algorithm parameters:
                - init_value: Initial hash value
                - operation: 'ror', 'rol', 'xor', 'add'
                - shift_val: Rotation amount (if applicable)
                - multiplier: Multiplication factor (if applicable)
                
        Returns:
            32-bit hash value
        """
        hash_val = algorithm_params.get('init_value', 0)
        operation = algorithm_params.get('operation', 'ror')
        shift_val = algorithm_params.get('shift_val', 13)
        multiplier = algorithm_params.get('multiplier', 1)
        
        for char in api_name:
            if operation == 'ror':
                hash_val = ((hash_val >> shift_val) | (hash_val << (32 - shift_val))) & 0xFFFFFFFF
            elif operation == 'rol':
                hash_val = ((hash_val << shift_val) | (hash_val >> (32 - shift_val))) & 0xFFFFFFFF
            elif operation == 'xor':
                hash_val = hash_val ^ (ord(char) * multiplier)
            
            # Common step: add character value to hash
            hash_val = (hash_val + ord(char)) & 0xFFFFFFFF
        
        return hash_val
    
    @staticmethod
    def compute_hash_batch(api_names, algorithm_name, params=None):
        """
        Compute hashes for a batch of API names using parallel processing
        
        Args:
            api_names: List of API name strings
            algorithm_name: Name of algorithm ('ror13', 'ror7', 'djb2', 'murmur', 'custom')
            params: Parameters for custom algorithm (if applicable)
            
        Returns:
            Dict mapping API names to their hash values
        """
        results = {}
        
        # Dispatch appropriate algorithm
        if algorithm_name == 'ror13':
            hash_func = HashAlgorithms.compute_ror13_hash
        elif algorithm_name == 'ror7':
            hash_func = HashAlgorithms.compute_ror7_hash
        elif algorithm_name == 'djb2':
            hash_func = HashAlgorithms.compute_djb2_hash
        elif algorithm_name == 'murmur':
            hash_func = lambda name: HashAlgorithms.compute_murmur_hash(name)
        elif algorithm_name == 'custom' and params:
            hash_func = lambda name: HashAlgorithms.compute_custom_hash(name, params)
        else:
            # Default to ROR-13
            hash_func = HashAlgorithms.compute_ror13_hash
        
        # Process in parallel for maximum performance
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_api = {executor.submit(hash_func, api): api for api in api_names}
            for future in concurrent.futures.as_completed(future_to_api):
                api = future_to_api[future]
                try:
                    hash_value = future.result()
                    results[api] = hash_value
                except Exception as exc:
                    print(f'Error computing hash for {api}: {exc}')
        
        return results
    
    @staticmethod
    def create_api_hash_database():
        """
        Create a database of known Windows API hashes using various algorithms
        
        Returns:
            Dict mapping API names to their hash values in different algorithms
        """
        # Common Windows APIs targeted by malware
        common_apis = [
            # Memory management
            "VirtualAlloc", "VirtualProtect", "VirtualFree", "HeapAlloc", "HeapCreate",
            # File operations
            "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
            "DeleteFileA", "DeleteFileW", "FindFirstFileA", "FindNextFileA",
            # Process/Thread operations
            "CreateProcessA", "CreateProcessW", "OpenProcess", "TerminateProcess",
            "CreateThread", "ExitThread", "GetCurrentProcess", "GetCurrentThread",
            # Module operations
            "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "GetModuleHandleA",
            "GetModuleHandleW", "FreeLibrary",
            # Registry operations
            "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegQueryValueExA",
            "RegCreateKeyExA", "RegDeleteKeyA",
            # Network operations
            "WSAStartup", "socket", "connect", "bind", "listen", "accept",
            "send", "recv", "WSACleanup", "gethostbyname", "inet_addr",
            # Synchronization
            "CreateMutexA", "CreateMutexW", "OpenMutexA", "ReleaseMutex",
            # Cryptography
            "CryptAcquireContextA", "CryptCreateHash", "CryptHashData", "CryptEncrypt",
            "CryptDecrypt", "CryptGenRandom",
            # Anti-analysis
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA",
            "GetTickCount", "QueryPerformanceCounter", "Sleep",
            # Command execution
            "WinExec", "ShellExecuteA", "ShellExecuteW", "system", "CreatePipe",
            # Service operations
            "OpenSCManagerA", "CreateServiceA", "StartServiceA", "ControlService",
            # COM/OLE
            "CoCreateInstance", "CoInitialize", "OleInitialize",
            # Keyboard/Mouse hooks
            "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
            # Windows UI
            "FindWindowA", "FindWindowExA", "GetForegroundWindow", "MessageBoxA",
            # DLL injection related
            "QueueUserAPC", "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
        ]
        
        # Generate hashes for each API using various algorithms
        api_hash_db = {}
        
        # Process each algorithm in parallel
        algorithms = [
            ("ror13", None),
            ("ror7", None),
            ("djb2", None),
            ("murmur", None),
            # Add custom algorithms as needed
        ]
        
        for algorithm_name, params in algorithms:
            hash_results = HashAlgorithms.compute_hash_batch(common_apis, algorithm_name, params)
            
            # Update the database
            for api, hash_val in hash_results.items():
                if api not in api_hash_db:
                    api_hash_db[api] = {}
                api_hash_db[api][algorithm_name] = hash_val
        
        return api_hash_db
    
    @staticmethod
    def reverse_lookup_hash(hash_value, algorithm_name, api_hash_db=None):
        """
        Look up an API name from its hash value
        
        Args:
            hash_value: Hash value to look up
            algorithm_name: Algorithm used to generate the hash
            api_hash_db: API hash database (will be created if None)
            
        Returns:
            List of API names that match the hash value, sorted by likelihood
        """
        if api_hash_db is None:
            api_hash_db = HashAlgorithms.create_api_hash_database()
        
        matches = []
        
        for api, hash_dict in api_hash_db.items():
            if algorithm_name in hash_dict and hash_dict[algorithm_name] == hash_value:
                matches.append(api)
        
        return matches
    
    @staticmethod
    def detect_algorithm_from_pattern(patterns):
        """
        Detect which hash algorithm is likely being used based on instruction patterns
        
        Args:
            patterns: List of instruction pattern descriptions
            
        Returns:
            Dict with algorithm name and confidence score
        """
        # Count pattern types
        pattern_counts = {
            'ror13': 0,
            'ror7': 0,
            'djb2': 0,
            'custom': 0
        }
        
        for pattern in patterns:
            if 'ROR' in pattern and '13' in pattern:
                pattern_counts['ror13'] += 1
            elif 'ROR' in pattern and '7' in pattern:
                pattern_counts['ror7'] += 1
            elif 'IMUL' in pattern and '33' in pattern:
                pattern_counts['djb2'] += 1
            elif '5381' in pattern:
                pattern_counts['djb2'] += 2  # Strong indicator
            elif 'ROL' in pattern or 'XOR' in pattern or 'ADD' in pattern:
                pattern_counts['custom'] += 1
        
        # Find the algorithm with the highest count
        algorithm = max(pattern_counts.items(), key=lambda x: x[1])
        
        # If no clear winner, mark as custom
        if algorithm[1] == 0:
            return {'algorithm': 'custom', 'confidence': 0.0}
        
        # Calculate confidence score (0.0 to 1.0)
        total_patterns = sum(pattern_counts.values())
        confidence = algorithm[1] / total_patterns
        
        return {
            'algorithm': algorithm[0],
            'confidence': confidence
        }
