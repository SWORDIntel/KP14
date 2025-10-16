"""
Hash Algorithm Patterns Module
----------------------------
Defines the instruction patterns and signatures for detecting
various API hashing algorithms in malware binaries.
"""

class HashPatterns:
    """
    Contains pattern definitions for common API hashing algorithms
    used in malware, particularly focusing on patterns seen in
    multi-layered encrypted malware.
    """
    
    # ROR-based hash algorithms (very common in malware)
    ROR_HASH_PATTERNS = [
        # ROR EAX, 13 (most common)
        (b"\xC1\xC8\x0D", "ROR EAX, 13 - common in many malware families"),
        # ROR EAX, 7
        (b"\xC1\xC8\x07", "ROR EAX, 7 - seen in APT malware"),
        # ROR EAX, 5
        (b"\xC1\xC8\x05", "ROR EAX, 5 - variation of common hash"),
        # ROR EDX, 13
        (b"\xC1\xCA\x0D", "ROR EDX, 13 - alternate register variant"),
        # ROR ECX, 13
        (b"\xC1\xC9\x0D", "ROR ECX, 13 - alternate register variant"),
        # ROR EBX, 13
        (b"\xC1\xCB\x0D", "ROR EBX, 13 - alternate register variant"),
    ]

    # ROL-based hash algorithms
    ROL_HASH_PATTERNS = [
        # ROL EAX, 9
        (b"\xC1\xC0\x09", "ROL EAX, 9 - custom hash algorithm"),
        # ROL EAX, 5
        (b"\xC1\xC0\x05", "ROL EAX, 5 - custom hash algorithm"),
        # ROL EDX, 3
        (b"\xC1\xC2\x03", "ROL EDX, 3 - custom hash algorithm"),
        # ROL ECX, 7
        (b"\xC1\xC1\x07", "ROL ECX, 7 - custom hash algorithm"),
    ]

    # Common hash initialization patterns
    HASH_INIT_PATTERNS = [
        # XOR EAX, EAX (zero initialization)
        (b"\x33\xC0", "XOR EAX, EAX - hash initialization"),
        # XOR ECX, ECX
        (b"\x33\xC9", "XOR ECX, ECX - hash initialization"),
        # XOR EDX, EDX
        (b"\x33\xD2", "XOR EDX, EDX - hash initialization"),
        # MOV EAX, 0
        (b"\xB8\x00\x00\x00\x00", "MOV EAX, 0 - hash initialization"),
        # MOV EAX, 5381 (djb2 hash initialization)
        (b"\xB8\x05\x15\x00\x00", "MOV EAX, 5381 - djb2 hash init"),
        # MOV EAX, 0x1505 (variation of djb2)
        (b"\xB8\x05\x15\x00\x00", "MOV EAX, 0x1505 - hash init"),
    ]

    # Common hash combination operations
    HASH_COMBINE_PATTERNS = [
        # ADD EAX, ECX (add character to hash)
        (b"\x03\xC1", "ADD EAX, ECX - character addition"),
        # ADD EAX, EDX
        (b"\x03\xC2", "ADD EAX, EDX - character addition"),
        # XOR EAX, ECX (xor character with hash)
        (b"\x33\xC1", "XOR EAX, ECX - character xor"),
        # XOR EAX, EDX
        (b"\x33\xC2", "XOR EAX, EDX - character xor"),
        # IMUL EAX, EAX, 33 (djb2 multiplication)
        (b"\x6B\xC0\x21", "IMUL EAX, EAX, 33 - djb2 multiply"),
        # IMUL EAX, 33
        (b"\x69\xC0\x21\x00\x00\x00", "IMUL EAX, 33 - djb2 multiply alt"),
    ]

    # Loop control for string processing
    STRING_LOOP_PATTERNS = [
        # Character load: MOVZX ECX, BYTE PTR [ESI]
        (b"\x0F\xB6\x0E", "MOVZX ECX, BYTE PTR [ESI] - load char"),
        # Character load: MOVZX EDX, BYTE PTR [ESI]
        (b"\x0F\xB6\x16", "MOVZX EDX, BYTE PTR [ESI] - load char"),
        # Character load: MOVZX EAX, BYTE PTR [ESI]
        (b"\x0F\xB6\x06", "MOVZX EAX, BYTE PTR [ESI] - load char"),
        # Character load: MOVZX ECX, BYTE PTR [EDI]
        (b"\x0F\xB6\x0F", "MOVZX ECX, BYTE PTR [EDI] - load char"),
        # Inc pointer: INC ESI
        (b"\x46", "INC ESI - increment string pointer"),
        # Inc pointer: INC EDI
        (b"\x47", "INC EDI - increment string pointer"),
        # String test: TEST AL, AL
        (b"\x84\xC0", "TEST AL, AL - string termination check"),
        # String test: CMP BYTE PTR [ESI], 0
        (b"\x80\x3E\x00", "CMP BYTE PTR [ESI], 0 - string end check"),
    ]

    # x64 variants of hash algorithms
    X64_HASH_PATTERNS = [
        # ROR RAX, 13
        (b"\x48\xC1\xC8\x0D", "ROR RAX, 13 - x64 hash algorithm"),
        # ROL RAX, 5
        (b"\x48\xC1\xC0\x05", "ROL RAX, 5 - x64 hash algorithm"),
        # XOR RAX, RAX
        (b"\x48\x33\xC0", "XOR RAX, RAX - x64 hash initialization"),
        # ADD RAX, RCX
        (b"\x48\x03\xC1", "ADD RAX, RCX - x64 character addition"),
    ]

    # PIC (Position Independent Code) hash calculation patterns
    PIC_HASH_PATTERNS = [
        # GET PC: CALL next_instruction / POP ECX
        (b"\xE8\x00\x00\x00\x00\x59", "GET PC: CALL+POP - PIC hash calculation"),
        # GET PC: CALL next_instruction / POP EAX
        (b"\xE8\x00\x00\x00\x00\x58", "GET PC: CALL+POP - PIC hash calculation"),
        # GET PC: FSTENV [ESP-12]
        (b"\xD9\x74\x24\xF4", "FSTENV [ESP-12] - PIC technique"),
    ]

    # Comparison of hash with expected value
    HASH_COMPARISON_PATTERNS = [
        # CMP EAX, immediate value
        (b"\x3D", "CMP EAX, imm32 - hash comparison"),
        # CMP ECX, immediate value
        (b"\x81\xF9", "CMP ECX, imm32 - hash comparison"),
        # CMP EDX, immediate value
        (b"\x81\xFA", "CMP EDX, imm32 - hash comparison"),
    ]
    
    # Possible hash values for commonly hashed APIs (examples)
    COMMON_API_HASH_VALUES = [
        # Example hashes for ROR-13 algorithm
        (b"\xEC\x0E\x4E\x6C", "Possible VirtualAlloc hash (ROR-13)"),
        (b"\x73\xE2\x3A\x98", "Possible CreateProcessA hash (ROR-13)"),
        (b"\x78\x02\xF7\x49", "Possible LoadLibraryA hash (ROR-13)"),
        (b"\x0E\xA1\x96\x91", "Possible GetProcAddress hash (ROR-13)"),
        # Example hashes for other algorithms would be added here
    ]
    
    @classmethod
    def get_all_patterns(cls):
        """
        Get all hash algorithm patterns
        
        Returns:
            List of all pattern tuples
        """
        all_patterns = []
        all_patterns.extend(cls.ROR_HASH_PATTERNS)
        all_patterns.extend(cls.ROL_HASH_PATTERNS)
        all_patterns.extend(cls.HASH_INIT_PATTERNS)
        all_patterns.extend(cls.HASH_COMBINE_PATTERNS)
        all_patterns.extend(cls.STRING_LOOP_PATTERNS)
        all_patterns.extend(cls.X64_HASH_PATTERNS)
        all_patterns.extend(cls.PIC_HASH_PATTERNS)
        all_patterns.extend(cls.HASH_COMPARISON_PATTERNS)
        all_patterns.extend(cls.COMMON_API_HASH_VALUES)
        
        return all_patterns
    
    @classmethod
    def get_algorithm_patterns(cls, algorithm_type):
        """
        Get patterns specific to a hash algorithm type
        
        Args:
            algorithm_type: Type of algorithm (e.g., 'ror13', 'djb2')
        
        Returns:
            List of pattern tuples for the specified algorithm
        """
        if algorithm_type == 'ror13':
            # ROR-13 specific patterns
            return [p for p in cls.ROR_HASH_PATTERNS if '13' in p[1]]
        elif algorithm_type == 'ror7':
            # ROR-7 specific patterns
            return [p for p in cls.ROR_HASH_PATTERNS if '7' in p[1]]
        elif algorithm_type == 'djb2':
            # DJB2 specific patterns
            djb2_patterns = []
            djb2_patterns.extend([p for p in cls.HASH_INIT_PATTERNS if '5381' in p[1]])
            djb2_patterns.extend([p for p in cls.HASH_COMBINE_PATTERNS if '33' in p[1]])
            return djb2_patterns
        elif algorithm_type == 'all':
            return cls.get_all_patterns()
        else:
            return []
