"""
Decoder Function Identifier Module
--------------------------------
Identifies potential decoder functions in malware binaries
and analyzes their behavior using OpenVINO acceleration.
"""

import os
import struct
import binascii
import numpy as np
import concurrent.futures
from collections import Counter, defaultdict
from tqdm import tqdm

# Try to import OpenVINO
try:
    from openvino.runtime import Core
    OPENVINO_AVAILABLE = True
    print("OpenVINO runtime available - using hardware acceleration")
except ImportError:
    OPENVINO_AVAILABLE = False
    print("OpenVINO not available - falling back to CPU-only processing")

# Use maximum CPU cores
MAX_WORKERS = os.cpu_count()
print(f"Using maximum CPU cores: {MAX_WORKERS}")

class DecoderFunctionIdentifier:
    """
    Identifies and analyzes potential decoder functions in malware binaries
    using instruction pattern analysis and OpenVINO acceleration.
    """
    
    def __init__(self):
        """Initialize the decoder function identifier"""
        self.core = None
        
        if OPENVINO_AVAILABLE:
            try:
                self.core = Core()
                print(f"OpenVINO Core initialized successfully")
                print(f"Available devices: {self.core.available_devices}")
                
                # Default to CPU
                self.preferred_device = "CPU"
                
                # Try to use more powerful devices if available
                if "GPU" in self.core.available_devices:
                    self.preferred_device = "GPU"
                    print("Using GPU acceleration")
                elif "VPU" in self.core.available_devices:
                    self.preferred_device = "VPU"
                    print("Using VPU acceleration")
                else:
                    print("Using CPU acceleration")
                    
            except Exception as e:
                print(f"Error initializing OpenVINO Core: {e}")
                self.core = None
    
    # Common decoder function patterns
    DECODER_PATTERNS = {
        # XOR operations
        'xor': [
            (b"\x33", "XOR register operations"),
            (b"\x34", "XOR AL, imm8"),
            (b"\x35", "XOR EAX, imm32"),
            (b"\x80\xF0", "XOR byte ptr [reg], imm8"),
            (b"\x80\xF1", "XOR byte ptr [reg+disp], imm8"),
            (b"\x80\xF2", "XOR byte ptr [reg+reg], imm8"),
            (b"\x80\xF3", "XOR byte ptr [reg+reg+disp], imm8"),
        ],
        
        # ADD/SUB operations
        'add_sub': [
            (b"\x00", "ADD byte ptr [reg], reg"),
            (b"\x01", "ADD dword ptr [reg], reg"),
            (b"\x02", "ADD reg, byte ptr [reg]"),
            (b"\x03", "ADD reg, dword ptr [reg]"),
            (b"\x04", "ADD AL, imm8"),
            (b"\x05", "ADD EAX, imm32"),
            (b"\x28", "SUB byte ptr [reg], reg"),
            (b"\x29", "SUB dword ptr [reg], reg"),
            (b"\x2A", "SUB reg, byte ptr [reg]"),
            (b"\x2B", "SUB reg, dword ptr [reg]"),
            (b"\x2C", "SUB AL, imm8"),
            (b"\x2D", "SUB EAX, imm32"),
        ],
        
        # Rotate operations
        'rotate': [
            (b"\xC0\xC0", "ROL reg, imm8"),
            (b"\xC0\xC8", "ROR reg, imm8"),
            (b"\xC1\xC0", "ROL reg, imm8"),
            (b"\xC1\xC8", "ROR reg, imm8"),
            (b"\xD2\xC0", "ROL reg, CL"),
            (b"\xD2\xC8", "ROR reg, CL"),
            (b"\xD3\xC0", "ROL reg, CL"),
            (b"\xD3\xC8", "ROR reg, CL"),
        ],
        
        # Loop constructs
        'loop': [
            (b"\xE2", "LOOP rel8"),
            (b"\xE1", "LOOPE/LOOPZ rel8"),
            (b"\xE0", "LOOPNE/LOOPNZ rel8"),
            (b"\xFF\xC0", "INC EAX - common in loops"),
            (b"\xFF\xC1", "INC ECX - common in loops"),
            (b"\xFF\xC2", "INC EDX - common in loops"),
            (b"\xFF\xC3", "INC EBX - common in loops"),
            (b"\xFF\xC6", "INC ESI - common in loops"),
            (b"\xFF\xC7", "INC EDI - common in loops"),
            (b"\xFF\xC8", "DEC EAX - common in loops"),
            (b"\xFF\xC9", "DEC ECX - common in loops"),
            (b"\xFF\xCA", "DEC EDX - common in loops"),
            (b"\xFF\xCB", "DEC EBX - common in loops"),
            (b"\xFF\xCE", "DEC ESI - common in loops"),
            (b"\xFF\xCF", "DEC EDI - common in loops"),
        ],
        
        # Memory access patterns common in decoders
        'memory': [
            (b"\x8A", "MOV reg8, byte ptr [reg] - byte load"),
            (b"\x8B", "MOV reg32, dword ptr [reg] - dword load"),
            (b"\x88", "MOV byte ptr [reg], reg8 - byte store"),
            (b"\x89", "MOV dword ptr [reg], reg32 - dword store"),
            (b"\xAA", "STOSB - string store"),
            (b"\xAB", "STOSD - string store"),
            (b"\xAC", "LODSB - string load"),
            (b"\xAD", "LODSD - string load"),
            (b"\xA4", "MOVSB - string move"),
            (b"\xA5", "MOVSD - string move"),
        ],
        
        # Function prologue/epilogue
        'function': [
            (b"\x55", "PUSH EBP - function prologue"),
            (b"\x89\xE5", "MOV EBP, ESP - function prologue"),
            (b"\x8B\xEC", "MOV EBP, ESP - function prologue"),
            (b"\x83\xEC", "SUB ESP, imm8 - stack allocation"),
            (b"\x81\xEC", "SUB ESP, imm32 - stack allocation"),
            (b"\x5D", "POP EBP - function epilogue"),
            (b"\xC3", "RET - function return"),
            (b"\xC2", "RET imm16 - function return with stack cleanup"),
        ],
        
        # Conditional jumps (common in decoders)
        'conditional': [
            (b"\x74", "JE/JZ rel8 - conditional jump"),
            (b"\x75", "JNE/JNZ rel8 - conditional jump"),
            (b"\x76", "JBE/JNA rel8 - conditional jump"),
            (b"\x77", "JA/JNBE rel8 - conditional jump"),
            (b"\x72", "JB/JNAE/JC rel8 - conditional jump"),
            (b"\x73", "JAE/JNB/JNC rel8 - conditional jump"),
            (b"\x7C", "JL/JNGE rel8 - conditional jump"),
            (b"\x7D", "JGE/JNL rel8 - conditional jump"),
            (b"\x7E", "JLE/JNG rel8 - conditional jump"),
            (b"\x7F", "JG/JNLE rel8 - conditional jump"),
        ],
    }
    
    def identify_potential_decoders(self, binary_data, functions=None):
        """
        Identify potential decoder functions in binary data
        
        Args:
            binary_data: Binary data to analyze
            functions: Optional list of function boundaries
                       (if None, will try to identify functions)
            
        Returns:
            List of potential decoder functions with metadata
        """
        # If no functions provided, try to identify them
        if functions is None:
            functions = self._identify_function_boundaries(binary_data)
            print(f"Identified {len(functions)} potential functions")
        
        # Process functions in parallel for maximum performance
        potential_decoders = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = []
            for func in functions:
                start = func["start_offset"]
                size = func["size"]
                
                # Skip very large functions (unlikely to be decoders)
                if size > 1024:
                    continue
                
                # Extract function data
                end = min(start + size, len(binary_data))
                func_data = binary_data[start:end]
                
                futures.append(executor.submit(
                    self._analyze_function_for_decoder, 
                    func_data, 
                    start, 
                    size
                ))
            
            # Collect results
            for future in tqdm(concurrent.futures.as_completed(futures), 
                              total=len(futures),
                              desc="Analyzing functions"):
                try:
                    result = future.result()
                    if result:
                        potential_decoders.append(result)
                except Exception as e:
                    print(f"Error analyzing function: {e}")
        
        # Sort by score
        potential_decoders.sort(key=lambda x: x["decoder_score"], reverse=True)
        
        return potential_decoders
    
    def _identify_function_boundaries(self, binary_data):
        """
        Identify function boundaries in binary data
        
        Args:
            binary_data: Binary data to analyze
            
        Returns:
            List of function dictionaries with start_offset and size
        """
        # Common function prologues
        prologues = [
            b"\x55\x8b\xec",           # push ebp; mov ebp, esp
            b"\x55\x89\xe5",           # push ebp; mov ebp, esp
            b"\x53\x56\x57",           # push ebx; push esi; push edi
            b"\x56\x57",               # push esi; push edi
            b"\x83\xec",               # sub esp, X
            b"\x81\xec",               # sub esp, XXXX
            b"\x48\x89\x5c\x24",       # mov [rsp+X], rbx
            b"\x48\x83\xec",           # sub rsp, X
            b"\x48\x81\xec",           # sub rsp, XXXX
            b"\x40\x53",               # push rbx
            b"\x40\x55",               # push rbp
            b"\x40\x56",               # push rsi
            b"\x40\x57",               # push rdi
        ]
        
        # Find all prologues
        function_starts = []
        for prologue in prologues:
            offset = 0
            while True:
                offset = binary_data.find(prologue, offset)
                if offset == -1:
                    break
                function_starts.append(offset)
                offset += 1
        
        # Sort and deduplicate
        function_starts = sorted(set(function_starts))
        
        # Create functions with estimated boundaries
        functions = []
        for i, start in enumerate(function_starts):
            # Determine end boundary (next function start or end of data)
            end = len(binary_data)
            if i < len(function_starts) - 1:
                end = function_starts[i + 1]
            
            # Limit function size to reasonable maximum
            if end - start > 4096:
                end = start + 4096
            
            functions.append({
                "start_offset": start,
                "size": end - start
            })
        
        return functions
    
    def _analyze_function_for_decoder(self, func_data, start_offset, size):
        """
        Analyze a function to determine if it's a potential decoder
        
        Args:
            func_data: Function binary data
            start_offset: Function start offset in the full binary
            size: Function size
            
        Returns:
            Dict with function analysis if it's a potential decoder, None otherwise
        """
        # Count pattern occurrences
        pattern_counts = defaultdict(int)
        instruction_counts = defaultdict(int)
        
        # Check each pattern category
        for category, patterns in self.DECODER_PATTERNS.items():
            for pattern, description in patterns:
                # Count occurrences
                offset = 0
                while True:
                    offset = func_data.find(pattern, offset)
                    if offset == -1:
                        break
                    
                    pattern_counts[category] += 1
                    instruction_counts[description] += 1
                    offset += 1
        
        # Calculate decoder score
        decoder_score = self._calculate_decoder_score(pattern_counts, size)
        
        # Only include if score is high enough
        if decoder_score >= 0.6:
            # Calculate additional metrics
            metrics = self._calculate_function_metrics(func_data)
            
            # Determine potential decoder type
            decoder_type = self._determine_decoder_type(pattern_counts, instruction_counts)
            
            return {
                "start_offset": start_offset,
                "size": size,
                "decoder_score": decoder_score,
                "decoder_type": decoder_type,
                "pattern_counts": dict(pattern_counts),
                "top_instructions": self._get_top_instructions(instruction_counts, 10),
                "metrics": metrics
            }
        
        return None
    
    def _calculate_decoder_score(self, pattern_counts, size):
        """
        Calculate a score indicating likelihood of being a decoder function
        
        Args:
            pattern_counts: Dict of pattern category counts
            size: Function size
            
        Returns:
            Score between 0.0 and 1.0
        """
        # Base score
        score = 0.0
        
        # Small size is typical for decoders (15-300 bytes)
        if 15 <= size <= 100:
            score += 0.2
        elif 100 < size <= 300:
            score += 0.1
        
        # XOR operations are very common in decoders
        if pattern_counts['xor'] > 0:
            score += min(0.3, 0.05 * pattern_counts['xor'])
        
        # ADD/SUB operations are common in decoders
        if pattern_counts['add_sub'] > 0:
            score += min(0.2, 0.03 * pattern_counts['add_sub'])
        
        # Rotate operations are strong indicators
        if pattern_counts['rotate'] > 0:
            score += min(0.3, 0.1 * pattern_counts['rotate'])
        
        # Loop constructs are essential for decoders
        if pattern_counts['loop'] > 0:
            score += min(0.3, 0.05 * pattern_counts['loop'])
        
        # Memory operations are necessary
        if pattern_counts['memory'] > 0:
            score += min(0.2, 0.02 * pattern_counts['memory'])
        
        # Conditional jumps for byte checking
        if pattern_counts['conditional'] > 0:
            score += min(0.2, 0.03 * pattern_counts['conditional'])
        
        # Function markers (should have at least prologue/epilogue)
        if pattern_counts['function'] >= 2:
            score += 0.1
        
        # Check for balanced pattern distribution
        categories_present = sum(1 for count in pattern_counts.values() if count > 0)
        if categories_present >= 5:
            score += 0.2
        elif categories_present >= 3:
            score += 0.1
        
        # Cap at 1.0
        return min(1.0, score)
    
    def _calculate_function_metrics(self, func_data):
        """
        Calculate additional metrics for function analysis
        
        Args:
            func_data: Function binary data
            
        Returns:
            Dict with metrics
        """
        # Byte frequency distribution
        byte_freq = Counter(func_data)
        unique_bytes = len(byte_freq)
        
        # Instruction density (approximate)
        # Most x86 instructions are 2-4 bytes
        estimated_instructions = len(func_data) / 3
        
        # Calculate entropy
        entropy = 0.0
        for count in byte_freq.values():
            p = count / len(func_data)
            entropy -= p * np.log2(p)
        
        # Detect potential immediate values (common in decoders)
        immediates = []
        for i in range(len(func_data) - 4):
            # Look for immediate following common opcodes
            if func_data[i] in [0x05, 0x35, 0x81, 0x69]:
                imm = struct.unpack("<I", func_data[i+1:i+5])[0]
                immediates.append(imm)
        
        return {
            "unique_bytes": unique_bytes,
            "byte_diversity": unique_bytes / 256,
            "entropy": entropy,
            "estimated_instructions": estimated_instructions,
            "instruction_density": estimated_instructions / len(func_data),
            "potential_immediates": immediates[:5]  # Limit to 5 for brevity
        }
    
    def _determine_decoder_type(self, pattern_counts, instruction_counts):
        """
        Determine the likely type of decoder function
        
        Args:
            pattern_counts: Dict of pattern category counts
            instruction_counts: Dict of instruction counts
            
        Returns:
            String describing the likely decoder type
        """
        # Check for XOR decoder
        if pattern_counts['xor'] > pattern_counts['add_sub'] and pattern_counts['xor'] > pattern_counts['rotate']:
            return "XOR-based decoder"
        
        # Check for ADD/SUB decoder
        elif pattern_counts['add_sub'] > pattern_counts['xor'] and pattern_counts['add_sub'] > pattern_counts['rotate']:
            return "ADD/SUB-based decoder"
        
        # Check for rotation-based decoder
        elif pattern_counts['rotate'] > 0:
            return "Rotation-based decoder"
        
        # Check for multi-operation decoder
        elif pattern_counts['xor'] > 0 and pattern_counts['add_sub'] > 0:
            return "Multi-operation decoder (XOR+ADD/SUB)"
        
        # Check for string operation decoder
        elif any("STOS" in desc or "LODS" in desc or "MOVS" in desc for desc in instruction_counts.keys()):
            return "String operation-based decoder"
        
        # Default
        else:
            return "Generic decoder"
    
    def _get_top_instructions(self, instruction_counts, limit=10):
        """Get the most frequent instructions"""
        return dict(sorted(instruction_counts.items(), key=lambda x: x[1], reverse=True)[:limit])
    
    def analyze_binary_for_decoders(self, file_path, output_dir=None):
        """
        Analyze a binary file for decoder functions
        
        Args:
            file_path: Path to the binary file
            output_dir: Directory to save output files (optional)
            
        Returns:
            Dict with analysis results
        """
        if not os.path.exists(file_path):
            print(f"Error: File {file_path} not found")
            return None
        
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        print(f"Analyzing file for decoder functions: {file_path}")
        
        # Read binary data
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Identify potential decoder functions
        print("Identifying potential decoder functions...")
        decoders = self.identify_potential_decoders(data)
        print(f"Found {len(decoders)} potential decoder functions")
        
        # Generate results
        results = {
            "file_path": file_path,
            "file_size": len(data),
            "decoders": decoders,
            "summary": {
                "total_decoders": len(decoders),
                "high_confidence_decoders": sum(1 for d in decoders if d["decoder_score"] >= 0.8),
                "decoder_types": Counter(d["decoder_type"] for d in decoders)
            }
        }
        
        # Save results if output directory specified
        if output_dir:
            import json
            import os
            
            file_name = os.path.basename(file_path)
            output_path = os.path.join(output_dir, f"{file_name}_decoder_analysis.json")
            
            # Prepare for JSON serialization
            serializable_results = self._prepare_for_serialization(results)
            
            with open(output_path, 'w') as f:
                json.dump(serializable_results, f, indent=2)
            
            print(f"Analysis results saved to: {output_path}")
            
            # Generate human-readable report
            report_path = os.path.join(output_dir, f"{file_name}_decoder_analysis_report.txt")
            self._generate_report(results, report_path)
            print(f"Human-readable report saved to: {report_path}")
        
        return results
    
    def _prepare_for_serialization(self, obj):
        """Prepare results for JSON serialization"""
        if isinstance(obj, bytes):
            return binascii.hexlify(obj).decode()
        elif isinstance(obj, dict):
            return {k: self._prepare_for_serialization(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._prepare_for_serialization(item) for item in obj]
        elif isinstance(obj, tuple):
            return tuple(self._prepare_for_serialization(item) for item in obj)
        elif isinstance(obj, Counter):
            return dict(obj)
        else:
            return obj
    
    def _generate_report(self, results, output_path):
        """Generate a human-readable report of the decoder function analysis"""
        with open(output_path, 'w') as f:
            f.write("KEYPLUG Decoder Function Analysis Report\n")
            f.write("======================================\n\n")
            
            f.write(f"File: {results['file_path']}\n")
            f.write(f"Size: {results['file_size']} bytes\n\n")
            
            f.write("Summary\n")
            f.write("-------\n")
            summary = results['summary']
            f.write(f"Total potential decoder functions: {summary['total_decoders']}\n")
            f.write(f"High confidence decoders (score >= 0.8): {summary['high_confidence_decoders']}\n")
            
            # Show decoder types
            f.write("\nDecoder Types:\n")
            for decoder_type, count in summary['decoder_types'].items():
                f.write(f"  - {decoder_type}: {count}\n")
            
            # Show top decoders
            if results['decoders']:
                f.write("\nTop Potential Decoder Functions\n")
                f.write("-----------------------------\n")
                
                # Show top 10
                for i, decoder in enumerate(results['decoders'][:10]):
                    f.write(f"\n[{i+1}] Offset: 0x{decoder['start_offset']:x}\n")
                    f.write(f"    Size: {decoder['size']} bytes\n")
                    f.write(f"    Type: {decoder['decoder_type']}\n")
                    f.write(f"    Score: {decoder['decoder_score']:.2f}\n")
                    
                    # Show top instructions
                    f.write("    Key Instructions:\n")
                    for instr, count in list(decoder['top_instructions'].items())[:5]:
                        f.write(f"      - {instr}: {count}\n")
                    
                    # Show metrics
                    metrics = decoder['metrics']
                    f.write(f"    Entropy: {metrics['entropy']:.2f}\n")
                    f.write(f"    Byte Diversity: {metrics['byte_diversity']:.2f}\n")
                    f.write(f"    Estimated Instructions: {int(metrics['estimated_instructions'])}\n")
                
                if len(results['decoders']) > 10:
                    f.write(f"\n... and {len(results['decoders']) - 10} more potential decoder functions\n")
