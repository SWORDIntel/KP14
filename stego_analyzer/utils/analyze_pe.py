#!/usr/bin/env python3
"""
Analyze extracted PE files from KEYPLUG malware
"""
import os
import sys
import binascii
import struct
from collections import defaultdict

def is_valid_pe(data):
    """Check if data contains a valid PE file signature"""
    if len(data) < 64:
        return False
    
    # Check for MZ signature
    if data[:2] != b'MZ':
        return False
    
    # Try to find PE header offset
    try:
        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
        if pe_offset >= len(data) - 4:
            return False
        
        # Check for PE signature
        if data[pe_offset:pe_offset+4] != b'PE\0\0':
            return False
        
        return True
    except Exception: # Changed bare except
        return False

def analyze_pe_header(data):
    """Analyze PE header information"""
    if not is_valid_pe(data):
        return {"error": "Not a valid PE file"}
    
    try:
        # Get PE header offset
        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
        
        # Basic header info
        machine = struct.unpack('<H', data[pe_offset+4:pe_offset+6])[0]
        num_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
        timestamp = struct.unpack('<I', data[pe_offset+8:pe_offset+12])[0]
        characteristics = struct.unpack('<H', data[pe_offset+22:pe_offset+24])[0]
        
        # Optional header
        opt_header_size = struct.unpack('<H', data[pe_offset+20:pe_offset+22])[0]
        subsystem = None # Initialize subsystem
        magic = 0 # Initialize magic
        if opt_header_size > 0:
            magic = struct.unpack('<H', data[pe_offset+24:pe_offset+26])[0]
            if magic == 0x10b:  # PE32
                if pe_offset + 70 <= len(data): # Check boundary
                    subsystem = struct.unpack('<H', data[pe_offset+68:pe_offset+70])[0]
            elif magic == 0x20b:  # PE32+
                if pe_offset + 68 <= len(data): # Check boundary for PE32+ subsystem (different offset)
                     subsystem = struct.unpack('<H', data[pe_offset+68:pe_offset+70])[0] # This offset is actually for ImageBase in PE32+
                     # Correct subsystem offset for PE32+ is typically pe_offset + 92
                     if pe_offset + 94 <= len(data): # Check boundary for PE32+ subsystem
                         subsystem = struct.unpack('<H', data[pe_offset+92:pe_offset+94])[0]


        # Machine types
        machine_types = {
            0x0: "IMAGE_FILE_MACHINE_UNKNOWN",
            0x1d3: "IMAGE_FILE_MACHINE_AM33",
            0x8664: "IMAGE_FILE_MACHINE_AMD64",
            0x1c0: "IMAGE_FILE_MACHINE_ARM",
            0xaa64: "IMAGE_FILE_MACHINE_ARM64",
            0x1c4: "IMAGE_FILE_MACHINE_ARMNT",
            0xebc: "IMAGE_FILE_MACHINE_EBC",
            0x14c: "IMAGE_FILE_MACHINE_I386",
            0x200: "IMAGE_FILE_MACHINE_IA64",
            0x9041: "IMAGE_FILE_MACHINE_M32R",
            0x266: "IMAGE_FILE_MACHINE_MIPS16",
            0x366: "IMAGE_FILE_MACHINE_MIPSFPU",
            0x466: "IMAGE_FILE_MACHINE_MIPSFPU16",
            0x1f0: "IMAGE_FILE_MACHINE_POWERPC",
            0x1f1: "IMAGE_FILE_MACHINE_POWERPCFP",
            0x166: "IMAGE_FILE_MACHINE_R4000",
            0x5032: "IMAGE_FILE_MACHINE_RISCV32",
            0x5064: "IMAGE_FILE_MACHINE_RISCV64",
            0x5128: "IMAGE_FILE_MACHINE_RISCV128",
            0x1a2: "IMAGE_FILE_MACHINE_SH3",
            0x1a3: "IMAGE_FILE_MACHINE_SH3DSP",
            0x1a6: "IMAGE_FILE_MACHINE_SH4",
            0x1a8: "IMAGE_FILE_MACHINE_SH5",
            0x1c2: "IMAGE_FILE_MACHINE_THUMB",
            0x169: "IMAGE_FILE_MACHINE_WCEMIPSV2"
        }
        
        # Subsystem types
        subsystem_types = {
            0: "IMAGE_SUBSYSTEM_UNKNOWN",
            1: "IMAGE_SUBSYSTEM_NATIVE",
            2: "IMAGE_SUBSYSTEM_WINDOWS_GUI",
            3: "IMAGE_SUBSYSTEM_WINDOWS_CUI",
            5: "IMAGE_SUBSYSTEM_OS2_CUI",
            7: "IMAGE_SUBSYSTEM_POSIX_CUI",
            8: "IMAGE_SUBSYSTEM_NATIVE_WINDOWS",
            9: "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
            10: "IMAGE_SUBSYSTEM_EFI_APPLICATION",
            11: "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER",
            12: "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER",
            13: "IMAGE_SUBSYSTEM_EFI_ROM",
            14: "IMAGE_SUBSYSTEM_XBOX",
            16: "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"
        }
        
        # Format characteristics
        characteristics_flags = []
        if characteristics & 0x0001: characteristics_flags.append("IMAGE_FILE_RELOCS_STRIPPED")
        if characteristics & 0x0002: characteristics_flags.append("IMAGE_FILE_EXECUTABLE_IMAGE")
        if characteristics & 0x0004: characteristics_flags.append("IMAGE_FILE_LINE_NUMS_STRIPPED")
        if characteristics & 0x0008: characteristics_flags.append("IMAGE_FILE_LOCAL_SYMS_STRIPPED")
        if characteristics & 0x0010: characteristics_flags.append("IMAGE_FILE_AGGRESSIVE_WS_TRIM")
        if characteristics & 0x0020: characteristics_flags.append("IMAGE_FILE_LARGE_ADDRESS_AWARE")
        if characteristics & 0x0080: characteristics_flags.append("IMAGE_FILE_BYTES_REVERSED_LO")
        if characteristics & 0x0100: characteristics_flags.append("IMAGE_FILE_32BIT_MACHINE")
        if characteristics & 0x0200: characteristics_flags.append("IMAGE_FILE_DEBUG_STRIPPED")
        if characteristics & 0x0400: characteristics_flags.append("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP")
        if characteristics & 0x0800: characteristics_flags.append("IMAGE_FILE_NET_RUN_FROM_SWAP")
        if characteristics & 0x1000: characteristics_flags.append("IMAGE_FILE_SYSTEM")
        if characteristics & 0x2000: characteristics_flags.append("IMAGE_FILE_DLL")
        if characteristics & 0x4000: characteristics_flags.append("IMAGE_FILE_UP_SYSTEM_ONLY")
        if characteristics & 0x8000: characteristics_flags.append("IMAGE_FILE_BYTES_REVERSED_HI")
        
        result = {
            "pe_offset": pe_offset,
            "machine": machine,
            "machine_type": machine_types.get(machine, f"Unknown ({machine})"),
            "num_sections": num_sections,
            "timestamp": timestamp,
            "characteristics": characteristics,
            "characteristics_flags": characteristics_flags,
        }
        
        if opt_header_size > 0:
            result["optional_header"] = {
                "magic": magic,
                "pe_type": "PE32" if magic == 0x10b else "PE32+" if magic == 0x20b else f"Unknown ({magic})",
                "subsystem": subsystem,
                "subsystem_type": subsystem_types.get(subsystem, f"Unknown ({subsystem})") if subsystem is not None else "N/A"
            }
        
        # Try to parse section headers if valid
        if pe_offset and num_sections and num_sections < 100:  # Sanity check
            sections = []
            section_header_size = 40  # Size of each section header
            section_table_offset = pe_offset + 24 + opt_header_size
            
            for i in range(num_sections):
                section_offset = section_table_offset + (i * section_header_size)
                if section_offset + section_header_size > len(data):
                    break
                
                section_name = data[section_offset:section_offset+8].rstrip(b'\0')
                section_vsize = struct.unpack('<I', data[section_offset+8:section_offset+12])[0]
                section_vaddr = struct.unpack('<I', data[section_offset+12:section_offset+16])[0]
                section_size = struct.unpack('<I', data[section_offset+16:section_offset+20])[0]
                section_paddr = struct.unpack('<I', data[section_offset+20:section_offset+24])[0]
                section_chars = struct.unpack('<I', data[section_offset+36:section_offset+40])[0]
                
                # Section characteristics
                characteristics_str = []
                if section_chars & 0x00000020: characteristics_str.append("CNT_CODE")
                if section_chars & 0x00000040: characteristics_str.append("CNT_INITIALIZED_DATA")
                if section_chars & 0x00000080: characteristics_str.append("CNT_UNINITIALIZED_DATA")
                if section_chars & 0x20000000: characteristics_str.append("MEM_EXECUTE")
                if section_chars & 0x40000000: characteristics_str.append("MEM_READ")
                if section_chars & 0x80000000: characteristics_str.append("MEM_WRITE")
                
                sections.append({
                    "name": section_name.decode('ascii', errors='ignore'),
                    "virtual_size": section_vsize,
                    "virtual_address": section_vaddr,
                    "size_of_raw_data": section_size,
                    "pointer_to_raw_data": section_paddr,
                    "characteristics": section_chars,
                    "characteristics_flags": characteristics_str
                })
            
            result["sections"] = sections
        
        return result
    except Exception as e:
        return {"error": f"Error parsing PE header: {str(e)}"}

def search_for_strings(data, min_length=4):
    """Search for ASCII and Unicode strings in the data"""
    ascii_strings = []
    unicode_strings = []
    
    # ASCII strings
    current = ""
    for i in range(len(data)):
        if 32 <= data[i] <= 126:  # Printable ASCII
            current += chr(data[i])
        else:
            if len(current) >= min_length:
                ascii_strings.append((i - len(current), current))
            current = ""
    
    if len(current) >= min_length:  # Don't forget the last string
        ascii_strings.append((len(data) - len(current), current))
    
    # Unicode strings (basic detection)
    current = ""
    i = 0
    while i < len(data) - 1:
        if data[i] >= 32 and data[i] <= 126 and data[i+1] == 0:  # Simple Unicode detection
            current += chr(data[i])
            i += 2
        else:
            if len(current) >= min_length:
                unicode_strings.append((i - len(current) * 2, current))
            current = ""
            i += 1
    
    if len(current) >= min_length:  # Don't forget the last string
        unicode_strings.append((len(data) - len(current) * 2, current))
    
    return {"ascii": ascii_strings, "unicode": unicode_strings}

def search_for_api_strings(strings):
    """Search for Windows API function names in strings"""
    api_functions = [
        # Process manipulation
        "CreateProcess", "OpenProcess", "TerminateProcess", "ExitProcess",
        "CreateThread", "OpenThread", "SuspendThread", "ResumeThread",
        "CreateRemoteThread", "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
        "VirtualAlloc", "VirtualFree", "VirtualProtect", "VirtualQuery",
        "ReadProcessMemory", "WriteProcessMemory",
        
        # File operations
        "CreateFile", "ReadFile", "WriteFile", "CloseHandle",
        "CopyFile", "DeleteFile", "MoveFile", "FindFirstFile", "FindNextFile",
        
        # Registry operations
        "RegOpenKey", "RegCreateKey", "RegDeleteKey", "RegSetValue", "RegQueryValue",
        "RegEnumKey", "RegEnumValue", "RegCloseKey",
        
        # Network operations
        "socket", "connect", "bind", "listen", "accept", "send", "recv",
        "WSAStartup", "WSACleanup", "WSASocket", "WSAConnect",
        "inet_addr", "htons", "gethostbyname", "gethostname",
        "HttpOpenRequest", "HttpSendRequest", "InternetOpen", "InternetConnect",
        "InternetOpenUrl", "InternetReadFile", "InternetWriteFile",
        
        # Cryptographic operations
        "CryptAcquireContext", "CryptCreateHash", "CryptHashData", "CryptDeriveKey",
        "CryptEncrypt", "CryptDecrypt", "CryptGenRandom", "CryptReleaseContext",
        
        # System information
        "GetSystemInfo", "GetVersionEx", "GetComputerName", "GetUserName",
        "GetSystemDirectory", "GetWindowsDirectory", "GetTempPath",
        
        # Process injection
        "SetWindowsHook", "CallNextHook", "GetMessage", "PeekMessage",
        
        # Anti-debugging
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugString",
        "GetTickCount", "QueryPerformanceCounter", "NtQueryInformationProcess",
        
        # Dynamic loading
        "LoadLibrary", "GetProcAddress", "FreeLibrary",
        
        # Shell operations
        "ShellExecute", "WinExec", "system", "_popen", 
        
        # Service operations
        "OpenSCManager", "CreateService", "OpenService", "StartService",
        "ControlService", "DeleteService", "CloseServiceHandle",
        
        # Persistence
        "RegSetValueEx", "SHGetSpecialFolderPath",
        
        # COM/OLE operations
        "CoCreateInstance", "CoInitialize", "OleInitialize",
        
        # Certificate operations
        "CertOpenStore", "CertFindCertificateInStore", "CertGetCertificateChain",
    ]
    
    results = defaultdict(list)
    
    for offset, string in strings["ascii"]:
        for api in api_functions:
            if api.lower() in string.lower():
                results[api].append((offset, string))
    
    for offset, string in strings["unicode"]:
        for api in api_functions:
            if api.lower() in string.lower():
                results[api].append((offset, string))
    
    return results

def check_embedded_exe(data):
    """Check if there are embedded executables within the data"""
    embedded = []
    offset = 0
    
    while offset < len(data) - 2:
        offset = data.find(b'MZ', offset)
        if offset == -1:
            break
        
        # Skip the current MZ signature at the beginning
        if offset == 0:
            offset += 2
            continue
        
        # Check if this might be a valid PE
        if offset + 0x40 < len(data):
            try:
                pe_offset_val = struct.unpack('<I', data[offset+0x3C:offset+0x40])[0]
                if offset + pe_offset_val + 4 < len(data) and data[offset+pe_offset_val:offset+pe_offset_val+4] == b'PE\0\0':
                    embedded.append({
                        "offset": offset,
                        "pe_offset": pe_offset_val
                    })
            except Exception: # Changed bare except
                pass
        
        offset += 2
    
    return embedded

def analyze_pe_file(file_path):
    """Analyze a potential PE file"""
    if not os.path.exists(file_path):
        return {"error": f"File {file_path} not found"}
    
    results = {"file_path": file_path}
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        results["file_size"] = len(data)
        results["md5"] = binascii.hexlify(data[:16]).decode()  # Just first 16 bytes for preview
        
        # Check if it's a valid PE
        if is_valid_pe(data):
            results["is_valid_pe"] = True
            results["pe_header"] = analyze_pe_header(data)
        else:
            results["is_valid_pe"] = False
        
        # Look for strings
        results["strings"] = search_for_strings(data)
        results["api_references"] = search_for_api_strings(results["strings"])
        
        # Check for embedded executables
        results["embedded_executables"] = check_embedded_exe(data)
        
        return results
    except Exception as e:
        return {"error": f"Error analyzing file: {str(e)}"}

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pe_file1> [pe_file2 ...]")
        sys.exit(1)
    
    for file_path in sys.argv[1:]:
        print(f"Analyzing file: {file_path}")
        results = analyze_pe_file(file_path)
        
        if "error" in results:
            print(f"Error: {results['error']}")
            continue
        
        print(f"File size: {results['file_size']} bytes")
        print(f"MD5 preview: {results['md5']}")
        
        if results["is_valid_pe"]:
            print("Valid PE file: Yes")
            header = results["pe_header"]
            
            print(f"Machine type: {header['machine_type']}")
            print(f"Number of sections: {header['num_sections']}")
            print(f"Characteristics: {', '.join(header['characteristics_flags'])}")
            
            if "optional_header" in header:
                opt = header["optional_header"]
                print(f"PE type: {opt['pe_type']}")
                if opt.get('subsystem_type') is not None : # Check if subsystem_type exists
                    print(f"Subsystem: {opt['subsystem_type']}")
            
            if "sections" in header and header["sections"]:
                print("\nSections:")
                for section in header["sections"]:
                    flags = ", ".join(section["characteristics_flags"])
                    print(f"  {section['name']} - Size: {section['size_of_raw_data']} bytes - Flags: {flags}")
        else:
            print("Valid PE file: No")
        
        # Print API references
        if results["api_references"]:
            print("\nAPI References:")
            for api, refs in results["api_references"].items():
                print(f"  {api}: {len(refs)} references")
        
        # Check for embedded executables
        if results["embedded_executables"]:
            print("\nEmbedded Executables:")
            for exe in results["embedded_executables"]:
                print(f"  Offset: 0x{exe['offset']:X}, PE Header Offset: 0x{exe['pe_offset']:X}")
        
        # Print some strings
        ascii_strings = results["strings"]["ascii"]
        if ascii_strings:
            print("\nSample ASCII Strings:")
            for i, (offset, string) in enumerate(ascii_strings[:10]):
                print(f"  [0x{offset:X}] {string}")
            if len(ascii_strings) > 10:
                print(f"  ... and {len(ascii_strings) - 10} more")
        
        print("-" * 80)

if __name__ == "__main__":
    main()
