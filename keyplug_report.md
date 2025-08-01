# KEYPLUG: ODG Embedded Payload Analysis Report

## Analysis Overview
- **File:** NDA.odg
- **Scan Time:** 2025-05-21 08:53:55
- **Scanner Version:** KEYPLUG 3.0
- **Deep Scan:** Enabled
- **Brute Force:** Enabled
- **Environment:** Linux 6.8.12-10-pve
- **Python Version:** 3.11.2

## Summary
- **Total JPEG Images Examined:** 3
- **Images with Hidden Payloads:** 3
- **High-Risk Payloads:** 2

⚠️ **WARNING: Potentially malicious content detected!** ⚠️

## Payload #1 (LOW RISK)

### Source
- **JPEG File:** 10000000000002EE000003B123F0F4409249C826.jpg
- **JPEG MD5:** 9f6dbfafbd464b029b9de5033b2df2fe
- **Location in ODG:** Pictures/10000000000002EE000003B123F0F4409249C826.jpg
- **Detection Method:** forced_heuristic

### Payload Details
- **Payload File:** 10000000000002EE000003B123F0F4409249C826_forced_091c103c.bin
- **Size:** 34,227 bytes
- **MD5:** `091c103c06f96a11e3c41ab6e305a267`
- **SHA1:** `8a2a3cff10fbb70c010cd0cb98d968ac5761b227`
- **SHA256:** `e5ebcfe7d2b388be037fc7c1f40a7ee3d5aedd8ffe316639afb25bcad9e2020e`
- **Detected Type:** data
- **MIME Type:** application/octet-stream
- **Entropy:** 7.76

### No obvious suspicious indicators found

### Recommendations
This payload shows limited risk indicators. Consider reviewing the content manually.

---

## Payload #2 (⚠️ HIGH RISK)

### Source
- **JPEG File:** 10000000000002EE000003C0C4539E29A848DE5F.jpg
- **JPEG MD5:** 9d201b8c1c6b75987cd25d9f18119f2d
- **Location in ODG:** Pictures/10000000000002EE000003C0C4539E29A848DE5F.jpg
- **Detection Method:** forced_heuristic

### Payload Details
- **Payload File:** 10000000000002EE000003C0C4539E29A848DE5F_forced_8ca7ab3b.bin
- **Size:** 170,043 bytes
- **MD5:** `8ca7ab3baee20670771fbc1485b5bd7f`
- **SHA1:** `9ef108d8699a1babcd6995bfb4e1860739f4ccba`
- **SHA256:** `543bd7ed04515926020b0526cb5b040beb27c26e059fb1b18fed8302c17561aa`
- **Detected Type:** data
- **MIME Type:** application/octet-stream
- **Entropy:** 7.97 (Likely encrypted, confidence: 0.60)
- **Encryption Assessment:** Very high entropy (7.97), No dominant byte patterns

### Decryption Attempts
#### Attempt #1
- **Method:** single-byte XOR
- **Key (Hex):** `9e`
- **Key (ASCII):** `�`
- **Result Type:** application/octet-stream
- **Score:** 12.13
- **Output File:** 10000000000002EE000003C0C4539E29A848DE5F_forced_8ca7ab3b_decrypted_1.bin
- **MD5:** 72c37fc64f883c771b50e0df631a89fe

#### Attempt #2
- **Method:** single-byte XOR
- **Key (Hex):** `d3`
- **Key (ASCII):** `�`
- **Result Type:** application/octet-stream
- **Score:** 12.06
- **Output File:** 10000000000002EE000003C0C4539E29A848DE5F_forced_8ca7ab3b_decrypted_2.bin
- **MD5:** 30c54be42ccb8988c90facbbcaaf14e9

#### Attempt #3
- **Method:** single-byte XOR
- **Key (Hex):** `a5`
- **Key (ASCII):** `�`
- **Result Type:** application/octet-stream
- **Score:** 11.97
- **Output File:** 10000000000002EE000003C0C4539E29A848DE5F_forced_8ca7ab3b_decrypted_3.bin
- **MD5:** 4437b1695e7aea28811d99d8ed74c450

### Interesting Byte Patterns
- **0xBEB5:** MZ - PE header (MZ)
- **0x1078C:** MZ - PE header (MZ)
- **0x19CED:** MZ - PE header (MZ)
- **0x22863:** MZ - PE header (MZ)
- **0x228B9:** MZ - PE header (MZ)
- **0x2621C:** MZ - PE header (MZ)

### ⚠️ Domain References
- `n.dF`

### Recommendations
This payload shows indicators of potentially malicious activity. Recommended actions:

1. Submit the payload to VirusTotal or a similar service for further analysis
2. Consider sandboxed execution to observe behavior
3. Investigate the source of this ODG file

---

## Payload #3 (⚠️ HIGH RISK)

### Source
- **JPEG File:** 10000000000002EE000003C67A1DCDCB7AEFBF3E.jpg
- **JPEG MD5:** 7cdda16f0ddc8d785352834c31a3d25a
- **Location in ODG:** Pictures/10000000000002EE000003C67A1DCDCB7AEFBF3E.jpg
- **Detection Method:** forced_heuristic

### Payload Details
- **Payload File:** 10000000000002EE000003C67A1DCDCB7AEFBF3E_forced_adbb0ac1.bin
- **Size:** 172,143 bytes
- **MD5:** `adbb0ac1c17e904da5e844e143c1583f`
- **SHA1:** `6053c0c805e1732d884e00566440731def5ccc5e`
- **SHA256:** `0bca2a488be7fc21b7a6965f755ecdbf473fb8d6d0fb380de27f574ea579a23f`
- **Detected Type:** data
- **MIME Type:** application/octet-stream
- **Entropy:** 7.96 (Likely encrypted, confidence: 0.60)
- **Encryption Assessment:** Very high entropy (7.96), No dominant byte patterns

### Decryption Attempts
#### Attempt #1
- **Method:** 4-byte XOR
- **Key (Hex):** `0a61200d`
- **Key (ASCII):** `
a 
`
- **Result Type:** application/octet-stream
- **Score:** 22.06
- **Output File:** 10000000000002EE000003C67A1DCDCB7AEFBF3E_forced_adbb0ac1_decrypted_1.bin
- **MD5:** 4562c7570ec8a655c1e6c49c7e602ab9

#### Attempt #2
- **Method:** 4-byte XOR
- **Key (Hex):** `410d200d`
- **Key (ASCII):** `A
 
`
- **Result Type:** application/octet-stream
- **Score:** 12.19
- **Output File:** 10000000000002EE000003C67A1DCDCB7AEFBF3E_forced_adbb0ac1_decrypted_2.bin
- **MD5:** a42eba4450a442a98a8a702b5265515d

#### Attempt #3
- **Method:** 4-byte XOR
- **Key (Hex):** `4100200d`
- **Key (ASCII):** `A  
`
- **Result Type:** application/octet-stream
- **Score:** 12.18
- **Output File:** 10000000000002EE000003C67A1DCDCB7AEFBF3E_forced_adbb0ac1_decrypted_3.bin
- **MD5:** 863f24f911a3f6a85039fec7fc47034f

### Interesting Byte Patterns
- **0x1A0B1:** MZ - PE header (MZ)
- **0x26889:** MZ - PE header (MZ)

### ⚠️ Domain References
- `m5.n.Rfvyf`
- `5Ko.Wx`

### Recommendations
This payload shows indicators of potentially malicious activity. Recommended actions:

1. Submit the payload to VirusTotal or a similar service for further analysis
2. Consider sandboxed execution to observe behavior
3. Investigate the source of this ODG file

---


## Analysis Completed
- **End Time:** 2025-05-21 08:53:55
- **Output Directory:** /home/john/Documents/keyplug
