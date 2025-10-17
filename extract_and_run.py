import os
import zlib
import tempfile
import struct

def find_chunk(data, chunk_type):
    """Finds all chunks of a given type in PNG data."""
    # Skip the 8-byte PNG signature
    offset = 8
    while offset < len(data):
        length = struct.unpack('>I', data[offset:offset+4])[0]
        ctype = data[offset+4:offset+8]

        if ctype == chunk_type:
            chunk_data = data[offset+8:offset+8+length]
            yield chunk_data

        # Move to the next chunk (4 bytes for length, 4 for type, N for data, 4 for CRC)
        offset += (12 + length)

def extract_payload(polyglot_path: str) -> bytes:
    """
    Extracts the payload from the polyglot PNG file by manually parsing chunks.
    """
    with open(polyglot_path, "rb") as f:
        png_data = f.read()

    payload_keyword = b"polyglot_payload"

    for chunk_data in find_chunk(png_data, b'tEXt'):
        if chunk_data.startswith(payload_keyword + b'\x00'):
            # The actual payload is after the keyword and the null separator
            compressed_payload = chunk_data[len(payload_keyword)+1:]
            return zlib.decompress(compressed_payload)

    raise ValueError(f"Could not find payload with keyword '{payload_keyword.decode()}' in the image.")

def main():
    polyglot_file = "polyglot.png"

    try:
        print(f"[*] Extracting payload from {polyglot_file}...")
        payload = extract_payload(polyglot_file)

        # Create a temporary file to store the executable
        with tempfile.NamedTemporaryFile(delete=False, suffix=".elf") as temp_exe:
            temp_exe.write(payload)
            executable_path = temp_exe.name

        # Make the temporary file executable
        os.chmod(executable_path, 0o755)

        print(f"[*] Payload extracted to: {executable_path}")
        print("[*] You can now run the executable manually:")
        print(f"    {executable_path}")

    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()