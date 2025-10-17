from PIL import Image
import zlib

# Read the executable data
with open("hello_polyglot", "rb") as f:
    executable_data = f.read()

# Open the base image
img = Image.open("base_image.png")

# Create a custom tEXt chunk
# The keyword must be 1-79 characters long and contain only printable ASCII
keyword = "polyglot_payload"
# The text can be any data, but it's often compressed
compressed_payload = zlib.compress(executable_data)
text_chunk = keyword.encode('ascii') + b'\x00' + compressed_payload

# PIL doesn't directly support adding raw chunks, so we'll have to manually
# insert the chunk into the PNG file structure. A PNG file is composed of
# a signature followed by a series of chunks. We'll insert our custom
# chunk before the IEND chunk.

# Read the original PNG data
with open("base_image.png", "rb") as f:
    png_data = f.read()

# Find the IEND chunk (which is always the last chunk)
iend_index = png_data.rfind(b'IEND')
if iend_index == -1:
    raise ValueError("Could not find IEND chunk in the base image.")

# A chunk is composed of:
# 4 bytes: length of the chunk data
# 4 bytes: chunk type (e.g., 'tEXt')
# N bytes: chunk data
# 4 bytes: CRC checksum of the chunk type and chunk data

# Construct our custom chunk
chunk_type = b'tEXt'
chunk_data = text_chunk
chunk_length = len(chunk_data).to_bytes(4, 'big')
crc = zlib.crc32(chunk_type + chunk_data).to_bytes(4, 'big')

custom_chunk = chunk_length + chunk_type + chunk_data + crc

# Insert the custom chunk before the IEND chunk
polyglot_data = png_data[:iend_index] + custom_chunk + png_data[iend_index:]

# Write the new polyglot file
with open("polyglot.png", "wb") as f:
    f.write(polyglot_data)

print("Polyglot file created successfully.")