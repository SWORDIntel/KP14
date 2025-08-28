import jpegio
import numpy as np
from PIL import Image # Keep for DELIMITER_BIT_STRING for now, or move DELIMITER

import csv
import os
from datetime import datetime

# --- Logging Utility ---
LOG_DIR = "results"
LOG_FILE = os.path.join(LOG_DIR, "stegtest_log.csv")
LOG_HEADER = ["Timestamp", "OperationName", "BaseImagePath", "StegoImagePath",
              "PayloadSample", "ExtractedPayloadSample", "Status", "Message"]

def log_stego_operation(log_data_dict):
    """
    Logs a steganography operation to a CSV file.
    log_data_dict should be a dictionary with keys matching LOG_HEADER.
    """
    try:
        os.makedirs(LOG_DIR, exist_ok=True)

        # Check if file exists to determine if header needs to be written
        file_exists = os.path.isfile(LOG_FILE)

        with open(LOG_FILE, mode='a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=LOG_HEADER)
            if not file_exists:
                writer.writeheader()
            writer.writerow(log_data_dict)
    except Exception as e:
        print(f"[Logging Error] Failed to write to log file {LOG_FILE}: {e}")
        # Do not let logging failure crash the main application

# DELIMITER_BIT_STRING is defined globally in the original file.
# Ensure it's available or defined here if this code is moved/restructured.
# For this replacement, we assume it's accessible.
DELIMITER_BIT_STRING = "0111111001111110" # Double ASCII ETX (End of Text)

# Standard 8x8 zigzag order indices for scanning DCT coefficients
ZIGZAG_ORDER = np.array([
    0,  1,  5,  6, 14, 15, 27, 28,
    2,  4,  7, 13, 16, 26, 29, 42,
    3,  8, 12, 17, 25, 30, 41, 43,
    9, 11, 18, 24, 31, 40, 44, 53,
    10, 19, 23, 32, 39, 45, 52, 54,
    20, 22, 33, 38, 46, 51, 55, 60,
    21, 34, 37, 47, 50, 56, 59, 61,
    35, 36, 48, 49, 57, 58, 62, 63
])

def get_zigzag_indices(block_shape=(8, 8)):
    """Generates zigzag indices for a given block shape."""
    if block_shape != (8,8):
        # Fallback for non-8x8 blocks, though JSteg is typically for 8x8 DCT blocks
        # This is a simple raster scan if not 8x8, not true zigzag.
        print("Warning: Using raster scan for non-8x8 block. JSteg typically uses 8x8 blocks.")
        return [(r, c) for r in range(block_shape[0]) for c in range(block_shape[1])]

    indices = []
    for i in range(len(ZIGZAG_ORDER)):
        idx = np.where(ZIGZAG_ORDER == i)[0][0]
        row = idx // 8
        col = idx % 8
        indices.append((row, col))
    return indices

# --- JPEG Steganography (JSteg Implementation using jpegio) ---
def embed_message_jsteg(image_path, secret_message, output_path):
    """
    Embeds a secret message into a JPEG image using JSteg algorithm with jpegio.
    Modifies the LSB of AC DCT coefficients (excluding 0 and 1).
    """
    try:
        # Load JPEG structure
        jpeg_struct = jpegio.read(image_path)
    except FileNotFoundError:
        print(f"Error: Input image not found at {image_path}")
        return False
    except Exception as e:
        print(f"Error reading JPEG file {image_path} with jpegio: {e}")
        return False

    # Data Preparation
    data_to_embed_bits = "".join(format(ord(char), '08b') for char in secret_message)
    data_to_embed_bits += DELIMITER_BIT_STRING
    data_len = len(data_to_embed_bits)
    data_idx = 0
    coeffs_modified_count = 0

    # Determine which coefficient arrays to use (e.g., Y channel for grayscale, all for color)
    # For simplicity, this example will try to embed in all available coefficient arrays.
    # Typically, JSteg targets the Y (luminance) channel primarily.

    coef_arrays = jpeg_struct.coef_arrays
    if not coef_arrays:
        print(f"Error: No DCT coefficient arrays found in {image_path}.")
        return False

    # Create a copy of coefficient arrays to modify
    modified_coef_arrays = [np.copy(arr) for arr in coef_arrays]

    for component_idx, component_array in enumerate(modified_coef_arrays):
        if data_idx >= data_len:
            break # All data embedded

        # JSteg operates on 8x8 blocks
        if component_array.ndim != 2 or component_array.shape[0] % 8 != 0 or component_array.shape[1] % 8 != 0:
            print(f"Warning: Component array {component_idx} is not a standard 8x8 block structure. Skipping.")
            continue

        zigzag_indices_8x8 = get_zigzag_indices((8,8)) # Pre-calculate for 8x8 blocks

        for r_block_start in range(0, component_array.shape[0], 8):
            if data_idx >= data_len: break
            for c_block_start in range(0, component_array.shape[1], 8):
                if data_idx >= data_len: break

                block = component_array[r_block_start:r_block_start+8, c_block_start:c_block_start+8]

                # Iterate AC coefficients in zigzag order (skip DC at index 0 of zigzag_indices_8x8)
                for i in range(1, len(zigzag_indices_8x8)): # Start from 1 to skip DC
                    if data_idx >= data_len: break

                    r_coeff, c_coeff = zigzag_indices_8x8[i]
                    coeff_val = block[r_coeff, c_coeff]

                    # JSteg rule: skip coefficients with value 0 or 1 (or -1, though LSB of -1 is same as 1)
                    if coeff_val != 0 and coeff_val != 1:
                        bit_to_embed = int(data_to_embed_bits[data_idx])

                        # Modify LSB
                        if bit_to_embed == 0:
                            block[r_coeff, c_coeff] = coeff_val & ~1 # Set LSB to 0
                        else:
                            block[r_coeff, c_coeff] = coeff_val | 1  # Set LSB to 1

                        data_idx += 1
                        coeffs_modified_count += 1

                # Put modified block back (though modification was in-place for this setup)
                # component_array[r_block_start:r_block_start+8, c_block_start:c_block_start+8] = block

    if data_idx < data_len:
        print(f"Error: Message too large for the image. Only {data_idx} of {data_len} bits embedded.")
        print(f"  (Only {coeffs_modified_count} suitable AC DCT coefficients were found and modified).")
        return False

    try:
        # Save the modified JPEG structure
        # jpegio.write expects a full jpeg_struct, so update the coef_arrays in the original struct
        jpeg_struct_to_write = jpegio.JpegStructure(
            coef_arrays=modified_coef_arrays,
            quant_tables=jpeg_struct.quant_tables,
            ac_huff_tables=jpeg_struct.ac_huff_tables,
            dc_huff_tables=jpeg_struct.dc_huff_tables,
            # Ensure other necessary attributes from jpeg_struct are passed if they exist and are needed by write
            # For example, some versions might need:
            # scan_headers=jpeg_struct.scan_headers,
            # com=jpeg_struct.com # Comments
        )
        jpegio.write(jpeg_struct_to_write, output_path)
        print(f"Message embedded successfully into {output_path}.")
        print(f"  {coeffs_modified_count} DCT coefficients modified.")
        print(f"  Message bit length (with delimiter): {data_len}")
        return True
    except Exception as e:
        print(f"Error writing JPEG file {output_path} with jpegio: {e}")
        return False

def convert_bits_to_string(bit_string):
    """Converts a bit string (e.g., '0110100001100101') to a string."""
    if len(bit_string) % 8 != 0:
        print("Warning: Bit string length is not a multiple of 8. Padding might be incorrect or data truncated.")
    byte_array = bytearray()
    for i in range(0, len(bit_string), 8):
        byte = bit_string[i:i+8]
        if len(byte) < 8: # Should not happen if previous check is fine, but as safeguard
            print(f"Warning: Final byte '{byte}' is less than 8 bits. Skipping.")
            continue
        try:
            byte_array.append(int(byte, 2))
        except ValueError:
            print(f"Warning: Could not convert byte '{byte}' to int. Skipping.")
            continue
    try:
        return byte_array.decode('utf-8', errors='replace') # Replace invalid UTF-8 sequences
    except UnicodeDecodeError as e:
        print(f"Error decoding byte array to string: {e}. Returning as is (lossy).")
        return byte_array.decode('latin-1', errors='replace') # Fallback to latin-1

def extract_message_jsteg(image_path):
    """
    Extracts a secret message from a JPEG image using JSteg algorithm with jpegio.
    Reads the LSB of AC DCT coefficients (excluding 0 and 1).
    """
    try:
        # Load JPEG structure
        jpeg_struct = jpegio.read(image_path)
    except FileNotFoundError:
        print(f"Error: Input image not found at {image_path}")
        return None
    except Exception as e:
        print(f"Error reading JPEG file {image_path} with jpegio: {e}")
        return None

    coef_arrays = jpeg_struct.coef_arrays
    if not coef_arrays:
        print(f"Error: No DCT coefficient arrays found in {image_path}.")
        return None

    extracted_bits = ""

    # Pre-calculate for 8x8 blocks if components are standard
    zigzag_indices_8x8 = get_zigzag_indices((8,8))

    for component_array in coef_arrays:
        # JSteg operates on 8x8 blocks
        if component_array.ndim != 2 or component_array.shape[0] % 8 != 0 or component_array.shape[1] % 8 != 0:
            print(f"Warning: Component array is not a standard 8x8 block structure. Skipping during extraction.")
            continue

        for r_block_start in range(0, component_array.shape[0], 8):
            for c_block_start in range(0, component_array.shape[1], 8):
                block = component_array[r_block_start:r_block_start+8, c_block_start:c_block_start+8]

                # Iterate AC coefficients in zigzag order (skip DC)
                for i in range(1, len(zigzag_indices_8x8)): # Start from 1 to skip DC
                    r_coeff, c_coeff = zigzag_indices_8x8[i]
                    coeff_val = block[r_coeff, c_coeff]

                    # JSteg rule: skip coefficients with value 0 or 1 (or -1)
                    if coeff_val != 0 and coeff_val != 1:
                        extracted_bits += str(int(coeff_val) & 1) # Extract LSB

                        # Check for delimiter
                        if extracted_bits.endswith(DELIMITER_BIT_STRING):
                            message_bits = extracted_bits[:-len(DELIMITER_BIT_STRING)]
                            return convert_bits_to_string(message_bits)

    print("Warning: Delimiter not found in the image. Message may be incomplete, corrupted, or not present.")
    return None

# --- JPEG Steganography (F5 Algorithm - Conceptual Implementation) ---
def embed_message_f5(image_path, secret_message, output_path):
    """
    Embeds a secret message into a JPEG image using a simplified F5-like algorithm.
    Modifies AC DCT coefficients by decrementing their absolute value if LSB mismatch.
    Skips zero coefficients and coefficients with absolute value 1 if LSB mismatches.
    """
    try:
        jpeg_struct = jpegio.read(image_path)
    except FileNotFoundError:
        print(f"Error F5: Input image not found at {image_path}")
        return False
    except Exception as e:
        print(f"Error F5: Reading JPEG file {image_path} with jpegio: {e}")
        return False

    # Data Preparation
    bits_to_embed = "".join(format(ord(char), '08b') for char in secret_message)
    bits_to_embed += DELIMITER_BIT_STRING
    len_bits_to_embed = len(bits_to_embed)

    if not jpeg_struct.coef_arrays:
        print(f"Error F5: No DCT coefficient arrays found in {image_path}.")
        return False

    # Capacity Check (Simplified: count non-zero AC coefficients)
    available_slots = 0
    zigzag_indices_8x8 = get_zigzag_indices((8,8)) # Assuming 8x8 blocks

    for component_array in jpeg_struct.coef_arrays:
        if component_array.ndim != 2 or component_array.shape[0] % 8 != 0 or component_array.shape[1] % 8 != 0:
            continue # Skip non-standard components for capacity check
        for r_block_start in range(0, component_array.shape[0], 8):
            for c_block_start in range(0, component_array.shape[1], 8):
                block = component_array[r_block_start:r_block_start+8, c_block_start:c_block_start+8]
                for i in range(1, len(zigzag_indices_8x8)): # AC coefficients
                    r_coeff, c_coeff = zigzag_indices_8x8[i]
                    coeff_val = block[r_coeff, c_coeff]
                    if coeff_val != 0:
                        available_slots += 1

    if len_bits_to_embed > available_slots:
        print(f"Error F5: Message too large for simplified capacity. "
              f"Bits to embed: {len_bits_to_embed}, Available non-zero AC slots: {available_slots}")
        return False

    # Embedding Loop
    data_idx = 0
    coeffs_modified_count = 0
    # Deep copy coefficient arrays for modification
    modified_coef_arrays = [np.copy(arr) for arr in jpeg_struct.coef_arrays]

    try:
        for component_array in modified_coef_arrays:
            if data_idx >= len_bits_to_embed: break
            if component_array.ndim != 2 or component_array.shape[0] % 8 != 0 or component_array.shape[1] % 8 != 0:
                continue # Skip non-standard components

            for r_block_start in range(0, component_array.shape[0], 8):
                if data_idx >= len_bits_to_embed: break
                for c_block_start in range(0, component_array.shape[1], 8):
                    if data_idx >= len_bits_to_embed: break

                    current_block = component_array[r_block_start:r_block_start+8, c_block_start:c_block_start+8]

                    for i in range(1, len(zigzag_indices_8x8)): # AC coeffs
                        if data_idx >= len_bits_to_embed: break

                        r_coeff, c_coeff = zigzag_indices_8x8[i]
                        coeff_val = current_block[r_coeff, c_coeff]

                        if coeff_val == 0:
                            continue # Cannot use zero coefficients for F5

                        message_bit = int(bits_to_embed[data_idx])
                        coeff_lsb = int(coeff_val) & 1

                        if coeff_lsb == message_bit:
                            data_idx += 1
                            continue
                        else: # LSB mismatch, need to change coefficient
                            if abs(coeff_val) == 1:
                                # Cannot change without making it zero, so skip this coefficient for this bit
                                continue

                            # Decrement absolute value (shrink towards zero)
                            if coeff_val > 0:
                                current_block[r_coeff, c_coeff] -= 1
                            else: # coeff_val < 0
                                current_block[r_coeff, c_coeff] += 1

                            coeffs_modified_count += 1
                            data_idx += 1

    except Exception as e: # Catch any unexpected errors during coefficient manipulation
        print(f"Error F5: Unexpected error during embedding loop: {e}")
        return False


    # Post-Embedding Check
    if data_idx < len_bits_to_embed:
        print(f"Error F5: Not all bits embedded. Message may be too large or too many unusable coefficients (abs(coeff)==1).")
        print(f"  Bits to embed: {len_bits_to_embed}, Bits successfully embedded: {data_idx}, Coeffs modified: {coeffs_modified_count}")
        return False

    # Save Output
    try:
        jpeg_struct_to_write = jpegio.JpegStructure(
            coef_arrays=modified_coef_arrays,
            quant_tables=jpeg_struct.quant_tables,
            ac_huff_tables=jpeg_struct.ac_huff_tables,
            dc_huff_tables=jpeg_struct.dc_huff_tables,
            # Potentially add other fields if jpegio.read provided them and write needs them
            # e.g., com=jpeg_struct.com if it exists
        )
        jpegio.write(jpeg_struct_to_write, output_path)
        print(f"F5: Message embedded successfully into {output_path}.")
        print(f"  {coeffs_modified_count} DCT coefficients modified.")
        print(f"  Message bit length (with delimiter): {len_bits_to_embed}")
        return True
    except Exception as e:
        print(f"Error F5: Writing JPEG file {output_path} with jpegio: {e}")
        return False

def extract_message_f5(image_path):
    """
    Extracts a secret message from a JPEG image embedded with a simplified F5-like algorithm.
    Reads the LSB of non-zero AC DCT coefficients.
    """
    try:
        jpeg_struct = jpegio.read(image_path)
    except FileNotFoundError:
        print(f"Error F5 Extract: Input image not found at {image_path}")
        return None
    except Exception as e:
        print(f"Error F5 Extract: Reading JPEG file {image_path} with jpegio: {e}")
        return None

    if not jpeg_struct.coef_arrays:
        print(f"Error F5 Extract: No DCT coefficient arrays found in {image_path}.")
        return None

    extracted_bits = ""
    zigzag_indices_8x8 = get_zigzag_indices((8,8)) # Assuming 8x8 blocks

    try:
        for component_array in jpeg_struct.coef_arrays:
            if component_array.ndim != 2 or component_array.shape[0] % 8 != 0 or component_array.shape[1] % 8 != 0:
                continue # Skip non-standard components

            for r_block_start in range(0, component_array.shape[0], 8):
                for c_block_start in range(0, component_array.shape[1], 8):
                    current_block = component_array[r_block_start:r_block_start+8, c_block_start:c_block_start+8]

                    for i in range(1, len(zigzag_indices_8x8)): # AC coeffs
                        r_coeff, c_coeff = zigzag_indices_8x8[i]
                        coeff_val = current_block[r_coeff, c_coeff]

                        if coeff_val == 0:
                            # F5 skips zero coefficients during embedding, so they don't carry data.
                            continue

                        extracted_bit = str(int(coeff_val) & 1)
                        extracted_bits += extracted_bit

                        if extracted_bits.endswith(DELIMITER_BIT_STRING):
                            message_bits = extracted_bits[:-len(DELIMITER_BIT_STRING)]
                            return convert_bits_to_string(message_bits)

    except Exception as e: # Catch any unexpected errors during coefficient reading
        print(f"Error F5 Extract: Unexpected error during extraction loop: {e}")
        return None

    print("Warning F5 Extract: Delimiter not found in the image. Message may be incomplete, corrupted, or not present.")
    return None

# --- UI Menu Functions ---

def handle_jsteg_embed():
    print("\n--- Embed Message using JSteg ---")
    input_image = input("Enter input JPEG image path: ")
    secret_message = input("Enter secret message to embed: ")
    output_image = input("Enter output JPEG image path: ")

    # Basic check for file existence (optional, stego functions also check)
    # import os # Add this import at the top if using os.path.exists
    # if not os.path.exists(input_image):
    #     print(f"Error: Input image '{input_image}' not found.")
    #     return

    log_data = {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "OperationName": "JSteg_Embed",
        "BaseImagePath": input_image,
        "StegoImagePath": output_image,
        "PayloadSample": secret_message[:20], # Log first 20 chars as sample
        "ExtractedPayloadSample": "",
        "Status": "",
        "Message": ""
    }

    result = embed_message_jsteg(input_image, secret_message, output_image)
    if result:
        print("JSteg embedding successful.")
        log_data["Status"] = "SUCCESS"
        log_data["Message"] = "JSteg embedding successful."
    else:
        print("JSteg embedding failed. Check error messages above.")
        log_data["Status"] = "FAILURE"
        log_data["Message"] = "JSteg embedding failed. See console for specific errors from embed_message_jsteg."
    log_stego_operation(log_data)

def handle_jsteg_extract():
    print("\n--- Extract Message using JSteg ---")
    input_image = input("Enter JPEG image path to extract from: ")

    log_data = {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "OperationName": "JSteg_Extract",
        "BaseImagePath": input_image,
        "StegoImagePath": "", # Not applicable for extraction
        "PayloadSample": "", # Not applicable for extraction
        "ExtractedPayloadSample": "",
        "Status": "",
        "Message": ""
    }

    message = extract_message_jsteg(input_image)
    if message is not None:
        print(f"Extracted JSteg message: {message}")
        log_data["Status"] = "SUCCESS"
        log_data["ExtractedPayloadSample"] = message[:20] # Log first 20 chars
        log_data["Message"] = "JSteg extraction successful."
    else:
        print("Failed to extract JSteg message or no message found.")
        log_data["Status"] = "FAILURE"
        log_data["Message"] = "JSteg extraction failed or no message found. See console for errors from extract_message_jsteg."
    log_stego_operation(log_data)

def handle_f5_embed():
    print("\n--- Embed Message using F5 ---")
    input_image = input("Enter input JPEG image path: ")
    secret_message = input("Enter secret message to embed: ")
    output_image = input("Enter output JPEG image path: ")

    log_data = {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "OperationName": "F5_Embed",
        "BaseImagePath": input_image,
        "StegoImagePath": output_image,
        "PayloadSample": secret_message[:20],
        "ExtractedPayloadSample": "",
        "Status": "",
        "Message": ""
    }

    result = embed_message_f5(input_image, secret_message, output_image)
    if result:
        print("F5 embedding successful.")
        log_data["Status"] = "SUCCESS"
        log_data["Message"] = "F5 embedding successful."
    else:
        print("F5 embedding failed. Check error messages above.")
        log_data["Status"] = "FAILURE"
        log_data["Message"] = "F5 embedding failed. See console for specific errors from embed_message_f5."
    log_stego_operation(log_data)

def handle_f5_extract():
    print("\n--- Extract Message using F5 ---")
    input_image = input("Enter JPEG image path to extract from: ")

    log_data = {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "OperationName": "F5_Extract",
        "BaseImagePath": input_image,
        "StegoImagePath": "",
        "PayloadSample": "",
        "ExtractedPayloadSample": "",
        "Status": "",
        "Message": ""
    }

    message = extract_message_f5(input_image)
    if message is not None:
        print(f"Extracted F5 message: {message}")
        log_data["Status"] = "SUCCESS"
        log_data["ExtractedPayloadSample"] = message[:20]
        log_data["Message"] = "F5 extraction successful."
    else:
        print("Failed to extract F5 message or no message found.")
        log_data["Status"] = "FAILURE"
        log_data["Message"] = "F5 extraction failed or no message found. See console for errors from extract_message_f5."
    log_stego_operation(log_data)

def jpeg_stego_menu():
    while True:
        print("\n--- JPEG Steganography Menu ---")
        print("1. Embed message using JSteg")
        print("2. Extract message using JSteg")
        print("3. Embed message using F5")
        print("4. Extract message using F5")
        print("5. Back to Main Menu")
        choice = input("Enter your choice (1-5): ")

        if choice == '1':
            handle_jsteg_embed()
        elif choice == '2':
            handle_jsteg_extract()
        elif choice == '3':
            handle_f5_embed()
        elif choice == '4':
            handle_f5_extract()
        elif choice == '5':
            break
        else:
            print("Invalid choice. Please enter a number between 1 and 5.")

def main_menu():
    # Import os at the top of the file if path checks are added to handlers
    # import os
    print("Welcome to Steganography Tool")
    while True:
        print("\n--- Main Menu ---")
        print("1. JPEG Steganography")
        print("2. Exit")
        choice = input("Enter your choice (1-2): ")

        if choice == '1':
            jpeg_stego_menu()
        elif choice == '2':
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please enter 1 or 2.")

if __name__ == "__main__":
    # Note: Running this script with UI might be problematic in some non-interactive
    # environments. The core functions are still importable and usable directly.
    # The previous environment issues with jpegio/numpy might also affect CLI execution.
    main_menu()
# --- END OF REPLACEMENT BLOCK ---
