import sys

def extract_appended_data(jpeg_path, output_path):
    """
    Checks for and extracts appended data from a JPEG file by finding the EOI marker.

    Args:
        jpeg_path (str): The path to the JPEG file.
        output_path (str): The path to save the extracted data.
    """
    try:
        with open(jpeg_path, "rb") as f:
            data = f.read()

        eoi_marker = b"\xff\xd9"
        eoi_index = data.rfind(eoi_marker)

        if eoi_index != -1:
            # The payload is everything after the EOI marker
            appended_data = data[eoi_index + len(eoi_marker):]
            if appended_data:
                print(f"Appended data found in {jpeg_path}.")
                with open(output_path, "wb") as out_f:
                    out_f.write(appended_data)
                print(f"Extracted data saved to {output_path}.")
            else:
                print(f"No appended data found in {jpeg_path}.")
        else:
            print(f"EOI marker not found in {jpeg_path}.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python extract_payload.py <jpeg_file> <output_file>")
        sys.exit(1)

    jpeg_file = sys.argv[1]
    output_file = sys.argv[2]
    extract_appended_data(jpeg_file, output_file)