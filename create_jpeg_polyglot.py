import sys

def create_polyglot(jpeg_in, payload_in, jpeg_out):
    """
    Creates a JPEG polyglot by appending the payload to the end of the image.

    Args:
        jpeg_in (str): Path to the input JPEG file.
        payload_in (str): Path to the payload file.
        jpeg_out (str): Path to the output JPEG file.
    """
    try:
        with open(jpeg_in, "rb") as f:
            jpeg_data = f.read()

        with open(payload_in, "rb") as f:
            payload_data = f.read()

        with open(jpeg_out, "wb") as f:
            f.write(jpeg_data)
            f.write(payload_data)

        print(f"Successfully created polyglot JPEG: {jpeg_out}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python create_jpeg_polyglot.py <input_jpeg> <payload_file> <output_jpeg>")
        sys.exit(1)

    jpeg_in = sys.argv[1]
    payload_in = sys.argv[2]
    jpeg_out = sys.argv[3]

    create_polyglot(jpeg_in, payload_in, jpeg_out)