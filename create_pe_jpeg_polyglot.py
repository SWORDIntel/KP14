import pefile
import sys

def create_pe_jpeg_polyglot(pe_in, jpeg_in, pe_out):
    """
    Creates a PE-JPEG polyglot by appending the JPEG image to the end of the PE file.

    Args:
        pe_in (str): Path to the input PE file.
        jpeg_in (str): Path to the input JPEG file.
        pe_out (str): Path to the output PE file.
    """
    try:
        # Check if the input file is a valid PE file.
        try:
            pe = pefile.PE(pe_in)
        except pefile.PEFormatError:
            print(f"Error: {pe_in} is not a valid PE file.")
            sys.exit(1)

        with open(jpeg_in, "rb") as f:
            jpeg_data = f.read()

        # Get the original size of the PE file.
        original_size = len(pe.write())

        # Update the size of the image.
        pe.OPTIONAL_HEADER.SizeOfImage = original_size + len(jpeg_data)

        # Write the new PE file.
        pe.write(pe_out)

        # Append the JPEG data to the end of the file.
        with open(pe_out, "ab") as f:
            f.write(jpeg_data)

        print(f"Successfully created PE-JPEG polyglot: {pe_out}")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python create_pe_jpeg_polyglot.py <input_pe> <input_jpeg> <output_pe>")
        sys.exit(1)

    pe_in = sys.argv[1]
    jpeg_in = sys.argv[2]
    pe_out = sys.argv[3]

    create_pe_jpeg_polyglot(pe_in, jpeg_in, pe_out)