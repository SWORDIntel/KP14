import jpegio
import numpy
import sys
import os

print(f"Python version: {sys.version}")
print(f"NumPy version: {numpy.__version__}")

try:
    print(f"jpegio version: {jpegio.__version__}")
except Exception as e:
    print(f"Could not get jpegio version: {e}")

# Use a known test image, ensure path is correct from repo root
image_path = "test_images_jpeg/jpeg_grayscale.jpg"
print(f"Attempting to read: {image_path}")

if not os.path.exists(image_path):
    print(f"Error: Test image not found at {image_path}. Current CWD: {os.getcwd()}", file=sys.stderr)
    sys.exit(1)

try:
    jpeg_struct = jpegio.read(image_path)
    print("jpegio.read() successful.")
    # Print some basic info if read is successful
    if jpeg_struct:
        print(f"Number of coefficient arrays: {len(jpeg_struct.coef_arrays)}")
        if jpeg_struct.coef_arrays and len(jpeg_struct.coef_arrays) > 0:
            print(f"Shape of first coefficient array: {jpeg_struct.coef_arrays[0].shape}")
        else:
            print("No coefficient arrays found in the JpegStructure.")
        print(f"Number of quantization tables: {len(jpeg_struct.quant_tables)}")
except ValueError as ve:
    print(f"ValueError during jpegio.read(): {ve}", file=sys.stderr)
    # Re-raise to ensure the error is caught by the test runner if it's specifically looking for it
    raise
except Exception as e:
    print(f"Other exception during jpegio.read(): {e}", file=sys.stderr)
    raise

print("Minimal test script finished.")
