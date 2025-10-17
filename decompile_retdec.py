import os
from retdec import decompiler

def decompile_payload(payload_path, output_path):
    """
    Decompiles the given payload using RetDec and saves the C code to the output directory.
    """
    try:
        # Set a dummy API key if one is not already set.
        if "RETDEC_API_KEY" not in os.environ:
            os.environ["RETDEC_API_KEY"] = "dummy_key"

        decompiler.decompile(payload_path, output=output_path)
        print(f"Decompiled source saved to {output_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    decompile_payload("reconstructed_payload1.exe", "decompiled_retdec.c")