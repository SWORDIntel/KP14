import configparser
from stego_analyzer.decompilers.factory import DecompilerFactory

def decompile_payload(payload_path, output_dir):
    """
    Decompiles the given payload and saves the C code to the output directory.
    """
    config = configparser.ConfigParser()
    config.read("settings.ini")

    decompiler = DecompilerFactory.create(config)
    decompiled_path = decompiler.decompile(payload_path, output_dir)
    print(f"Decompiled source saved to {decompiled_path}")

if __name__ == "__main__":
    decompile_payload("payload1.exe", ".")