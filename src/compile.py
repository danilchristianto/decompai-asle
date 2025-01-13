import os
import src.utils as utils  # Assuming utils.py is in the src directory
import subprocess

# Define paths
c_code_path = "c_code/fibonacci.c"
binary_path = "binaries/fibonacci.bin"

# Ensure the output directory exists
os.makedirs(os.path.dirname(binary_path), exist_ok=True)

# Compile the C code into a binary
try:
    utils.compile(target="linux", c_code_path=c_code_path, binary_path=binary_path)
    print(f"Compilation successful! Binary created at: {binary_path}")
except subprocess.CalledProcessError as e:
    print(f"Error during compilation: {e}")
