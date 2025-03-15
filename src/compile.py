import os
import subprocess

import src.utils.utils as utils  # Assuming utils.py is in the src directory

# Define paths
c_code_path = "source_code/simu_core.c"
binary_path = "binaries/simu_core.bin"

# Ensure the output directory exists
os.makedirs(os.path.dirname(binary_path), exist_ok=True)

# Compile the C code into a binary
try:
    utils.compile(target="linux", c_code_path=c_code_path, binary_path=binary_path)
    print(f"Compilation successful! Binary created at: {binary_path}")
except subprocess.CalledProcessError as e:
    print(f"Error during compilation: {e}")
