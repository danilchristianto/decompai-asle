import sys
import os
import subprocess

WORKSPACE_DIR = "decompile_workspace"
os.makedirs(WORKSPACE_DIR, exist_ok=True)

def extract_function_asm(disassemble_path, function_name):
    # Extract the specified function's assembly
    input_asm = ''
    with open(disassemble_path, 'r') as f:
        asm = f.read()
        if f'<{function_name}>:' not in asm:
            raise ValueError(f"Function {function_name} not found in the assembly.")
        # Isolate the assembly for the specified function
        asm = f'<{function_name}>:' + asm.split(f'<{function_name}>:')[-1].split('\n\n')[0]
        asm_clean = ""
        for line in asm.splitlines():
            if len(line.split("\t")) < 3 and '00' in line:
                continue
            # Remove binary codes and comments
            asm_clean += "\t".join(line.split("\t")[2:]).split("#")[0].strip() + "\n"
    input_asm = asm_clean.strip()
    return input_asm

def compile(target: str, c_code_path: str, binary_path: str):
    if target == "mac":
        # Compile locally on macOS
        compile_command = f"gcc -o {binary_path}.o {c_code_path} -lm"
        subprocess.run(compile_command, shell=True, check=True)
    else:
        # Use Docker for cross-platform compilation (Linux x86_64)
        docker_image = "gcc_linux_x86_64:latest"
        container_name = "c_code_compiler"
        
        # Build Docker image targeting linux/amd64 architecture
        docker_build_command = (
            f"docker buildx build --platform linux/amd64 "
            f"-t {docker_image} . --load"
        )
        docker_run_command = (
            f"docker run --rm --name {container_name} "
            f"-v {os.getcwd()}:/workspace {docker_image} "
            f"gcc -o /workspace/{binary_path}.o /workspace/{c_code_path} -lm"
        )
        
        # Build Docker image
        subprocess.run(docker_build_command, shell=True, check=True)
        # Compile using Docker
        subprocess.run(docker_run_command, shell=True, check=True)

def disassemble_binary(binary_path, function_name, target: str):
    # Disassemble the binary directly
    disassemble_path = os.path.join(WORKSPACE_DIR, "disassembled_code.asm")
    
    if target == "mac":
        # Disassemble locally
        disassemble_command = ["objdump", "-d", binary_path]
        result = subprocess.run(disassemble_command, capture_output=True, text=True, check=True)
    else:
        # Use Docker for disassembly
        docker_image = "gcc_linux_x86_64:latest"
        container_name = "disassembler"
        
        docker_run_command = (
            f"docker run --rm --name {container_name} "
            f"-v {os.getcwd()}:/workspace {docker_image} "
            f"objdump -d /workspace/{binary_path}.o"
        )
        result = subprocess.run(docker_run_command, shell=True, capture_output=True, text=True, check=True)

    # Save disassembled code to a file for inspection
    with open(disassemble_path, "w") as f:
        f.write(result.stdout)
        
    input_asm = extract_function_asm(disassemble_path, function_name)
    
    return input_asm


def compile_and_disassemble_c_code(c_code_path, function_name):
    binary_path = os.path.join(WORKSPACE_DIR, "compiled_binary")
    target = "linux"
    
    if target == "mac":
        function_name = "_" + function_name

    # Compile the C code
    compile(target, c_code_path, binary_path)

    # Disassemble the binary
    input_asm = disassemble_binary(binary_path, function_name, target)
    
    return input_asm

def disassemble(input_path, function_name):
    # Copy the C code or binary to the workspace for reference
    input_basename = os.path.basename(input_path)
    workspace_input_path = os.path.join(WORKSPACE_DIR, input_basename)
    if not os.path.exists(workspace_input_path):
        os.system(f"cp {input_path} {workspace_input_path}")
    
    if input_path.endswith(".c"):
        print("Input detected as C code. Compiling and disassembling...")
        disassembled_code = compile_and_disassemble_c_code(input_path, function_name)
    else:
        print("Input detected as binary. Disassembling...")
        disassembled_code = disassemble_binary(input_path, function_name)
    
    return disassembled_code