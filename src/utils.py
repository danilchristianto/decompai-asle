import sys
import os
import subprocess
import re
import pprint

WORKSPACE_DIR = "decompile_workspace"
os.makedirs(WORKSPACE_DIR, exist_ok=True)

DOCKER_IMAGE = "gcc_linux_x86_64:latest"

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
        compile_command = f"gcc -o {binary_path} {c_code_path} -lm"
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
            f"gcc -o /workspace/{binary_path} /workspace/{c_code_path} -lm"
        )
        
        # Build Docker image
        subprocess.run(docker_build_command, shell=True, check=True)
        # Compile using Docker
        subprocess.run(docker_run_command, shell=True, check=True)
        
def objdump(args: str) -> str:
    """
    Runs the objdump command with the specified arguments and returns its output.
    Args:
        args (str): The arguments to pass to the objdump command.
    Returns:
        str: The output from the objdump command.
    """
    # Use Docker for disassembly
    container_name = "disassembler"
    
    docker_run_command = (
        f"docker run --rm --name {container_name} "
        f"-v {os.getcwd()}:/workspace -w /workspace --platform linux/amd64 gcc:latest "
        f"objdump {args}"
    )
    try:
        result = subprocess.run(docker_run_command, shell=True, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error running objdump: {e.stderr}")
    
    return result.stdout

def disassemble_binary(binary_path, function_name=None, target_platform: str="linux"):
    # Disassemble the binary directly
    disassemble_path = os.path.join(WORKSPACE_DIR, "disassembled_code.asm")
    
    if target_platform == "mac":
        # Disassemble locally
        disassemble_command = ["objdump", "-dstrx", binary_path]
        # disassemble_command = ["objdump", "-ds", binary_path]
        result = subprocess.run(disassemble_command, capture_output=True, text=True, check=True)
    else:
        # Use Docker for disassembly
        docker_image = "gcc_linux_x86_64:latest"
        container_name = "disassembler"
        
        docker_run_command = (
            f"docker run --rm --name {container_name} "
            f"-v {os.getcwd()}:/workspace {docker_image} "
            f"objdump -ds /workspace/{binary_path}"
        )
        result = subprocess.run(docker_run_command, shell=True, capture_output=True, text=True, check=True)

    # Save disassembled code to a file for inspection
    with open(disassemble_path, "w") as f:
        f.write(result.stdout)
    
    if function_name is None:
        return result.stdout
    else:
        input_asm = extract_function_asm(disassemble_path, function_name)
    
    return input_asm

def disassemble_section(binary_path, section_name):
    input_asm = disassemble_binary(binary_path)
    
    pattern = rf"Disassembly of section {re.escape(section_name)}:\n(.*?)(?=\nDisassembly of|$)"
    
    # Use re.DOTALL to match across multiple lines
    match = re.search(pattern, input_asm, re.DOTALL)
    
    # Return the matched content if found
    if match:
        return match.group(1).strip()
    else:
        return None


def compile_and_disassemble_c_code(c_code_path, function_name, target_platform):
    binary_path = os.path.join(WORKSPACE_DIR, "compiled_binary")
    
    if target_platform == "mac":
        function_name = "_" + function_name

    # Compile the C code
    compile(target_platform, c_code_path, binary_path)

    # Disassemble the binary
    input_asm = disassemble_binary(binary_path, function_name, target_platform)
    
    return input_asm

def disassemble(input_path, function_name):
    # If the workspace directory does not exist, create it
    if not os.path.exists(WORKSPACE_DIR):
        os.makedirs(WORKSPACE_DIR)
    
    # Copy the C code or binary to the workspace for reference
    input_basename = os.path.basename(input_path)
    workspace_input_path = os.path.join(WORKSPACE_DIR, input_basename)
    if not os.path.exists(workspace_input_path):
        os.system(f"cp {input_path} {workspace_input_path}")
        
    target_platform = "linux"
    
    if input_path.endswith(".c"):
        print("Input detected as C code. Compiling and disassembling...")
        disassembled_code = compile_and_disassemble_c_code(input_path, function_name, target_platform)
    else:
        print("Input detected as binary. Disassembling...")
        disassembled_code = disassemble_binary(input_path, function_name, target_platform)
    
    return disassembled_code

def summarize_assembly(objdump_output=None, binary_path=None):
    """
    Summarizes the key details from assembly code or the output of objdump.
    Args:
        objdump_output (str): The output of objdump as a string.
        binary_path (str): Path to the binary to analyze. If provided, objdump will be run.
    Returns:
        dict: A summary containing architecture, start address, sections, functions, and more.
    """
    if binary_path:
        objdump_output = objdump(f"-dstrx {binary_path}")  # Assume objdump is defined elsewhere

    if not objdump_output:
        return {"error": "No objdump output or binary path provided."}

    summary = {}

    # Extract architecture and start address
    arch_match = re.search(r"architecture:\s+([^\n,]+)", objdump_output)
    start_addr_match = re.search(r"start address\s+(0x[0-9a-fA-F]+)", objdump_output)
    summary["architecture"] = arch_match.group(1) if arch_match else "Unknown"
    summary["start_address"] = start_addr_match.group(1) if start_addr_match else "Unknown"

    # Extract program headers
    program_headers = re.findall(
        r"([A-Z]+)\s+off\s+(0x[0-9a-f]+)\s+vaddr\s+(0x[0-9a-f]+)\s+paddr\s+(0x[0-9a-f]+)\s+align\s+2\*\*(\d+).*?\n\s+filesz\s+(0x[0-9a-f]+)\s+memsz\s+(0x[0-9a-f]+)\s+flags\s+([rwx\-]+)",
        objdump_output,
        re.S,
    )
    summary["program_headers"] = [
        {
            "type": ph[0],
            "offset": ph[1],
            "virtual_address": ph[2],
            "physical_address": ph[3],
            "alignment": int(ph[4]),
            "file_size": ph[5],
            "memory_size": ph[6],
            "flags": ph[7],
        }
        for ph in program_headers
    ]

    # Extract dynamic section
    dynamic_section_match = re.search(r"Dynamic Section:(.*?)Version References:", objdump_output, re.S)
    if dynamic_section_match:
        dynamic_entries = re.findall(r"([A-Z_]+)\s+(0x[0-9a-f]+|.+)", dynamic_section_match.group(1))
        summary["dynamic_section"] = {entry[0]: entry[1] for entry in dynamic_entries}

    # Extract sections and their properties
    sections = re.findall(
        r"(\d+)\s+([\.\w]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+2\*\*(\d+)\s+(.*)",
        objdump_output,
    )
    summary["sections"] = [
        {
            "index": int(sec[0]),
            "name": sec[1],
            "size": sec[2],
            "vma": sec[3],
            "lma": sec[4],
            "file_offset": sec[5],
            "alignment": int(sec[6]),
            "flags": sec[7],
        }
        for sec in sections
    ]

    # Extract symbol table
    symbol_table_match = re.search(r"SYMBOL TABLE:(.*?)Contents of section", objdump_output, re.S)
    if symbol_table_match:
        # symbols = re.findall(
        #     r"([0-9a-f]+)\s+\w\s+([\.\w]+)\s+([0-9a-f]+)\s+(.*)", symbol_table_match.group(1)
        # )
        symbols = re.findall(
            r"([0-9a-f]{8})\s[\w\s]{7}\s([\.\w]+|\*ABS\*|\*UND\*)\s+([0-9a-f]+)\s+(.*)", 
            symbol_table_match.group(1)
        )
        summary["symbol_table"] = [
            {"address": sym[0], "section": sym[1], "size": sym[2], "name": sym[3]} for sym in symbols
        ]

    # # Extract disassembled functions
    # disassembly = {}
    # disassembled_sections = re.findall(r"Disassembly of section (.*?):\n(.*?)(?=\n\n|\Z)", objdump_output, re.S)
    # for section, content in disassembled_sections:
    #     functions = re.findall(r"([0-9a-f]+) <([^>]+)>:\n((?:.+\n)+?)(?=\n[0-9a-f]+ <|$)", content)
    #     disassembly[section] = [
    #         {"address": func[0], "name": func[1], "instructions": func[2].strip()} for func in functions
    #     ]
    # summary["disassembly"] = disassembly

    return summary

if __name__ == "__main__":
    pp = pprint.PrettyPrinter(indent=2)
    
    # print(objdump("-sdxtr decompile_workspace/uploaded_binary.bin"))
    
    # pp.pprint(summarize_assembly(binary_path="decompile_workspace/uploaded_binary.bin"))
    
    print(disassemble_section("decompile_workspace/uploaded_binary.bin", ".init"))
    