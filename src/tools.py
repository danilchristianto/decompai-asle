import os
import subprocess
from typing_extensions import Optional, Annotated
from langchain_core.tools import tool
from langgraph.prebuilt import InjectedState, InjectedStore

import src.config as config
import src.utils as utils
from src.utils import extract_function_asm
from src.state import State

@tool
def summarize_assembly(
    state: Annotated[State, InjectedState]
    ) -> str:
    """List functions in the binary at binary_path."""
    summary = str(utils.summarize_assembly(binary_path=state["binary_path"]))
    return f"Summary of assembly code:\n\n{summary}"


@tool
def disassemble_binary(
    state: Annotated[State, InjectedState]
    ) -> str:
    """Disassemble the binary at binary_path."""
    assembly_code = utils.disassemble_binary(binary_path=state["binary_path"])
    return f"Disassembly of binary:\n\n{assembly_code}"

def disassemble_section(
    section_name: str,
    state: Annotated[State, InjectedState]
    ) -> str:
    """Disassemble a section of the binary at binary_path."""
    assembly_code = utils.disassemble_section(binary_path=state["binary_path"], section_name=section_name)
    return f"Disassembly of section {section_name}:\n\n{assembly_code}"

@tool
def get_asm(args: str) -> str:
    """Get assembly for a function. Input: 'binary_path,function_name'."""
    parts = args.split(",")
    if len(parts) != 2:
        return "Please provide 'binary_path,function_name' as input."
    binary, func = parts
    return get_function_asm(binary, func)

@tool
def run_gdb(args: str) -> str:
    """Run a GDB command on the binary. Input: 'binary_path;gdb_command'."""
    parts = args.split(";", 1)
    if len(parts) != 2:
        return "Please provide 'binary_path;gdb_command' as input."
    binary, gdb_cmd = parts
    return run_gdb_command(binary, gdb_cmd)

@tool
def run_ghidra(args: str) -> str:
    """Run Ghidra headless analysis. Input: 'binary_path;optional_script'."""
    parts = args.split(";", 1)
    if len(parts) == 2:
        binary, script = parts
        return run_ghidra_analysis(binary, script)
    else:
        binary = args
        return run_ghidra_analysis(binary, None)

@tool
def readfile(path: str) -> str:
    """Read a file from the workspace."""
    return read_file(path)

@tool
def writefile(args: str) -> str:
    """Write content to a file. Input: 'filepath;content'."""
    parts = args.split(";", 1)
    if len(parts) != 2:
        return "Please provide 'filepath;content' as input."
    filepath, content = parts
    return write_file(filepath, content)

def get_function_asm(binary_path: str, function_name: str) -> str:
    # Re-run disassembly for just one function by name
    # We'll just reuse a snippet from utils by writing a temporary file to run extraction on.
    # In a real scenario, you'd rely on the previously saved disassembly file or cache.
    disasm_cmd = ["objdump", "-ds", binary_path]
    result = subprocess.run(disasm_cmd, capture_output=True, text=True, check=True)
    asm_path = os.path.join(config.WORKSPACE_ROOT, "temp_disassembly.asm")
    with open(asm_path, "w") as f:
        f.write(result.stdout)
    
    try:
        return extract_function_asm(result.stdout, function_name)
    except ValueError:
        return f"Function {function_name} not found."

def run_gdb_command(binary_path: str, gdb_command: str) -> str:
    # Run GDB in batch mode:
    cmd = [
        "gdb", "-q", "-nx", "-batch", 
        "-ex", gdb_command, 
        "-ex", "quit", 
        binary_path
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def run_ghidra_analysis(binary_path: str, script_name: Optional[str] = None) -> str:
    # This would call Ghidra headless. Adjust as needed.
    # Example Ghidra headless command (make sure Ghidra is installed and accessible):
    project_dir = os.path.join(config.WORKSPACE_ROOT, "ghidra_project")
    os.makedirs(project_dir, exist_ok=True)
    ghidra_path = "/path/to/ghidra/support/analyzeHeadless"
    cmd = [ghidra_path, project_dir, "test_project", "-import", binary_path, "-analysisTimeout", "300", "-deleteProject"]
    if script_name:
        cmd += ["-postScript", script_name]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def read_file(filepath: str) -> str:
    with open(filepath, "r") as f:
        return f.read()

def write_file(filepath: str, content: str) -> str:
    with open(filepath, "w") as f:
        f.write(content)
    return "File written successfully."