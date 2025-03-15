import os
import subprocess
from typing_extensions import Optional, Annotated, List, Dict, Type, Callable, Any
from langchain_core.tools import tool
from langchain_community.tools.file_management.write import WriteFileTool, WriteFileInput, BaseFileToolMixin
from langchain_core.messages import (
    AIMessage,
    AnyMessage,
    ToolCall,
    ToolMessage,
    convert_to_messages,
)
from langgraph.prebuilt import InjectedState, InjectedStore
from langchain_core.callbacks import CallbackManagerForToolRun
import json
from pydantic import BaseModel, Field
from inspect import Signature, Parameter

import src.config as config
import src.utils as utils
from src.utils import extract_function_asm
from src.state import State

def get_decompiled_folder_path(state: State) -> str:
    """Ensure the decompiled folder exists and return its path."""
    workspace = state.get("workspace_path")
    if not workspace:
        raise ValueError("Workspace path not set in state.")
    decompiled_path = os.path.join(workspace, config.DECOMPILED_FOLDER_NAME)
    os.makedirs(decompiled_path, exist_ok=True)
    return decompiled_path

def create_tool_function(cls: Type) -> Callable:
    """
    Factory that creates a tool function from a given class.
    The generated function will:
      - Accept `state` and parameters defined by cls.args_schema.
      - Be decorated with @tool.
      - Have a name and docstring based on cls attributes.
    """
    # Instantiate the class to access its attributes
    cls_instance = cls()
    args_schema: Type[BaseModel] = cls_instance.args_schema
    func_name: str = cls_instance.name
    func_doc: str = cls_instance.description
    
    # Define the function without decoration first
    def dynamic_tool(
        state: Annotated[Any, InjectedState],
        **kwargs: Any
    ) -> Any:
        workspace_path = state["workspace_path"]
        instance = cls(root_dir=os.path.join(workspace_path, config.DECOMPILED_FOLDER_NAME))
        return instance._run(**kwargs)

    # Set the function's name and docstring before decoration
    dynamic_tool.__name__ = func_name
    dynamic_tool.__doc__ = func_doc
    class NewSchema(args_schema):
        state: Annotated[State, InjectedState]
    
    # Now apply the @tool decorator with the description
    dynamic_tool = tool(args_schema=NewSchema)(dynamic_tool)
    
    return dynamic_tool

@tool
def get_decompiled_directory_tree(
    state: Annotated[State, InjectedState]
) -> str:
    """Return a JSON-formatted tree of files in the decompiled subfolder."""
    decompiled_path = get_decompiled_folder_path(state)
    tree = {}
    for root, dirs, files in os.walk(decompiled_path):
        rel_root = os.path.relpath(root, decompiled_path)
        tree[rel_root] = files
    return json.dumps(tree, indent=2)

@tool
def read_decompiled_files(
    file_paths: List[str],
    state: Annotated[State, InjectedState]
) -> str:
    """
    Read one or multiple files from the decompiled subfolder.
    Input: List of relative file paths.
    Output: JSON mapping of file paths to their contents.
    """
    import json
    decompiled_path = get_decompiled_folder_path(state)
    
    print("Reading files:", file_paths)
    
    result = {}
    for rel_path in file_paths:
        abs_path = os.path.join(decompiled_path, rel_path)
        # Ensure the file is inside the decompiled folder
        if not abs_path.startswith(decompiled_path):
            result[rel_path] = "Access denied."
            continue
        if os.path.exists(abs_path) and os.path.isfile(abs_path):
            with open(abs_path, "r") as f:
                result[rel_path] = f.read()
        else:
            result[rel_path] = "File does not exist."
    return json.dumps(result, indent=2)

@tool
def write_decompiled_files(
    file_path_content_pairs: Dict[str, str],
    state: Annotated[State, InjectedState]
) -> str:
    """
    Writes decompiled files to the specified relative paths within the decompiled folder.
    Args:
        file_path_content_pairs (Dict[str, str]): A dictionary where keys are relative file paths and values are the file contents.
    Returns:
        str: A JSON-formatted string indicating the result of each file write operation. The keys are the relative file paths and the values are the status messages.
    """
    import json
    decompiled_path = get_decompiled_folder_path(state)
    
    result = {}
    for rel_path, content in file_path_content_pairs.items():
        # Remove leading slashes of the relative path, and remove "decompiled/" if present
        rel_path = rel_path.lstrip("/")
        if rel_path.startswith(config.DECOMPILED_FOLDER_NAME):
            rel_path = rel_path[len(config.DECOMPILED_FOLDER_NAME):].lstrip("/")
        
        abs_path = os.path.join(decompiled_path, rel_path)
        # Ensure the file is inside the decompiled folder
        if not abs_path.startswith(decompiled_path):
            result[rel_path] = "Access denied."
            continue
        # Create directories if they don't exist
        os.makedirs(os.path.dirname(abs_path), exist_ok=True)
        with open(abs_path, "w") as f:
            f.write(content)
        result[rel_path] = "File written successfully."
    return json.dumps(result, indent=2)

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

@tool
def disassemble_section(
    section_name: str,
    state: Annotated[State, InjectedState]
    ) -> str:
    """Disassemble a section of the binary at binary_path."""
    assembly_code = utils.disassemble_section(binary_path=state["binary_path"], section_name=section_name)
    return f"Disassembly of section {section_name}:\n\n{assembly_code}"

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
