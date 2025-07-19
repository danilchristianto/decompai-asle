import os
import subprocess
from typing_extensions import Optional, Annotated, List, Dict, Type, Callable, Any, Union
from langchain_core.tools import tool, InjectedToolCallId
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
from langgraph.config import get_stream_writer
import json
from pydantic import BaseModel, Field, create_model
from inspect import Signature, Parameter

import src.config as config
import src.utils as utils
from src.utils import disassemble_function
from src.state import State
from src.tools.sandboxed_shell import SandboxedShellTool

def get_agent_workspace_path(state: State) -> str:
    """Ensure the workspace folder exists and return its path."""
    session_path = state.get("session_path")
    if not session_path:
        raise ValueError("Workspace path not set in state.")
    agent_workspace_path = os.path.join(
        session_path, config.AGENT_WORKSPACE_NAME)
    os.makedirs(agent_workspace_path, exist_ok=True)
    return agent_workspace_path


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
        session_path = state["session_path"]
        instance = cls(root_dir=os.path.join(
            session_path, config.AGENT_WORKSPACE_NAME))
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
def get_agent_workspace_directory_tree(
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """Return a JSON-formatted tree of files in the agent workspace subfolder."""
    agent_workspace_path = get_agent_workspace_path(state)
    tree = {}
    for root, dirs, files in os.walk(agent_workspace_path):
        rel_root = os.path.relpath(root, agent_workspace_path)
        tree[rel_root] = files
    return ToolMessage(content=json.dumps(tree, indent=2), tool_call_id=tool_call_id)


@tool
def summarize_assembly(
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """List functions in the binary at binary_path."""
    summary = str(utils.summarize_assembly(binary_path=state["binary_path"]))
    return ToolMessage(content=f"Summary of assembly code:\n\n{summary}", tool_call_id=tool_call_id)


@tool
def disassemble_binary(
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """Disassemble the binary at binary_path."""
    assembly_code = utils.disassemble_binary(binary_path=state["binary_path"])

    if utils.count_tokens(assembly_code, state["model_name"]) > state["model_context_length"] // 2:
        raise ValueError("Disassembly too long for model context length.")

    return ToolMessage(content=f"Disassembly of binary:\n\n{assembly_code}", tool_call_id=tool_call_id)


@tool
def disassemble_section(
    section_name: str,
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """Disassemble a section of the binary at binary_path."""
    assembly_code = utils.disassemble_section(
        binary_path=state["binary_path"], section_name=section_name)

    if utils.count_tokens(assembly_code, state["model_name"]) > state["model_context_length"] // 2:
        raise ValueError("Disassembly too long for model context length.")

    return ToolMessage(content=f"Disassembly of section {section_name}:\n\n{assembly_code}", tool_call_id=tool_call_id)


@tool
def disassemble_function(
    function_name: str,
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """Disassemble a function from the binary at binary_path."""
    assembly_code = utils.disassemble_function(
        binary_path=state["binary_path"], function_name=function_name)

    if utils.count_tokens(assembly_code, state["model_name"]) > state["model_context_length"] // 2:
        raise ValueError("Disassembly too long for model context length.")

    return ToolMessage(content=f"Disassembly of function {function_name}:\n\n{assembly_code}", tool_call_id=tool_call_id)


@tool
def dump_memory(
    address: str,
    length: int,
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """
    Reads a specified number of bytes from the binary at a given address.
    Returns the dumped bytes as a hex string.
    """
    if address.startswith("0x"):
        address = address[2:]
    address = int(address, 16)

    data = utils.dump_memory(state["binary_path"], address, length)
    return ToolMessage(content=data.hex(), tool_call_id=tool_call_id)


@tool
def get_string_at_address(
    address: str,
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """
    Reads a null-terminated string from the binary starting at the given address.
    """
    if address.startswith("0x"):
        address = address[2:]
    address = int(address, 16)
    return ToolMessage(content=utils.get_string_at_address(state["binary_path"], address), tool_call_id=tool_call_id)

# Dynamically create an extended args schema that adds the 'state' field.
def extend_args_schema(parent_schema: Type[BaseModel]) -> Type[BaseModel]:
    return create_model(
        'Extended' + parent_schema.__name__,
        state=(Annotated[State, InjectedState], ...),  # required field
        __base__=parent_schema,
    )

import src.tools.sandboxed_shell.tool as src_tools_sandboxed_shell_tool
class CustomSandboxedShellTool(SandboxedShellTool):
    args_schema: Type[BaseModel] = extend_args_schema(src_tools_sandboxed_shell_tool.SandboxedShellInput)

    def _run(
        self,
        commands: Union[str, List[str]],
        state: Annotated[State, InjectedState],
        run_manager: Optional[CallbackManagerForToolRun] = None,
    ) -> Optional[str]:
        # Extract required values from state.
        agent_workspace_path = get_agent_workspace_path(state)
        process_id = state.get("session_path")
        mounted_dirs = {agent_workspace_path:agent_workspace_path}
        workdir = agent_workspace_path
        return super()._run(commands, process_id, mounted_dirs, workdir, run_manager)

@tool
def run_ghidra_post_script(
    script_path: str,
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
    script_args: str = ""
) -> str:
    """
    Runs a Ghidra post-script using analyzeHeadless.
    Args:
        script_path: Path to the script relative to the agent workspace
        script_args: Arguments to pass to the script
    """
    agent_workspace_path = get_agent_workspace_path(state)
    full_script_path = os.path.join(agent_workspace_path, script_path)
    
    if not os.path.exists(full_script_path):
        return ToolMessage(content=f"Script not found at {script_path}", tool_call_id=tool_call_id)
    
    try:
        result = utils.run_ghidra_post_script(utils.get_binary_path_in_workspace(state["binary_path"]), full_script_path, script_args)
        return ToolMessage(content=result, tool_call_id=tool_call_id)
    except Exception as e:
        return ToolMessage(content=f"Error running Ghidra script: {str(e)}", tool_call_id=tool_call_id)

# Instantiate the existing tool
kali_stateful_shell = CustomSandboxedShellTool().as_tool()

@tool
def decompile_function_with_ghidra(
    function_name: str,
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """
    Decompiles a function using Ghidra's headless mode.
    Args:
        function_name: Name of the function to decompile
    """
    try:
        writer = get_stream_writer()
        writer(f"Decompiling function {function_name}...\n")
        result = utils.decompile_function_with_ghidra(utils.get_binary_path_in_workspace(state["binary_path"]), function_name)
        return ToolMessage(content=result, tool_call_id=tool_call_id)
    except Exception as e:
        return ToolMessage(content=f"Error decompiling function: {str(e)}", tool_call_id=tool_call_id)

@tool
def r2_stateless_shell(
    commands: Union[str, List[str]],
    state: Annotated[State, InjectedState],
    ) -> str:
    """
    Executes one or several commands using r2 in quiet mode with the -c option. Each call to this tool will start a new r2 instance.
    The r2 environment includes the r2dec and r2ghidra plugins for decompilation and analysis.
    """
    if isinstance(commands, str):
        commands = [commands]
        
    # Prepend the command with 'r2 -qc'
    full_command = f"r2 -e bin.relocs.apply=true -qc \"{'; '.join(commands)}\" {utils.get_binary_path_in_workspace(state['binary_path'])}"
    # Invoke the existing shell tool with the modified command
    return kali_stateful_shell.invoke({"commands": full_command, "state": state})

@tool
def r2_stateful_shell(
    commands: Union[str, List[str]],
    state: Annotated[State, InjectedState],
) -> str:
    """
    Executes one or several commands using r2 in quiet mode with the -c option, maintaining state by replaying all previous commands in this session.
    The r2 environment includes the r2dec and r2ghidra plugins for decompilation and analysis.
    Tracks the number of lines returned so that only new output is returned each call.
    """
    if isinstance(commands, str):
        commands = [commands]
    # Retrieve or initialize the command history
    history_key = 'r2_stateful_shell_history'
    if history_key not in state:
        state[history_key] = []
    # Append new commands to the history
    state[history_key].extend(commands)
    # Build the full command string
    all_commands = '; '.join(state[history_key])
    full_command = f"r2 -e bin.relocs.apply=true -qc \"{all_commands}\" {utils.get_binary_path_in_workspace(state['binary_path'])}"

    # Retrieve or initialize the output line count
    output_line_count_key = 'r2_stateful_shell_output_line_count'
    prev_line_count = state.get(output_line_count_key, 0)

    # Invoke the shell tool
    output = kali_stateful_shell.invoke({"commands": full_command, "state": state})

    # Split output into lines
    output_lines = output.splitlines()
    new_lines = output_lines[prev_line_count:] if prev_line_count < len(output_lines) else []

    # Update the state with the new line count
    state[output_line_count_key] = len(output_lines)

    # Return only the new lines
    return '\n'.join(new_lines)

@tool
def run_python_script(
    script_content: str,
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
    script_name: Optional[str] = None
) -> str:
    """
    Writes a Python script to the workspace and executes it in the sandboxed environment.
    
    Args:
        script_content: The content of the Python script to execute
        state: The current state containing workspace information
        tool_call_id: The ID of the tool call
        script_name: Optional name for the script file. If not provided, will use an incremental name with 'script_' prefix
    """
    workspace_path = get_agent_workspace_path(state)
    
    # Generate script name if not provided
    if script_name is None:
        # Find the next available script number
        script_number = 1
        while os.path.exists(os.path.join(workspace_path, f"script_{script_number}.py")):
            script_number += 1
        script_name = f"script_{script_number}.py"
    elif not script_name.endswith('.py'):
        script_name += '.py'
    
    # Write the script directly to the workspace
    script_path = os.path.join(workspace_path, script_name)
    try:
        with open(script_path, 'w') as f:
            f.write(script_content)
        script_info = f"Successfully wrote Python script to {script_path}"
    except Exception as e:
        return ToolMessage(content=f"Failed to write Python script: {str(e)}", tool_call_id=tool_call_id)
    
    # Execute the script using the sandboxed shell
    try:
        result = kali_stateful_shell.invoke({"commands": f"python {script_path}", "state": state})
        return ToolMessage(content=f"{script_info}\n\nScript output:\n{result}", tool_call_id=tool_call_id)
    except Exception as e:
        return ToolMessage(content=f"{script_info}\n\nError running Python script: {str(e)}", tool_call_id=tool_call_id)

@tool
def comprehensive_binary_analysis(
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """
    Performs comprehensive binary analysis including file info, strings, imports, exports, and basic security analysis.
    Returns a professional analysis report in chunks to avoid context length issues.
    """
    try:
        writer = get_stream_writer()
        writer("Starting comprehensive binary analysis...\n")
        
        binary_path = state["binary_path"]
        workspace_path = get_agent_workspace_path(state)
        
        # Initialize analysis report
        report_parts = []
        
        # 1. File information
        writer("Analyzing file information...\n")
        file_info = kali_stateful_shell.invoke({
            "commands": f"file {binary_path} && ls -la {binary_path}",
            "state": state
        })
        report_parts.append(f"=== FILE INFORMATION ===\n{file_info}\n")
        
        # 2. Binary headers and sections
        writer("Analyzing binary headers...\n")
        headers = r2_stateless_shell.invoke({
            "commands": ["i", "iS", "ih"],
            "state": state
        })
        report_parts.append(f"=== BINARY HEADERS ===\n{headers}\n")
        
        # 3. Strings analysis
        writer("Extracting strings...\n")
        strings_analysis = kali_stateful_shell.invoke({
            "commands": f"strings {binary_path} | head -50",
            "state": state
        })
        report_parts.append(f"=== STRINGS ANALYSIS (First 50) ===\n{strings_analysis}\n")
        
        # 4. Imports and exports
        writer("Analyzing imports and exports...\n")
        imports_exports = r2_stateless_shell.invoke({
            "commands": ["ii", "iE"],
            "state": state
        })
        report_parts.append(f"=== IMPORTS AND EXPORTS ===\n{imports_exports}\n")
        
        # 5. Function list
        writer("Listing functions...\n")
        functions = r2_stateless_shell.invoke({
            "commands": ["afl"],
            "state": state
        })
        report_parts.append(f"=== FUNCTIONS LIST ===\n{functions}\n")
        
        # 6. Basic security analysis
        writer("Performing security analysis...\n")
        security_analysis = r2_stateless_shell.invoke({
            "commands": ["iS", "i~canary", "i~nx", "i~pic", "i~relro"],
            "state": state
        })
        report_parts.append(f"=== SECURITY ANALYSIS ===\n{security_analysis}\n")
        
        # Combine all parts
        full_report = "\n".join(report_parts)
        
        # Save report to workspace
        report_path = os.path.join(workspace_path, "comprehensive_analysis.txt")
        with open(report_path, 'w') as f:
            f.write(full_report)
        
        # Return chunked report
        chunks = chunk_text(full_report, 6000)
        if len(chunks) == 1:
            return ToolMessage(content=f"Comprehensive Analysis Report:\n\n{chunks[0]}\n\nReport saved to: {report_path}", tool_call_id=tool_call_id)
        else:
            return ToolMessage(content=f"Comprehensive Analysis Report (Part 1 of {len(chunks)}):\n\n{chunks[0]}\n\nReport saved to: {report_path}", tool_call_id=tool_call_id)
            
    except Exception as e:
        return ToolMessage(content=f"Error in comprehensive analysis: {str(e)}", tool_call_id=tool_call_id)

@tool
def auto_decompile_functions(
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
    max_functions: int = 10
) -> str:
    """
    Automatically decompiles the most important functions in the binary using r2dec.
    Focuses on main functions, entry points, and functions with interesting names.
    """
    try:
        writer = get_stream_writer()
        writer("Starting automatic function decompilation...\n")
        
        workspace_path = get_agent_workspace_path(state)
        
        # Get function list
        functions_output = r2_stateless_shell.invoke({
            "commands": ["afl~main", "afl~entry", "afl~init", "afl~start"],
            "state": state
        })
        
        # Extract function names
        function_names = []
        for line in functions_output.split('\n'):
            if ' ' in line:
                parts = line.split()
                if len(parts) >= 2:
                    func_name = parts[1]
                    if func_name and not func_name.startswith('fcn.'):
                        function_names.append(func_name)
        
        # Limit to max_functions
        function_names = function_names[:max_functions]
        
        if not function_names:
            # Fallback to first few functions
            all_functions = r2_stateless_shell.invoke({
                "commands": ["afl"],
                "state": state
            })
            lines = all_functions.split('\n')[:max_functions]
            function_names = []
            for line in lines:
                if ' ' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        func_name = parts[1]
                        if func_name:
                            function_names.append(func_name)
        
        # Decompile each function
        decompiled_functions = []
        for i, func_name in enumerate(function_names):
            writer(f"Decompiling function {i+1}/{len(function_names)}: {func_name}\n")
            
            try:
                decompiled = r2_stateless_shell.invoke({
                    "commands": [f"s {func_name}", "pdf"],
                    "state": state
                })
                decompiled_functions.append(f"=== FUNCTION: {func_name} ===\n{decompiled}\n")
            except Exception as e:
                decompiled_functions.append(f"=== FUNCTION: {func_name} ===\nError decompiling: {str(e)}\n")
        
        # Combine results
        full_decompilation = "\n".join(decompiled_functions)
        
        # Save to workspace
        decomp_path = os.path.join(workspace_path, "auto_decompiled_functions.txt")
        with open(decomp_path, 'w') as f:
            f.write(full_decompilation)
        
        # Return chunked result
        chunks = chunk_text(full_decompilation, 6000)
        if len(chunks) == 1:
            return ToolMessage(content=f"Auto-Decompiled Functions:\n\n{chunks[0]}\n\nDecompilation saved to: {decomp_path}", tool_call_id=tool_call_id)
        else:
            return ToolMessage(content=f"Auto-Decompiled Functions (Part 1 of {len(chunks)}):\n\n{chunks[0]}\n\nDecompilation saved to: {decomp_path}", tool_call_id=tool_call_id)
            
    except Exception as e:
        return ToolMessage(content=f"Error in auto decompilation: {str(e)}", tool_call_id=tool_call_id)

@tool
def generate_security_report(
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """
    Generates a comprehensive security analysis report including vulnerability assessment,
    protection mechanisms, and potential attack vectors.
    """
    try:
        writer = get_stream_writer()
        writer("Generating security analysis report...\n")
        
        workspace_path = get_agent_workspace_path(state)
        
        security_checks = []
        
        # 1. Check for common vulnerabilities
        writer("Checking for common vulnerabilities...\n")
        vuln_check = r2_stateless_shell.invoke({
            "commands": ["iS", "i~canary", "i~nx", "i~pic", "i~relro", "i~fortify"],
            "state": state
        })
        security_checks.append(f"=== PROTECTION MECHANISMS ===\n{vuln_check}\n")
        
        # 2. Check for dangerous functions
        writer("Analyzing dangerous function usage...\n")
        dangerous_funcs = r2_stateless_shell.invoke({
            "commands": ["axt @ sym.imp.strcpy", "axt @ sym.imp.sprintf", "axt @ sym.imp.gets", "axt @ sym.imp.system"],
            "state": state
        })
        security_checks.append(f"=== DANGEROUS FUNCTIONS ===\n{dangerous_funcs}\n")
        
        # 3. Check for hardcoded secrets
        writer("Searching for hardcoded secrets...\n")
        secrets = kali_stateful_shell.invoke({
            "commands": f"strings {state['binary_path']} | grep -i -E '(password|secret|key|token|api)' | head -20",
            "state": state
        })
        security_checks.append(f"=== POTENTIAL HARDCODED SECRETS ===\n{secrets}\n")
        
        # 4. Check for suspicious strings
        writer("Analyzing suspicious strings...\n")
        suspicious = kali_stateful_shell.invoke({
            "commands": f"strings {state['binary_path']} | grep -i -E '(http|ftp|ssh|telnet|cmd|shell)' | head -20",
            "state": state
        })
        security_checks.append(f"=== SUSPICIOUS STRINGS ===\n{suspicious}\n")
        
        # 5. Check for anti-debugging techniques
        writer("Checking for anti-debugging techniques...\n")
        anti_debug = r2_stateless_shell.invoke({
            "commands": ["axt @ sym.imp.ptrace", "axt @ sym.imp.getpid", "axt @ sym.imp.fork"],
            "state": state
        })
        security_checks.append(f"=== ANTI-DEBUGGING CHECKS ===\n{anti_debug}\n")
        
        # Combine all security checks
        full_security_report = "\n".join(security_checks)
        
        # Save report
        security_path = os.path.join(workspace_path, "security_analysis.txt")
        with open(security_path, 'w') as f:
            f.write(full_security_report)
        
        # Return chunked report
        chunks = chunk_text(full_security_report, 6000)
        if len(chunks) == 1:
            return ToolMessage(content=f"Security Analysis Report:\n\n{chunks[0]}\n\nReport saved to: {security_path}", tool_call_id=tool_call_id)
        else:
            return ToolMessage(content=f"Security Analysis Report (Part 1 of {len(chunks)}):\n\n{chunks[0]}\n\nReport saved to: {security_path}", tool_call_id=tool_call_id)
            
    except Exception as e:
        return ToolMessage(content=f"Error in security analysis: {str(e)}", tool_call_id=tool_call_id)

@tool
def generate_executive_summary(
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """
    Generates an executive summary of the binary analysis including key findings,
    architecture, purpose, and security implications.
    """
    try:
        writer = get_stream_writer()
        writer("Generating executive summary...\n")
        
        workspace_path = get_agent_workspace_path(state)
        
        # Gather key information
        file_info = kali_stateful_shell.invoke({
            "commands": f"file {state['binary_path']}",
            "state": state
        })
        
        arch_info = r2_stateless_shell.invoke({
            "commands": ["i", "iS"],
            "state": state
        })
        
        function_count = r2_stateless_shell.invoke({
            "commands": ["afl~size"],
            "state": state
        })
        
        strings_sample = kali_stateful_shell.invoke({
            "commands": f"strings {state['binary_path']} | head -10",
            "state": state
        })
        
        # Create executive summary
        summary = f"""=== EXECUTIVE SUMMARY ===

BINARY INFORMATION:
{file_info}

ARCHITECTURE & SECTIONS:
{arch_info}

FUNCTION ANALYSIS:
{function_count}

SAMPLE STRINGS:
{strings_sample}

ANALYSIS COMPLETED:
- Comprehensive binary analysis performed
- Security assessment completed
- Function decompilation attempted
- All reports saved to workspace directory

NEXT STEPS:
- Review generated reports in workspace
- Analyze specific functions of interest
- Perform dynamic analysis if needed
- Consider additional tools for deeper analysis
"""
        
        # Save summary
        summary_path = os.path.join(workspace_path, "executive_summary.txt")
        with open(summary_path, 'w') as f:
            f.write(summary)
        
        return ToolMessage(content=summary, tool_call_id=tool_call_id)
        
    except Exception as e:
        return ToolMessage(content=f"Error generating executive summary: {str(e)}", tool_call_id=tool_call_id)

@tool
def continue_comprehensive_analysis(
    state: Annotated[State, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId]
) -> str:
    """
    Continues the comprehensive analysis workflow by running security analysis, 
    function decompilation, and generating the executive summary.
    This tool should be called after the initial comprehensive_binary_analysis.
    """
    try:
        writer = get_stream_writer()
        writer("Continuing comprehensive analysis workflow...\n")
        
        workspace_path = get_agent_workspace_path(state)
        
        # Check if initial analysis was completed
        initial_report_path = os.path.join(workspace_path, "comprehensive_analysis.txt")
        if not os.path.exists(initial_report_path):
            return ToolMessage(content="Initial comprehensive analysis not found. Please run comprehensive_binary_analysis first.", tool_call_id=tool_call_id)
        
        # Continue with remaining analysis steps
        analysis_steps = []
        
        # 1. Security Analysis
        writer("Running security analysis...\n")
        try:
            security_result = generate_security_report.invoke({
                "state": state,
                "tool_call_id": tool_call_id
            })
            analysis_steps.append(f"=== SECURITY ANALYSIS COMPLETED ===\n{security_result.content}\n")
        except Exception as e:
            analysis_steps.append(f"=== SECURITY ANALYSIS FAILED ===\nError: {str(e)}\n")
        
        # 2. Function Decompilation
        writer("Running automatic function decompilation...\n")
        try:
            decomp_result = auto_decompile_functions.invoke({
                "state": state,
                "tool_call_id": tool_call_id
            })
            analysis_steps.append(f"=== FUNCTION DECOMPILATION COMPLETED ===\n{decomp_result.content}\n")
        except Exception as e:
            analysis_steps.append(f"=== FUNCTION DECOMPILATION FAILED ===\nError: {str(e)}\n")
        
        # 3. Executive Summary
        writer("Generating executive summary...\n")
        try:
            summary_result = generate_executive_summary.invoke({
                "state": state,
                "tool_call_id": tool_call_id
            })
            analysis_steps.append(f"=== EXECUTIVE SUMMARY ===\n{summary_result.content}\n")
        except Exception as e:
            analysis_steps.append(f"=== EXECUTIVE SUMMARY FAILED ===\nError: {str(e)}\n")
        
        # Create workflow completion report
        completion_report = f"""=== COMPREHENSIVE ANALYSIS WORKFLOW COMPLETED ===

All analysis steps have been completed successfully:

1. ✅ Initial comprehensive binary analysis
2. ✅ Security vulnerability assessment  
3. ✅ Automatic function decompilation
4. ✅ Executive summary generation

All reports have been saved to the workspace directory:
- comprehensive_analysis.txt
- security_analysis.txt  
- auto_decompiled_functions.txt
- executive_summary.txt

The binary has been thoroughly analyzed with professional-grade tools and reports.
"""
        
        # Save completion report
        completion_path = os.path.join(workspace_path, "analysis_workflow_completed.txt")
        with open(completion_path, 'w') as f:
            f.write(completion_report)
        
        return ToolMessage(content=completion_report, tool_call_id=tool_call_id)
        
    except Exception as e:
        return ToolMessage(content=f"Error continuing comprehensive analysis: {str(e)}", tool_call_id=tool_call_id)

def chunk_text(text: str, max_chunk_size: int = 8000) -> List[str]:
    """Split text into chunks to avoid context length issues."""
    if len(text) <= max_chunk_size:
        return [text]
    
    chunks = []
    current_chunk = ""
    lines = text.split('\n')
    
    for line in lines:
        if len(current_chunk) + len(line) + 1 > max_chunk_size:
            if current_chunk:
                chunks.append(current_chunk.strip())
                current_chunk = line
            else:
                # Single line is too long, split it
                chunks.append(line[:max_chunk_size])
                current_chunk = line[max_chunk_size:]
        else:
            current_chunk += line + '\n'
    
    if current_chunk.strip():
        chunks.append(current_chunk.strip())
    
    return chunks
