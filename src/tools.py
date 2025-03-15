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
from src.utils import disassemble_function
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
        instance = cls(root_dir=os.path.join(
            workspace_path, config.DECOMPILED_FOLDER_NAME))
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

    if utils.count_tokens(assembly_code, state["model_name"]) > state["model_context_length"] // 2:
        raise ValueError("Disassembly too long for model context length.")

    return f"Disassembly of binary:\n\n{assembly_code}"


@tool
def disassemble_section(
    section_name: str,
    state: Annotated[State, InjectedState]
) -> str:
    """Disassemble a section of the binary at binary_path."""
    assembly_code = utils.disassemble_section(
        binary_path=state["binary_path"], section_name=section_name)

    if utils.count_tokens(assembly_code, state["model_name"]) > state["model_context_length"] // 2:
        raise ValueError("Disassembly too long for model context length.")

    return f"Disassembly of section {section_name}:\n\n{assembly_code}"


@tool
def disassemble_function(
    function_name: str,
    state: Annotated[State, InjectedState]
) -> str:
    """Disassemble a function from the binary at binary_path."""
    assembly_code = utils.disassemble_function(
        binary_path=state["binary_path"], function_name=function_name)

    if utils.count_tokens(assembly_code, state["model_name"]) > state["model_context_length"] // 2:
        raise ValueError("Disassembly too long for model context length.")

    return f"Disassembly of function {function_name}:\n\n{assembly_code}"
