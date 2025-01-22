import os
import uuid
import json
import gradio as gr
from typing_extensions import Literal, Annotated
from langchain_core.messages import HumanMessage, SystemMessage, BaseMessage, AIMessage, ToolMessage, AIMessageChunk
from langchain_core.tools import tool
from langchain_core.runnables import RunnableConfig
from langchain.load.dump import dumps
from langchain.load.load import loads
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import START, END, StateGraph, MessagesState
from langgraph.prebuilt import ToolNode
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import InjectedState, InjectedStore
from langchain_community.agent_toolkits import FileManagementToolkit
from langchain_community.tools import CopyFileTool, DeleteFileTool, FileSearchTool, MoveFileTool, ReadFileTool, WriteFileTool, ListDirectoryTool
import tiktoken
import asyncio
import shutil

import src.config as config
from src.utils import disassemble_binary
import src.utils as utils
import src.tools as tools
from src.state import State

# Collect all tools
custom_tools = [tools.summarize_assembly, tools.disassemble_binary, tools.disassemble_section] #, tools.get_decompiled_directory_tree, tools.read_decompiled_files, tools.write_decompiled_files] #, get_asm, run_gdb, run_ghidra, readfile, writefile]
# file_management_tools = [tools.write_file] # FileManagementToolkit(root_dir=config.WORKSPACE_ROOT+"/decompiled").get_tools()]
file_management_tools = [tools.create_tool_function(tool) for tool in [WriteFileTool]]


all_tools = custom_tools + file_management_tools

tool_node = ToolNode(all_tools)

model_name = "gpt-4o-mini"

# Use the OpenAI model, bind it to the tools
model = ChatOpenAI(model=model_name, temperature=0, openai_api_key=os.getenv("OPENAI_API_KEY"), streaming=True).bind_tools(all_tools)

encoding = tiktoken.encoding_for_model(model_name)

# Define the function that calls the model
async def call_model(state: State, config: RunnableConfig):
    
    messages = state['messages']
    
    print(f"Messages: {messages}")
    # input("Press Enter to call the model...")
    
    response = await model.ainvoke(messages, config)
    
    # messages.append(AIMessage(content=response.content))
    print(f"Model response: {response}")
    # return state
    state["messages"] = response
    return state


# Define a function to request feedback
def request_feedback(state: State):
    """Prompt the user for feedback."""
    print("Requesting user feedback...")
    # Simulate user feedback
    feedback = input("Please provide your feedback (or press Enter to skip): ")
    if feedback:
        state['messages'].append(HumanMessage(content=f"User Feedback: {feedback}"))
    return {"messages": state['messages']}


# Modify the conditional logic to decide when to ask for feedback
def should_continue_or_feedback(state: State) -> Literal["tools", "feedback", END]:
    messages = state['messages']
    last_message = messages[-1]
    if last_message.tool_calls:
        return "tools"
    elif "critical_step" in last_message.content.lower():
        return "feedback"
    print("\nFinished the conversation.")
    return END

def save_state(state: State):
    workspace_path = state.get("workspace_path")
    if not workspace_path:
        print("No workspace path found. Cannot save conversation history.")
        print(state)
        return
    history_file = os.path.join(workspace_path, "state.json")
    with open(history_file, "w") as hf:
        hf.write(dumps(state))
    print(f"Conversation history saved to {history_file}")

def load_state(workspace_path: str) -> dict:
    """
    Load the state from a JSON file if it exists. Otherwise, return a new state.
    """
    state_file = os.path.join(workspace_path, "state.json")
    if os.path.exists(state_file):
        with open(state_file, "r") as f:
            state = loads(f.read())
        return state
    else:
        # Return a default state structure if no previous state exists
        return None
    
def erase_workspace(workspace_path: str):
    if os.path.exists(workspace_path):
        # Ensure the path starts with "decompile_workspace/"
        if not workspace_path.startswith("decompile_workspace/"):
            raise ValueError(f"Invalid workspace path: {workspace_path}")
        else:
            # Delete the decompiled folder
            decompiled_path = os.path.join(workspace_path, config.DECOMPILED_FOLDER_NAME)
            if os.path.exists(decompiled_path):
                shutil.rmtree(decompiled_path)
                
            # Delete the state.json file if it exists
            state_file = os.path.join(workspace_path, "state.json")
            if os.path.exists(state_file):
                os.remove(state_file)
            
            # Delete the .asm file if it exists
            asm_file = os.path.join(workspace_path, "disassembled_code.asm")
            if os.path.exists(asm_file):
                os.remove(asm_file)
    else:
        print(f"Workspace not found at {workspace_path}")

# Create the graph
workflow = StateGraph(State)
workflow.add_node("agent", call_model)
workflow.add_node("tools", tool_node)
workflow.add_node("feedback", request_feedback)

workflow.add_edge(START, "agent")
workflow.add_conditional_edges("agent", should_continue_or_feedback)
workflow.add_edge("tools", "agent")
workflow.add_edge("feedback", "agent")

checkpointer = MemorySaver()
graph = workflow.compile(checkpointer=checkpointer)

# graph.get_graph().draw_mermaid_png(output_file_path="graph.png")

########################################
# Gradio Interface
########################################

CSS = """
.contain { display: flex; flex-direction: column; }
#component-0 { height: 100%; }
#chatbot { flex-grow: 1; overflow: auto;}
"""

def demo_block():
    gr.Markdown("""
    # Binary Analysis and Decompilation Agent
    
    This agent can:
    - Analyze a binary, list its functions, run gdb, run ghidra, etc.
    - Decompile functions step by step.

    Upload a binary and type your request. The agent will use tools as needed.
    """)

    memory = MemorySaver()
    
    chatbot = gr.Chatbot(
        show_copy_button=False,
        show_share_button=True,
        label="Binary Analysis Assistant",
        elem_id="chatbot",
        type="messages"
    )
    gradio_msg: gr.Textbox = gr.Textbox(
        placeholder="Ask something about the binary...",
        container=False,
        scale=7
    )
    user_id = gr.State(None)
    gradio_state = gr.State(None)  # {"messages": [...BaseMessage...]}
    
    # Replace UploadButton with File component
    file_input = gr.File(
        label="Upload a Binary File",
        file_types=[".bin"],
        file_count="single",
        type="filepath"
    )
    
    erase_button = gr.Button("Erase Session", visible=False)
    
    def start_session(file, chatbot: gr.Chatbot, erase_button: gr.Button):
        if file is None:
            return gr.update(visible=True), None, "Please upload a binary file."
        
        erase_button = gr.Button(erase_button, visible=True)

        # Compute hash and create a unique workspace
        workspace_path = utils.create_workspace_for_binary(file)
        binary_filename = os.path.basename(file)
        binary_path = os.path.join(workspace_path, binary_filename)
        
        # Initialize or load conversation history if it exists
        state = load_state(workspace_path)
        if state is None:
            # No conversation history found for this binary, create a new state
            messages = []
            
            system_prompt ="""You are a binary analysis and decompilation agent. Your task is to analyze and decompile the binary provided by the user into separate files within a subfolder in the binary's workspace. You have access to tools that let you read from and write to this subfolder, as well as list its file tree. Use only paths relative to the workspace folder to access files.

            Guidelines:
            - If the user does not specify an instruction, start iterating to decompile the entire binary.
            - Use the file tools to manage decompiled code.
            - Maintain a summary of the decompiled codebase and keep track of the decompiled folder tree in your context to avoid redundant decompilation of the same functions or sections.

            Now, begin by analyzing and decompiling the binary step by step until the entire binary is decompiled.
            """
            # - Always operate within the 'decompiled' subfolder of the binary's workspace, and do not access files outside of this folder.

            messages.append(SystemMessage(content=system_prompt))

            # Disassemble the binary
            disassembled_code = disassemble_binary(binary_path, function_name=None, target_platform="mac")
            disassembled_path = os.path.join(workspace_path, "disassembled_code.asm")
            
            # Save disassembled code in the workspace
            with open(disassembled_path, "w") as f:
                f.write(disassembled_code)

            # Encode the text to get the list of tokens
            tokens = encoding.encode(disassembled_code)
            num_tokens = len(tokens)
            print(f"Number of tokens: {num_tokens}")

            # Initialize state with binary and disassembled paths
            state = {
                "messages": messages,
                "binary_path": binary_path,
                "disassembled_path": disassembled_path,
                "workspace_path": workspace_path
            }
        
            if num_tokens <= 64000: # Half of the token limit
                # Add the disassembled code to the message history
                
                tool_call_message = AIMessage(
                    content="The binary is small enough to disassemble. Disassembling the binary...",
                    tool_calls=[
                        {
                            "name": "disassemble_binary",
                            "args": {},
                            "id": f"{uuid.uuid4()}",
                            "type": "tool_call",
                        }
                    ],
                )
                messages.append(tool_call_message)
                
                disassembled_msg = ToolMessage(content=f"Disassembly of binary:\n\n{disassembled_code}", tool_call_id=tool_call_message.tool_calls[0]["id"])
                messages.append(disassembled_msg)
            else:
                tool_call_message = AIMessage(
                    content="The binary is too large to get the full disassembly. Summarizing the assembly code...",
                    tool_calls=[
                        {
                            "name": "summarize_assembly",
                            "args": {},
                            "id": f"{uuid.uuid4()}",
                            "type": "tool_call",
                        }
                    ],
                )
                messages.append(tool_call_message)
                messages.extend(tool_node.invoke(state)["messages"])
        
            save_state(state)
        
        # Reset the chatbot
        chatbot.clear()
            
        # Load messages into the chatbot
        print(state["messages"])
        for msg in state["messages"]:
            if isinstance(msg, HumanMessage):
                chatbot.append({"role": "user", "content": msg.content})
            elif isinstance(msg, AIMessage):
                chatbot.append({"role": "assistant", "content": msg.content})
            # elif isinstance(msg, SystemMessage):
            #     chatbot.append({"role": "assistant", "content": msg.content})
            # elif isinstance(msg, ToolMessage):
            #     chatbot.append({"role": "assistant", "content": msg.content, "tool_call_id": msg.tool_call_id})
        
        return state, chatbot, erase_button
    
    def erase_session(state, chatbot):
        workspace_path = state.get("workspace_path")
        if not workspace_path:
            print("No workspace path found. Cannot erase the session.")
            return state, chatbot
        erase_workspace(workspace_path)
        chatbot.clear()
        return start_session(state["binary_path"], chatbot, erase_button)

    async def process_request(message, history, state, user_id):
        if not user_id:
            user_id = str(uuid.uuid4())

        config = {"configurable": {"thread_id": user_id}}

        if state is None:
            print("State is None. Starting a new session...")
            state = {"messages": []}

        # Check if the binary path exists in the state
        if "binary_path" not in state:
            yield history, state, user_id, "Please upload a binary first."
            return

        state["messages"].append(HumanMessage(content=message))
        history.append({
            "role": "user",
            "content": message
        })
        
        first = True
        async for tuple in graph.astream(state, config=config, stream_mode=["messages", "values"]):
            
            stream_mode, data = tuple
            if stream_mode == "values":
                state = data
            else:
                msg, metadata = data
            
                # if msg.content and not isinstance(msg, HumanMessage):
                #     print(msg.content, end="|", flush=True)

                if isinstance(msg, AIMessageChunk):
                    if first:
                        gathered = msg
                        first = False
                        history.append({
                            "role": "assistant",
                            "content": gathered.content
                        })
                    else:
                        gathered = gathered + msg
                        history[-1]["content"] += msg.content

                    yield history, state, user_id, gr.Textbox(value="", interactive=False)
        else:
            save_state(state)
        yield history, state, user_id, gr.Textbox(value="", interactive=True)
        
    
    file_input.upload(
        start_session,
        inputs=[file_input, chatbot, erase_button],
        outputs=[gradio_state, chatbot, erase_button]
    )

    gradio_msg.submit(
        process_request,
        inputs=[gradio_msg, chatbot, gradio_state, user_id],
        outputs=[chatbot, gradio_state, user_id, gradio_msg]
    )
    
    # Link the erase_button to the erase_history function
    erase_button.click(
        erase_session,
        inputs=[gradio_state, chatbot],
        outputs=[gradio_state, chatbot]
    )


    gr.Markdown("""
    **Instructions:**
    1. Upload your binary.
    2. Start a new session.
    3. Ask the agent to analyze or decompile the binary.
    4. Check the 'Debug Information' panel below the chat to see the raw messages, responses, and tool calls.
    """)

if __name__ == "__main__":
    with gr.Blocks(css=CSS, title="Binary Analysis Agent") as demo:
        demo_block()
    demo.launch()