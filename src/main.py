import os
import uuid
import json
import gradio as gr
from typing_extensions import Literal, Annotated
from langchain_core.messages import HumanMessage, SystemMessage, BaseMessage, AIMessage, ToolMessage, AIMessageChunk
from langchain_core.tools import tool
from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import START, END, StateGraph, MessagesState
from langgraph.prebuilt import ToolNode
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import InjectedState, InjectedStore
from langchain_core.runnables import RunnableConfig
import tiktoken
import asyncio

from src.utils import WORKSPACE_DIR, disassemble_binary
import src.tools as tools
from src.state import State

# Collect all tools
tools = [tools.summarize_assembly, tools.disassemble_binary, tools.disassemble_section] #, get_asm, run_gdb, run_ghidra, readfile, writefile]

tool_node = ToolNode(tools)

model_name = "gpt-4o-mini"

# Use the OpenAI model, bind it to the tools
model = ChatOpenAI(model=model_name, temperature=0, openai_api_key=os.getenv("OPENAI_API_KEY"), streaming=True).bind_tools(tools)

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

with gr.Blocks(css=CSS, title="Binary Analysis Agent") as demo:
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
    # upload_button = gr.UploadButton("Click to Upload a File", file_types=[".bin"], file_count="single")
    
    # Replace UploadButton with File component
    file_input = gr.File(
        label="Upload a Binary File",
        file_types=[".bin"],
        file_count="single",
        type="filepath"
    )

    # A Markdown component to display debug info
    debug_markdown = gr.Markdown(label="Debug Information", value="")

    def start_session(file, chatbot: gr.Chatbot):
        if file is None:
            return gr.update(visible=True), None, "Please upload a binary file."

        # Save the uploaded file to the workspace
        new_filepath = os.path.join(WORKSPACE_DIR, "uploaded_binary.bin")
        print(f"Saving file {file}")
        with open(new_filepath, "wb") as f:
            with open(file, "rb") as f2:
                f.write(f2.read())

        # Disassemble the binary
        disassembled_code = disassemble_binary(new_filepath, function_name=None, target_platform="mac")
        disassembled_path = os.path.join(WORKSPACE_DIR, "disassembled_code.asm")
        
        # Encode the text to get the list of tokens
        tokens = encoding.encode(disassembled_code)

        # Count the number of tokens
        num_tokens = len(tokens)
        print(f"Number of tokens: {num_tokens}")

        messages = []
        
        # Initialize state with binary and disassembled paths
        state = {
            "messages": messages,
            "binary_path": new_filepath,
            "disassembled_path": disassembled_path
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
            # Summarize the assembly code of the binary
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
        
        # Reset the chatbot
        chatbot.clear()
        
        return state, chatbot

    async def process_request(message, history, state, user_id):
        if not user_id:
            user_id = str(uuid.uuid4())

        config = {"configurable": {"thread_id": user_id}}

        if state is None:
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
        
        yield history, state, user_id, gr.Textbox(value="", interactive=True)
        
    
    file_input.upload(
        start_session,
        inputs=[file_input, chatbot],
        outputs=[gradio_state, chatbot]
    )

    gradio_msg.submit(
        process_request,
        inputs=[gradio_msg, chatbot, gradio_state, user_id],
        outputs=[chatbot, gradio_state, user_id, gradio_msg]
    )

    gr.Markdown("""
    **Instructions:**
    1. Upload your binary.
    2. Start a new session.
    3. Ask the agent to analyze or decompile the binary.
    4. Check the 'Debug Information' panel below the chat to see the raw messages, responses, and tool calls.
    """)

demo.launch()