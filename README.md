# DecompAI: Binary Analysis and Decompilation Agent

This repository contains a Gradio application that serves as a binary analysis and decompilation agent. The agent can analyze binaries, list their functions, run debugging and reverse engineering tools, and decompile functions step by step using an AI-driven workflow integrated with various tools.

## Features

- **Binary Analysis**: Analyze a binary to list functions, disassemble code, or summarize assembly.
- **Decompilation Assistance**: Step-by-step decompilation of binary functions.
- **Tool Integration**: Uses tools such as `objdump`, `gdb`, and Ghidra for binary inspection and debugging.
- **Interactive Feedback**: Requests user feedback during critical steps.
- **Gradio Interface**: Web-based interface for uploading binaries and interacting with the agent.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/louisgthier/decompai.git
cd decompai
```

2. Install required Python packages:
```bash
pip install -r requirements.txt
```

3. Ensure Docker is installed and running on your machine, as some operations (e.g., cross-compilation, disassembly) use Docker containers.

## Directory Structure

```plaintext
.
├── src/
│   ├── main.py         [Main Gradio app logic and UI components]
│   ├── state.py        [State definitions for the agent’s workflow]
│   ├── tools.py        [Tool functions for binary analysis and decompilation]
│   ├── utils.py        [Utility functions for compilation, disassembly, and assembly summarization]
    └── requirements.txt     [Dependencies required for the project]
├── run.py               [Script to run the Gradio app with or without hot reload]

```

## Running the Application

To start the Gradio app, you can use the following commands:

- **Standard Run**:  

    ```bash
    python run.py
    ```

- **With Hot Reload (Gradio CLI)**:  

    ```bash
    gradio run.py
    ```

This setup allows you to run the app normally or with automatic hot reload during development.

## Usage

1. Open the application in your browser (Gradio will provide a local URL).
2. **Upload a Binary File**: Use the file upload component to select and upload a binary.
3. **Start a Session**: After uploading, the agent will disassemble or summarize the binary based on its size.
4. **Interact with the Agent**: Use the chat interface to ask questions about the binary, request decompilation steps, or analyze functions.
5. **Review Debug Information**: Check the "Debug Information" panel to inspect raw messages, responses, and tool calls.

## Example Commands

- **Summarize Assembly**: Ask the agent to provide a summary of the assembly code.
- **Disassemble Section**: Request the disassembly of a specific section using appropriate commands.
- **Run GDB/Ghidra**: Execute GDB commands or initiate Ghidra analysis through the chat interface.

## Contributing

Contributions are welcome! Please fork the repository, make changes, and submit a pull request.

## License

This project is licensed under the MIT License.