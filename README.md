# DecompAI - Binary Analysis and Decompilation Agent

A professional binary reverse engineering and decompilation agent that provides comprehensive analysis with minimal user intervention.

## Features

### 🚀 **Automatic Comprehensive Analysis**
- **Zero User Intervention**: Upload a binary and get professional results automatically
- **Complete Workflow**: File analysis → Function decompilation → Executive summary
- **Chunked Output**: Large reports are automatically split to avoid context length issues
- **Professional Reports**: All analysis saved to workspace for easy review

### 🛠️ **Analysis Tools**
- **Comprehensive Binary Analysis**: File info, headers, strings, imports/exports, functions
- **Automatic Function Decompilation**: Key functions decompiled using r2dec
- **Executive Summary Generation**: Professional summary for stakeholders
- **Radare2 Integration**: Stateful and stateless shell access
- **Ghidra Integration**: Post-analysis scripts and function decompilation
- **Kali Linux Environment**: Sandboxed shell for general tools

### 📊 **Generated Reports**
- `comprehensive_analysis.txt` - Complete binary overview
- `auto_decompiled_functions.txt` - Decompiled key functions
- `executive_summary.txt` - Professional summary
- `analysis_workflow_completed.txt` - Workflow completion status

## Quick Start

1. **Upload Binary**: Simply upload any binary file through the interface
2. **Automatic Analysis**: The system automatically runs comprehensive analysis
3. **Review Results**: All reports are saved to the workspace directory
4. **Professional Output**: Get actionable insights and security recommendations

## Workflow

### Automatic Analysis Pipeline
1. **File Upload** → Binary copied to session directory
2. **Comprehensive Analysis** → File info, headers, strings, imports/exports
3. **Function Decompilation** → Key functions automatically decompiled
4. **Executive Summary** → Professional summary generated
5. **Results Saved** → All reports available in workspace

### Minimal User Intervention
- No manual tool selection required
- No step-by-step prompting
- Professional-grade analysis automatically performed
- Results chunked to avoid large text issues
- All files saved for easy access

## Environment Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Set up environment variables
export GEMINI_API_KEY=your_api_key_here
export LLM_MODEL=gemini-1.5-flash

# Run the application
python run.py
```

## API Key Configuration

The system supports both `GEMINI_API_KEY` and `GOOGLE_API_KEY` environment variables for flexibility.

## Architecture

- **LangGraph**: Workflow orchestration
- **Gradio**: Web interface
- **Radare2**: Binary analysis and decompilation
- **Ghidra**: Advanced decompilation
- **Kali Linux**: Sandboxed analysis environment

## Professional Use Cases

- **Reverse Engineering**: Understanding binary behavior and structure
- **Software Analysis**: Code review and functionality analysis
- **Malware Analysis**: Understanding malicious binary behavior
- **Software Auditing**: Code review and functionality evaluation
- **Research**: Binary analysis for academic and research purposes

## Output Format

All analysis results are provided in professional, chunked format:
- **Executive Summary**: High-level findings and recommendations
- **Technical Details**: Comprehensive technical analysis
- **Function Analysis**: Decompiled code with explanations
- **Binary Structure**: Architecture and section analysis
- **Actionable Insights**: Professional recommendations

The system is designed for professional use with minimal setup and maximum automation.
