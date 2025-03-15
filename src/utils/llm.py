model_tokenizer = None

def get_context_length(
    model: str
) -> int:
    """Return the length of the context window for the specified model.
    Args:
        model (str): The model name.
    Returns:
        int: The length of the context window.
    """
    
    if "gpt-4o" in model:
        return 128e3
    elif "gemini-2.0" in model:
        return 1e6

def count_tokens(
    text: str,
    model_name: str | None = None
) -> int:
    """Return the number of tokens in the text.
    Args:
        text (str): The text.
    Returns:
        int: The number of tokens.
    """
    global model_tokenizer
    
    if model_tokenizer is None:
        import tiktoken
        model_tokenizer = tiktoken.encoding_for_model("gpt-4o-mini") # TODO: Get the tokenizer of the selected model
    
    return len(model_tokenizer.encode(text))
