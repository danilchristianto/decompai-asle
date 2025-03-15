
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
