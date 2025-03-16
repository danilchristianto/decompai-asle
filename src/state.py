from typing_extensions import Annotated, TypedDict
from langgraph.graph.message import AnyMessage, add_messages

class MessagesState(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]

class State(MessagesState):
    binary_path: str
    disassembled_path: str | None
    session_path: str | None
    model_name: str | None
    model_context_length: int | None