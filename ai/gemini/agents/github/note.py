from langchain_core.tools import tool

@tool(args_schema={
    "note": {
        "type": "string",
        "description": "The text note to save"
    }
})
def note_tool(note: str):
    """
    save a note to a local file

    Args:
        note: the text note to save
    """
    with open('notes.txt', 'a') as f:
        f.write(f"{note}\n")
