import os
from langchain_core.tools import Tool

def save_note(note: str) -> str:
    """Save a note to a local file."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    notes_path = os.path.join(current_dir, 'notes.txt')
    
    try:
        with open(notes_path, 'a') as f:
            f.write(f"{note}\n")
    except Exception as e:
        print(f"Error saving note: {e}")
        return f"Failed to save note: {e}"

note_tool = Tool(
    name="note_tool",
    description="Save a note to a local file. Input should be the text to save.",
    func=save_note
)

if __name__ == "__main__":
    # Test the tool directly
    result = save_note("This is a direct test note")
    print(result)
