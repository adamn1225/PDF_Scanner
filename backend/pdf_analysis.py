import subprocess

def analyze_pdf_structure(path):
    try:
        result = subprocess.run(
            ["./pdf-parser.py", path],
            capture_output=True,
            text=True
        )
        output = result.stdout.strip()
        print(f"PDF Parser Output: {output}")  # Debug print
        return output if output else "No structure analysis available"
    except Exception as e:
        print(f"Error analyzing PDF structure: {e}")
        return "Error analyzing PDF structure"