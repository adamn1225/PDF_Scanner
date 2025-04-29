
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import fitz  # PyMuPDF
import pandas as pd
import shutil
from datetime import datetime
from pdf_analysis import analyze_pdf_structure


app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = './uploads'
QUARANTINE_FOLDER = './quarantine'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

@app.route('/')
def index():
    return send_from_directory('../frontend', 'index.html')

def scan_pdf(path):
    suspicious_blocks = 0
    total_blocks = 0
    metadata = {}
    page_count = 0
    encrypted = False
    is_modified = False
    has_suspicious_dates = False
    additional_metadata = {}
    structure_analysis = analyze_pdf_structure(path)
    is_suspicious = check_threat_intelligence(structure_analysis)

    try:
        doc = fitz.open(path)
        encrypted = doc.is_encrypted
        metadata = doc.metadata or {}
        page_count = doc.page_count

        # Extract additional metadata fields
        additional_metadata = {
            "title": metadata.get("title", "Unknown"),
            "subject": metadata.get("subject", "Unknown"),
            "keywords": metadata.get("keywords", "Unknown")
        }

        # Check if the PDF has been modified
        creation_date = metadata.get("creationDate", "Unknown")
        modification_date = metadata.get("modDate", "Unknown")
        if creation_date != "Unknown" and modification_date != "Unknown":
            is_modified = creation_date != modification_date

        # Check for suspicious dates (e.g., future dates)
        now = datetime.now()
        try:
            creation_datetime = datetime.strptime(creation_date[2:16], "%Y%m%d%H%M%S")
            modification_datetime = datetime.strptime(modification_date[2:16], "%Y%m%d%H%M%S")
            if creation_datetime > now or modification_datetime > now:
                has_suspicious_dates = "Future dates"
        except Exception:
            pass  # Ignore parsing errors for invalid dates

        # Inspect the PDF structure
        for page in doc:
            blocks = page.get_text("dict")["blocks"]
            total_blocks += len(blocks)
            for block in blocks:
                if block["type"] == 0 and "text" in block:
                    if any(c in block["text"] for c in ["<", ">"]):
                        suspicious_blocks += 1
        doc.close()

        # Analyze the PDF structure using pdf-parser.py
        structure_analysis = analyze_pdf_structure(path)

    except Exception as e:
        print(f"Error scanning {path}: {e}")

    file_size = os.path.getsize(path)

    # Prepare the result
    result = {
        "suspicious_blocks": suspicious_blocks,
        "total_blocks": total_blocks,
        "file_size_bytes": file_size,
        "file_size_kb": round(file_size / 1024, 2),
        "page_count": page_count,
        "encrypted": encrypted,
        "is_modified": is_modified,
        "Note": has_suspicious_dates,
        "created": metadata.get("creationDate", "Unknown"),
        "modified": metadata.get("modDate", "Unknown"),
        **additional_metadata,  # Include additional metadata fields
        "structure_analysis": structure_analysis,  # Include structure analysis
        "is_suspicious": is_suspicious,
    }

    # Print the result for debugging
    print(result)

    return result


def check_threat_intelligence(structure_analysis):
    suspicious_keywords = ['/JavaScript', '/Launch', '/OpenAction']
    for keyword in suspicious_keywords:
        if keyword in structure_analysis:
            return True
    return False

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        print("No file part in the request")
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if file.filename == '':
        print("No selected file")
        return jsonify({"error": "No file selected"}), 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    try:
        file.save(filepath)
        print(f"File saved to {filepath}")
    except Exception as e:
        print(f"Error saving file: {e}")
        return jsonify({"error": f"Error saving file: {e}"}), 500

    try:
        scan_result = scan_pdf(filepath)  # Get the full dictionary
        suspicious_count = scan_result["suspicious_blocks"]  # Extract suspicious_blocks
        print(f"Scanned file {file.filename}, suspicious blocks: {suspicious_count}")
    except Exception as e:
        print(f"Error scanning file: {e}")
        return jsonify({"error": f"Error scanning file: {e}"}), 500

    result = {
        "filename": file.filename,
        **scan_result  # Include all scan results in the response
    }

    if suspicious_count >= 10:
        try:
            shutil.move(filepath, os.path.join(QUARANTINE_FOLDER, file.filename))
            print(f"File moved to quarantine: {file.filename}")
        except Exception as e:
            print(f"Error moving file to quarantine: {e}")
            return jsonify({"error": f"Error moving file to quarantine: {e}"}), 500

    return jsonify(result)

@app.route('/batch-scan', methods=['POST'])
def batch_scan():
    results = []
    files = os.listdir(UPLOAD_FOLDER)
    for file in files:
        filepath = os.path.join(UPLOAD_FOLDER, file)
        suspicious_count = scan_pdf(filepath)
        results.append({"filename": file, "suspicious_blocks": suspicious_count})
        if suspicious_count >= 10:
            shutil.move(filepath, os.path.join(QUARANTINE_FOLDER, file))

    df = pd.DataFrame(results)
    df.to_csv('scan_results.csv', index=False)

    return jsonify(results)

if __name__ == "__main__":
    app.run(port=5000, debug=True)
