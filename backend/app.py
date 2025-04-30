
from flask import Flask, request, jsonify, send_from_directory, render_template
from flask_cors import CORS
import os
import fitz  # PyMuPDF
import pandas as pd
import shutil
from datetime import datetime
from pdf_analysis import analyze_pdf_structure
import logging
import hashlib
from pdf_obfuscation import scan_pdf_for_obfuscation

app = Flask(__name__, static_folder='static', static_url_path='/static')
CORS(app)

UPLOAD_FOLDER = './uploads'
QUARANTINE_FOLDER = './quarantine'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

@app.route("/")
def index():
    return render_template("index.html")

# Route to serve static files (optional, Flask serves static files automatically)
@app.route("/static/<path:path>")
def serve_static(path):
    return send_from_directory("static", path)

# Add other routes for your backend API as needed
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

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

        # Call the obfuscation scan
        obfuscation_results = scan_pdf_for_obfuscation(path)

    except Exception as e:
        logging.error(f"Error scanning {path}: {e}")

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
        **obfuscation_results  # Include obfuscation scan results
    }

    # Print the result for debugging
    logging.info(result)

    return result


def check_threat_intelligence(structure_analysis):
    suspicious_keywords = ['/JavaScript', '/Launch', '/OpenAction']
    for keyword in suspicious_keywords:
        if keyword in structure_analysis:
            return True
    return False

def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def test_calculate_file_hash():
    test_file = "test.pdf"
    with open(test_file, "wb") as f:
        f.write(b"Test content")
    expected_hash = hashlib.sha256(b"Test content").hexdigest()
    assert calculate_file_hash(test_file) == expected_hash

@app.route('/upload', methods=['POST'])
def upload_file():
    # Retrieve the file from the request
    file = request.files.get('file')  # Use .get() to avoid KeyError if 'file' is missing

    # Check if no file was uploaded
    if not file or file.filename == '':
        logging.error("No file selected")
        return jsonify({"error": "No file selected"}), 400

    # Check if the file is a PDF
    if not file.filename.lower().endswith('.pdf'):
        logging.error("Invalid file type")
        return jsonify({"error": "Only PDF files are allowed"}), 400

    # Save the file to the upload folder
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    try:
        file.save(filepath)
        logging.info(f"File saved to {filepath}")
    except Exception as e:
        logging.error(f"Error saving file: {e}")
        return jsonify({"error": f"Error saving file: {e}"}), 500

    # Scan the file for suspicious content
    try:
        scan_result = scan_pdf(filepath)  # Get the full dictionary
        suspicious_count = scan_result["suspicious_blocks"]  # Extract suspicious_blocks
        logging.info(f"Scanned file {file.filename}, suspicious blocks: {suspicious_count}")
    except Exception as e:
        logging.error(f"Error scanning file: {e}")
        return jsonify({"error": f"Error scanning file: {e}"}), 500

    # Prepare the result
    result = {
        "filename": file.filename,
        **scan_result  # Include all scan results in the response
    }

    # Move the file to the quarantine folder if it is suspicious
    if suspicious_count >= 10:
        try:
            shutil.move(filepath, os.path.join(QUARANTINE_FOLDER, file.filename))
            logging.info(f"File moved to quarantine: {file.filename}")
        except Exception as e:
            logging.error(f"Error moving file to quarantine: {e}")
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
