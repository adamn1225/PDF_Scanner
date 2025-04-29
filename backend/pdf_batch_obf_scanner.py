
import re
import sys
import json
import os
import hashlib
import datetime
from PyPDF2 import PdfReader

def calculate_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def scan_single_pdf(file_path, output_dir):
    suspicious_hex_count = 0
    suspicious_font_count = 0
    total_objects_scanned = 0
    findings = []

    file_hash = calculate_file_hash(file_path)
    scan_timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    try:
        reader = PdfReader(file_path)
        for i, page in enumerate(reader.pages):
            page_text = page.extract_text() or ""
            total_objects_scanned += 1

            hex_blocks = re.findall(r'<[0-9A-Fa-f]{8,}>', page_text)
            if hex_blocks:
                suspicious_hex_count += len(hex_blocks)
                findings.append({
                    "page": i + 1,
                    "type": "hex_block",
                    "count": len(hex_blocks),
                    "sample": hex_blocks[:3]
                })

            if "/Font" in page_text or "/FlateDecode" in page_text:
                suspicious_font_count += 1
                findings.append({
                    "page": i + 1,
                    "type": "font_or_compression_reference",
                    "details": "/Font or /FlateDecode found"
                })

    except Exception as e:
        print(f"Error reading PDF {file_path}: {e}")
        return None

    report = {
        "scan_timestamp": scan_timestamp,
        "file_name": os.path.basename(file_path),
        "file_path": file_path,
        "file_sha256": file_hash,
        "total_pages": total_objects_scanned,
        "suspicious_hex_blocks": suspicious_hex_count,
        "suspicious_font_references": suspicious_font_count,
        "findings": findings,
        "verdict": "LIKELY TAMPERED" if suspicious_hex_count > 5 or suspicious_font_count > 2 else "LIKELY CLEAN"
    }

    output_filename = os.path.join(output_dir, os.path.basename(file_path).replace(".pdf", "_forensic_report.json"))
    with open(output_filename, "w") as f:
        json.dump(report, f, indent=2)

    print(f" {os.path.basename(file_path)} → {report['verdict']} → Report saved to {output_filename}")
    return report

def scan_pdf_folder(folder_path):
    output_dir = os.path.join(folder_path, "forensic_reports")
    os.makedirs(output_dir, exist_ok=True)

    pdf_files = [f for f in os.listdir(folder_path) if f.lower().endswith('.pdf')]
    if not pdf_files:
        print("No PDF files found in the folder.")
        return

    print(f"🔍 Found {len(pdf_files)} PDFs. Starting scan...\n")
    for pdf_file in pdf_files:
        full_path = os.path.join(folder_path, pdf_file)
        scan_single_pdf(full_path, output_dir)

    print(f"\n All reports saved to {output_dir}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pdf_batch_obfuscation_scanner.py <path_to_folder_with_pdfs>")
    else:
        scan_pdf_folder(sys.argv[1])

# This script scans all PDF files in a specified folder for signs of obfuscation or tampering.