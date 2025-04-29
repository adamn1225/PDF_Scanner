# This code scans a PDF file for obfuscation patterns, generates a forensic report, and saves it as a JSON file.
import re
import sys
import json
import hashlib
import datetime
from PyPDF2 import PdfReader

def calculate_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def scan_pdf_for_obfuscation(file_path):
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
                    "sample": hex_blocks[:3]  # Show first 3 hex samples
                })

            if "/Font" in page_text or "/FlateDecode" in page_text:
                suspicious_font_count += 1
                findings.append({
                    "page": i + 1,
                    "type": "font_or_compression_reference",
                    "details": "/Font or /FlateDecode found"
                })

    except Exception as e:
        print(f"Error reading PDF: {e}")
        return

    report = {
        "scan_timestamp": scan_timestamp,
        "file_path": file_path,
        "file_sha256": file_hash,
        "total_pages": total_objects_scanned,
        "suspicious_hex_blocks": suspicious_hex_count,
        "suspicious_font_references": suspicious_font_count,
        "findings": findings,
        "verdict": "LIKELY TAMPERED" if suspicious_hex_count > 5 or suspicious_font_count > 2 else "LIKELY CLEAN"
    }

    # Save JSON report
    output_filename = file_path.split("/")[-1].replace(".pdf", "") + "_forensic_report.json"
    with open(output_filename, "w") as f:
        json.dump(report, f, indent=2)

    print(f"\n Chain-of-custody forensic report saved to: {output_filename}\n")
    print(f"Summary Verdict: {report['verdict']}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pdf_obfuscation_scanner_with_chain.py <path_to_pdf>")
    else:
        scan_pdf_for_obfuscation(sys.argv[1])

