# This script scans a PDF file for signs of obfuscation or tampering.
# It looks for long hexadecimal strings and suspicious font references.
# If it finds more than a certain threshold, it flags the PDF as potentially tampered.
import re
import sys
from PyPDF2 import PdfReader

def scan_pdf_for_obfuscation(file_path):
    suspicious_hex_count = 0
    suspicious_font_count = 0
    total_objects_scanned = 0

    try:
        reader = PdfReader(file_path)
        for i, page in enumerate(reader.pages):
            page_text = page.extract_text() or ""
            total_objects_scanned += 1

            # Look for long hex strings like <00FE12...>
            hex_blocks = re.findall(r'<[0-9A-Fa-f]{8,}>', page_text)
            suspicious_hex_count += len(hex_blocks)

            # Look for font references, common in obfuscated PDFs
            if "/Font" in page_text or "/FlateDecode" in page_text:
                suspicious_font_count += 1

    except Exception as e:
        print(f"Error reading PDF: {e}")
        return

    print(f"Scan results for {file_path}:")
    print(f"  - Total pages scanned: {total_objects_scanned}")
    print(f"  - Hex blocks found: {suspicious_hex_count}")
    print(f"  - Suspicious font encoding references: {suspicious_font_count}")

    # Heuristic: If >5 hex blocks or fonts, HIGHLY suspicious
    if suspicious_hex_count > 5 or suspicious_font_count > 2:
        print("\n  This PDF is LIKELY TAMPERED or OBFUSCATED.\n")
    else:
        print("\n  This PDF appears clean.\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pdf_obfuscation_scanner.py <path_to_pdf>")
    else:
        scan_pdf_for_obfuscation(sys.argv[1])
