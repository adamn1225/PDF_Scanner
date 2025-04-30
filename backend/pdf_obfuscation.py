import re
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
        return {"error": f"Error reading PDF: {e}"}

    # Return the results as a dictionary
    return {
        "total_objects_scanned": total_objects_scanned,
        "suspicious_hex_count": suspicious_hex_count,
        "suspicious_font_count": suspicious_font_count,
        "is_obfuscated": suspicious_hex_count > 5 or suspicious_font_count > 2
    }