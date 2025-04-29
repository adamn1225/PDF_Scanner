## PDF Forensic Scanner (Zero Dependency Edition)

## Usage:

### What It Does:
✔ Scans each PDF for suspicious content (hex blocks, custom fonts, stream tampering)
✔ Flags suspicious PDFs and moves them into /quarantine
✔ Saves a report JSON file into /reports
✔ Does not require pandas, numpy, or any big libraries. 100% lightweight.

### Requirements:
- Python 3.8+
- No external packages needed

### Tips:
- Run on copies of files, not originals.
- Review quarantine/ folder manually for anomalies.
- This scanner won't catch *everything* — it's a first pass.