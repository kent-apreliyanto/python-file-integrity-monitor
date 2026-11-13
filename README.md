# File Integrity Monitor (FIM)

A lightweight, cryptographic File Integrity Monitor (FIM) built with Python. This cybersecurity Blue Team tool monitors a specific directory and alerts administrators to any unauthorized file modifications, creations, or deletions.

## Features
- **SHA-256 Cryptography:** Uses advanced cryptographic hashing to generate unique fingerprints for every file.
- **Memory-Safe Scanning:** Reads files in 4KB chunks, ensuring the script can safely hash massive files without crashing the system RAM.
- **Intrusion Detection:** Accurately flags `MODIFIED`, `NEW`, or `DELETED` files by comparing current states against a trusted JSON baseline.
- **CLI Interface:** Built with `argparse` for easy terminal execution with `build` and `scan` modes.

## Technology Stack
- Python 3
- `hashlib` (Cryptography)
- `os` & `json` (System traversal and state management)
- `argparse` (Command-line interface)

## How to Run
1. Clone this repository.
2. Build the trusted security baseline for a target directory (e.g., `./rahasia`):
   ```bash
   python fim.py build ./rahasia
3. For Scanning folder:
   ```bash
   python fim.py scan ./rahasia

## Security Notice
This tool is designed for educational purposes, system administration, and authorized security auditing.