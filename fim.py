import os
import hashlib
import json
import argparse
from datetime import datetime

BASELINE_FILE = "baseline.json"

def get_file_hash(filepath: str) -> str:
    """Calculate the SHA-256 hash of a file in chunks."""
    sha256_hash = hashlib.sha256()
    try: 
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return "ERROR"
    
def build_baseline(target_dir: str):
    """Scans the directory and creates a trusted baseline database."""
    baseline_data = {}
    print(f"--- Building Security Baseline for: {target_dir} ---")
    
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            filepath = os.path.join(root, file)
            file_hash = get_file_hash(filepath)
            
            if file_hash != "ERROR":
                baseline_data[filepath] = file_hash
        
    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline_data, f, indent=4)
        
    print(f"[+] Successfully saved {len(baseline_data)} file hashes to {BASELINE_FILE}")
    
def scan_directory(target_dir: str):
    """Compares current directory state against the trusted baseline."""
    print(f"---Scanning Directory: {target_dir} ---")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if not os.path.exists(BASELINE_FILE):
        print("[-] Baseline file not found. Please run 'build' mode first.")
        return
    
    with open(BASELINE_FILE, "r") as f:
        baseline_data = json.load(f)
        
    current_data ={}
    for root, dirs, files in os.walk(target_dir):
        for file in files:
            filepath = os.path.join(root, file)
            current_hash = get_file_hash(filepath)
            if current_hash != "ERROR":
                current_data[filepath] = current_hash
    print("\n--- INTRUSION DETECTION REPORT")
    alerts = 0
    
    for filepath, current_hash in current_data.items():
        if filepath not in baseline_data:
            print(f"[!] NEW FILE DETECTED:      {filepath}")
            alerts += 1
        elif current_hash != baseline_data[filepath]:
            print(f"[!] MODIFIED FILE DETECTED: {filepath}")
            alerts += 1
    
    for filepath in baseline_data:
        if filepath not in current_data:
            print(f"[!] DELETED FILE DETECTED:      {filepath}")
            alerts += 1
            
    if alerts == 0:
        print("[+] System is secure. No unautorized changes detected.")
    else:
        print(f"[-] WARNING: {alerts} integrity violation(s) found!")
    
    print("--- Scan Completed ---")
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File Integrity Monitor (FIM) - CyberSecurity Auditing Tool")
    parser.add_argument("mode", choices=["build", "scan"], help="Execution mode: 'build' to create trusted baseline, 'scan' to detect changes")
    parser.add_argument("directory", help="The target directory path to monitor")
    
    args = parser.parse_args()
    
    if args.mode == "build":
        build_baseline(args.directory)
    elif args.mode == "scan":
        scan_directory(args.directory)

        