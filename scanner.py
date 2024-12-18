import os
import sys
import time
import json
import datetime
import argparse
from virustotal_python import Virustotal
import openai
from dotenv import load_dotenv
from scan_tracker import ScanTracker

# Load API keys from .env file
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Initialize API clients
vtotal = Virustotal(API_KEY=VT_API_KEY)
openai.api_key = OPENAI_API_KEY

def upload_and_get_report(file_path, scan_tracker, test_mode=False):
    """Uploads a file to VirusTotal and retrieves the analysis report."""
    try:
        # Check if file already scanned
        if scan_tracker.is_file_scanned(file_path):
            print(f"[SKIP] File already analyzed: {file_path}")
            return None

        print(f"[UPLOAD] Uploading file: {file_path}")

        if test_mode:
            # Simulate API response for testing tracking
            print("[TEST] Using simulated response")
            return {
                "data": {
                    "attributes": {
                        "stats": {
                            "malicious": 0,
                            "suspicious": 0
                        }
                    }
                }
            }

        with open(file_path, "rb") as file_to_upload:
            files = {"file": (os.path.basename(file_path), file_to_upload)}
            response = vtotal.request("files", files=files, method="POST")

        # Extract scan_id for the analysis
        scan_id = response.json()["data"]["id"]
        print(f"[SCAN] Waiting for analysis completion for file: {file_path}")

        # Wait for analysis to complete with timeout
        max_retries = 3
        wait_time = 20

        for retry in range(max_retries):
            time.sleep(wait_time)
            try:
                report = vtotal.request(f"analyses/{scan_id}").json()
                return report
            except Exception as e:
                print(f"[RETRY] Attempt {retry + 1}/{max_retries} failed: {e}")
                wait_time *= 2  # Exponential backoff

        print("[ERROR] Max retries reached, moving to next file")
        return None

    except Exception as e:
        print(f"[ERROR] Error uploading or analyzing file {file_path}: {e}")
        return None

def summarize_with_openai(vt_report, test_mode=False):
    """Summarizes the VirusTotal report with OpenAI API."""
    try:
        print("[AI] Generating OpenAI analysis...")

        if test_mode:
            return "Test mode: Simulated analysis summary"

        prompt = f"""
Analyze this VirusTotal report and highlight key considerations:
- Malware detections
- Severity level
- Suspicious behaviors
- Known malicious indicators
Report data: {json.dumps(vt_report, indent=2)}
"""
        response = openai.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are an expert in malware analysis."},
                {"role": "user", "content": prompt},
            ],
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"[ERROR] Error generating summary with OpenAI: {e}")
        return None

def analyze_files_in_directory(directory_path, test_mode=False):
    """Processes files in the specified directory."""
    print(f"\n=== Starting Directory Analysis: {directory_path} ===")
    print(f"[TIME] Analysis started at: {datetime.datetime.now()}")

    # Initialize tracker
    scan_tracker = ScanTracker()

    # Get list of all files
    all_files = []
    for root, _, files in os.walk(directory_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            all_files.append(file_path)

    # Get unscanned files
    files_to_scan = scan_tracker.get_unscanned_files(all_files)
    total_files = len(files_to_scan)

    print(f"[INFO] Found {total_files} new files to analyze")

    for index, file_path in enumerate(files_to_scan, 1):
        print(f"\n[PROGRESS] Processing file {index}/{total_files}")
        print(f"[FILE] Analyzing: {file_path}")

        # Check file size (<32MB)
        try:
            if os.path.getsize(file_path) > 32 * 1024 * 1024:
                print(f"[SKIP] File exceeds 32MB size limit: {file_path}")
                continue
        except Exception as e:
            print(f"[ERROR] Error checking file size: {e}")
            continue

        try:
            # Step 1: Upload and get VirusTotal report
            vt_report = upload_and_get_report(file_path, scan_tracker, test_mode)
            if not vt_report:
                continue

            # Step 2: Get OpenAI summary
            summary = summarize_with_openai(vt_report, test_mode)
            if not summary:
                continue

            # Step 3: Mark file as scanned and save results
            scan_tracker.mark_file_scanned(file_path)

            # Create log entry
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = f"./file_analysis_{timestamp}.log"
            with open(log_file, "a") as f:
                f.write(f"File: {file_path}\n")
                f.write(f"Analysis Time: {datetime.datetime.now()}\n")
                f.write(f"OpenAI Summary:\n{summary}\n")
                f.write("-" * 80 + "\n")
            print(f"[LOG] Results saved to: {log_file}")

        except Exception as e:
            print(f"[ERROR] Analysis failed for {file_path}: {e}")

        # Pause between files for API rate limits
        if not test_mode and index < total_files:
            print("[WAIT] Waiting before next file...")
            time.sleep(15)

    # Print final statistics
    stats = scan_tracker.get_scan_stats()
    print("\n=== Analysis Complete ===")
    print(f"[TIME] Analysis completed at: {datetime.datetime.now()}")
    print(f"[SUMMARY] Total files scanned: {stats['total_scanned']}")
    print(f"[SUMMARY] Last scan time: {stats['last_scan']}")
    print(f"[SUMMARY] Last file processed: {stats['last_file']}")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="File Analysis Tool")
    parser.add_argument("--directory", required=True, help="Directory to scan")
    parser.add_argument("--test", action="store_true", help="Run in test mode (no API calls)")
    return parser.parse_args()

if __name__ == "__main__":
    try:
        args = parse_args()
        analyze_files_in_directory(args.directory, args.test)
    except Exception as e:
        print(f"[ERROR] Script encountered an error: {e}")
        sys.exit(1)
