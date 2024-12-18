import os
import sys
import time
import datetime
import argparse
from virustotal_python import Virustotal
import openai
from dotenv import load_dotenv
import json
from scan_tracker import ScanTracker

# Load API keys from .env file
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Initialize clients
vtotal = Virustotal(API_KEY=VT_API_KEY)
openai.api_key = OPENAI_API_KEY

# Initialize scan tracker
scan_tracker = ScanTracker()

def get_test_vt_report():
    """Generate a test VirusTotal report for testing."""
    return {
        "data": {
            "id": "test-scan-id",
            "attributes": {
                "status": "completed",
                "stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 60
                },
                "results": {
                    "test-av": {
                        "category": "undetected",
                        "result": None
                    }
                }
            }
        }
    }

def get_test_openai_response():
    """Generate a test OpenAI response for testing."""
    return "Test file analysis: No malicious indicators found. Severity: Low. No suspicious behaviors detected."

def upload_and_get_report(file_path, test_mode=False):
    """Uploads a file to VirusTotal and retrieves the analysis report."""
    try:
        # Check if file already scanned
        if scan_tracker.is_file_scanned(file_path):
            print(f"[SKIP] File already analyzed: {file_path}")
            return None

        print(f"[UPLOAD] Uploading file: {file_path}")

        if test_mode:
            print("[TEST] Using simulated VirusTotal response")
            time.sleep(2)  # Simulate API delay
            return get_test_vt_report()

        with open(file_path, "rb") as file_to_upload:
            files = {"file": (os.path.basename(file_path), file_to_upload)}
            response = vtotal.request("files", files=files, method="POST")

        # Extract scan_id for the analysis
        scan_id = response.json()["data"]["id"]
        print(f"[SCAN] Waiting for analysis completion for file: {file_path}")

        # Wait for analysis to complete
        time.sleep(60)
        report = vtotal.request(f"analyses/{scan_id}").json()

        # Mark file as scanned after successful analysis
        scan_tracker.mark_file_scanned(file_path)

        return report
    except Exception as e:
        print(f"[ERROR] Error uploading or analyzing file {file_path}: {e}")
        return None

def summarize_with_openai(vt_report, test_mode=False):
    """Summarizes the VirusTotal report with OpenAI API."""
    try:
        print("[AI] Generating OpenAI analysis...")

        if test_mode:
            print("[TEST] Using simulated OpenAI response")
            time.sleep(1)  # Simulate API delay
            return get_test_openai_response()

        prompt = f"""
You are a cybersecurity expert. Analyze the following VirusTotal report and highlight key considerations such as:
- Malware detections
- Severity level
- Suspicious behaviors
- Known malicious indicators
Here is the report data:
{json.dumps(vt_report, indent=2)}
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
    print(f"[MODE] Running in {'test' if test_mode else 'production'} mode")

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

        # Create log file for this analysis
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = f"./file_analysis_{timestamp}.log"

        try:
            # Step 1: Upload and get VirusTotal report
            vt_report = upload_and_get_report(file_path, test_mode)
            if not vt_report:
                continue

            # Step 2: Get OpenAI summary
            summary = summarize_with_openai(vt_report, test_mode)
            if not summary:
                continue

            # Step 3: Append results to log file
            with open(log_file, "a") as f:
                f.write(f"File: {file_path}\n")
                f.write(f"Analysis Time: {datetime.datetime.now()}\n")
                f.write(f"OpenAI Summary:\n{summary}\n")
                f.write("-" * 80 + "\n")
            print(f"[LOG] Results saved to: {log_file}")

            # Mark file as scanned after successful analysis
            scan_tracker.mark_file_scanned(file_path)

        except Exception as e:
            print(f"[ERROR] Analysis failed for {file_path}: {e}")

        # Pause between files for API rate limits (shorter in test mode)
        if index < total_files:
            delay = 2 if test_mode else 15
            print(f"[WAIT] Waiting {delay} seconds before next file...")
            time.sleep(delay)

    # Print final statistics
    stats = scan_tracker.get_scan_stats()
    print("\n=== Analysis Complete ===")
    print(f"[TIME] Analysis completed at: {datetime.datetime.now()}")
    print(f"[SUMMARY] Total files scanned: {stats['total_scanned']}")
    print(f"[SUMMARY] Last scan time: {stats['last_scan']}")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True, help="Directory to scan")
    parser.add_argument("--test", action="store_true", help="Run in test mode with simulated API responses")
    return parser.parse_args()

if __name__ == "__main__":
    try:
        args = parse_args()

        if not os.path.exists(args.directory):
            print(f"[ERROR] Directory not found: {args.directory}")
            sys.exit(1)

        analyze_files_in_directory(args.directory, test_mode=args.test)

    except Exception as e:
        print(f"[ERROR] Script encountered an error: {e}")
        sys.exit(1)
