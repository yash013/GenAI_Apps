import os
import sys
import time
import datetime
import argparse
import json
from virustotal_python import Virustotal
import openai
from dotenv import load_dotenv
from file_tracker import FileTracker

# Load API keys from .env file
load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Initialize VirusTotal and OpenAI clients
vtotal = Virustotal(API_KEY=VT_API_KEY)
openai.api_key = OPENAI_API_KEY

# Path to test files directory (using this instead of System32 for testing)
TEST_FILES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "test_files")
SYSTEM32_DIR = TEST_FILES_DIR  # Use test files directory for testing

# Constants
DAILY_LIMIT = 500  # VirusTotal API daily request limit

# Output log file
RESULT_LOG_FILE = f"./system32_analysis_{datetime.datetime.now().strftime('%Y%m%d')}.log"

def get_checkpoint():
    """Get the current checkpoint information."""
    try:
        with open(".checkpoint", "r") as f:
            data = json.load(f)
            return data.get("last_file", None), data.get("processed_count", 0)
    except (FileNotFoundError, json.JSONDecodeError):
        return None, 0

def save_checkpoint(file_path, processed_count):
    """Save the current checkpoint."""
    with open(".checkpoint", "w") as f:
        json.dump({
            "last_file": file_path,
            "processed_count": processed_count,
            "timestamp": datetime.datetime.now().isoformat()
        }, f, indent=2)

def get_request_count():
    """Get the current request count for today."""
    try:
        with open(".request_count", "r") as f:
            return int(f.read().strip())
    except FileNotFoundError:
        return 0

def increment_request_count():
    """Increment the request count for today."""
    count = get_request_count() + 1
    with open(".request_count", "w") as f:
        f.write(str(count))
    return count

def analyze_files_in_system32():
    """Processes files in System32 one by one."""
    print("\n=== Starting System32 File Analysis ===")
    print(f"[TIME] Analysis started at: {datetime.datetime.now()}")

    # Initialize file tracker
    file_tracker = FileTracker()

    # Get list of files to process
    files_to_process = []
    for root, _, files in os.walk(SYSTEM32_DIR):
        for filename in files:
            file_path = os.path.join(root, filename)
            files_to_process.append(file_path)

    print(f"[INFO] Found {len(files_to_process)} files to analyze")

    # Process each file
    for index, file_path in enumerate(files_to_process, 1):
        print(f"\n[PROGRESS] Processing file {index}/{len(files_to_process)}")
        print(f"[FILE] Current file: {file_path}")

        # Check if file was already processed
        if file_tracker.is_processed(file_path):
            print(f"[SKIP] Already processed: {file_path}")
            continue

        try:
            # Check file size (<32MB)
            if os.path.getsize(file_path) > 32 * 1024 * 1024:
                print(f"[SKIP] File too large (>32MB): {file_path}")
                continue

            # Upload and get VirusTotal report
            report = upload_and_get_report(file_path)
            if not report:
                print("[ERROR] Failed to get VirusTotal report")
                continue

            # Get OpenAI summary
            summary = summarize_with_openai(report)
            if not summary:
                print("[ERROR] Failed to generate OpenAI summary")
                continue

            # Write results to log file
            timestamp = datetime.datetime.now().strftime("%Y%m%d")
            log_file = f"./system32_analysis_{timestamp}.log"

            with open(log_file, "a") as f:
                f.write(f"\nFile: {file_path}\n")
                f.write(f"Analysis Time: {datetime.datetime.now()}\n")
                f.write(f"OpenAI Summary:\n{summary}\n")
                f.write("-" * 80 + "\n")

            print(f"[LOG] Analysis for {file_path} appended to log file")

            # Mark file as processed
            file_tracker.mark_processed(file_path)

            print("\n-----------------------------------------------------------")
            print("[STATUS] File processed successfully. Safe to stop here.")
            print("-----------------------------------------------------------")
            print("                          ")

            # Print progress status
            print("[STATUS] Safe to stop here - progress has been saved")

            # Pause between files
            time.sleep(60)  # 60-second delay between file processing

        except Exception as e:
            print(f"[ERROR] Error processing file {file_path}: {e}")
            continue

    print("\n=== System32 File Analysis Complete ===")
    print(f"[TIME] Analysis completed at: {datetime.datetime.now()}")
    print(f"[SUMMARY] Total files processed: {file_tracker.get_processed_count()}")

def check_report_status(scan_id, max_retries=5, initial_delay=60):
    """Check VirusTotal report status with exponential backoff."""
    delay = initial_delay
    for attempt in range(1, max_retries + 1):
        try:
            # Check request limit before status check
            current_count = get_request_count()
            if current_count >= DAILY_LIMIT:
                print(f"[LIMIT] Daily request limit ({DAILY_LIMIT}) reached during status check")
                return None

            print(f"[STATUS] Checking report status (attempt {attempt}/{max_retries})")
            report = vtotal.request(f"analyses/{scan_id}").json()

            # Increment request counter for status check
            count = increment_request_count()
            print(f"[COUNT] VirusTotal API requests today: {count}/{DAILY_LIMIT}")

            status = report["data"]["attributes"]["status"]

            if status == "completed":
                stats = report["data"]["attributes"]["stats"]
                malicious_count = stats.get("malicious", 0)
                suspicious_count = stats.get("suspicious", 0)
                print(f"[COMPLETE] Analysis completed. Malicious: {malicious_count}, Suspicious: {suspicious_count}")
                return report

            print(f"[QUEUED] Status: {status}. Waiting {delay} seconds before retry...")
            time.sleep(delay)
            delay = delay * 1.5  # Use 1.5x backoff instead of 2x

        except Exception as e:
            print(f"[ERROR] Error checking report status: {e}")
            time.sleep(delay)

    print("[TIMEOUT] Max retries reached, analysis incomplete")
    return None

def upload_and_get_report(file_path):
    """Uploads a file to VirusTotal and retrieves the analysis report."""
    try:
        print(f"[SCAN] Uploading file: {file_path}")

        # Check request limit before proceeding
        current_count = get_request_count()
        if current_count >= DAILY_LIMIT:
            print(f"[LIMIT] Daily request limit ({DAILY_LIMIT}) reached. Saving state...")
            return None

        with open(file_path, "rb") as file_to_upload:
            response = vtotal.request("files", files={"file": file_to_upload}, method="POST")

        # Increment request counter for upload
        count = increment_request_count()
        print(f"[COUNT] VirusTotal API requests today: {count}/{DAILY_LIMIT}")

        # Extract scan_id and wait for completion
        scan_id = response.json()["data"]["id"]
        print(f"[SCAN] Waiting for analysis completion for file: {file_path}")

        # Use check_report_status to wait for completion with retries
        report = check_report_status(scan_id, max_retries=5, initial_delay=60)
        if not report:
            print("[ERROR] Analysis timed out or failed")
            return None

        print("[SUCCESS] Analysis completed successfully")
        return report
    except Exception as e:
        print(f"[ERROR] Error uploading or analyzing file {file_path}: {e}")
        return None

def summarize_with_openai(vt_report):
    """Summarizes the VirusTotal report with OpenAI API."""
    try:
        print("[AI] Generating OpenAI analysis...")
        prompt = f"""
You are a cybersecurity expert. Analyze the following VirusTotal report and highlight key considerations such as:
- Malware detections (including total detections and detection names)
- Severity level (Low/Medium/High based on detection ratio)
- Suspicious behaviors or characteristics
- Known malicious indicators
- Recommendation (Clean/Suspicious/Malicious)

Report Analysis:
{json.dumps(vt_report, indent=2)}

Please provide a detailed analysis focusing on security implications.
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

def analyze_single_file(file_path):
    """Analyzes a single file using VirusTotal and OpenAI."""
    print("\n=== Starting Single File Analysis ===")
    print(f"[TIME] Analysis started at: {datetime.datetime.now()}")
    print(f"[FILE] Analyzing file: {file_path}")

    # Create log file for this analysis
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = f"./file_analysis_{timestamp}.log"
    print(f"[LOG] Writing results to: {log_file}")

    try:
        # Check if file was already completed
        try:
            with open("completed_file.txt", "r") as f:
                completed_file = f.read().strip()
                if completed_file and os.path.normpath(file_path) == os.path.normpath(completed_file):
                    print(f"[SKIP] File already processed: {file_path}")
                    return
        except FileNotFoundError:
            pass

        # Create/update current file tracker
        with open("current_file.txt", "w") as f:
            f.write(file_path)

        # Get checkpoint information
        last_file, processed_count = get_checkpoint()
        print(f"[CHECKPOINT] Previous scan state:")
        print(f"[CHECKPOINT] Last completed file: {last_file}")
        print(f"[CHECKPOINT] Files processed: {processed_count}")

        # Check file size
        if os.path.getsize(file_path) > 32 * 1024 * 1024:
            print(f"[SKIP] File too large (>32MB): {file_path}")
            return

        # Check daily request limit
        if get_request_count() >= DAILY_LIMIT:
            print(f"[LIMIT] Daily request limit ({DAILY_LIMIT}) reached")
            return

        # Upload and get VirusTotal report
        vt_report = upload_and_get_report(file_path)
        if not vt_report:
            print("[ERROR] Failed to get VirusTotal report")
            return

        # Get OpenAI summary
        summary = summarize_with_openai(vt_report)
        if not summary:
            print("[ERROR] Failed to generate OpenAI summary")
            return

        # Write results to log file
        with open(log_file, "w") as f:
            f.write(f"File: {file_path}\n")
            f.write(f"Analysis Time: {datetime.datetime.now()}\n")
            f.write(f"OpenAI Summary:\n{summary}\n")
            f.write("-" * 80 + "\n")

        # Mark file as completed
        with open("completed_file.txt", "w") as f:
            f.write(os.path.normpath(file_path))

        # Update checkpoint
        processed_count += 1
        save_checkpoint(file_path, processed_count)

        print("\n=== Single File Analysis Complete ===")
        print(f"[TIME] Analysis completed at: {datetime.datetime.now()}")
        print(f"[SUMMARY] Results saved to: {log_file}")
        print("[STATUS] File processed successfully. Safe to stop here.")

    except Exception as e:
        print(f"[ERROR] Analysis failed: {e}")
    finally:
        # Clear current file tracker
        with open("current_file.txt", "w") as f:
            f.write("")

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="Virus Scanner")
        parser.add_argument("--mode", choices=["single", "system32"], required=True,
                          help="Analysis mode: single file or system32 directory")
        parser.add_argument("--file-path", help="Path to single file for analysis")
        args = parser.parse_args()

        if args.mode == "single":
            if not args.file_path:
                parser.error("--file-path required for single mode")
            if not os.path.exists(args.file_path):
                print(f"[ERROR] File not found: {args.file_path}")
                sys.exit(1)
            analyze_single_file(args.file_path)
        else:
            print("Starting System32 file analysis...")
            analyze_files_in_system32()
    except Exception as e:
        print(f"[ERROR] Script encountered an error: {e}")
