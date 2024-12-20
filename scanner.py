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
    """Uploads a file to VirusTotal and retrieves the analysis report with parent relationships."""
    try:
        print(f"[SCAN] Uploading file: {file_path}")

        # Check request limit before proceeding
        current_count = get_request_count()
        if current_count >= DAILY_LIMIT:
            print(f"[LIMIT] Daily request limit ({DAILY_LIMIT}) reached. Saving state...")
            return None

        # Upload file
        with open(file_path, "rb") as file_to_upload:
            response = vtotal.request("files", files={"file": file_to_upload}, method="POST")

        # Increment request counter for upload
        count = increment_request_count()
        print(f"[COUNT] VirusTotal API requests today: {count}/{DAILY_LIMIT}")

        # Extract scan_id and wait for completion
        scan_id = response.json()["data"]["id"]
        print(f"[SCAN] Waiting for analysis completion for file: {file_path}")

        # Wait for analysis to complete with retries
        analysis = check_report_status(scan_id, max_retries=5, initial_delay=60)
        if not analysis:
            print("[ERROR] Analysis timed out or failed")
            return None

        # Add short delay before fetching relationship data
        print("[WAIT] Waiting 15 seconds for relationship data to be processed...")
        time.sleep(15)

        # Get full report with relationships after analysis is complete
        max_retries = 2  # Reduced retries for relationship data
        for attempt in range(max_retries):
            try:
                report = vtotal.request(f"files/{scan_id}?relationships=execution_parents,pe_resource_parents").json()

                # Verify relationships data structure
                if 'data' not in report or 'relationships' not in report['data']:
                    print("[INFO] No relationship data found in report")
                    report['data']['relationships'] = {
                        'execution_parents': {'data': []},
                        'pe_resource_parents': {'data': []}
                    }

                # Combine report and analysis data
                report['analysis'] = analysis
                print("[SUCCESS] Analysis completed successfully")
                return report

            except Exception as e:
                if "404" in str(e):
                    print("[INFO] No relationship data available (404)")
                    # Return report with empty relationships if 404
                    return {'data': {'id': scan_id, 'relationships': {
                        'execution_parents': {'data': []},
                        'pe_resource_parents': {'data': []}
                    }}, 'analysis': analysis}
                elif attempt < max_retries - 1:
                    wait_time = 15  # Reduced wait time between retries
                    print(f"[RETRY] Failed to fetch relationship data (attempt {attempt + 1}/{max_retries}): {e}")
                    print(f"[WAIT] Waiting {wait_time} seconds before retry...")
                    time.sleep(wait_time)
                else:
                    print(f"[ERROR] Failed to fetch relationship data after {max_retries} attempts: {e}")
                    # Return basic report without relationships if relationship fetch fails
                    return {'data': {'id': scan_id, 'relationships': {
                        'execution_parents': {'data': []},
                        'pe_resource_parents': {'data': []}
                    }}, 'analysis': analysis}

    except Exception as e:
        print(f"[ERROR] Error uploading or analyzing file {file_path}: {e}")
        return None

def analyze_parent_relationships(report_data):
    """Analyzes parent relationships for malicious indicators.

    Args:
        report_data (dict): The complete VirusTotal report data

    Returns:
        dict: Analysis of execution_parents and pe_resource_parents with their malicious indicators
    """
    parent_analysis = {
        'execution_parents': [],
        'pe_resource_parents': []
    }

    for relationship in ['execution_parents', 'pe_resource_parents']:
        if relationship in report_data.get('data', {}).get('relationships', {}):
            parents = report_data['data']['relationships'][relationship].get('data', [])
            for parent in parents:
                attributes = parent.get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                verdicts = attributes.get('sandbox_verdicts', {})

                # Calculate detection ratio
                total_detections = sum(stats.values()) if stats else 0
                malicious_count = stats.get('malicious', 0)
                suspicious_count = stats.get('suspicious', 0)
                detection_ratio = (malicious_count + suspicious_count) / total_detections if total_detections > 0 else 0

                # Analyze sandbox verdicts
                malicious_verdicts = []
                for sandbox_name, verdict in verdicts.items():
                    if verdict.get('category') in ['malicious', 'suspicious']:
                        malicious_verdicts.append({
                            'sandbox': sandbox_name,
                            'category': verdict.get('category'),
                            'confidence': verdict.get('confidence'),
                            'classification': verdict.get('malware_classification', []),
                            'names': verdict.get('malware_names', [])
                        })

                parent_analysis[relationship].append({
                    'sha256': parent.get('id'),
                    'type': parent.get('type'),
                    'detections': {
                        'total': total_detections,
                        'malicious': malicious_count,
                        'suspicious': suspicious_count,
                        'ratio': detection_ratio
                    },
                    'sandbox_verdicts': malicious_verdicts,
                    'names': attributes.get('names', []),
                    'type_tags': attributes.get('type_tags', []),
                    'threat_label': attributes.get('popular_threat_classification', {}).get('suggested_threat_label')
                })

    return parent_analysis

def summarize_with_openai(vt_report):
    """Summarizes the VirusTotal report with OpenAI API."""
    try:
        print("[AI] Generating OpenAI analysis...")

        # Extract parent relationship data
        relationships = vt_report.get('data', {}).get('relationships', {})
        exec_parents = relationships.get('execution_parents', {}).get('data', [])
        pe_parents = relationships.get('pe_resource_parents', {}).get('data', [])

        # Format parent relationship details
        parent_analysis = "\n2) Parent Relationship Analysis:\n"

        # Execution Parents
        parent_analysis += f"\n- Execution Parents: {len(exec_parents)} found"
        malicious_exec = sum(1 for p in exec_parents if p.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0)
        parent_analysis += f", {malicious_exec} malicious\n"

        for idx, parent in enumerate(exec_parents, 1):
            attrs = parent.get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            detections = f"{stats.get('malicious', 0)}/{sum(stats.values())}"
            verdict = "Malicious" if stats.get('malicious', 0) > 0 else "Clean"
            confidence = (stats.get('malicious', 0) / sum(stats.values())) * 100 if sum(stats.values()) > 0 else 0

            parent_analysis += f"  * Parent {idx}: [{parent.get('id', 'Unknown SHA256')}]\n"
            parent_analysis += f"    - Detections: {detections} engines ({verdict})\n"
            parent_analysis += f"    - Sandbox Verdict: {verdict} ({confidence:.0f}% confidence)\n"
            if verdict == "Malicious":
                parent_analysis += f"    - Malware Family: {attrs.get('popular_threat_classification', {}).get('suggested_threat_label', 'Unknown')}\n"

        # PE Resource Parents
        parent_analysis += f"\n- PE Resource Parents: {len(pe_parents)} found"
        malicious_pe = sum(1 for p in pe_parents if p.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0)
        parent_analysis += f", {malicious_pe} malicious\n"

        for idx, parent in enumerate(pe_parents, 1):
            attrs = parent.get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            detections = f"{stats.get('malicious', 0)}/{sum(stats.values())}"
            verdict = "Malicious" if stats.get('malicious', 0) > 0 else "Clean"
            confidence = (stats.get('malicious', 0) / sum(stats.values())) * 100 if sum(stats.values()) > 0 else 0

            parent_analysis += f"  * Parent {idx}: [{parent.get('id', 'Unknown SHA256')}]\n"
            parent_analysis += f"    - Detections: {detections} engines ({verdict})\n"
            parent_analysis += f"    - Sandbox Verdict: {verdict} ({confidence:.0f}% confidence)\n"
            if verdict == "Malicious":
                parent_analysis += f"    - Malware Classification: {attrs.get('popular_threat_classification', {}).get('suggested_threat_label', 'Unknown')}\n"

        prompt = f"""
You are a cybersecurity expert. Analyze the following VirusTotal report and provide a detailed analysis in two sections:

1) Basic Analysis:
- Malware detections
- Severity level
- Suspicious behaviors
- Known malicious indicators

2) Parent Relationship Analysis:
{parent_analysis}

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
        # Check file size
        if os.path.getsize(file_path) > 32 * 1024 * 1024:
            print(f"[SKIP] File too large (>32MB): {file_path}")
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

        print("\n=== Single File Analysis Complete ===")
        print(f"[TIME] Analysis completed at: {datetime.datetime.now()}")
        print(f"[SUMMARY] Results saved to: {log_file}")
        print("[STATUS] File processed successfully. Safe to stop here.")

    except Exception as e:
        print(f"[ERROR] Analysis failed: {e}")

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
