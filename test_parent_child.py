import os
import time
from scanner import analyze_single_file

def test_parent_child_relationship():
    print("\n=== Testing Parent-Child Relationship Analysis ===\n")

    # Analyze parent first to ensure it's in VirusTotal database
    parent_file = os.path.join('test_files', 'malicious_parent.ps1')
    print(f'Testing parent file: {parent_file}')
    analyze_single_file(parent_file)

    # Wait for parent analysis to be indexed
    wait_time = 30  # Reduced from 180 to 30 seconds
    print(f"\nWaiting {wait_time} seconds for parent file to be processed...")
    time.sleep(wait_time)

    # Then analyze child to see parent relationships
    child_file = os.path.join('test_files', 'test_child.ps1')
    print(f'\nTesting child file: {child_file}')
    analyze_single_file(child_file)

if __name__ == "__main__":
    test_parent_child_relationship()
