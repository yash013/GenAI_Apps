import json
import os
from datetime import datetime

class ScanTracker:
    def __init__(self, tracker_file="scanned_files.json"):
        self.tracker_file = tracker_file
        self._load_or_create_tracker()

    def _load_or_create_tracker(self):
        """Load existing tracker or create new one if doesn't exist"""
        if os.path.exists(self.tracker_file):
            with open(self.tracker_file, 'r') as f:
                self.data = json.load(f)
        else:
            self.data = {
                "scanned_files": [],
                "last_scan": None,
                "total_scanned": 0
            }
            self._save_tracker()

    def _save_tracker(self):
        """Save tracker data to file"""
        with open(self.tracker_file, 'w') as f:
            json.dump(self.data, f, indent=4)

    def is_file_scanned(self, file_path):
        """Check if file has been scanned"""
        return file_path in self.data["scanned_files"]

    def mark_file_scanned(self, file_path):
        """Mark a file as scanned"""
        if not self.is_file_scanned(file_path):
            self.data["scanned_files"].append(file_path)
            self.data["total_scanned"] += 1
            self.data["last_scan"] = datetime.now().isoformat()
            self._save_tracker()

    def get_unscanned_files(self, file_list):
        """Get list of files that haven't been scanned yet"""
        return [f for f in file_list if not self.is_file_scanned(f)]

    def get_scan_stats(self):
        """Get scanning statistics"""
        return {
            "total_scanned": self.data["total_scanned"],
            "last_scan": self.data["last_scan"]
        }
