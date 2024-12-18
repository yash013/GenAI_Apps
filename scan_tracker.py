import os
import json
import datetime

class ScanTracker:
    def __init__(self, json_file="scanned_files.json", text_file="scanned_files.txt"):
        self.json_file = json_file
        self.text_file = text_file
        self.data = {
            "last_file": None,
            "processed_count": 0,
            "timestamp": None,
            "scanned_files": set()
        }
        self._load_or_create_tracker()

    def _normalize_path(self, path):
        """Normalize path for consistent comparison across platforms"""
        if path is None:
            return None
        return os.path.normpath(path).replace('\\', '/')

    def _load_or_create_tracker(self):
        """Load existing tracker or create new one if doesn't exist"""
        # Load JSON data
        if os.path.exists(self.json_file):
            with open(self.json_file, 'r') as f:
                data = json.load(f)
                # Convert loaded list to set and normalize paths
                self.data = {
                    "last_file": self._normalize_path(data.get("last_file")),
                    "processed_count": data.get("processed_count", 0),
                    "timestamp": data.get("timestamp"),
                    "scanned_files": set(self._normalize_path(p) for p in data.get("scanned_files", []))
                }
        else:
            self._save_tracker()

        # Create/update text file if needed
        self._update_text_file()

    def _save_tracker(self):
        """Save tracker data to both JSON and text files"""
        # Update timestamp
        self.data["timestamp"] = datetime.datetime.now().isoformat()

        # Save JSON - convert set to list for JSON serialization and ensure paths are normalized
        with open(self.json_file, 'w') as f:
            json_data = {
                "last_file": self._normalize_path(self.data["last_file"]),
                "processed_count": self.data["processed_count"],
                "timestamp": self.data["timestamp"],
                "scanned_files": list(self.data["scanned_files"])  # Already normalized
            }
            json.dump(json_data, f, indent=2)

        # Update text file
        self._update_text_file()

    def _update_text_file(self):
        """Update the human-readable text file"""
        with open(self.text_file, 'w') as f:
            f.write("# Scanned Files List\n")
            f.write(f"# Last Updated: {self.data['timestamp']}\n")
            f.write(f"# Total Files Processed: {self.data['processed_count']}\n")
            f.write(f"# Last File Processed: {self._normalize_path(self.data['last_file'])}\n")
            f.write("#" + "-" * 50 + "\n\n")

            for file_path in sorted(self.data["scanned_files"]):  # Already normalized
                f.write(f"[SCANNED] {file_path}\n")

    def is_file_scanned(self, file_path):
        """Check if file has been scanned"""
        return self._normalize_path(file_path) in self.data["scanned_files"]

    def mark_file_scanned(self, file_path):
        """Mark a file as scanned"""
        norm_path = self._normalize_path(file_path)
        if norm_path not in self.data["scanned_files"]:
            self.data["scanned_files"].add(norm_path)
            self.data["processed_count"] += 1
            self.data["last_file"] = file_path  # Store original path for display
            self._save_tracker()
            return True
        return False

    def get_unscanned_files(self, file_list):
        """Get list of files that haven't been scanned yet"""
        return [f for f in file_list if not self.is_file_scanned(f)]

    def get_scan_stats(self):
        """Get scanning statistics"""
        return {
            "total_scanned": self.data["processed_count"],
            "last_scan": self.data["timestamp"],
            "last_file": self.data["last_file"]
        }
