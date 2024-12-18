import os

class FileTracker:
    def __init__(self, tracking_file='processed_files.txt'):
        self.tracking_file = tracking_file
        self.processed_files = set()
        self._load_processed_files()

    def _load_processed_files(self):
        """Load the set of processed files from the tracking file."""
        try:
            with open(self.tracking_file, 'r') as f:
                self.processed_files = set(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            self.processed_files = set()

    def is_processed(self, file_path):
        """Check if a file has been processed."""
        normalized_path = os.path.normpath(file_path).replace('\\', '/')
        return normalized_path in self.processed_files

    def mark_processed(self, file_path):
        """Mark a file as processed."""
        normalized_path = os.path.normpath(file_path).replace('\\', '/')
        if normalized_path not in self.processed_files:
            self.processed_files.add(normalized_path)
            with open(self.tracking_file, 'a') as f:
                f.write(f"{normalized_path}\n")

    def get_processed_count(self):
        """Get the number of processed files."""
        return len(self.processed_files)
