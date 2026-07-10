import os
import time
from typing import List, Dict, Any, Callable
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class SentinelWatchHandler(FileSystemEventHandler):
    """Listens to filesystem events and runs a callback scan on modified files."""
    def __init__(self, root_dir: str, on_change_callback: Callable[[str], None]):
        self.root_dir = os.path.abspath(root_dir)
        self.on_change_callback = on_change_callback
        
        # Parse gitignores if present to avoid scanning ignored modifications
        from sentinel_scan.sources.file_source import GitIgnoreParser, DEFAULT_EXCLUDES, DEFAULT_EXCLUDE_EXTENSIONS
        self.gitignore_parser = GitIgnoreParser(self.root_dir)
        self.excludes = DEFAULT_EXCLUDES
        self.exclude_exts = DEFAULT_EXCLUDE_EXTENSIONS
        
        # Skip self-generated report file modifications
        self.report_keywords = ["sentinel_report", "report.json", "report.html", "report.csv", "report.md", "report.sarif"]

    def on_modified(self, event):
        if event.is_directory:
            return
        self._process_event(event.src_path)

    def on_created(self, event):
        if event.is_directory:
            return
        self._process_event(event.src_path)

    def _process_event(self, abs_path: str) -> None:
        # Normalize paths
        abs_path = os.path.abspath(abs_path)
        filename = os.path.basename(abs_path)
        
        # Skip files from excluded directories
        parts = os.path.relpath(abs_path, self.root_dir).replace(os.path.sep, '/').split('/')
        if any(part in self.excludes for part in parts):
            return
            
        # Skip excluded extensions
        _, ext = os.path.splitext(filename)
        if ext.lower() in self.exclude_exts:
            return
            
        # Skip self-generated reports
        if any(kw in filename.lower() for kw in self.report_keywords):
            return
            
        # Skip if ignored in gitignore
        if self.gitignore_parser.is_ignored(abs_path):
            return
            
        # Trigger the scan callback
        self.on_change_callback(abs_path)

def start_watch_mode(root_dir: str, on_change_callback: Callable[[str], None]) -> None:
    """Starts the watchdog observer to watch for directory file modifications."""
    abs_root = os.path.abspath(root_dir)
    event_handler = SentinelWatchHandler(abs_root, on_change_callback)
    observer = Observer()
    observer.schedule(event_handler, path=abs_root, recursive=True)
    
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
