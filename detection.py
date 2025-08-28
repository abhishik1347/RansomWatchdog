#!/usr/bin/env python3
"""
Real-time ransomware extension monitor (watchdog + ntfy + mitigation).
Monitors user folder C:\Users\ransomed excluding AppData.
"""

import time
import logging
import json
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests
import mitigation   # your mitigation.py file

# -----------------------
# Configuration
# -----------------------

USER_NAME = "ransomed"
MONITOR_PATH = Path(fr"C:\Users\{USER_NAME}")   # User home folder
EXCLUDE_DIR = "appdata"                         # exclude AppData
TARGET_EXTENSIONS = [
    "wncry", "wncryt", "wcry",       # WannaCry
    "locked", "thanos",              # Thanos
    "locky", "zepto", "odin", "thor", "aesir", "osiris",  # Locky
    "rdm", "rrk",                    # Radamant
]

CRITICAL_THRESHOLD = 10
NTFY_TOPIC_URL = "https://ntfy.sh/ransomedtest"

# -----------------------
# Logging setup
# -----------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)

# -----------------------
# ntfy Notification
# -----------------------

def notify_admins_ntfy(message: str, title: str = "Ransomware Alert",
                       priority: str = "urgent", tags: str = "ransomware"):
    headers = {
        "Title": title,
        "Priority": priority,
        "Tags": tags,
        "Content-Type": "text/plain"
    }
    logging.debug(f"[ntfy] Sending notification: {message[:80]}...")
    try:
        resp = requests.post(NTFY_TOPIC_URL, headers=headers, data=message.encode("utf-8"))
        if resp.status_code in (200, 204):
            logging.info("✅ ntfy notification sent successfully")
        else:
            logging.error(f"❌ ntfy error {resp.status_code}: {resp.text}")
    except Exception as ex:
        logging.error(f"❌ Failed to send ntfy notification: {ex}")

# -----------------------
# Detection Handler
# -----------------------

class RansomwareHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()

    def should_monitor(self, path: str) -> bool:
        """Skip AppData directory"""
        return EXCLUDE_DIR not in Path(path).as_posix().lower()

    def process_event(self, file_path: str):
        if not self.should_monitor(file_path):
            return
        ext = Path(file_path).suffix.lstrip(".").lower()
        if ext in TARGET_EXTENSIONS:
            severity = "CRITICAL" if len(ext) >= CRITICAL_THRESHOLD else "HIGH"
            summary = f"Suspicious file detected: {file_path} | Extension: .{ext}"
            logging.warning(f"[{severity}] {summary}")

            alert = {
                "type": "RANSOM_EXT_DETECTED",
                "severity": severity,
                "extension": ext,
                "paths": [file_path],
                "timestamp": int(time.time())
            }
            print(json.dumps(alert))

            # notify
            notify_admins_ntfy(
                message=f"{summary}",
                title=f"Ransomware Extension Alert: .{ext}",
                priority="urgent",
                tags="ransomware"
            )

            # mitigation
            mitigation.run_mitigation(ext, [file_path])

    # Event callbacks
    def on_created(self, event):
        if not event.is_directory:
            self.process_event(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_event(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.process_event(event.dest_path)

# -----------------------
# Orchestrator
# -----------------------

def main():
    logging.info(f"🔍 Starting ransomware monitor on {MONITOR_PATH} (excluding AppData)")

    if not MONITOR_PATH.exists():
        logging.error(f"User folder {MONITOR_PATH} not found!")
        return

    event_handler = RansomwareHandler()
    observer = Observer()
    observer.schedule(event_handler, str(MONITOR_PATH), recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping monitor...")
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
