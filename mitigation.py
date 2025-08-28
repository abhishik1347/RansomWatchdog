"""
    Mitigation module - triggered by detection.py
"""
import psutil
import subprocess
import logging

# Map extensions → ransomware processes
EXT_PROCESS_MAP = {
    "wncry": ["tasksche.exe", "@WanaDecryptor@.exe"],   # WannaCry
    "wcry":  ["tasksche.exe"],
    "locky": ["locky.exe"],
    "thanos": ["thanos.exe"],
}

def kill_ransomware_processes(extension: str):
    """
    Kill processes known to belong to ransomware families.
    """
    killed = []
    targets = EXT_PROCESS_MAP.get(extension.lower(), [])

    for p in psutil.process_iter(['pid', 'name']):
        try:
            if p.info['name'] and p.info['name'].lower() in [t.lower() for t in targets]:
                psutil.Process(p.info['pid']).kill()
                killed.append(p.info['name'])
                logging.warning(f"Killed ransomware process: {p.info['name']} (PID {p.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not killed:
        logging.info(f"No matching ransomware processes found for extension {extension}")
    return killed

def disable_network():
    """
    Disable network interfaces to stop exfiltration/spread.
    """
    try:
        subprocess.run("netsh interface set interface name=\"Ethernet\" admin=disable", shell=True)
        subprocess.run("netsh interface set interface name=\"Wi-Fi\" admin=disable", shell=True)
        logging.warning("Network interfaces disabled.")
    except Exception as e:
        logging.error(f"Failed to disable network: {e}")

def backup_safe_files(files):
    """
    (Simulation) Backup safe/unaffected files.
    """
    logging.info(f"Backing up {len(files)} files (simulation).")
    for f in files[:5]:
        logging.debug(f"Backed up: {f}")

def run_mitigation(extension: str, new_files: list):
    """
    Main entry point for detection.py to call.
    """
    logging.info(f"Mitigation triggered for .{extension} detection")

    killed = kill_ransomware_processes(extension)
    disable_network()
    backup_safe_files(new_files)

    logging.info(f"Mitigation completed. Processes killed: {killed}")
