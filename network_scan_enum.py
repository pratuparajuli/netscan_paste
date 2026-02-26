#!/usr/bin/env python3
"""
Network Scan + Port 80 Web Enumeration Script
"""

import os
import sys
import time
import subprocess
import xml.etree.ElementTree as ET
import shutil
from pathlib import Path

# ==================== CONFIGURATION ====================
TARGET_SPEC = "192.168.1.103"              # Safe VirtualBox Host-Only lab network
MAX_HOSTS_TO_ENUMERATE = 20
GOBUSTER_THREADS = 20
GOBUSTER_EXTENSIONS = "php,html,txt,js,bak,zip"
GOBUSTER_TIMEOUT_SEC = 300
OVERALL_TIMEOUT_SEC = 3600
WORDLIST_PATH = "/usr/share/wordlists/dirb/common.txt"
OUTPUT_DIRECTORY = "scan_results"

INTERESTING_CODES = {200, 301, 302, 403, 500, 401, 405}
# =========================================================

def validate_tools_and_files():
    """Validate that nmap and gobuster are in PATH and wordlist exists"""
    required = {
        "nmap": "nmap",
        "gobuster": "gobuster",
        "wordlist": WORDLIST_PATH
    }
    for name, path in required.items():
        if name == "wordlist":
            if not os.path.isfile(path):
                print(f"Error: Wordlist not found at {path}")
                sys.exit(1)
        else:
            if not shutil.which(path):
                print(f"Error: {name} not found in PATH")
                sys.exit(1)
    print("All required tools and wordlist found.")

def sanitize_filename(ip: str) -> str:
    """Simple IP sanitizer for filename"""
    return ip.replace(".", "_").replace(":", "_")

def main():
    start_time = time.time()

    output_dir = Path(OUTPUT_DIRECTORY)
    output_dir.mkdir(parents=True, exist_ok=True)

    validate_tools_and_files()

    live_web_hosts = []
    summary_report = []

    # 1. Network scan phase
    print(f"Starting nmap scan on {TARGET_SPEC} to find hosts with port 80 open...")

    scan_xml_path = output_dir / "scan.xml"

    nmap_cmd = [
        "nmap",
#        "-sn",                # host discovery#
        "-p80",               # only port 80
        "--open",             # only show open ports
        "-oX", str(scan_xml_path),
        TARGET_SPEC
    ]

    try:
        subprocess.run(nmap_cmd, check=True)
        print("nmap completed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"nmap failed: {e}")
        sys.exit(1)

    # Parse live hosts
    live_web_hosts = []
    try:
        tree = ET.parse(scan_xml_path)
        root = tree.getroot()
        for host in root.findall("./host"):
            address = host.find("address")
            if address is None:
                continue
            addrtype = address.get("addrtype")
            if addrtype !="ipv4":
                continue
            ip = address.get("addr")
            if ip is None:
                continue

            ports = host.find("ports")
            if ports is None:
                continue
            port_open = False
            for port in ports.findall("port"):
                portid = port.get("portid")
                if portid =="80":
                    state = port.find("state") 
                    if state is not None:
                        state_value = state.get("state")
                        if state_value == "open":
                            port_open = True
                            break

            if port_open:
                live_web_hosts.append(ip)

        print(f"Found {len(live_web_hosts)} hosts with port 80 open.")
    except ET.ParseError as e:
        print(f"XML format invalid: {e}")
    except Exception as e:
        print(f"Error parsing nmap XML: {type(e).__name__} - {str(e)}")             #    live_web_hosts[:MAX_HOSTS_TO_ENUMERATE]

    # 2. Web enumeration phase
    if not live_web_hosts:
        summary_report.append("No hosts with port 80 open found.")
    else:
        print(f"Starting Gobuster enumeration on {len(live_web_hosts)} hosts...")

        for ip in live_web_hosts:
            output_file_name = f"{sanitize_filename(ip)}_gobuster.txt"
            output_path = output_dir / output_file_name

            print(f"  Running Gobuster on http://{ip} → saving to {output_path}")

            gobuster_cmd = [
                "gobuster",
                "dir",
                "-u", f"http://{ip}",
                "-w", WORDLIST_PATH,
                "-t", str(GOBUSTER_THREADS),
                "-x", GOBUSTER_EXTENSIONS,
                "-o", str(output_path),
                "--timeout", f"{GOBUSTER_TIMEOUT_SEC}s",
                "-q"  # quiet mode
            ]

            try:
                subprocess.run(
                    gobuster_cmd,
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=OVERALL_TIMEOUT_SEC
                )
                print(f"    Gobuster finished for {ip}. Results in {output_path}")

                # Parse gobuster output
                interesting_paths = []
                with open(output_path, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line and any(str(code) in line for code in INTERESTING_CODES):
                            interesting_paths.append(line)

                if interesting_paths:
                    summary_report.append(f"{ip}: {len(interesting_paths)} interesting paths found")
                    summary_report.extend(interesting_paths[:10])
                else:
                    summary_report.append(f"{ip}: No interesting paths found (likely only 404s)")

            except subprocess.TimeoutExpired:
                summary_report.append(f"{ip}: Gobuster TIMEOUT after {GOBUSTER_TIMEOUT_SEC}s")
            except subprocess.CalledProcessError as e:
                summary_report.append(f"{ip}: Gobuster failed (exit code {e.returncode})")
            except Exception as e:
                summary_report.append(f"{ip}: Error - {str(e)}")

    # 3. Reporting
    end_time = time.time()
    duration = round(end_time - start_time, 1)

    print("\n" + "="*60)
    print(f"Scan completed in {duration} seconds")
    print(f"Total web hosts found: {len(live_web_hosts)}")
    print("\nSummary:")
    for line in summary_report:
        print(line)
    print("\nResults saved in:", OUTPUT_DIRECTORY)
    print("="*60)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
    except Exception as e:
        print(f"Unexpected error: {e}")
