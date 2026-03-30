"""
Software Name : decret_auto
Version : 0.1
SPDX-FileCopyrightText : Copyright (c) 2023-2026 Orange
SPDX-License-Identifier : BSD-3-Clause

This software is distributed under the BSD 3-Clause "New" or "Revised" License,
the text of which is available at https://opensource.org/licenses/BSD-3-Clause
or see the "license.txt" file for more not details.

Author: CHAKER Zakaria, Nicolas DEJON
Software Descritpion : This script is designed to automatically test the DECRET tool by running it on a list of Debian CVEs for different releases.
For each CVE and release, it checks if DECRET can successfully generate a valid Dockerfile and reports the result.
The main goal is to evaluate the functionality of DECRET, identify errors or unexpected behaviors, and help improve the tool.
"""

import os
import socket
import shutil
import subprocess
from datetime import datetime
import concurrent.futures
import sys

def check_internet_state():
    """
    Checks if the machine has internet connectivity.
    Uses the 'ping' command to test connectivity to 8.8.8.8.
    Returns True if the connection works, False otherwise.
    """
    try:
        result = subprocess.run(
            ["ping", "-c", "2", "8.8.8.8"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False

def parse_cve_file(filename):
    """
    Parses a configuration file containing CVEs and their associated releases.
    Each line should be formatted as: 
        - XXXX-YYYY: release1, release2, ...
        - CVE-XXXX-YYYY: release1, release2, release3, ...
    If no release is specified (empty after ':' or no ':'), uses 4 default releases:
        `trixie`, `bookworm`, `bullseye` and `buster`.
    Empty lines are ignored.
    Args:
        filename (str): Path to the configuration file.
    Returns:
        dict: Dictionary mapping each CVE to a list of releases.
    Raises: 
        FileNotFoundError: If the configuration file does not exist.
        Exception: If a release specified in the file is not in the 4 supported releases
    """
    DEFAULT_RELEASES = ["trixie", "bookworm", "bullseye", "buster"]
    cve_dict = {}

    try:
        with open(filename, "r") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line :
                    continue
                if ":" in line:
                    cve, releases = line.split(":", 1)
                    cve = cve.strip()
                    releases_list = [r.strip() for r in releases.split(",") if r.strip()]
                    if not releases_list:
                        releases_list = DEFAULT_RELEASES.copy()
                    for release in releases_list:
                        if release not in DEFAULT_RELEASES:
                            f"Invalid release '{release}' for CVE '{CVE}' on L.{line_num}."  
                            f"Supported releases are: {', '.join(DEFAULT_RELEASES)}!" 
                    cve_dict[cve] = releases_list
                else:
                    cve = line.strip()
                    if cve:
                        cve_dict[cve] = DEFAULT_RELEASES.copy()
    except FileNotFoundError:
        raise FileNotFoundError(f"Exception catched, configuration file not found...")
    except Exception as error:
        raise RuntimeError(f"Error occurs during parsing the configuration file: {error}")
    return cve_dict

def run_decret_CVE(name_cve, name_release):
    """
    Runs the DECRET tool for a given CVE and Debian release in '--dont-run' mode.
     For each run, directories are created in an 'out/' subfolder, organized by CVE and then by release, for example:
        out/
        |__CVE-2015-xxxx/
        |   |__trixie/
        |__CVE-2014-xxxx/
            |__bullseye/
            |__buster/

    For each release, the script generates up 4 files: logfile, Dockerfile (if available), cmdline and status.
    If a complete Dockerfile is generated and the return code is 0, the container is considered functional for that release.
    Otherwise, it is considered an error.

    Args:
        name_cve (str): The CVE identifier
        name_release (str): The release name (e.g., 'buster', 'bullseye').

    Raises:
        ValueError: If the release name is not supported.
    """
    output_base = os.path.join("out", name_cve)
    os.makedirs(output_base, exist_ok=True)
    output_dir = os.path.join(output_base, name_release)
    os.makedirs(output_dir, exist_ok=True)

    log_file_path = os.path.join(output_dir, "log.txt")
    dockerfile_generated = os.path.join(output_dir, "Dockerfile")
    cmdline_path = os.path.join(output_dir, "cmdline.txt")
    status_path = os.path.join(output_dir, "status.txt")


    if not check_internet_state():
        with open(log_file_path, 'w') as l:
            l.write('Error: no connection to internet.\n')
        with open(status_path, 'w') as s:
            s.write('error\n')
        print(f"[ERROR] {name_cve} ({name_release}): no internet connection.")
        return


    cmd = f"python3 -m decret -n {name_cve} -r {name_release} --dont-run --selenium -d {output_dir}"
    print(f"[DEBUG] Command executed: {cmd}")

    with open(log_file_path, 'w') as log:
        log.write(f"Command launched: {cmd}\n")
        log.write(f"Date: {datetime.now()}\n\n")
        try:
            # Run the command and capture outputs
            result = subprocess.run(
                cmd, shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=600
            )
            
            log.write(result.stdout)
            if result.stderr.strip():
                log.write(result.stderr)
            log.write(f"\n=== Return code: {result.returncode} ===\n")
            if os.path.exists(dockerfile_generated) and result.returncode == 0:
                status = "functional"
                print(f"[OK] {name_cve} ({name_release}): Dockerfile generated.")
            else:
                status = "error"
                print(f"[ERROR] {name_cve} ({name_release}): Execution failed or Dockerfile missing.")
            with open(status_path, 'w') as s:
                s.write(status + '\n')

            with open(cmdline_path, "w") as fcmd:
                fcmd.write(cmd + "\n")

        except Exception as exception:
            log.write(f"\nException caught during execution: {exception}\n")
            with open(status_path, 'w') as s:
                s.write('error\n')
            print(f"[EXCEPTION] {name_cve} ({name_release}): {exception}")

if __name__ == "__main__":
    """
    Main entry point.
    Parses the CVE file and launches the classification using run_decret_CVE for each CVE/release.
    Uses a thread pool (10 workers) to process multiple CVEs/releases in parallel. 
    """
    if len(sys.argv) < 2:
        print("Usage: python3 decret_auto.py <cve_file>")
        sys.exit(1)
    cve_file = sys.argv[1]
    cve_dict = parse_cve_file(cve_file)

    # Use a thread pool to process multiple CVEs/releases in parallel
    max_workers = 10
    tasks = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for cve, releases in cve_dict.items():
            for release in releases:
                future = executor.submit(run_decret_CVE, cve, release)
                tasks.append(future)
        for future in concurrent.futures.as_completed(tasks):
            try:
                future.result()
            except Exception as exc:
                print(f"[THREAD ERROR] {exc}")
    print("All tasks completed.")