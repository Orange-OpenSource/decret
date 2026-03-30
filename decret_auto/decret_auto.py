import os
import socket
import shutil
import subprocess
from datetime import datetime
import concurrent.futures
import sys

# --------------------------------------------------------------------------------------------------------------------------------------------------------- 
# Author: CHAKER Zakaria
# Description:
#   This script automates the classification of CVEs and the generation of associated Dockerfiles.
#   It uses the DECRET tool to determine, for each provided Debian CVE, whether a complete Dockerfile can be constructed.
#   CVEs are classified automatically: if the Dockerfile is built without error, the CVE is considered functional for DECRET.
#   This version can be improved by adding more exception handling and advanced checks.
#   ---
#   Ce script a pour but d'automatiser la classification des CVEs et la génération des Dockerfiles associés à chaque CVE (en plus d'autres fichiers utiles à leur analyse).
#   Nous utiliserons DECRET pour cette classification qui determinera, en fonction des CVEs DEBIAN entrées, celles qui amèneront à la construction complète d'un Dockerfile valide. 
#   Et donc indirectement celles qui permetteront de générer un conteneur...
#   Cette version peut être ameliorée: en ajoutant des vérifications supplémentaires (exceptions et optimisations liées à la complexité du script).
# Version: 1.0
# --------------------------------------------------------------------------------------------------------------------------------------------------------- 

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
    If no release is specified (empty after ':' or no ':'), uses 4 default releases.
    Empty lines are ignored.
    Args:
        filename (str): Path to the configuration file.
    Returns:
        dict: Dictionary mapping each CVE to a list of releases.
    """
    DEFAULT_RELEASES = ["trixie", "bookworm", "bullseye", "buster"]
    cve_dict = {}
    with open(filename, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                cve, releases = line.split(":", 1)
                cve = cve.strip()
                releases_list = [r.strip() for r in releases.split(",") if r.strip()]
                if not releases_list:
                    releases_list = DEFAULT_RELEASES.copy()
                cve_dict[cve] = releases_list
            else:
                cve = line.strip()
                if cve:
                    cve_dict[cve] = DEFAULT_RELEASES.copy()
    return cve_dict

def run_decret_CVE(name_cve, name_release):
    """
    For a given cve and release its run the Decret tool with the mode --dont-run.
    For each running, creates directorites by CVE and subdirectories by release.
    For example:
       /
       |_CVE-2015-xxxx
       | |_trixie
       |_CVE-2014-xxxx
         |_bullseye
         |_buster
    For each release, it generates 4 files (logfile, Dockerfile (if CVE available), cmdline and status).
    If a complete Dockerfile is generated and the return code is 0, the CVE is considered functional.
    Otherwise, it is considered an error.

    Args:
        name_cve (str): The CVE identifier
        name_release (str): The release name (e.g., 'buster', 'bullseye'). #We have to add a verification of the release name... If the release is correct?
    """
    
    cve_dir = f"decret_{name_cve}"
    os.makedirs(cve_dir, exist_ok=True)
    output_dir = os.path.join(cve_dir, name_release)
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
        print(f"[ERROR] {name_cve} ({name_release}): no connection internet.")
        return

    cmd = f"python3 -m decret -n {name_cve} -r {name_release} --dont-run --selenium -d {output_dir}"
    print(f"[DEBUG] Commande exécutée : {cmd}")

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
        print("Usage: python3 decret_auto.py <fichier_cve>")
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