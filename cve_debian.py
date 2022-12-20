from typing import Tuple

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

import requests
from selenium import webdriver
from selenium.webdriver.common.by import By

DEBIAN_VERSIONS = [
    "sarge",
    "etch",
    "lenny",
    "squeeze",
    "wheezy",
    "jessie",
    "stretch",
    "buster",
    "bullseye",
]

LATEST_VERSION = DEBIAN_VERSIONS[-1]

DEFAULT_TIMEOUT = 10


class FatalError(BaseException):
    pass


class CVENotFound(BaseException):
    pass


def arg_parsing():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-n",
        "--number",
        dest="cve_number",
        type=str,
        help="A CVE number to search (e.g.: 2022-38392)",
        required=True,
    )
    parser.add_argument(
        "-v",
        "--version",
        dest="version",
        type=str,
        choices=DEBIAN_VERSIONS,
        help="Debian Version name from 2005 to 2022",
        required=True,
    )
    parser.add_argument(
        "-d",
        "--directory",
        dest="directory",
        type=str,
        help="Directory path for the CVE experiment",
        default="./default",
    )
    parser.add_argument(
        "--fixed-version",
        dest="fixed_version",
        type=str,
        help="The fixed version number of the package",
    )
    parser.add_argument(
        "-p",
        "--package",
        dest="bin_package",
        type=str,
        help="Name of the binary package targeted.",
    )
    parser.add_argument(
        "--port",
        dest="port",
        type=int,
        help="Port forwarding between the Docker and the host",
    )
    parser.add_argument(
        "-s",
        "--selenium",
        dest="selenium",
        action="store_true",
        help="Activate the use of selenium (mandatory to download the exploit)",
    )
    parser.add_argument(
        "--do-not-use-sudo",
        dest="do_not_use_sudo",
        action="store_true",
        help="Do not use sudo to run docker commands",
    )
    parser.add_argument(
        "--cache-main-json-file",
        dest="cache_main_json_file",
        type=str,
        help="Path to load/save https://security-tracker.debian.org/tracker/data/json",
    )

    args = parser.parse_args()

    if not re.match(r"^2\d{3}-(0\d{2}[1-9]|[1-9]\d{3,})$", args.cve_number):
        parser.print_usage(sys.stderr)
        raise FatalError("Wrong CVE format.")

    return args


def check_program_is_present(progname, cmdline):
    try:
        subprocess.run(cmdline, check=True, shell=False, capture_output=True)
    except subprocess.CalledProcessError as exc:
        raise FatalError(
            f"{progname} does not seem to be installed. {cmdline} did not return 0."
        ) from exc


def check_requirements(args):
    check_program_is_present("Curl", ["curl", "-V"])
    check_program_is_present("Docker", ["docker", "-v"])
    if args.selenium:
        check_program_is_present("Firefox", ["firefox", "-v"])


def get_exploit(browser, args: argparse.Namespace):
    browser.get(f"https://www.exploit-db.com/search?cve={args.cve_number}")
    time.sleep(3)
    exploit_table = browser.find_element(By.ID, "exploits-table").find_element(
        By.XPATH, "./tbody"
    )

    if not os.path.exists(args.directory):
        os.makedirs(args.directory)

    i = 0
    for row in exploit_table.find_elements(By.XPATH, "./tr"):
        if row.text == "No data available in table":
            print("No exploit available. Continuing.")
            break
        link_exploit = row.find_element(By.XPATH, "./td[2]/a").get_attribute("href")
        verified = bool(
            "check" in row.find_element(By.XPATH, "./td[4]/i").get_attribute("class")
        )
        name_file = f"exploit_{i}"
        if verified:
            name_file += "_verified"

        with open(f"{args.directory}/{name_file}", "wb") as exploit_file:
            subprocess.run(["curl", link_exploit], stdout=exploit_file, check=True)
        i += 1


def prepare_browser():
    try:
        options = webdriver.FirefoxOptions()
        options.add_argument("--headless")
        return webdriver.Firefox(options=options)
    except Exception as exc:
        raise Exception("Selenium not installed ?") from exc


def search_in_table(version: str, info_table) -> Tuple[list[dict], list[str]]:
    results = []
    available_versions = []
    i = 0
    desired_version = False
    for row in info_table.find_elements(By.XPATH, "./tr"):
        if i == 0:
            i += 1
            continue
        data = row.text.split(" ")
        if "(unfixed)" in data:
            results.append(
                {
                    "src_package": data[0],
                    "release": "bullseye" if (data[2] == "(unstable)") else data[2],
                    "fixed_version": "(unfixed)",
                }
            )
        else:
            if version in data:
                desired_version = True
                src_package = data[0]
                release = data[2]
                fixed_version = data[3]
                results.append(
                    {
                        "src_package": src_package,
                        "release": release,
                        "fixed_version": fixed_version,
                    }
                )
            else:
                available_versions.append(data[2])
        i += 1

    if (
        desired_version
    ):  # If the desired version of Debian is present, we remove the unfixed version.
        results = [
            results[i] for i in range(len(results)) if results[i]["release"] == version
        ]
    return results, available_versions


def get_cve_details_from_selenium(browser, args: argparse.Namespace) -> list[dict]:
    cve_id = f"CVE-{args.cve_number}"
    try:
        browser.get(f"https://security-tracker.debian.org/tracker/{cve_id}")
    except Exception as exc:
        raise Exception("Selenium : Page not found. Wrong CVE number ?") from exc

    try:
        info_table = browser.find_element(By.XPATH, "/html/body/table[3]/tbody")

    except Exception:
        try:
            info_table = browser.find_element(By.XPATH, "/html/body/table[2]/tbody")
        except Exception as exc:
            raise Exception(
                "Selenium : Table not found. Are you connected to internet ?"
            ) from exc

    results, available_versions = search_in_table(args.version, info_table)

    if not results:
        versions_string = ", ".join(available_versions)
        raise Exception(
            f"Vulnerability not found for given Debian version. Try {versions_string}."
        )

    return results


def get_cve_details_from_json(args: argparse.Namespace) -> list[dict]:
    response = None
    if args.cache_main_json_file:
        json_cache_file = Path(args.cache_main_json_file)
        if json_cache_file.exists():
            json_content = json_cache_file.read_text(encoding="utf-8")
            response = json.loads(json_content)
    if not response:
        url = "https://security-tracker.debian.org/tracker/data/json"
        print(f"Fetching {url}")
        server_answer = requests.get(url, timeout=DEFAULT_TIMEOUT)
        response = server_answer.json()
        if args.cache_main_json_file:
            json_cache_file = Path(args.cache_main_json_file)
            json_cache_file.write_bytes(server_answer.content)

    results = []

    cve_id = f"CVE-{args.cve_number}"
    for package_name, package_info in response.items():
        if cve_id not in package_info:
            continue

        cve_info = package_info[cve_id]
        if args.version not in cve_info["releases"]:
            continue

        if args.fixed_version:
            fixed_version = args.fixed_version
        else:
            fixed_version = cve_info["releases"][args.version]["fixed_version"]
        if fixed_version == "0":
            raise CVENotFound(
                f"Debian {args.version} was not affected by {cve_id}.\n"
                f"Try another version."
                f"(see https://security-tracker.debian.org/tracker/CVE-{args.cve_number})."
            )
        results.append(
            {
                "src_package": package_name,
                "release": args.version,
                "fixed_version": fixed_version,
            }
        )

    if not results:
        raise CVENotFound("No affected package found.")

    return results


def get_vuln_version(cve_details: list[dict]) -> list[dict]:
    for item in cve_details:
        url = f"http://snapshot.debian.org/mr/package/{item['src_package']}/"
        response = requests.get(url, timeout=DEFAULT_TIMEOUT).json()["result"]
        known_versions = [x["version"] for x in response]
        if item["fixed_version"] == "(unfixed)":
            item["vuln_version"] = known_versions[0]  # We select the latest version
        else:
            for version, prev_version in zip(known_versions[:-1], known_versions[1:]):
                if version == item["fixed_version"]:
                    item["vuln_version"] = prev_version
                    break
        if not item["vuln_version"]:
            raise Exception("Vulnerable version of the packages not found.")
    return cve_details


def get_bin_names(cve_details: list[dict]) -> list[str]:
    bin_names = []
    for item in cve_details:
        url = f"http://snapshot.debian.org/mr/package/{item['src_package']}/{item['vuln_version']}/binpackages"
        response = requests.get(url, timeout=DEFAULT_TIMEOUT).json()["result"]
        for res in response:
            bin_names.append(res["name"])

    return bin_names


def get_hash_and_bin_names(
    args: argparse.Namespace, cve_details: list[dict]
) -> list[dict]:
    i = 0
    for item in cve_details:
        try:
            url = f"http://snapshot.debian.org/mr/binary/{item['src_package']}/{item['vuln_version']}/binfiles"
            response = requests.get(url, timeout=DEFAULT_TIMEOUT).json()["result"]
            for res in response:
                if res["architecture"] == "amd64" or res["architecture"] == "all":
                    item["hash"] = res["hash"]
            item["bin_name"] = [item["src_package"]]
        except Exception:
            try:
                # We get the hash from the src files, but we also collect the
                # binary packages names associated for the Dockerfile.
                url = f"http://snapshot.debian.org/mr/package/{item['src_package']}/{item['vuln_version']}/srcfiles"
                response = requests.get(url, timeout=DEFAULT_TIMEOUT).json()["result"]
                item["hash"] = response[-1]["hash"]
                item["bin_name"] = get_bin_names(cve_details)

            except Exception as exc:
                raise Exception(
                    "Couldn't find the source files for the Linux packages."
                ) from exc

        if item["src_package"] == "linux":
            item["bin_name"] = []

        if args.bin_package:
            if args.bin_package in item["bin_name"]:
                item["bin_name"] = args.bin_package
            else:
                raise Exception(
                    "Non existing binary package provided. Check your '-p' option."
                )

        i += 1
    return cve_details


def get_snapshot(cve_details: list[dict]):
    snapshot_id = []
    for item in cve_details:
        url = f"http://snapshot.debian.org/mr/file/{item['hash']}/info"
        response = requests.get(url, timeout=DEFAULT_TIMEOUT).json()["result"][0]
        snapshot_id.append(response["first_seen"])

    if not snapshot_id:
        raise Exception("Snapshot id not found.")

    return snapshot_id


def write_sources(args: argparse.Namespace, snapshot_id: str, vuln_fixed: bool):
    with open(f"{args.directory}/sources.list", "w", encoding="utf-8") as file:
        if vuln_fixed:
            file.write(
                f"deb http://snapshot.debian.org/archive/debian/{snapshot_id}/ {args.version} main\n"
            )
        else:
            file.write(
                f"deb http://deb.debian.org/debian {LATEST_VERSION} main\n"
                f"deb http://deb.debian.org/debian-security {LATEST_VERSION}-security main\n"
                f"deb http://deb.debian.org/debian {LATEST_VERSION}-updates main\n"
            )


def docker_build_and_run(args, cve_details, vuln_fixed):
    binary_packages = []
    for item in cve_details:
        binary_packages.extend(item["bin_name"])
    packages_string = " ".join(binary_packages)
    if not vuln_fixed:
        print(f"\n\nVulnerability unfixed. Using a {LATEST_VERSION} container.\n\n")
        args.version = LATEST_VERSION

    docker_image_name = f"{args.version}/cve-{args.cve_number}"
    print("Building the Docker image.")
    try:
        if args.do_not_use_sudo:
            build_cmd = []
        else:
            build_cmd = ["sudo"]
        build_cmd.extend(["docker", "build"])
        build_cmd.extend(["-t", docker_image_name])
        for arg_name, arg_value in [
            ("DEBIAN_VERSION", args.version),
            ("PACKAGE_NAME", packages_string),
            ("DIRECTORY", args.directory),
        ]:
            build_cmd.extend(["--build-arg", f"{arg_name}={arg_value}"])
        build_cmd.append(".")
        try:
            subprocess.run(build_cmd, check=True)
        except subprocess.CalledProcessError as exc:
            print("The building process has failed.", file=sys.stderr)
            raise exc

        print("Running the Docker. The shared directory is '/tmp/snappy'.")

        if args.do_not_use_sudo:
            run_cmd = []
        else:
            run_cmd = ["sudo"]
        run_cmd.extend(["docker", "run", "--privileged", "-it", "--rm"])
        run_cmd.extend(["-v", f"{os.path.abspath(args.directory)}:/tmp/snappy"])
        run_cmd.extend(["-h", f"cve-{args.cve_number}"])
        run_cmd.extend(["--name", f"cve-{args.cve_number}"])
        if args.port:
            run_cmd.extend(["-p" f"{args.port}:{args.port}"])
        run_cmd.append(docker_image_name)

        subprocess.run(run_cmd, check=True)

    except Exception as exc:
        exit(exc)


def main():  # pragma: no cover
    try:
        args = arg_parsing()
        check_requirements(args)
        if args.selenium:
            # Get the exploits from https://www.exploit-db.com/
            browser = prepare_browser()
            get_exploit(browser, args)
    except Exception as exc:
        exit(exc)
    try:
        # We try to get the details by the Debian JSON
        cve_details = get_cve_details_from_json(args)
    except CVENotFound:
        if args.selenium:
            try:
                # We use Selenium when the CVE is not in the Tracker JSON
                cve_details = get_cve_details_from_selenium(browser, args)
            except Exception as exc:
                exit(exc)
            finally:
                browser.quit()
        else:
            exit(
                "Can't get the details for CVE. You should activate selenium with --selenium."
            )

    vuln_fixed = not any(
        [item["fixed_version"] == "(unfixed)" for item in cve_details]
    )  # False if (unfixed) in cve_details
    cve_details = get_vuln_version(cve_details)
    cve_details = get_hash_and_bin_names(args, cve_details)
    snapshot_id = min(
        get_snapshot(cve_details)
    )  # We keep the oldest snapshot possibility

    if not os.path.exists(args.directory):  # Create the directory if necessary
        os.makedirs(args.directory)

    write_sources(args, snapshot_id, vuln_fixed)

    docker_build_and_run(args, cve_details, vuln_fixed)

    return 0


if __name__ == "__main__":  # pragma: no cover
    main()
