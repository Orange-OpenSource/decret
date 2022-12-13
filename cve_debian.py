import argparse
import os
import re
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service
import time


def arg_parsing():
    debian_versions = ["sarge", "etch", "lenny", "squeeze", "wheezy", "jessie", "stretch", "buster", "bullseye"]

    parser = argparse.ArgumentParser(prog="Debian CVE reproduction automation")
    parser.add_argument("-n", "--number", dest="cve_number", type=str, help="A CVE number to search", required=True)
    parser.add_argument("-v", "--version", dest="version", type=str,
                        help="Debian Version name from 2005 to 2022 (sarge, etch, "
                             "lenny, squeeze, "
                             "wheezy, jessie, stretch, buster, bullseye)",
                        required=True)
    parser.add_argument("-d", "--directory", dest="directory", type=str, help="Directory path for the CVE experiment",
                        default="./default")
    parser.add_argument("--fixed-version", dest="fixed_version", type=str,
                        help="The fixed version number of the package")
    parser.add_argument("-p", "--package", dest="bin_package", type=str, help="Name of the binary package targeted.")
    parser.add_argument("-s", "--selenium", dest="selenium", action='store_true',
                        help="Activate the use of selenium (mandatory to download the exploit)")

    args = parser.parse_args()

    if args.version not in debian_versions:
        raise Exception(
            "Wrong Debian version. Available versions: sarge, etch, lenny, squeeze, wheezy, jessie, stretch, buster, bullseye")

    if not bool(re.match("^2\d{3}-(0\d{2}[1-9]|[1-9]\d{3,})$", args.cve_number)):
        raise Exception("Wrong CVE formatting. Please enter a number like '2022-38392'.")
    return args


def check_curl():  # Check if curl is installed
    try:
        os.system('curl -V')
        return True
    except Exception:
        raise Exception("Curl is not installed. Please install it and retry.")


def get_exploit(browser, args: argparse.Namespace):
    browser.get('https://www.exploit-db.com/search?cve=%s' % args.cve_number)
    time.sleep(3)
    exploit_table = browser.find_element(By.ID, "exploits-table").find_element(By.XPATH, "./tbody")

    if not os.path.exists(args.directory):
        os.makedirs(args.directory)

    i = 0
    for row in exploit_table.find_elements(By.XPATH, "./tr"):
        if row.text == "No data available in table":
            print("No exploit available. Continuing.")
            break
        link_exploit = row.find_element(By.XPATH, "./td[2]/a").get_attribute("href")
        verified = bool("check" in row.find_element(By.XPATH, "./td[4]/i").get_attribute("class"))
        name_file = "exploit_%s" % i
        if verified:
            name_file += "_verified"

        if check_curl():
            os.system("curl %s > %s/%s" % (link_exploit, args.directory, name_file))
        i += 1


def prepare_browser():  # TODO: make it universal
    try:
        options = webdriver.FirefoxOptions()
        options.binary_location = "/usr/bin/firefox"
        options.add_argument("--headless")
        driverService = Service('/usr/local/bin/geckodriver')
        return webdriver.Firefox(service=driverService, options=options)
    except Exception as e:
        raise Exception("%s : Selenium not installed ?" % e)


def search_in_table(version: str, info_table) -> (list[dict], str):
    results = []
    available_versions = ""
    i = 0
    for row in info_table.find_elements(By.XPATH, "./tr"):
        if i == 0:
            i += 1
            continue
        data = row.text.split(" ")
        if "(unfixed)" in data:
            results.append(
                {'src_package': data[0], 'release': "bullseye" if (data[2] == "(unstable)") else data[2],
                 'fixed_version': "(unfixed)"})
        else:
            if version in data:
                src_package = data[0]
                release = data[2]
                fixed_version = data[3]
                results.append({"src_package": src_package, "release": release, "fixed_version": fixed_version})
            else:
                available_versions += "%s," % data[2]
        i += 1
    return results, available_versions[:-1]


def get_cve_details(browser, args: argparse.Namespace):
    try:
        browser.get('https://security-tracker.debian.org/tracker/CVE-%s' % args.cve_number)
    except Exception:
        raise Exception("Selenium : Page not found. Wrong CVE number ?")

    try:
        info_table = browser.find_element(By.XPATH, "/html/body/table[3]/tbody")

    except Exception:
        try:
            info_table = browser.find_element(By.XPATH, "/html/body/table[2]/tbody")
        except Exception:
            raise Exception("Selenium : Table not found. Are you connected to internet ?")

    results, available_versions = search_in_table(args.version, info_table)

    if not results:
        raise Exception("Vulnerability not found for given Debian version. Try %s." % available_versions)
    else:
        return results


def get_cve_details_json(args: argparse.Namespace) -> list[dict]:
    response = requests.get("https://security-tracker.debian.org/tracker/data/json").json()
    results = []
    available_versions = ""
    for p in response:
        if "CVE-%s" % args.cve_number in response[p].keys():
            available_versions += "%s," % response[p]["CVE-%s" % args.cve_number]["releases"].keys()
            if args.version in response[p]["CVE-%s" % args.cve_number]["releases"].keys():
                fixed_version = response[p]["CVE-%s" % args.cve_number]["releases"][args.version][
                    "fixed_version"]
                if fixed_version == "0":
                    raise Exception(
                        "Debian version not affected. Try an other version (see https://security-tracker.debian.org/tracker/CVE-%s)." % args.cve_number)
                results.append({"src_package": p, "release": args.version,
                                "fixed_version": fixed_version})

    if not results:
        raise Exception

    if args.fixed_version:
        results[0]["fixed_version"] = args.fixed_version
    return results


def get_vuln_version(cve_details: list[dict]) -> list[dict]:
    for el in cve_details:
        response = requests.get("http://snapshot.debian.org/mr/package/%s/" % el["src_package"]).json()["result"]
        if el["fixed_version"] == "(unfixed)":
            el["vuln_version"] = response[0]["version"]  # We select the latest version
        else:
            for v in range(len(response)):
                if response[v]["version"] == el["fixed_version"] and v != len(response):
                    el["vuln_version"] = response[v + 1]["version"]
        if not el["vuln_version"]:
            raise Exception("Vulnerable version of the packages not found.")
    return cve_details


def get_bin_names(cve_details):
    bin_names = ""
    for el in cve_details:
        response = requests.get(
            "http://snapshot.debian.org/mr/package/%s/%s/binpackages" % (el["src_package"], el["vuln_version"])).json()[
            "result"]
        for res in response:
            bin_names += res["name"] + " "

    return bin_names.strip()


def get_hash_and_bin_names(args: argparse.Namespace, cve_details: list[dict]) -> list[dict]:
    i = 0
    for el in cve_details:
        try:
            response = \
                requests.get(
                    "http://snapshot.debian.org/mr/binary/%s/%s/binfiles" % (
                        el["src_package"], el["vuln_version"])).json()[
                    "result"]
            for res in response:
                if res["architecture"] == "amd64" or res["architecture"] == "all":
                    el["hash"] = res["hash"]
            el["bin_name"] = el["src_package"]
        except Exception:
            try:  # We get the hash from the src files, but we also collect the binary packages names associated for the Dockerfile.
                response = requests.get(
                    "http://snapshot.debian.org/mr/package/%s/%s/srcfiles" % (
                        el["src_package"], el["vuln_version"])).json()["result"]
                el["hash"] = response[-1]["hash"]
                el["bin_name"] = get_bin_names(cve_details)

            except Exception:
                raise Exception("Couldn't find the source files for the Linux packages.")

        if el["src_package"] == "linux":
            el["bin_name"] = ""

        if args.bin_package:
            if bool(re.match(".*\s%s\s.*" % args.bin_package, el["bin_name"])):
                el["bin_name"] = args.bin_package
            else:
                raise Exception("Non existing binary package provided. Check your '-p' option.")

        i += 1
    return cve_details


def get_snapshot(cve_details: list[dict]):
    snapshot_id = []
    for el in cve_details:
        response = requests.get("http://snapshot.debian.org/mr/file/%s/info" % el["hash"]).json()["result"][0]
        snapshot_id.append(response["first_seen"])

    if not snapshot_id:
        raise Exception("Snapshot id not found.")
    else:
        return snapshot_id


def write_sources(args, snapshot_id, vuln_fixed: bool):
    with open("%s/sources.list" % args.directory, "w") as file:  # TODO : make only one write() call
        if vuln_fixed:
            file.write("deb http://snapshot.debian.org/archive/debian/%s/ %s main\n" % (snapshot_id, args.version))
            file.write("#deb-src http://snapshot.debian.org/archive/debian/%s/ %s main\n" % (snapshot_id, args.version))
            file.write("#deb http://snapshot.debian.org/archive/debian-security/%s/ %s-updates main\n" % (
                snapshot_id, args.version))
            file.write("#deb-src http://snapshot.debian.org/archive/debian-security/%s/ %s-updates main\n" % (
                snapshot_id, args.version))
        else:
            file.write("deb http://deb.debian.org/debian bullseye main\n"
                       "deb http://deb.debian.org/debian-security bullseye-security main\n"
                       "deb http://deb.debian.org/debian bullseye-updates main\n")


def docker_build_and_run(args, cve_details):
    packages_string = "".join([i["bin_name"] + " " for i in cve_details]).strip()
    docker_image_name = "%s/cve-%s" % (args.version, args.cve_number)
    print("Building the Docker image")
    try:
        i = os.system(
            "sudo docker build -t %s --build-arg DEBIAN_VERSION=%s --build-arg PACKAGE_NAME='%s' --build-arg DIRECTORY=%s . || false" % (
                docker_image_name, args.version, packages_string, args.directory))
        if bool(i):
            raise Exception("The building process has failed.")

        print("Running the Docker")
        os.system("sudo docker run --privileged -v %s:/tmp/snappy -h 'cve-%s' --name cve-%s -it --rm %s " % (
            os.path.abspath(args.directory), args.cve_number, args.cve_number, docker_image_name))
    except Exception as e:
        exit(e)


def main():
    try:
        args = arg_parsing()
        if args.selenium:  # Get the exploits from https://www.exploit-db.com/
            browser = prepare_browser()
            get_exploit(browser, args)
    except Exception as e:
        exit(e)
    try:
        cve_details = get_cve_details_json(args)  # We try to get the details by the Debian JSON
    except Exception:
        if args.selenium:
            try:
                cve_details = get_cve_details(browser, args)  # We use Selenium when the CVE is not in the Tracker JSON
            except Exception as e:
                exit(e)
            finally:
                browser.quit()
        else:
            exit("Can't get the details for CVE. You should activate selenium with --selenium.")

    vuln_fixed = not any(
        [el["fixed_version"] == "(unfixed)" for el in cve_details])  # False if (unfixed) in cve_details
    cve_details = get_vuln_version(cve_details)
    cve_details = get_hash_and_bin_names(args, cve_details)
    snapshot_id = min(get_snapshot(cve_details))  # We keep the oldest snapshot possibility

    if not os.path.exists(args.directory):
        os.makedirs(args.directory)

    write_sources(args, snapshot_id, vuln_fixed)

    docker_build_and_run(args, cve_details)

    return 0


if __name__ == "__main__":
    start = time.time()
    main()
    # print("Executed in %.2fs." % (time.time() - start))
