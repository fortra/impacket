# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Custom URL Parser
#
#   A custom url parser based on the "urlparse" library.
#   Helps to capture usernames from the targets file which were specified with regex.
#
# Author:
#   Roy Rahamim / @0xRoyR
#
import re
from urllib.parse import urlparse


class ParsedCustom:
    def __init__(self, url):
        self.scheme = None
        self.username = None
        self.netloc = None
        self.hostname = None
        self.port = None
        self.geturl = None

        parsed = urlparse(url)
        match_username = re.search('://(.*?)@', url)
        if match_username:
            self.scheme = parsed.scheme
            self.username = match_username.group(1)
            self.netloc = parsed.netloc
            self.hostname = url.split('@')[-1]
            self.port = parsed.port
            self.geturl = parsed.geturl
            self._replace = parsed._replace
    
    # For debugging purposes
    def __str__(self):
        return '----- Custom Parsed URL -----\nscheme:{0}\nusername:{1}\nnetloc:{2}\nhostname:{3}\nport:{4}\ngeturl:{5}\n------------------------------'.format(self.scheme, self.username, self.netloc, self.hostname, self.port, self.geturl)