#!/usr/bin/python
# $Id$

import glob
import os

from distutils.core import setup

PACKAGE_NAME = "Impacket"

setup(name = PACKAGE_NAME,
      version = "0.9.5.2",
      description = "Network protocols Constructors and Dissectors",
      url = "http://oss.coresecurity.com/projects/impacket.html",
      author = "CORE Security Technologies",
      author_email = "oss@coresecurity.com",
      maintainer = "Max Caceres",
      maintainer_email = "max@coresecurity.com",
      packages = ['impacket', 'impacket.dcerpc'],
      scripts = glob.glob(os.path.join('examples', '*.py')),
      data_files = [(os.path.join('share', 'doc', PACKAGE_NAME),
                     ['README', 'LICENSE'])],
      )
