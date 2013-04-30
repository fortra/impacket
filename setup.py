#!/usr/bin/python
# $Id$

import glob
import os

from distutils.core import setup

PACKAGE_NAME = "impacket"

setup(name = PACKAGE_NAME,
      version = "1.0.0.0-dev",
      description = "Network protocols Constructors and Dissectors",
      url = "http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Impacket",
      author = "CORE Security Technologies",
      author_email = "oss@coresecurity.com",
      maintainer = "Alberto Solino",
      maintainer_email = "bethus@gmail.com",
      packages = ['impacket', 'impacket.dcerpc', 'impacket.examples'],
      scripts = glob.glob(os.path.join('examples', '*.py')),
      data_files = [(os.path.join('share', 'doc', PACKAGE_NAME),
                     ['README', 'LICENSE']+glob.glob('doc/*'))],
      )
