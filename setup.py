#!/usr/bin/python
# $Id$

import glob
import os

from distutils.core import setup

PACKAGE_NAME = "Impacket"

setup(name = PACKAGE_NAME,
      version = "0.9.9.0-dev",
      description = "Network protocols Constructors and Dissectors",
      url = "http://oss.coresecurity.com/projects/impacket.html",
      author = "CORE Security Technologies",
      author_email = "oss@coresecurity.com",
      maintainer = "Alberto Solino",
      maintainer_email = "bethus@gmail.com",
      packages = ['impacket', 'impacket.dcerpc'],
      scripts = glob.glob(os.path.join('examples', '*.py')),
      data_files = [(os.path.join('share', 'doc', PACKAGE_NAME),
                     ['README', 'LICENSE']+glob.glob('doc/*'))],
      )
