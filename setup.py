#!/usr/bin/python
# $Id$

import glob
import os

from distutils.core import setup

setup(name = "Impacket",
      version = "0.9",
      description = "Network protocols Constructors and Dissectors",
      url = "http://oss.coresecurity.com/impacket",
      author = "CORE Security Technologies",
      author_email = "oss@coresecurity.com",
      maintainer = "Javier Kohen",
      maintainer_email = "jkohen@coresecurity.com",
      packages = ['impacket', 'impacket.dcerpc'],
      scripts = glob.glob(os.path.join('examples', '*.py')),
      )
