#!/usr/bin/python
# $Id$

import glob
import os

from distutils.core import setup

setup(name = "Conspired",
      version = "0.9",
      description = "Network Protocols Constructors and Dissectors",
      url = "http://oss.coresecurity.com/conspired",
      author = "CORE Security Technologies",
      author_email = "oss@coresecurity.com",
      maintainer = "Javier Kohen",
      maintainer_email = "jkohen@coresecurity.com",
      packages = ['impact', 'impact.dcerpc'],
      scripts = glob.glob(os.path.join('examples', '*.py')),
      )
