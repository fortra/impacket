#!/usr/bin/python

import glob
import os

from distutils.core import setup

setup(name = "Conspired",
      version = "0.0",
      description = "Network Protocols Constructors and Dissectors",
      author = "CORE Security Technologies",
      author_email = "opensource@coresecurity.com",
      maintainer = "Javier Kohen",
      maintainer_email = "jkohen@coresecurity.com",
##       url = "http://opensource.coresecurity.com/",
      packages = ['impact', 'impact.dcerpc'],
      scripts = glob.glob(os.path.join('examples', '*.py')),
      )
