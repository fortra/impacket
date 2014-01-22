#!/usr/bin/python
# $Id$

import glob
import os

from distutils.core import setup

PACKAGE_NAME = "impacket"

setup(name = PACKAGE_NAME,
      version = "0.9.11",
      description = "Network protocols Constructors and Dissectors",
      url = "http://oss.coresecurity.com/projects/impacket.html",
      author = "CORE Security Technologies",
      author_email = "oss@coresecurity.com",
      maintainer = "Alberto Solino",
      maintainer_email = "bethus@gmail.com",
      license = "Apache modified",
      long_description = 'Impacket is a collection of Python classes focused on providing access to network packets. Impacket allows Python developers to craft and decode network packets in simple and consistent manner.',
      platforms = ["Unix","Windows"],
      packages = ['impacket', 'impacket.dcerpc', 'impacket.examples', 'impacket.dcerpc.v5'],
      scripts = glob.glob(os.path.join('examples', '*.py')),
      data_files = [(os.path.join('share', 'doc', PACKAGE_NAME),
                     ['README', 'LICENSE']+glob.glob('doc/*'))],

      )
