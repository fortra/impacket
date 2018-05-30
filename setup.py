#!/usr/bin/env python
# $Id$

import glob
import os
import platform
import sys

from setuptools import setup

PACKAGE_NAME = "impacket"

if platform.system() != 'Darwin':
    data_files = [(os.path.join('share', 'doc', PACKAGE_NAME), ['README.md', 'LICENSE']+glob.glob('doc/*'))]
else:
    data_files = []

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name = PACKAGE_NAME,
      version = "0.9.17",
      description = "Network protocols Constructors and Dissectors",
      url = "https://www.coresecurity.com/corelabs-research/open-source-tools/impacket",
      author = "Core Security Technologies",
      author_email = "oss@coresecurity.com",
      maintainer = "Alberto Solino",
      maintainer_email = "bethus@gmail.com",
      license = "Apache modified",
      long_description = read('README.md'),
      long_description_content_type="text/markdown",
      platforms = ["Unix","Windows"],
      packages=['impacket', 'impacket.dcerpc', 'impacket.examples', 'impacket.dcerpc.v5', 'impacket.dcerpc.v5.dcom',
                'impacket.krb5', 'impacket.ldap', 'impacket.examples.ntlmrelayx',
                'impacket.examples.ntlmrelayx.clients', 'impacket.examples.ntlmrelayx.servers',
                'impacket.examples.ntlmrelayx.servers.socksplugins', 'impacket.examples.ntlmrelayx.utils',
                'impacket.examples.ntlmrelayx.attacks'],
      scripts = glob.glob(os.path.join('examples', '*.py')),
      data_files = data_files,
      install_requires=['pyasn1>=0.2.3', 'pycrypto>=2.6.1', 'pyOpenSSL>=0.13.1', 'six', 'ldap3>=2.5.0', 'ldapdomaindump', 'flask'],
      extras_require={
                      'pyreadline:sys_platform=="win32"': [],
                      ':python_version<"2.7"': [ 'argparse' ],
                    },
      classifiers = [
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 2.6",
      ]
      )

