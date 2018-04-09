#!/usr/bin/env python
# $Id$

import glob
import os
import platform
import sys

from setuptools import setup

PACKAGE_NAME = "impacket"

if platform.system() != 'Darwin':
    data_files = [(os.path.join('share', 'doc', PACKAGE_NAME), ['README.md', 'LICENSE']+glob.glob('doc/*')),
                    (os.path.join('share', 'doc', PACKAGE_NAME, 'tests', 'dot11'),glob.glob('tests/dot11/*')),
                    (os.path.join('share', 'doc', PACKAGE_NAME, 'tests', 'ImpactPacket'),glob.glob('tests/ImpactPacket/*')),
                    (os.path.join('share', 'doc', PACKAGE_NAME, 'tests', 'SMB_RPC'),glob.glob('tests/SMB_RPC/*'))]
else:
    data_files = []

setup(name = PACKAGE_NAME,
      version = "0.9.17-dev",
      description = "Network protocols Constructors and Dissectors",
      url = "https://www.coresecurity.com/corelabs-research/open-source-tools/impacket",
      author = "Core Security Technologies",
      author_email = "oss@coresecurity.com",
      maintainer = "Alberto Solino",
      maintainer_email = "bethus@gmail.com",
      license = "Apache modified",
      long_description = 'Impacket is a collection of Python classes focused on providing access to network packets. Impacket allows Python developers to craft and decode network packets in simple and consistent manner.',
      platforms = ["Unix","Windows"],
      packages=['impacket', 'impacket.dcerpc', 'impacket.examples', 'impacket.dcerpc.v5', 'impacket.dcerpc.v5.dcom',
                'impacket.krb5', 'impacket.ldap', 'impacket.examples.ntlmrelayx',
                'impacket.examples.ntlmrelayx.clients', 'impacket.examples.ntlmrelayx.servers',
                'impacket.examples.ntlmrelayx.servers.socksplugins', 'impacket.examples.ntlmrelayx.utils'],
      scripts = glob.glob(os.path.join('examples', '*.py')),
      data_files = data_files,
      install_requires=['pyasn1>=0.2.3', 'pycrypto>=2.6.1', 'pyOpenSSL>=0.13.1', 'six'],
      extras_require={
                      'pyreadline:sys_platform=="win32"': [],
                      ':python_version<"2.7"': [ 'argparse' ],
                      'examples': [ 'ldap3==2.4.1', 'ldapdomaindump', 'flask'],
                    },
      classifiers = [
          "Programming Language :: Python :: 2.7",
          "Programming Language :: Python :: 2.6",
      ]
      )

