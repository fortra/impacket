#!/usr/bin/env python
# $Id$

import glob
import os
import platform
import sys

from setuptools import setup

PACKAGE_NAME = "impacket"

with open('requirements.txt') as file_requirements:
    requirements = file_requirements.read().splitlines()

with open('requirements_examples.txt') as example_reqs:
    examples_requirements = example_reqs.read().splitlines()

if platform.system() == 'Windows':
    requirements.append('pyreadline')

if platform.system() != 'Darwin':
    data_files = [(os.path.join('share', 'doc', PACKAGE_NAME), ['README.md', 'LICENSE']+glob.glob('doc/*')),
                    (os.path.join('share', 'doc', PACKAGE_NAME, 'testcases', 'dot11'),glob.glob('impacket/testcases/dot11/*')),
                    (os.path.join('share', 'doc', PACKAGE_NAME, 'testcases', 'ImpactPacket'),glob.glob('impacket/testcases/ImpactPacket/*')),
                    (os.path.join('share', 'doc', PACKAGE_NAME, 'testcases', 'SMB_RPC'),glob.glob('impacket/testcases/SMB_RPC/*'))]
else:
    data_files = []

if sys.version_info[:2] < (2, 7):
    requirements.append('argparse')

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
      install_requires=requirements,
      extras_require={
                      'examples': [item for item in examples_requirements if item not in requirements]
                    }
      )

