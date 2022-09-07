Impacket
========

[![Latest Version](https://img.shields.io/pypi/v/impacket.svg)](https://pypi.python.org/pypi/impacket/)
[![Build and test Impacket](https://github.com/SecureAuthCorp/impacket/actions/workflows/build_and_test.yml/badge.svg)](https://github.com/SecureAuthCorp/impacket/actions/workflows/build_and_test.yml)

SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.

Impacket is a collection of Python classes for working with network
protocols. Impacket is focused on providing low-level
programmatic access to the packets and for some protocols (e.g.
SMB1-3 and MSRPC) the protocol implementation itself.
Packets can be constructed from scratch, as well as parsed from 
raw data, and the object-oriented API makes it simple to work with 
deep hierarchies of protocols. The library provides a set of tools
as examples of what can be done within the context of this library.

A description of some of the tools can be found at
[SecureAuth Labs' Open Source Website](https://www.secureauth.com/labs/open-source-tools/impacket).


What protocols are featured?
----------------------------

 * Ethernet, Linux "Cooked" capture.
 * IP, TCP, UDP, ICMP, IGMP, ARP.
 * IPv4 and IPv6 Support.
 * NMB and SMB1, SMB2 and SMB3 (high-level implementations).
 * MSRPC version 5, over different transports: TCP, SMB/TCP, SMB/NetBIOS and HTTP.
 * Plain, NTLM and Kerberos authentications, using password/hashes/tickets/keys.
 * Portions/full implementation of the following MSRPC interfaces: EPM, DTYPES, LSAD, LSAT, NRPC, RRP, SAMR, SRVS, WKST, SCMR, BKRP, DHCPM, EVEN6, MGMT, SASEC, TSCH, DCOM, WMI, OXABREF, NSPI, OXNSPI.
 * Portions of TDS (MSSQL) and LDAP protocol implementations.
 
Maintainer
==========

[<img src="https://www.secureauth.com/wp-content/uploads/2020/10/SA_Logo_Blue_Hori-web.png" width="320"/>](https://www.secureauth.com/)


Table of Contents
=================

* [Getting Impacket](#getting-impacket)
* [Setup](#setup)
* [Testing](#testing)
* [Licensing](#licensing)
* [Disclaimer](#disclaimer)
* [Contact Us](#contact-us)

Getting Impacket
================

### Latest version

* Impacket v0.10.0

  [![Python versions](https://img.shields.io/pypi/pyversions/impacket.svg)](https://pypi.python.org/pypi/impacket/)

[Current and past releases](https://github.com/SecureAuthCorp/impacket/releases)

### Development version

* Impacket v0.10.1-dev (**[master branch](https://github.com/SecureAuthCorp/impacket/tree/master)**)

  [![Python versions](https://img.shields.io/badge/python-3.6%20|%203.7%20|%203.8%20|%203.9-blue.svg)](https://github.com/SecureAuthCorp/impacket/tree/master)


Setup
=====

### Quick start

In order to grab the latest stable release with `pip` run:

    python3 -m pip install impacket

> :information_source: This will make the Impacket library available to
your Python code, but will not provide you with the example scripts. 

### Installing the library + example scripts

In order to install the library and the example scripts, download and
extract the package, and execute the following command from the
directory where the Impacket's release has been unpacked:

    python3 -m pip install .

> :information_source: This will install the library into the default Python
modules path, where you can make use of the example scripts from the directory.

> :warning: Make sure the example scripts you're using are consistent with the
library version that's installed in your python environment.
We recommend using [virtual environments](https://docs.python.org/3/library/venv.html) to
make sure system-wide installations doesn't interfere with it.


### Docker Support

Build Impacket's image:

      $ docker build -t "impacket:latest" .

Using Impacket's image:

      $ docker run -it --rm "impacket:latest"

Testing
=======

The library leverages the [pytest](https://docs.pytest.org/) framework for organizing
and marking test cases, [tox](https://tox.readthedocs.io/) to automate the process of
running them across supported Python versions, and [coverage](https://coverage.readthedocs.io/)
to obtain coverage statistics.

A [comprehensive testing guide](TESTING.md) is available.


Licensing
=========

This software is provided under a slightly modified version of
the Apache Software License. See the accompanying [LICENSE](LICENSE) file for
more information.

SMBv1 and NetBIOS support based on Pysmb by Michael Teo.

Disclaimer
==========

The spirit of this Open Source initiative is to help security researchers,
and the community, speed up research and educational activities related to
the implementation of networking protocols and stacks.

The information in this repository is for research and educational purposes
and not meant to be used in production environments and/or as part
of commercial products.

If you desire to use this code or some part of it for your own uses, we
recommend applying proper security development life cycle and secure coding
practices, as well as generate and track the respective indicators of
compromise according to your needs.


Contact Us
==========

Whether you want to report a bug, send a patch, or give some suggestions
on this package, drop us a few lines at oss@secureauth.com.

For security-related questions check our [security policy](SECURITY.md).
