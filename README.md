What is Impacket?
=================

Impacket is a collection of Python classes for working with network
protocols. Impacket is focused on providing low-level
programmatic access to the packets and for some protocols (for
instance NMB, SMB1-3 and MS-DCERPC) the protocol implementation itself.
Packets can be constructed from scratch, as well as parsed from 
raw data, and the object oriented API makes it simple to work with 
deep hierarchies of protocols. The library provides a set of tools
as examples of what can be done within the context of this library.

A description of some of the tools can be found at:
http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Impacket

What protocols are featured?
----------------------------

 * Ethernet, Linux "Cooked" capture.
 * IP, TCP, UDP, ICMP, IGMP, ARP. (IPv4 and IPv6)
 * NMB and SMB1/2/3 (high-level implementations).
 * DCE/RPC versions 4 and 5, over different transports: UDP (version 4
   exclusively), TCP, SMB/TCP, SMB/NetBIOS and HTTP.
 * Portions of the following DCE/RPC interfaces: Conv, DCOM (WMI, OAUTH),
   EPM, SAMR, SCMR, RRP, SRVSC, LSAD, LSAT, WKST, NRPC.


Getting Impacket
================

* [Current and past releases](https://github.com/CoreSecurity/impacket/releases)
* [Trunk](https://github.com/CoreSecurity/impacket)

Setup
=====

Quick start
-----------

Grab the latest stable release, unpack it and run `python setup.py
install` from the directory where you placed it. Isn't that easy?


Requirements
============

 * A Python interpreter. Versions 2.0.1 and newer are known to work. 
   1. If you want to run the examples and you have Python < 2.7, you
      will need to install the `argparse` package for them to work.
   2. For Kerberos support you will need `pyasn1` package
   3. For cryptographic operations you will need `pycrypto` package
   4. For some examples you will need pyOpenSSL (rdp_check.py) and ldap3 (ntlmrelayx.py)
   5. If you're under Windows, you will need pyReadline
 * A recent release of Impacket.

Installing
----------

In order to install the source execute the following command from the
directory where the Impacket's distribution has been unpacked: `python
setup.py install`. This will install the classes into the default
Python modules path; note that you might need special permissions to
write there. For more information on what commands and options are
available from setup.py, run `python setup.py --help-commands`.


Licensing
=========

This software is provided under under a slightly modified version of
the Apache Software License. See the accompanying LICENSE file for
more information.

SMBv1 and NetBIOS support based on Pysmb by Michael Teo.


Contact Us
==========

Whether you want to report a bug, send a patch or give some
suggestions on this package, drop us a few lines at
oss@coresecurity.com.
