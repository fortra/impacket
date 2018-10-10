What is Impacket?
=================

Impacket is a collection of Python classes for working with network
protocols. Impacket is focused on providing low-level
programmatic access to the packets and for some protocols (e.g.
SMB1-3 and MSRPC) the protocol implementation itself.
Packets can be constructed from scratch, as well as parsed from 
raw data, and the object oriented API makes it simple to work with 
deep hierarchies of protocols. The library provides a set of tools
as examples of what can be done within the context of this library.

A description of some of the tools can be found at:
https://www.secureauth.com/labs/open-source-tools/impacket

What protocols are featured?
----------------------------

 * Ethernet, Linux "Cooked" capture.
 * IP, TCP, UDP, ICMP, IGMP, ARP.
 * IPv4 and IPv6 Support.
 * NMB and SMB1, SMB2 and SMB3 (high-level implementations).
 * MSRPC version 5, over different transports: TCP, SMB/TCP, SMB/NetBIOS and HTTP.
 * Plain, NTLM and Kerberos authentications, using password/hashes/tickets/keys.
 * Portions/full implementation of the following MSRPC interfaces: EPM, DTYPES, LSAD, LSAT, NRPC, RRP, SAMR, SRVS, WKST, SCMR, BKRP, DHCPM, EVEN6, MGMT, SASEC, TSCH, DCOM, WMI.
 * Portions of TDS (MSSQL) and LDAP protocol implementations.


Getting Impacket
================

* [Current and past releases](https://github.com/SecureAuthCorp/impacket/releases)
* [Trunk](https://github.com/SecureAuthCorp/impacket)

Setup
=====

Quick start
-----------

Grab the latest stable release, unpack it and run `pip install .` from the directory where you placed it. Isn't that easy?


Requirements
============

 * A Python interpreter. Versions 2.6 and newer are known to work.
   1. If you want to run the examples and you have Python < 2.7, you
      will need to install the `argparse` package for them to work.
   2. For Kerberos support you will need `pyasn1` package
   3. For cryptographic operations you will need `pycryptodomex` package
   4. For some examples you will need `pyOpenSSL` (rdp_check.py) and ldap3 (ntlmrelayx.py)
   5. For ntlmrelayx.py you will also need `ldapdomaindump`, `flask` and `ldap3`
   6. If you're under Windows, you will need `pyReadline`
 * A recent release of Impacket.

Installing
----------

In order to install the source execute the following command from the
directory where the Impacket's distribution has been unpacked: `pip install .`
This will install the classes into the default
Python modules path; note that you might need special permissions to
write there. For more information on what commands and options are
available from setup.py, run `python setup.py --help-commands`.

Testing
-------

If you want to run the library test cases you need to do mainly three things:

1. Install and configure a Windows 2012 R2 Domain Controller.
   * Be sure the RemoteRegistry service is enabled and running.
2. Configure the [dcetest.cfg](https://github.com/SecureAuthCorp/impacket/blob/impacket_0_9_17/tests/SMB_RPC/dcetests.cfg) file with the necessary information
3. Install tox (`pip install tox`)

Once that's done, you can run `tox` and wait for the results. If all goes well, all test cases should pass.
You will also have a coverage HTML report located at `impacket/tests/htlmcov/index.html`

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
oss@secureauth.com.
