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
 * Portions/full implementation of the following MSRPC interfaces: EPM, DTYPES, LSAD, LSAT, NRPC, RRP, SAMR, SRVS, WKST, SCMR, BKRP, DHCPM, EVEN6, MGMT, SASEC, TSCH, DCOM, WMI, OXABREF, NSPI, OXNSPI.
 * Portions of TDS (MSSQL) and LDAP protocol implementations.


Getting Impacket
================

* [Current and past releases](https://github.com/SecureAuthCorp/impacket/releases)
* [Trunk](https://github.com/SecureAuthCorp/impacket)

Setup
=====

Quick start
-----------

Grab the latest stable release, unpack it and run `python3 -m pip install .` (`python2 -m pip install .` for Python 2.x) from the directory where you placed it. Isn't that easy?

Installing
----------

In order to install the source execute the following command from the
directory where the Impacket's distribution has been unpacked: `python3 -m pip install .` (`python2 -m pip install . `for Python 2.x).
This will install the classes into the default
Python modules path; note that you might need special permissions to
write there. 

Testing
-------

The library leverages the [pytest](https://docs.pytest.org/) framework for organizing
and marking test cases, [tox](https://tox.readthedocs.io/) to automate the process of
running them across supported Python versions, and [coverage](https://coverage.readthedocs.io/)
to obtain coverage statistics.

### Test environment setup

Some test cases are "local", meaning that don't require a target environment and can
be run off-line, while the bulk of the test cases are "remote" and requires some
prior setup.

If you want to run the full set of library test cases, you need to prepare your
environment by completing the following steps:

1. Install and configure a Windows 2012 R2 Domain Controller.
   * Be sure to enable and run the `RemoteRegistry` service. You can do so by
     running the following command from an elevated prompt:
     
         sc start remoteregistry

2. Configure the [dcetest.cfg](tests/dcetests.cfg) file with the necessary information.
   Make sure you set a user with proper administrative privileges on the target Active
   Directory domain.

3. Install testing requirements. You can use the following command to do so:
   
         python3 -m pip install tox -r requirements-test.txt

### Running tests

Once that's done, you would be able to run the test suite with `pytest`. For example,
you can run all "local" test cases using the following command:

      $ pytest -m "not remote"

Or run the "remote" test cases with the following command:

      $ pytest -m "remote" 

If all goes well, all test cases should pass.

### Automating runs

If you want to run the test cases in a new fresh environment, or run those across
different Python versions, you can use `tox`. You can specify the group of test cases
you want to run, which would be passed to `pytest`. As an example, the following
command will run all "local" test cases across all the Python versions defined in
the `tox` configuration:

      $ tox -- -m "not remote"

### Coverage

If you want to measure  coverage in your test cases run, you can use it via the
`pytest-cov` plugin, for example by running the following command:

      $ pytest --cov --cov-config=tox.ini

`tox` will collect and report coverage statistics as well, and combine it across
different Python version environment runs. You will have a coverage HTML report
located at the default `Coverage`'s location `htlmcov/index.html`.


### Configuration

Configuration of all `pytest`, `coverage` and `tox` is contained in the
[tox.ini](tox.ini) file. Refer to each tool documentation for further details
about the different settings.


Docker Support
--------------

Build Impacket's image:

      $ docker build -t "impacket:latest" .

Using Impacket's image:

      $ docker run -it --rm "impacket:latest"

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
