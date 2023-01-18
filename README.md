> :information_source: This is a fork specifically maintained for [The Exegol Project](https://exegol.rtfd.io/) but it can be used outside of Exegol as well. This is a fork of the official Impacket project at https://github.com/SecureAuthCorp/Impacket. It aims at being a quicker on the merge of pull requests and other community contributions. See this as a bleeding-edge version maintained by lover of Impacket.

> :warning: keep in mind this fork can be less stable than the official version at times. But we think the community is strong enough to offer fixes when issues rise. We, as maintainers of this fork, will just need to be fast enough to review and merge.

> :information_source: we are also working on a documentation project at [The Hacker Tools - Impacket](https://tools.thehacker.recipes/impacket). Feel free to contribute as well on the [GitHub repo](https://github.com/ShutdownRepo/The-Hacker-Tools).

Impacket
========

FORTRA. Copyright (C) 2022 Fortra. All rights reserved.

Impacket was originally created by [SecureAuth](https://www.secureauth.com/labs/open-source-tools/impacket), and now maintained by Fortra's Core Security.

Impacket is a collection of Python classes for working with network
protocols. Impacket is focused on providing low-level
programmatic access to the packets and for some protocols (e.g.
SMB1-3 and MSRPC) the protocol implementation itself.
Packets can be constructed from scratch, as well as parsed from 
raw data, and the object-oriented API makes it simple to work with 
deep hierarchies of protocols. The library provides a set of tools
as examples of what can be done within the context of this library.

Setup
=====

### Quick start

```
git clone https://github.com/ThePorgs/impacket
pipx install /path/to/impacket
```

Licensing
=========

This software is provided under a slightly modified version of
the Apache Software License. See the accompanying [LICENSE](LICENSE) file for
more information.

SMBv1 and NetBIOS support based on Pysmb by Michael Teo.
