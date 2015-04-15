**Impacket** is a collection of Python classes focused on providing access to network packets. Impacket allows Python developers to craft and decode network packets in simple and consistent manner.
It includes support for several protocols such as:
| **Layer** | **Protocols** |
|:----------|:--------------|
|Pseudo Link|LinuxSLL|
|Data Link| 802.3 (Ethernet), 802.11 (WLAN), ARP, NDP, CDP|
|Internet|IPv4, IPv6, ICMPv4, ICMPv6, IGMP|
|Transport|UDP, TCP|
|Session|NMB, SMB|
|Application|DNS, DHCP, DCE/RPC, DCOM|

**Impacket** is highly effective when used in conjunction with a packet capture utility or package such as Pcapy. Packets can be constructed from scratch, as well as parsed from raw data. Furthermore, the object oriented API makes it simple to work with deep protocol hierarchies.

LATEST STABLE RELEASE (0.9.12): [impacket-0.9.12.tar.gz](https://pypi.python.org/packages/source/i/impacket/impacket-0.9.12.tar.gz)

DESCRIPTION: [Corelabs Impacket](http://corelabs.coresecurity.com/index.php?module=Wiki&action=view&type=tool&name=Impacket)