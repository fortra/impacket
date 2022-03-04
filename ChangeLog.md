# ChangeLog

Project's main page at [www.secureauth.com](https://www.secureauth.com/labs/open-source-tools/impacket).

Complete list of changes can be found at:
https://github.com/SecureAuthCorp/impacket/commits/master

## Unreleased changes

1. Library improvements 
    * Dropped support for Python 2.7. We'll keep it running under GitHub Actions/`Tox` as experimental just for visibility.
    * Refactored the testing infrastructure:
      * Added `pytest` as the testing framework to organize and mark test
        cases. `Tox` remain as the automation framework, and `Coverage.py`
        for measuring code coverage.
      * Custom bash scripts were replaced with test cases auto-discovery.
      * Local and remote test cases were marked for easy run and configuration. 
      * DCE/RPC endpoint test cases were refactored and moved to a new layout. 
      * An initial testing guide with the main steps to prepare a testing environment and run them. 
      * Fixed a good amount of DCE/RPC endpoint test cases that were failing, and added tests for `[MS-PAR]`.
    * Added a function to compute the Netlogon Authenticator at client-side in `[MS-NRPC]` (@0xdeaddood)
    * Added `[MS-DSSP]` protocol implementation (@simondotsh)
    * Added GetDriverDirectory functions to `[MS-PAR]` and `[MS-RPRN]` (@raithedavion)

2. Examples improvements
	* [ntlmrelayx.py](examples/ntlmrelayx.py):
	   * Implemented RAWRelayServer (@CCob)
    
3. New examples
	* [machine_role.py](examples/machine_role.py): This script retrieves a host's role along with its primary domain details (@simondotsh)

## Impacket v0.9.24 (October 2021):

1. Library improvements 
	* Fixed WMI objects parsing (@franferrax)
	* Added the RpcAddPrinterDriverEx method and related structures to `[MS-RPRN]`: Print System Remote Protocol (@cube0x0)
	* Initial implementation of `[MS-PAR]`: Print System Asynchronous Remote Protocol (@cube0x0)
	* Complying `[MS-RPCH]` with HTTP/1.1 (@mohemiv) 
	* Added return of server time in case of Kerberos error (@ShutdownRepo and @Hackndo)

2. Examples improvements
	* [getST.py](examples/getST.py):
	   * Added support for a custom additional ticket for S4U2Proxy (@ShutdownRepo)
	* [ntlmrelayx.py](examples/ntlmrelayx.py):
	   * Added Negotiate authentication support to the HTTP server (@LZD-TMoreggia) 
	   * Added anonymous session handling in the HTTP server (@0xdeaddood)
	   * Fixed error in ldapattack.py when trying to escalate with machine account (@Rcarnus) 
	   * Added the implementation of AD CS attack (@ExAndroidDev)
	   * Disabled the anonymous logon in the SMB server (@ly4k)
	* [psexec.py](examples/psexec.py):
	   * Fixed decoding problems on multi bytes characters (@p0dalirius)
	* [reg.py](examples/reg.py):
	   * Implemented ADD and DELETE functionalities (@Gifts) 
	* [secretsdump.py](examples/secretsdump.py):
	   * Speeding up NTDS parsing (@skelsec)
	* [smbclient.py](examples/smbclient.py):
	   * Added 'mget' command which allows the download of multiple files (@deadjakk)
	   * Handling empty search count in FindFileBothDirectoryInfo (@martingalloar)
	* [smbpasswd.py](examples/smbpasswd.py):
	   * Added the ability to change a user's password providing NTLM hashes (@snovvcrash)
	* [smbserver.py](examples/smbserver.py): 
	   * Added NULL SMBv2 client connection handling (@0xdeaddood)
	   * Hardened path checks and Added TID checks (@martingalloar)
	   * Added SMB2 support to QUERY_INFO Request and Enabled SMB_COM_FLUSH method (@0xdeaddood)
	   * Added missing constant and structure for the QUERY_FS Information Level SMB_QUERY_FS_DEVICE_INFO (@martingalloar)  
	* [wmipersist.py](examples/wmipersist.py):
	   * Fixed VBA script execution and improved error checking (@franferrax)

3. New examples
	* [rbcd.py](examples/rbcd.py): Example script for handling the msDS-AllowedToActOnBehalfOfOtherIdentity property of a target computer (@ShutdownRepo and @p0dalirius) (based on the previous work of @tothi and @NinjaStyle82)

As always, thanks a lot to all these contributors that make this library better every day (since last version):

@deadjakk @franferrax @cube0x0 @w0rmh013 @skelsec @mohemiv @LZD-TMoreggia @exploide @ShutdownRepo @Hackndo @snovvcrash @rmaksimov @Gifts @Rcarnus @ExAndroidDev @ly4k @p0dalirius


## Impacket v0.9.23 (June 2021):

1. Library improvements 
	* Support connect timeout with SMBTransport (@vruello)
	* Speeding up DcSync (@mohemiv)
	* Fixed Python3 issue when serving SOCKS5 requests (@agsolino) 
	* Moved docker container to Python 3.8 (@mgallo) 
	* Added basic GitHub Actions workflow (@mgallo)  
	* Fixed Path Traversal vulnerabilities in `smbserver.py` - CVE-2021-31800 (@omriinbar AppSec Researcher at CheckMarx) 
	* Fixed POST request processing in `httprelayserver.py` (@Rcarnus) 
	* Added cat command to `smbclient.py` (@mxrch) 
	* Added new features to the LDAP Interactive Shell to facilitate AD exploitation (@AdamCrosser) 
	* Python 3.9 support (@meeuw and @cclauss) 

2. Examples improvements
	* [addcomputer.py](examples/addcomputer.py):  
	   * Enable the machine account created via SAMR (@0xdeaddood) 
	* [getST.py](examples/getST.py):  
	   * Added exploit for CVE-2020-17049 - Kerberos Bronze Bit attack (@jakekarnes42) 
	   * Compute NTHash and AESKey for the Bronze Bit attack automatically (@snovvcrash) 
	* [ntlmrelayx.py](examples/ntlmrelayx.py): 
	   * Fixed target parsing error (@0xdeaddood) 
	* [wmipersist.py](examples/wmipersist.py):  
	   * Fixed `filterBinding` error (@franferrax) 
	   * Added PowerShell option for semi-interactive shells in `dcomexec.py`, `smbexec.py`
         and `wmiexec.py` (@snovvcrash) 
	   * Added new parameter to select `COMVERSION` in `dcomexec.py`, `wmiexec.py`,
         `wmipersist.py` and `wmiquery.py` (@zexusx26) 

3. New examples 
	* [Get-GPPPassword.py](examples/Get-GPPPassword.py): This example extracts and decrypts
      Group Policy Preferences passwords using streams for treating files instead of mounting
      shares. Additionally, it can parse GPP XML files offline (@ShutdownRepo and @p0dalirius) 
	* [smbpasswd.py](examples/smbpasswd.py): This script is an alternative to `smbpasswd` tool and
      intended to be used for changing expired passwords remotely over SMB (MSRPC-SAMR) (@snovvcrash) 

As always, thanks a lot to all these contributors that make this library better every day (since last version): 

@mpgn @vruello @mohemiv @jagotu @jakekarnes42 @snovvcrash @zexusx26 @omriinbar @Rcarnus @nuschpl @mxrch @ShutdownRepo @p0dalirius @AdamCrosser @franferrax @meeuw and @cclauss 


## Impacket v0.9.22 (November 2020):

1. Library improvements
    * Added implementation of RPC over HTTP v2 protocol (by @mohemiv).
    * Added `[MS-NSPI]`, `[MS-OXNSPI]` and `[MS-OXABREF]` protocol implementations (by @mohemiv).
    * Improved the multi-page results in LDAP queries (by @ThePirateWhoSmellsOfSunflowers).
    * NDR parser optimization (by @mohemiv).
    * Improved serialization of WMI method parameters (by @tshmul).
    * Introduce the `[MS-NLMP]` `2.2.2.10` `VERSION` structure in `NTLMAuthNegotiate` messages (by @franferrax).
    * Added some NETLOGON structs for `NetrServerPasswordSet2` (by @dirkjanm).
    * Python 3.8 support.

2. Examples improvements
	* [atexec.py](examples/atexec.py):
      * Fixed after MS patches related to RPC attacks (by @mohemiv).
	* [dpapi.py](examples/dpapi.py):
      * Added `-no-pass`, `pass-the-hash` and AES Key support for backup subcommand.
	* [GetNPUsers.py](examples/GetNPUsers.py):
      * Added ability to enumerate targets with Kerberos KRB5CC (by @rmaksimov).
	* [GetUserSPNs.py](examples/GetUserSPNs.py):
      * Added new features for kerberoasting (by @mohemiv).
	* [ntlmrelayx.py](examples/ntlmrelayx.py):
	  * Added ability to relay on new Windows versions that have SMB guest access disabled by default.
	  * Added option to specify the NTLM Server Challenge used when receiving a connection.
	  * Added relaying to RPC support (by @mohemiv).
	  * Implemented WCFRelayServer (by @cnotin).
	  * Added Zerologon DCSync Relay Client (by @dirkjanm).
	  * Fixed issue in ldapattack.py when relaying and creating computer in CN=Computers (by @Hackndo).
	* [rpcdump.py](examples/rpcdump.py):
      * Added RPC over HTTP v2 support (by @mohemiv).
	* [secretsdump.py](examples/secretsdump.py):
	   * Added ability to specifically delete a shadow based on its ID (by @phefley).
	   * Dump plaintext machine account password when dumping the local registry secrets(by @dirkjanm).

3. New examples
	- [exchanger.py](examples/exchanger.py): A tool for connecting to MS Exchange via
      RPC over HTTP v2 (by @mohemiv).
	- [rpcmap.py](examples/rpcmap.py): Scan for listening DCE/RPC interfaces (by @mohemiv).

As always, thanks a lot to all these contributors that make this library better every day (since last version):
@mohemiv @mpgn @Romounet @ThePirateWhoSmellsOfSunflowers @rmaksimov @fuzzKitty @tshmul @spinenkoia @AaronRobson @ABCIFOGeowi40 @cclauss @cnotin @5alt @franferrax @Dliv3 @dirkjanm @Mr-Gag @vbersier @phefley @Hackndo


## Impacket v0.9.21 (March 2020):

1. Library improvements 
    * New methods into `CCache` class to import/export kirbi (`KRB-CRED`) formatted tickets (by @Zer1t0). 
    * Add `FSCTL_SRV_ENUMERATE_SNAPSHOTS` functionality to `SMBConnection` (by @rxwx). 
    * Changes in NetBIOS classes in `nmb.py` (`select()` by `poll()` read from socket) (by @cnotin). 
    * Timestamped logging added. 
    * Interactive shell to perform LDAP operations (by @mlefebvre). 
    * Added two DCE/RPC calls in `tsch.py` (by @mohemiv). 
    * Single-source the version number and standardize on semantic + pre-release + local versioning (by @jsherwood0). 
    * Added implementation for keytab files (by @kcirtapw). 
    * Added SMB 3.1.1 support for Client SMB Connections.

2. Examples improvements 
    * [smbclient.py](examples/smbclient.py):
      * List the VSS snapshots for a specified path (by @rxwx). 
    * [GetUserSPNs.py](examples/GetUserSPNs.py):
      * Added delegation information associated with accounts (by @G0ldenGunSec). 
    * [dpapi.py](examples/dpapi.py):  
      * Added more functions to decrypt masterkeys based on SID + hashes/key. Also support supplying hashes instead of the password for decryption(by @dirkjanm). 
      * Pass the hash support for backup key retrieval (by @imaibou). 
      * Added feature to decrypt a user's masterkey using the MS-BKRP (by @imaibou). 
    * [raiseChild.py](examples/raiseChild.py):
      * Added a new flag to specify the RID of a user to dump credentials (by @0xdeaddood). 
    * Added flags to bypass badly made detection use cases (by @MaxNad): 
      * [smbexec.py](examples/smbexec.py):
        * Possibility to rename the PSExec uploaded binary name with the `-remote-binary-name` flag. 
      * [psexec.py](examples/psexec.py):
        * Possibility to use another service name with the `-service-name` flag. 
    * [ntlmrelayx.py](examples/ntlmrelayx.py): 
      * Added a flag to use a SID as the escalate user for delegation attacks (by @0xe7). 
      * Support for dumping LAPS passwords (by @praetorian-adam-crosser). 
      * Added LDAP interactive mode that allow an attacker to manually perform basic operations
        like creating a new user, adding a user to a group , dump the AD, etc. (by @mlefebvre). 
      * Support for multiple relays through one SMB connection (by @0xdeaddood). 
      * Added support for dumping gMSA passwords (by @cube0x0). 
    * [ticketer.py](examples/ticketer.py):
      * Added an option to use the SPNs keys from a keytab for a silver ticket(by @kcirtapw) 

3. New Examples 
    - [addcomputer.py](examples/addcomputer.py): Allows add a computer to a domain using LDAP
      or SAMR (SMB) (by @jagotu) 
    - [ticketConverter.py](examples/ticketConverter.py): This script converts kirbi files,
      commonly used by mimikatz, into ccache files used by Impacket, and vice versa (by @Zer1t0). 
    - [findDelegation.py](examples/findDelegation.py): Simple script to quickly list all
      delegation relationships (unconstrained, constrained, resource-based constrained) in
      an AD environment (by @G0ldenGunSec). 

As always, thanks a lot to all these contributors that make this library better every day (since last version): 

@jagotu, @Zer1t0 ,@rxwx, @mpgn, @danhph, @awsmhacks, @slasyz, @cnotin, @exploide, @G0ldenGunSec, @dirkjanm, @0xdeaddood, @MaxNad, @imaibou, @BarakSilverfort, @0xe7, @mlefebvre, @rmaksimov, @praetorian-adam-crosser, @jsherwood0, @mohemiv, @justin-p, @cube0x0, @spinenkoia, @kcirtapw, @MrAnde7son, @fridgehead, @MarioVilas. 


## Impacket v0.9.20 (September 2019):

1. Library improvements
    * Python 3.6 support! This is the first release supporting Python 3.x so please issue tickets
      whenever you find something not working as expected. Libraries and examples should be fully
      functional. 
    * Test coverage [improvements](https://github.com/SecureAuthCorp/impacket/pull/540) by @infinnovation-dev
    * Anonymous SMB 2.x Connections are not encrypted anymore (by @cnotin)   
    * Support for [multiple PEKs](https://github.com/SecureAuthCorp/impacket/pull/618) when decrypting Windows 2016 DIT files (by @mikeryan) 

2. Examples improvements
    * [ntlmrelayx.py](examples/ntlmrelayx.py): 
      * [CVE-2019-1019](https://github.com/SecureAuthCorp/impacket/pull/635): Bypass SMB singing for unpatched (by @msimakov)
      * Added [POC](https://github.com/SecureAuthCorp/impacket/pull/637) code for CVE-2019-1040 (by @dirkjanm)
      * Added NTLM relays leveraging [Webdav](https://github.com/SecureAuthCorp/impacket/pull/652) authentications (by @salu90)

3. New Examples
    * [kintercept.py](examples/kintercept.py): A tool for intercepting krb5 connections and for
      testing KDC handling S4U2Self with unkeyed checksum (by @iboukris)

As always, thanks a lot to all these contributors that make this library better every day (since last version):

@infinnovation-dev, @cnotin, @mikeryan, @SR4ven, @cclauss, @skorov, @msimakov, @dirkjanm, @franferrax, @iboukris, @n1ngod, @c0d3z3r0, @MrAnde7son.


## Impacket v0.9.19 (April 2019):

1. Library improvements
    * [[MS-EVEN]](impacket/dcerpc/v5/even.py) Interface implementation (Initial - by @MrAnde7son )

2. Examples improvements
    * [ntlmrelayx.py](examples/ntlmrelayx.py): 
      * Socks local admin check (by @imaibou)
      * Add Resource Based Delegation features (by @dirkjanm)
    * [smbclient.py](examples/smbclient.py):
      * Added ability to create/remove mount points to exploit James Forshaw's
        [Abusing Mount Points over the SMB Protocol](https://tyranidslair.blogspot.com/2018/12/abusing-mount-points-over-smb-protocol.html) technique (by @Qwokka)
    * [GetST.py](examples/getST.py):
      * Added resource-based constrained delegation support to S4U (@eladshamir)
    * [GetNPUsers.py](examples/GetNPUsers.py):
      * Added hashcat/john format and users file input (by @Zer1t0)

As always, thanks a lot to all these contributors that make this library better every day (since last version):

@dirkjanm, @MrAnde7son, @ibo, @franferrax, @Qwokka, @CaledoniaProject , @eladshamir, @Zer1t0, @martingalloar, @muizzk, @Petraea, @SR4ven, @Fist0urs, @Zer1t0.


## Impacket v0.9.18 (December 2018):

1. Library improvements
    * Replace unmaintained PyCrypto for pycryptodome (@dirkjanm)
    * Using cryptographically secure pseudo-random generators
    * Kerberos "no pre-auth and RC4" handling in GetKerberosTGT (by @qlemaire)
    * Test cases adjustments, travis and flake support (@cclauss)
    * Python3 test cases fixes (@eldipa)
    * Adding DPAPI / Vaults related structures and functions to decrypt secrets
    * [[MS-RPRN]](impacket/dcerpc/v5/rprn.py) Interface implementation (Initial)

2. Examples improvements
    * [ntlmrelayx.py](examples/ntlmrelayx.py):
      * Optimize ACL enumeration and improve error handling in ntlmrelayx LDAP attack (by @dirkjanm)
    * [secretsdump.py](examples/secretsdump.py):
      * Added dumping of machine account Kerberos keys (@dirkjanm). `DPAPI_SYSTEM` LSA Secret is now parsed and key contents are shown.
    * [GetUserSPNs.py](examples/GetUserSPNs.py):
      * Bugfixes and cross-domain support (@dirkjanm)

3. New Examples
    * [dpapi.py](examples/dpapi.py): Allows decrypting vaults, credentials and masterkeys protected by DPAPI. Domain backup key support added by @MrAnde7son 

As always, thanks a lot to all these contributors that make this library better every day (since last version):

@dirkjanm, @MrAnde7son, @franferrax, @MrRobot86, @qlemaire, @cauan, @eldipa.


## Impacket v0.9.17 (May 2018):

1. Library improvements
    * New `[MS-PAC]` [Implementation](impacket/krb5/pac.py).
    * [LDAP engine](impacket/ldap): Added extensibleMatch string filter parsing, simple
      paging support and handling of unsolicited notification (by @kacpern)
    * [ImpactDecoder](impacket/ImpactDecoder.py): Add `EAPOL`, `BOOTP` and `DHCP` packet
      decoders (by Michael Niewoehner)
    * [Kerberos engine](impacket/krb5): `DES-CBC-MD5` support to kerberos added (by @skelsec)
    * [SMB3 engine](https://github.com/SecureAuthCorp/impacket/commit/f62fc5c3946430374f92404e892f8c48943d411c): If target server supports SMB >= 3, encrypt packets by default.
    * Initial `[MS-DHCPM]` and `[MS-EVEN6]` Interface implementation by @MrAnde7son 
    * Major improvements to the [NetBIOS layer](https://github.com/SecureAuthCorp/impacket/commit/0808e45b796741aea4162bd756e3f54522e8045b).
      More use of [structure.py](impacket/structure.py) in there.
    * [MQTT](https://github.com/SecureAuthCorp/impacket/commit/8cef002928ca52be4e9476a87a54d836b5efa81e) Protocol Implementation and example.
    * Tox/Coverage Support added, test cases moved to its own directory. Major overhaul.
    * Many fixes and improvements in Kerberos, SMB and DCERPC (too much to name in a few lines).

2. Examples improvements
    * [GetUserSPNs.py](examples/GetUserSPNs.py):
      * `-request-user` parameter added. Requests STs for the SPN associated to the user
        specified. Added support for AES Kerberoast tickets (by @elitest).
    * [services.py](examples/services.py):
      * Added port 139 support and related options (by @real-datagram).
    * [samrdump.py](examples/samrdump.py): 
      * `-csv` switch to output format in CSV added.
    * [ntlmrelayx.py](examples/ntlmrelayx.py):
      * Major architecture overhaul. Now working mostly through dynamically loaded plugins. SOCKS proxy support for relayed connections. Specific attacks for every protocol and new protocols support (IMAP, POP3, SMTP). Awesome contributions by @dirkjanm.
    * [secretsdump.py](examples/secretsdump.py):
      * AES(128) support for SAM hashes decryption. OldVal parameter dump added to LSA
        secrets dump (by @Ramzeth).
    * [mssqlclient.py](examples/mssqlclient.py):
      * Alternative method to execute cmd's on MSSQL (sp_start_job). (by @Kayzaks).
    * [lsalookupsid.py](examples/lsalookupsid.py):
      * Added no-pass and domain-users options (by @ropnop). 

3. New Examples
    * [ticketer.py](examples/ticketer.py): Create Golden/Silver tickets from scratch or
      based on a template (legally requested from the KDC) allowing you to customize 
      some of the parameters set inside the `PAC_LOGON_INFO` structure, in particular the
      groups, extrasids, duration, etc. Silver tickets creation by @machosec and @bransh.
    * [GetADUsers.py](examples/GetADUsers.py):  Gathers data about the domain's users and
      their corresponding email addresses. It will also include some extra information
      about last logon and last password set attributes.
    * [getPac.py](examples/getPac.py): Gets the PAC (Privilege Attribute Certificate)
      structure of the specified target user just having a normal authenticated user
      credentials. It does so by using a mix of `[MS-SFU]`'s `S4USelf` + User to User
      Kerberos Authentication.
    * [getArch.py](examples/getArch.py): Will connect against a target (or list of targets)
      machine/s and gather the OS architecture type installed by (ab)using a documented MSRPC feature.
    * [mimikatz.py](examples/mimikatz.py): Mini shell to control a remote mimikatz RPC
      server developed by @gentilkiwi.
    * [sambaPipe.py](examples/sambaPipe.py): Will exploit CVE-2017-7494, uploading and
      executing the shared library specified by the user through the `-so` parameter.
    * [dcomexec.py](examples/dcomexec.py): A semi-interactive shell similar to `wmiexec.py`,
      but using different DCOM endpoints. Currently supports `MMC20.Application`, `ShellWindows` and
      `ShellBrowserWindow` objects. (contributions by @byt3bl33d3r).
    * [getTGT.py](examples/getTGT.py): Given a password, hash or aesKey, this script will
      request a TGT and save it as ccache.
    * [getST.py](examples/getST.py): Given a password, hash, aesKey or TGT in ccache, this
      script will request a Service Ticket and save it as ccache. If the account has constrained
      delegation (with protocol transition) privileges you will be able to use the `-impersonate`
      switch to request the ticket on behalf other user.

As always, thanks a lot to all these contributors that make this library better every day (since last version):

@dirkjanm, @real-datagram, @kacpern, @martinuy, @xelphene, @blark, @the-useless-one, @contactr2m, @droc, @martingalloar, @skelsec, @franferrax, @Fr0stbyt3, @ropnop, @MrAnde7son, @machosec, @federicoemartinez, @elitest, @symeonp, @Kanda-Motohiro, @Ramzeth, @mohemiv, @arch4ngel, @derekchentrendmicro, @Kayzaks, @donwayo, @bao7uo, @byt3bl33d3r, @xambroz, @luzpaz, @TheNaterz, @Mikkgn, @derUnbekannt.


## Impacket v0.9.15 (June 2016):

1. Library improvements
   * `SMB3.create`: define `CreateContextsOffset` and `CreateContextsLength` when applicable (by @rrerolle)
   * Retrieve user principal name from `CCache` file allowing to call any script with `-k` and just the target system (by @MrTchuss)
   * Packet fragmentation for DCE RPC layer mayor overhaul.
   * Improved pass-the-key attacks scenarios (by @skelsec)
   * Adding a minimalistic LDAP/s implementation (supports PtH/PtT/PtK). Only search is available (and you need to
     build the search filter yourself)
   * IPv6 improvements for DCERPC/LDAP and Kerberos

2. Examples improvements
   * Adding `-dc-ip` switch to all examples. It allows specifying what the IP for the domain is.
     It assumes the DC and KDC resides in the same server.
   * `secretsdump.py`:
     * Adding support for Win2016 TP4 in LOCAL or `-use-vss` mode
     * Adding `-just-dc-user` switch to download just a single user data (DRSUAPI mode only)
     * Support for different ReplEpoch (DRSUAPI only)
     * pwdLastSet is also included in the output file
     * New structures/flags added for 2016 TP5 PAM support
   * `wmiquery.py`:
     * Adding `-rpc-auth-level` switch (by @gadio)
   * `smbrelayx.py`:
     * Added option to specify authentication status code to be sent to requesting client (by @mgeeky)
     * Added one-shot parameter. After successful authentication, only execute the attack once for each target (per protocol)

3. New Examples
   * `GetUserSPNs.py`: This module will try to find Service Principal Names that are associated with normal user account.
     This is part of the kerberoast attack researched by Tim Medin (@timmedin)
   * `ntlmrelayx.py`: `smbrelayx.py` on steroids!. NTLM relay attack from/to multiple protocols (HTTP/SMB/LDAP/MSSQL/etc)
     (by @dirkjanm)


## Impacket v0.9.14 (January 2016):

1. Library improvements
   * `[MS-TSCH]` - ATSVC, SASec and ITaskSchedulerService Interface implementations
   * `[MS-DRSR]` - Directory Replication Service DRSUAPI Interface implementation
   * Network Data Representation (NDR) runtime overhaul. Big performance and reliability improvements achieved
   * Unicode support (optional) for the SMBv1 stack (by @rdubourguais)
   * NTLMv2 enforcement option on SMBv1 client stack (by @scriptjunkie)
   * Kerberos support for TDS (MSSQL)
   * Extended present flags support on RadioTap class
   * Old DCERPC runtime code removed

2. Examples improvements
   * `mssqlclient.py`:
     * Added Kerberos authentication support
   * `atexec.py`:
     * It now uses ITaskSchedulerService interface, adding support for Windows 2012 R2
   * `smbrelayx.py`:
     * If no file to upload and execute is specified (-E) it just dumps the target user's hashes by default
     * Added -c option to execute custom commands in the target (by @byt3bl33d3r)
   * `secretsdump.py`:
     * Active Directory hashes/Kerberos keys are dumped using `[MS-DRSR]` (`IDL_DRSGetNCChanges` method)
       by default. VSS method is still available by using the -use-vss switch
     * Added `-just-dc` (Extract only NTDS.DIT NTLM Hashes and Kerberos) and
       `-just-dc-ntlm` (only NTDS.DIT NTLM Hashes) options
     * Added resume capability (only for NTDS in DRSUAPI mode) in case the connection drops.
       Use `-resumefile` option.
     * Added Primary:CLEARTEXT Property from supplementalCredentials attribute dump (`[MS-SAMR]` `3.1.1.8.11.5`)
     * Add support for multiple password encryption keys (PEK) (by @s0crat)
   * `goldenPac.py`:
     * Tests all DCs in domain and adding forest's enterprise admin group inside PAC

3. New examples
   * `raiseChild.py`: Child domain to forest privilege escalation exploit. Implements a
     child-domain to forest privilegeescalation as [detailed by Sean Metcalf](https://adsecurity.org/?p=1640).
   * `netview.py`: Gets a list of the sessions opened at the remote hosts and keep track of them (original idea by @mubix)


## Impacket v0.9.13 (May 2015):

1. Library improvements
   * Kerberos support for SMB and DCERPC featuring:
      * `kerberosLogin()` added to SMBConnection (all SMB versions).
      * Support for `RPC_C_AUTHN_GSS_NEGOTIATE` at the DCERPC layer. This will 
        negotiate Kerberos. This also includes DCOM.
      * Pass-the-hash, pass-the-ticket and pass-the-key support.
      * Ccache support, compatible with Kerberos utilities (kinit, klist, etc).
      * Support for `RC4`, `AES128_CTS_HMAC_SHA1_96` and `AES256_CTS_HMAC_SHA1_96` ciphers.
      * Support for `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`/`RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`.
   * `[MS-SAMR]`: Supplemental Credentials support (used by secretsdump.py)
   * SMBSERVER improvements:
      * SMB2 (2.002) dialect experimental support. 
      * Adding capability to export to John The Ripper format files
   * Library logging overhaul. Now there's a single logger called `impacket`.

2. Examples improvements
   * Added Kerberos support to all modules (incl. pass-the-ticket/key)
   * Ported most of the modules to the new dcerpc.v5 runtime.
   * `secretsdump.py`:
     * Added dumping Kerberos keys when parsing NTDS.DIT
   * `smbserver.py`:
     * Support for SMB2 (not enabled by default)
   * `smbrelayx.py`:
     * Added support for MS15-027 exploitation.

3. New examples
   * `goldenPac.py`: MS14-068 exploit. Saves the golden ticket and also launches a 
     psexec session at the target.
   * `karmaSMB.py`: SMB Server that answers specific file contents regardless of
     the SMB share and pathname requested. 
   * `wmipersist.py`: Creates persistence over WMI. Adds/Removes WMI Event 
     Consumers/Filters to execute VBS based on a WQL filter or timer specified.


## Impacket v0.9.12 (July 2014):

1. Library improvements
   * The following protocols were added based on its standard definition
      * `[MS-DCOM]` - Distributed Component Object module Protocol (`dcom.py`)
      * `[MS-OAUT]` - OLE Automation Protocol (`dcom/oaut.py`)
      * `[MS-WMI]`/`[MS-WMIO]` : Windows Management Instrumentation Remote Protocol (`dcom/wmi.py`)

2. New examples
   * `wmiquery.py`: executes WMI queries and get WMI object's descriptions.
   * `wmiexec.py`: agent-less, semi-interactive shell using WMI.
   * `smbserver.py`: quick an easy way to share files using the SMB protocol.


## Impacket v0.9.11 (February 2014):

1. Library improvements
   * New RPC and NDR runtime (located at `impacket.dcerpc.v5`, old one still available)
       * Support marshaling/unmarshaling for NDR20 and NDR64 (experimental)
       * Support for `RPC_C_AUTHN_NETLOGON` (experimental)
       * The following interface were developed based on its standard definition:
           * `[MS-LSAD]` - Local Security Authority (Domain Policy) Remote Protocol (lsad.py)
           * `[MS-LSAT]` - Local Security Authority (Translation Methods) Remote Protocol (lsat.py)
           * `[MS-NRPC]` - Netlogon Remote Protocol (nrpc.py) 
           * `[MS-RRP]` - Windows Remote Registry Protocol (rrp.py)
           * `[MS-SAMR]` - Security Account Manager (SAM) Remote Protocol (samr.py)
           * `[MS-SCMR]` - Service Control Manager Remote Protocol (scmr.py)
           * `[MS-SRVS]` - Server Service Remote Protocol (srvs.py) 
           * `[MS-WKST]` - Workstation Service Remote Protocol (wkst.py) 
           * `[MS-RPCE]-C706` -  Remote Procedure Call Protocol Extensions (epm.py)
           * `[MS-DTYP]` - Windows Data Types (dtypes.py)
       * Most of the DCE Calls have helper functions for easier use. Test cases added for 
         all calls (check the test cases directory)
   * ESE parser (Extensive Storage Engine) (ese.py)
   * Windows Registry parser (winregistry.py)
   * TDS protocol now supports SSL, can be used from mssqlclient
   * Support for EAPOL, EAP and WPS decoders
   * VLAN tagging (IEEE 802.1Q and 802.1ad) support for ImpactPacket, done by dan.pisi

2. New examples
  * `rdp_check.py`: tests whether an account (pwd or hashes) is valid against an RDP server
  * `esentutl.py`: ESE example to show how to interact with ESE databases (e.g. NTDS.dit)
  * `ntfs-read.py`: mini shell for browsing an NTFS volume
  * `registry-read.py`: Windows offline registry reader
  * `secretsdump.py`: agent-less remote windows secrets dump (SAM, LSA, CDC, NTDS)


## Impacket v0.9.10 (March 2013):

1. Library improvements
   * SMB version 2 and 3 protocol support (`[MS-SMB2]`). Signing supported, encryption for
     SMB3 still pending.
   * Added a SMBConnection layer on top of each SMB specific protocol. Much simpler and
     SMB version independent. It will pick the best SMB Version when connecting against the
     target. Check `smbconnection.py` for a list of available methods across all the protocols.
   * Partial TDS implementation (`[MS-TDS]` & `[MC-SQLR]`) so we could talk with MSSQL Servers.
   * Unicode support for the smbserver. Newer OSX won't connect to a non unicode SMB Server.
   * DCERPC Endpoints' new calls
     * EPM: `lookup()`: It can work as a general portmapper, or just to find specific interfaces/objects.

2. New examples
    * `mssqlclient.py`: A MS SQL client, allowing to do MS SQL or Windows Authentication (accepts hashes) and then gives
      you an SQL prompt for your pleasure.
    * `mssqlinstance.py`: Lists the MS SQL instances running on a target machine.
    * `rpcdump.py`: Output changed. Hopefully more useful. Parsed all the Windows Protocol Specification looking for the
      UUIDs used and that information is included as well. This could be helpful when reading a portmap output and to
      develop new functionality to interact against a target interface.
    * `smbexec.py`: Another alternative to psexec. Less capabilities but might work on tight AV environments. Based on the
      technique described at https://www.optiv.com/blog/owning-computers-without-shell-access. It also
      supports instantiating a local smbserver to receive the output of the commandos executed for those situations
      where no share is available on the other end.
    * `smbrelayx.py`: It now also listens on port 80 and forwards/reflects the credentials accordingly.

And finally tons of fixes :).


## Impacket v0.9.9 (July 2012):

1. Library improvements
   * Added 802.11 packets encoding/decoding
   * Addition of support for IP6, ICMP6 and NDP packets. Addition of `IP6_Address` helper class.
   * SMB/DCERPC:
     * GSS-API/SPNEGO Support.
     * SPN support in auth blob.
     * NTLM2 and NTLMv2 support. 
     * Default SMB port now 445. If `*SMBSERVER` is specified the library will try to resolve the netbios name.
     * Pass the hash supported for SMB/DCE-RPC.
     * IPv6 support for SMB/NMB/DCERPC.
     * DOMAIN support for authentication. 
     * SMB signing support when server enforces it.
     * DCERPC signing/sealing for all NTLM flavours.
     * DCERPC transport now accepts an already established SMB connection.
     * Basic SMBServer implementation in Python. It allows third-party DCE-RPC servers to handle DCERPC Request (by
       forwarding named pipes requests).
     * Minimalistic SRVSVC dcerpc server to be used by SMBServer in order to avoid Windows 7 nasty bug when that pipe's
       not functional.
   * DCERPC Endpoints' new calls:
       * `SRVSVC`: `NetrShareEnum(Level1)`, `NetrShareGetInfo(Level2)`, `NetrServerGetInfo(Level2)`,
         `NetrRemoteTOD()`, `NetprNameCanonicalize()`.
       * `SVCCTL`: `CloseServiceHandle()`, `OpenSCManagerW()`, `CreateServiceW()`, `StartServiceW()`,
         `OpenServiceW()`, `OpenServiceA()`, `StopService()`, `DeleteService()`, `EnumServicesStatusW()`,
         `QueryServiceStatus()`, `QueryServiceConfigW()`.
       * `WKSSVC`: `NetrWkstaTransportEnum()`.
       * `SAMR`: `OpenAlias()`, `GetMembersInAlias()`.
       * `LSARPC`: `LsarOpenPolicy2()`, `LsarLookupSids()`, `LsarClose()`.

2. New examples
    * `ifmap.py`: First, this binds to the MGMT interface and gets a list of interface IDs. It adds to this a large list
      of interface UUIDs seen in the wild. It then tries to bind to each interface and reports whether the interface is
      listed and/or listening.
    * `lookupsid.py`: DCE/RPC lookup sid brute forcer example.
    * `opdump.py`: This binds to the given hostname:port and DCERPC interface. Then, it tries to call each of the first
      256 operation numbers in turn and reports the outcome of each call.
    * `services.py`: SVCCTL services common functions for manipulating services (START/STOP/DELETE/STATUS/CONFIG/LIST).
    * `test_wkssvc`: DCE/RPC WKSSVC examples, playing with the functions Implemented.
    * `smbrelayx`: Passes credentials to a third party server when doing MiTM.
    * `smbserver`: Multiprocess/threading smbserver supporting common file server functions. Authentication all done but
      not enforced. Tested under Windows, Linux and MacOS clients.
    * `smbclient.py`: now supports history, new commands also added.
    * `psexec.py`: Execute remote commands on Windows machines
