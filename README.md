Impacket-Console
========



The goal of this project is to create a msfconsole-like console for AD red-teaming.

- Use all the well-known and tested impacket tools
- Simple load the tool you want to use (e.g. GetUserSPNs)
- "Set" your variables and fire

Down the line:
- Docker version - run impacket on docker rather than with python on your machine
- Search feature - e.g. "Kerberoast" will return the GetUserSPN module with the request flag
- Link to helpful resources such as HackRecipes


Objective:
- Personal growth in software development and AD red teaming
- Make AD engagements more streamline


Progress:

| Module Name | Integrated | Tested |
|---|---|---|
| CheckLDAPStatus.py | :x: | :x: |
| DumpNTLMInfo.py | :x: | :x: |
| Get-GPPPassword.py | :x: | :x: |
| GetADComputers.py | :x: | :x: |
| GetADUsers.py | :x: | :x: |
| GetLAPSPassword.py | :x: | :x: |
| GetNPUsers.py | :x: | :x: |
| GetUserSPNs.py | :white_check_mark: | :white_check_mark: |
| addcomputer.py | :x: | :x: |
| atexec.py | :x: | :x: |
| attrib.py | :x: | :x: |
| badsuccessor.py | :x: | :x: |
| changepasswd.py | :x: | :x: |
| checkMSSQLStatus.py | :x: | :x: |
| dacledit.py | :x: | :x: |
| dcomexec.py | :x: | :x: |
| describeTicket.py | :x: | :x: |
| dpapi.py | :x: | :x: |
| dpapidump.py | :x: | :x: |
| esentutl.py | :x: | :x: |
| exchanger.py | :x: | :x: |
| filetime.py | :x: | :x: |
| findDelegation.py | :x: | :x: |
| getArch.py | :x: | :x: |
| getPac.py | :x: | :x: |
| getST.py | :x: | :x: |
| getTGT.py | :x: | :x: |
| goldenPac.py | :x: | :x: |
| karmaSMB.py | :x: | :x: |
| keylistattack.py | :x: | :x: |
| kintercept.py | :x: | :x: |
| lookupsid.py | :x: | :x: |
| machine_role.py | :x: | :x: |
| mimikatz.py | :x: | :x: |
| mqtt_check.py | :x: | :x: |
| mssqlclient.py | :x: | :x: |
| mssqlinstance.py | :x: | :x: |
| net.py | :x: | :x: |
| netview.py | :x: | :x: |
| ntfs-read.py | :x: | :x: |
| ntlmrelayx.py | :x: | :x: |
| owneredit.py | :x: | :x: |
| ping.py | :x: | :x: |
| ping6.py | :x: | :x: |
| psexec.py | :x: | :x: |
| raiseChild.py | :x: | :x: |
| rbcd.py | :x: | :x: |
| rdp_check.py | :x: | :x: |
| reg.py | :x: | :x: |
| registry-read.py | :x: | :x: |
| regsecrets.py | :x: | :x: |
| rpcdump.py | :x: | :x: |
| rpcmap.py | :x: | :x: |
| sambaPipe.py | :x: | :x: |
| samedit.py | :x: | :x: |
| samrdump.py | :x: | :x: |
| secretsdump.py | :x: | :x: |
| services.py | :x: | :x: |
| smbclient.py | :x: | :x: |
| smbexec.py | :x: | :x: |
| smbserver.py | :x: | :x: |
| sniff.py | :x: | :x: |
| sniffer.py | :x: | :x: |
| split.py | :x: | :x: |
| ticketConverter.py | :x: | :x: |
| ticketer.py | :x: | :x: |
| tstool.py | :x: | :x: |
| wmiexec.py | :x: | :x: |
| wmipersist.py | :x: | :x: |
| wmiquery.py | :x: | :x: |