Testing
=======

The library leverages the [pytest](https://docs.pytest.org/) framework for organizing
and marking test cases, [tox](https://tox.readthedocs.io/) to automate the process of
running them across supported Python versions, and [coverage](https://coverage.readthedocs.io/)
to obtain coverage statistics.


Test environment setup
----------------------

Some test cases are "local", meaning that don't require a target environment and can
be run off-line, while the bulk of the test cases are "remote" and requires some
prior setup.

If you want to run the full set of library test cases, you need to prepare your
environment by completing the following steps:

1. Install testing requirements. You can use the following command to do so:

         python3 -m pip install tox -r requirements-test.txt

1. [Install and configure a target Active Directory Domain Controller](#active-directory-setup-and-configuration).

1. [Configure remote test cases](#configure-remote-test-cases).


> **Important note**
> 
> Bear in mind that some remote tests are not idempotent, that means that they perform
> changes on the target environment and the results of the tests depends on that. As an
> example, some tests require the creation/modification/deletion of user accounts. If those
> tests fail at some point during the process, user accounts might lay down there and
> subsequent tests might fail when trying to create the user account. We recommend taking
> snapshots of the target environment that can be then rolled back after a testing session.

Running tests
-------------

Once that's done, you would be able to run the test suite with `pytest`. For example,
you can run all "local" test cases using the following command:

      $ pytest -m "not remote"

Or run the "remote" test cases with the following command:

      $ pytest -m "remote" 

If all goes well, all test cases should pass.

You can also leverage `pytest` [markers](https://docs.pytest.org/en/4.6.x/example/markers.html)
or [keyword expressions](https://docs.pytest.org/en/4.6.x/usage.html#select-tests)
to select which test case you want to run. Although we recommend using `pytest`, it's also possible to run individual test
case modules via `unittest.main` method. For example, to only run `ldap` test cases,
you can execute:

      $ pytest -k "ldap"


Automating runs
---------------

If you want to run the test cases in a new fresh environment, or run those across
different Python versions, you can use `tox`. You can specify the group of test cases
you want to run, which would be passed to `pytest`. As an example, the following
command will run all "local" test cases across all the Python versions defined in
the `tox` configuration:

      $ tox -- -m "not remote"

Coverage
--------

If you want to measure coverage in your test cases run, you can use it via the
`pytest-cov` plugin, for example by running the following command:

      $ pytest --cov --cov-config=tox.ini

`tox` will collect and report coverage statistics as well, and combine it across
different Python version environment runs. You will have a coverage HTML report
located at the default `Coverage`'s location `htlmcov/index.html`.


Configuration
-------------

Configuration of all `pytest`, `coverage` and `tox` is contained in the
[tox.ini](tox.ini) file. Refer to each tool documentation for further details
about the different settings.


Active Directory Setup and Configuration
----------------------------------------

In order to run remote test cases, a target Active Directory need to be properly
configured with the expected objects. Current remote test cases are expected to
work against a Windows Server 2012 R2 Domain Controller. Some protocol tests need
additional server roles or newer Windows versions; see
[Protocol-specific remote test prerequisites](#protocol-specific-remote-test-prerequisites).
The following are the main steps required:

1. Make sure to disable the firewall on the interface you want to use for connecting
   to the Domain Controller.
   
        PS C:\> Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False

1. Install the Active Directory Domain Services on the target server.
   
        PS C:\> Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools 

1. Make sure the server's Administrator user password meet the complexity policy, as it's required
   for promoting it to Domain Controller.

        PS C:\> $AdminPassword = "<Admin Password>"
        PS C:\> $Admin=[adsi]("WinNT://$env:COMPUTERNAME/Administrator, user")
        PS C:\> $Admin.psbase.invoke("setpassword", $AdminPassword)

1. Promote the installed Windows Server 2012 R2 to a Domain Controller, and configure
   a domain of your choice.

        PS C:\> $DomainName = "<Domain Name>"
        PS C:\> $NetBIOSName = "<NetBIOS Name>"
        PS C:\> $RecoveryPassword = "<Recovery Password>"
        PS C:\> $SecureRecoveryPassword = ConvertTo-SecureString $RecoveryPassword -AsPlainText -Force
        PS C:\> Install-ADDSForest -DomainName $DomainName -InstallDns -SafeModeAdministratorPassword $SecureRecoveryPassword -DomainNetbiosName $NetBIOSName -SkipPreChecks

1. Install DHCP services on the target Domain Controller.

        PS C:\> Install-WindowsFeature -name DHCP -IncludeManagementTools

1. Create the DHCP administration groups and authorize the server.
   
        PS C:\> netsh dhcp add securitygroups
        PS C:\> Restart-Service dhcpserver
        PS C:\> Add-DhcpServerInDC -DnsName <Server Name> -IPAddress <IP Address>
        PS C:\> $Credential = Get-Credential
        PS C:\> Set-DhcpServerDnsCredential -Credential $Credential -ComputerName <Server Name>

1. Be sure to enable and run the `RemoteRegistry` service on the target Domain 
   Controller.

        PS C:\> Start-Service RemoteRegistry

1. Create a Domain User with administrative rights. This is the user that will be used
   to run the remote tests. We make sure to enable AES Kerberos encryption type and add
   it to the Domain Admins group. 

        PS C:\> $AdminUserName = "<Admin User Name>"
        PS C:\> $AdminAccountName = "<Admin Account Name>"
        PS C:\> $AdminUserPassword = "<Admin User Password>"
        PS C:\> $SecureAdminUserPassword = ConvertTo-SecureString $AdminUserPassword -AsPlainText -Force
        PS C:\> New-ADUser -Name $AdminUserName -SamAccountName $AdminAccountName -UserPrincipalName $AdminAccountName@$DomainName -AccountPassword $SecureAdminUserPassword -Enabled $true -ChangePasswordAtLogon $false  -KerberosEncryptionType RC4,AES128,AES256
        PS C:\> Add-ADGroupMember -Identity "Domain Admins" -Members <Account Name>


### LDAPS (LDAP over SSL/TLS) configuration

For running LDAPS (LDAP over SSL/TLS) test cases, make sure you have a certificate
installed and configured on the target Domain Controller. You can follow
Microsoft's [guidelines to configure LDAPS](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-ldap-over-ssl-3rd-certification-authority).

You can use self-signed certificates by:

   1. Create a CA private key and certificate:

          $ openssl genrsa -aes256 -out ca_private.key 4096
          $ openssl req -new -x509 -days 3650 -key ca_private.key -out ca_public.crt

   1. Copying and importing the CA public certificate into the Domain
      Controller server:

          PS C:\> Import-Certificate -FilePath ca_public.crt -CertStoreLocation 'Cert:\LocalMachine\Root' -Verbose

   1. Creating a certificate request for the LDAP service, by editing the following
      configuration file:
      
          ;----------------- request.inf -----------------
          [Version]
          Signature="$Windows NT$
            
          [NewRequest]
          Subject = "CN=<DC fqdn>" ; replace with the FQDN of the DC
          KeySpec = 1
          KeyLength = 1024
          Exportable = TRUE
          MachineKeySet = TRUE
          SMIME = False
          PrivateKeyArchive = FALSE
          UserProtected = FALSE
          UseExistingKeySet = FALSE
          ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
          ProviderType = 12
          RequestType = PKCS10
          KeyUsage = 0xa0
      
          [EnhancedKeyUsageExtension]
          OID=1.3.6.1.5.5.7.3.1 ; this is for Server Authentication
          ;-----------------------------------------------

      And then running the following command:

          PS C:\> certreq -new request.inf ldapcert.csr

   1. Signing the LDAP service certificate with the CA, by creating the
      `v3ext.txt` configuration file:
      
          keyUsage=digitalSignature,keyEncipherment
          extendedKeyUsage=serverAuth
          subjectKeyIdentifier=hash

      And running the following command:
      
          $ openssl x509 -req -days 365 -in ldapcert.csr -CA ca_public.crt -CAkey ca_private.key -extfile v3ext.txt -set_serial 01 -out ldapcert.crt

   1. Copying and installing the new signed LDAP service certificate into
      the Domain Controller server:

          PS C:\> certreq -accept ldapcert.crt

   1. Finally, restarting the Domain Controller.


### Mimilib configuration

[Mimilib](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib) test
cases require the service to be installed on the target Domain Controller. You can
do that by running Mimikatz with an elevated user and executing:

        mimikatz # rpc::server


Configure Remote Test Cases
---------------------------

Create a copy of the [dcetests.cfg.template](tests/dcetests.cfg.template) file and
configure it with the necessary information associated to the Active Directory you
configured. Path to the configuration file to use when running tests can be then
specified in the following ways:

  * Using the pytest `--remote-config` command-line option.
  * Using the pytest `remote-config` option in `tox.ini`.  
  * Using the `REMOTE_CONFIG` environment variable.
  * Default to loading from `tests/dcetests.cfg`.

For example, you can keep configuration of different environments in
separate files, and specify which one you want the test to run against:

        $ pytest --remote-config=tests/dcetests-win2016.cfg
        $ pytest --remote-config=tests/dcetests-win2019.cfg

Make sure you set a user with proper administrative privileges on the
target Active Directory domain and that the user hashes and keys match with those
in the environment. Hashes and Kerberos keys can be grabbed from the target Domain
Controller using [secretsdump.py](examples/secretsdump.py) example script.

Make sure also to have full network visibility into the target hosts and be able to
resolve DNS queries for the Active Directory Domain configured. If you don't want to
change your test machine's DNS settings to point to the AD DNS server, you can
configure your system to statically resolve (e.g. via `/etc/hosts` file) the host
and domain FQDN to the server's IP address.


Protocol-specific remote test prerequisites
------------------------------------------

Some RPC interfaces require additional Windows roles or a newer operating system
than the Windows Server 2012 R2 environment described above. Configure the target
for each interface as follows, then specify its connection information as
described in [Configure Remote Test Cases](#configure-remote-test-cases).

### SCMR: RCreateWowService and ROpenSCManager2

For the `RCreateWowService` and `ROpenSCManager2` cases in
[test_scmr.py](tests/dcerpc/test_scmr.py):

These cases skip automatically when the target reports an unsupported RPC
operation or `ERROR_CALL_NOT_IMPLEMENTED`. Other errors, including access denied
and connection failures, still fail the tests. No version flag is required.

1. Prepare a Windows host supporting these methods, such as Windows 11.
   A domain controller is not required for these cases. Refer to the
   [MS-SCMR product behavior notes](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/041d2a89-9d7d-4f79-91a1-c336d0a668f6)
   for version restrictions. In particular, `ROpenSCManager2` is unavailable on
   Windows 10 version 1809 and earlier and Windows Server version 1809 and earlier.

1. Configure an administrator account with network logon access and permission
   to open the SCM database and create, query, and delete services.

1. Allow SMB connections on TCP 445. For the TCP transport cases, also allow
   TCP 135 and the dynamic RPC ports used by the server.

1. Set the account and target details in the remote configuration file's
   `[TCPTransport]` section, which is used by both transport classes. For a local
   account on a standalone host, set `domain` to the target computer name and
   `username` to the local account name.

### FSRVP: file-server shadow copies

For [test_fsrvp.py](tests/dcerpc/test_fsrvp.py), prepare a Windows Server with
storage that supports shadow copies through FSRVP. Run the following setup steps
in an elevated PowerShell session on the target:

1. Install the File Server VSS Agent Service role service. Complete any restart
   requested by the installation before continuing.

        PS C:\> Install-WindowsFeature -Name File-Services,FS-VSS-Agent

1. Enable and start the `FSSAgent` service.

        PS C:\> Set-Service -Name FSSAgent -StartupType Automatic
        PS C:\> Start-Service -Name FSSAgent

1. Create a regular SMB share named `Windows`, matching the `SHARE_NAME` constant
   in the test module. Administrative shares such as `C$` cannot be used. For
   example, create a test directory and share it with the test administrator:

        PS C:\> New-Item -Path C:\FSRVPTest -ItemType Directory
        PS C:\> New-SmbShare -Name Windows -Path C:\FSRVPTest -FullAccess '<Domain>\<Admin User Name>'

1. Ensure the test administrator has access to both the share and its underlying
   directory, and allow SMB connections on TCP 445.

1. Configure the target address and administrator credentials in the remote
   test configuration file.
