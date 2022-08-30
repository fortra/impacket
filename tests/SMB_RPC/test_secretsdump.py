# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
import os
import logging
import pytest
import unittest
from tests import RemoteTestCase

from impacket.examples.secretsdump import LocalOperations, RemoteOperations, SAMHashes, LSASecrets, NTDSHashes
from impacket.smbconnection import SMBConnection


def _print_helper(*args, **kwargs):
    try:
        print(args[-1])
    except UnicodeError:
        pass


class DumpSecrets:

    def __init__(self, remoteName, username='', password='', domain='', options=None):
        self.__useVSSMethod = options.use_vss
        self.__remoteName = remoteName
        self.__remoteHost = options.target_ip
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aes_key_128 = options.aes_key_128
        self.__smbConnection = None
        self.__remoteOps = None
        self.__SAMHashes = None
        self.__NTDSHashes = None
        self.__LSASecrets = None
        self.__systemHive = options.system
        self.__bootkey = options.bootkey
        self.__securityHive = options.security
        self.__samHive = options.sam
        self.__ntdsFile = options.ntds
        self.__history = options.history
        self.__noLMHash = True
        self.__isRemote = True
        self.__outputFileName = options.outputfile
        self.__doKerberos = options.k
        self.__justDC = options.just_dc
        self.__justDCNTLM = options.just_dc_ntlm
        self.__justUser = options.just_dc_user
        self.__pwdLastSet = options.pwd_last_set
        self.__printUserStatus= options.user_status
        self.__resumeFileName = options.resumefile
        self.__canProcessSAMLSA = True
        self.__kdcHost = options.dc_ip
        self.__options = options

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

    def connect(self):
        self.__smbConnection = SMBConnection(self.__remoteName, self.__remoteHost)
        if self.__doKerberos:
            self.__smbConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash,
                                               self.__nthash, self.__aes_key_128, self.__kdcHost)
        else:
            self.__smbConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)

    def dump(self):
        try:
            if self.__remoteName.upper() == 'LOCAL' and self.__username == '':
                self.__isRemote = False
                self.__useVSSMethod = True
                if self.__systemHive:
                    localOperations = LocalOperations(self.__systemHive)
                    bootKey = localOperations.getBootKey()
                    if self.__ntdsFile is not None:
                    # Let's grab target's configuration about LM Hashes storage
                        self.__noLMHash = localOperations.checkNoLMHashPolicy()
                else:
                    import binascii
                    bootKey = binascii.unhexlify(self.__bootkey)

            else:
                self.__isRemote = True
                bootKey = None
                try:
                    try:
                        self.connect()
                    except Exception as e:
                        if os.getenv('KRB5CCNAME') is not None and self.__doKerberos is True:
                            # SMBConnection failed. That might be because there was no way to log into the
                            # target system. We just have a last resort. Hope we have tickets cached and that they
                            # will work
                            logging.debug('SMBConnection didn\'t work, hoping Kerberos will help (%s)' % str(e))
                            pass
                        else:
                            raise

                    self.__remoteOps  = RemoteOperations(self.__smbConnection, self.__doKerberos, self.__kdcHost)
                    self.__remoteOps.setExecMethod(self.__options.exec_method)
                    if self.__justDC is False and self.__justDCNTLM is False or self.__useVSSMethod is True:
                        self.__remoteOps.enableRegistry()
                        bootKey             = self.__remoteOps.getBootKey()
                        # Let's check whether target system stores LM Hashes
                        self.__noLMHash = self.__remoteOps.checkNoLMHashPolicy()
                except Exception as e:
                    self.__canProcessSAMLSA = False
                    if str(e).find('STATUS_USER_SESSION_DELETED') and os.getenv('KRB5CCNAME') is not None \
                        and self.__doKerberos is True:
                        # Giving some hints here when SPN target name validation is set to something different to Off
                        # This will prevent establishing SMB connections using TGS for SPNs different to cifs/
                        logging.error('Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user')
                    else:
                        logging.error('RemoteOperations failed: %s' % str(e))

            # If RemoteOperations succeeded, then we can extract SAM and LSA
            if self.__justDC is False and self.__justDCNTLM is False and self.__canProcessSAMLSA:
                try:
                    if self.__isRemote is True:
                        SAMFileName         = self.__remoteOps.saveSAM()
                    else:
                        SAMFileName         = self.__samHive

                    self.__SAMHashes    = SAMHashes(SAMFileName, bootKey, isRemote = self.__isRemote)
                    self.__SAMHashes.dump()
                    if self.__outputFileName is not None:
                        self.__SAMHashes.export(self.__outputFileName)
                except Exception as e:
                    logging.error('SAM hashes extraction failed: %s' % str(e))

                try:
                    if self.__isRemote is True:
                        SECURITYFileName = self.__remoteOps.saveSECURITY()
                    else:
                        SECURITYFileName = self.__securityHive

                    self.__LSASecrets = LSASecrets(SECURITYFileName, bootKey, self.__remoteOps,
                                                   isRemote=self.__isRemote, history=self.__history)
                    self.__LSASecrets.dumpCachedHashes()
                    if self.__outputFileName is not None:
                        self.__LSASecrets.exportCached(self.__outputFileName)
                    self.__LSASecrets.dumpSecrets()
                    if self.__outputFileName is not None:
                        self.__LSASecrets.exportSecrets(self.__outputFileName)
                except Exception as e:
                    if logging.getLogger().level == logging.DEBUG:
                        import traceback
                        traceback.print_exc()
                    logging.error('LSA hashes extraction failed: %s' % str(e))

            # NTDS Extraction we can try regardless of RemoteOperations failing. It might still work
            if self.__isRemote is True:
                if self.__useVSSMethod and self.__remoteOps is not None:
                    NTDSFileName = self.__remoteOps.saveNTDS()
                else:
                    NTDSFileName = None
            else:
                NTDSFileName = self.__ntdsFile

            self.__NTDSHashes = NTDSHashes(NTDSFileName, bootKey, isRemote=self.__isRemote, history=self.__history,
                                           noLMHash=self.__noLMHash, remoteOps=self.__remoteOps,
                                           useVSSMethod=self.__useVSSMethod, justNTLM=self.__justDCNTLM,
                                           pwdLastSet=self.__pwdLastSet, resumeSession=self.__resumeFileName,
                                           outputFileName=self.__outputFileName, justUser=self.__justUser,
                                           printUserStatus= self.__printUserStatus)
            try:
                self.__NTDSHashes.dump()
            except Exception as e:
                if logging.getLogger().level == logging.DEBUG:
                    import traceback
                    traceback.print_exc()
                if str(e).find('ERROR_DS_DRA_BAD_DN') >= 0:
                    # We don't store the resume file if this error happened, since this error is related to lack
                    # of enough privileges to access DRSUAPI.
                    resumeFile = self.__NTDSHashes.getResumeSessionFile()
                    if resumeFile is not None:
                        os.unlink(resumeFile)
                logging.error(e)
                if self.__justUser and str(e).find("ERROR_DS_NAME_ERROR_NOT_UNIQUE") >=0:
                    logging.info("You just got that error because there might be some duplicates of the same name. "
                                 "Try specifying the domain name for the user as well. It is important to specify it "
                                 "in the form of NetBIOS domain name/user (e.g. contoso/Administratror).")
                elif self.__useVSSMethod is False:
                    logging.info('Something wen\'t wrong with the DRSUAPI approach. Try again with -use-vss parameter')
            self.cleanup()
        except (Exception, KeyboardInterrupt) as e:
            if logging.getLogger().level == logging.DEBUG:
                import traceback
                traceback.print_exc()
            logging.error(e)
            if self.__NTDSHashes is not None:
                if isinstance(e, KeyboardInterrupt):
                    while True:
                        answer =  input("Delete resume session file? [y/N] ")
                        if answer.upper() == '':
                            answer = 'N'
                            break
                        elif answer.upper() == 'Y':
                            answer = 'Y'
                            break
                        elif answer.upper() == 'N':
                            answer = 'N'
                            break
                    if answer == 'Y':
                        resumeFile = self.__NTDSHashes.getResumeSessionFile()
                        if resumeFile is not None:
                            os.unlink(resumeFile)
            try:
                self.cleanup()
            except Exception:
                pass

    def cleanup(self):
        try:
            logging.info('Cleaning up... ')
            if self.__remoteOps:
                self.__remoteOps.finish()
            if self.__SAMHashes:
                self.__SAMHashes.finish()
            if self.__LSASecrets:
                self.__LSASecrets.finish()
            if self.__NTDSHashes:
                self.__NTDSHashes.finish()
        except Exception as e:
            if str(e).find('ERROR_DEPENDENT_SERVICES_RUNNING') < 0:
                raise

class Options(object):
    aes_key_128 = None
    bootkey=None
    dc_ip=None
    debug=False
    exec_method='smbexec'
    hashes=None
    history=False
    just_dc=False
    just_dc_ntlm=False
    just_dc_user=None
    k=False
    no_pass=False
    ntds=None
    outputfile=None
    pwd_last_set=False
    resumefile=None
    sam=None
    security=None
    system=None
    target=''
    target_ip=''
    use_vss=False
    user_status=False


class SecretsDumpTests(RemoteTestCase):

    def test_VSS_History(self):
        options = Options()
        options.target_ip = self.machine
        options.use_vss = True
        options.history = True
        dumper = DumpSecrets(self.serverName, self.username, self.password, self.domain, options)
        dumper.dump()

    def aaaa_VSS_WMI(self):
        options = Options()
        options.target_ip = self.machine
        options.use_vss = True
        options.exec_method='wmiexec'
        dumper = DumpSecrets(self.serverName, self.username, self.password, self.domain, options)
        dumper.dump()

    def test_DRSUAPI_DC_USER(self):
        options = Options()
        options.target_ip = self.machine
        options.use_vss = False
        options.just_dc = True
        options.just_dc_user = '%s/%s' % (self.domain.split('.')[0], 'Administrator')
        dumper = DumpSecrets(self.serverName, self.username, self.password, self.domain, options)
        dumper.dump()

    def aaaa_VSS_MMC(self):
        options = Options()
        options.target_ip = self.machine
        options.use_vss = True
        options.exec_method='mmcexec'
        dumper = DumpSecrets(self.serverName, self.username, self.password, self.domain, options)
        dumper.dump()

    def test_DRSUAPI(self):
        options = Options()
        options.target_ip = self.machine
        options.use_vss = False
        dumper = DumpSecrets(self.serverName, self.username, self.password, self.domain, options)
        dumper.dump()


@pytest.mark.remote
class Tests(SecretsDumpTests, unittest.TestCase):

    def setUp(self):
        super(Tests, self).setUp()
        self.set_transport_config(aes_keys=True)


if __name__ == "__main__":
    unittest.main(verbosity=1)
