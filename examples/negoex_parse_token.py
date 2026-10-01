#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   MS-NEGOEX (SPNEGO Extended Negotiation) build / parse utility.
#   Builds a demo NEGOEX token, or decodes a token captured from the wire
#   (hex string or raw file) and prints its message sequence and the
#   advertised auth-scheme GUIDs.
#
# Author:
#   Lu Ping (@lupingQAQ)

import argparse
import binascii
import sys

from impacket import version
from impacket.examples import logger
from impacket.negoex import (
    MESSAGE_TYPE,
    AUTH_SCHEME_PKU2U,
    createNegoMessage,
    createExchangeMessage,
    parseNegoExToken,
)


def describe(token):
    messages = parseNegoExToken(token)
    print("[+] token is %d bytes, %d message(s)" % (len(token), len(messages)))
    for idx, pm in enumerate(messages):
        name = pm.getMessageType().name if hasattr(pm.getMessageType(), "name") else pm.getMessageType()
        print("    [%d] type=%-18s offset=0x%04x len=%d" % (idx, name, pm.offset, len(pm.raw_data)))
        msg = pm.message
        if msg is None:
            continue
        if pm.getMessageType() in (MESSAGE_TYPE.INITIATOR_NEGO, MESSAGE_TYPE.ACCEPTOR_NEGO):
            for scheme in msg.getAuthSchemeList():
                print("         auth-scheme=%s" % binascii.hexlify(scheme).decode())
        if pm.getMessageType() in (MESSAGE_TYPE.CHALLENGE, MESSAGE_TYPE.AP_REQUEST):
            print("         exchange-auth-scheme=%s" % binascii.hexlify(msg.getAuthScheme()).decode())
            print("         exchange-data=%d bytes" % len(msg.getExchangeData()))


def demo():
    import uuid

    conversation_id = uuid.uuid4()
    # INITIATOR_NEGO advertising a single scheme, then an AP_REQUEST carrying
    # an "optimistic token" (the initiator's first message to the mechanism).
    nego = createNegoMessage(MESSAGE_TYPE.INITIATOR_NEGO, 0, conversation_id, [AUTH_SCHEME_PKU2U])
    ap_request = createExchangeMessage(MESSAGE_TYPE.AP_REQUEST, 1, conversation_id, AUTH_SCHEME_PKU2U, b"\x60\x01\x02\x03")
    token = nego + ap_request
    print("[*] Built a demo NEGOEX token with 2 messages")
    describe(token)


def main():
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help=True,
        description="Parse or build NEGOEX (MS-NEGOEX) messages.")
    parser.add_argument("-hex", action="store", default=None, help="hex-encoded NEGOEX token to parse")
    parser.add_argument("-file", action="store", default=None, help="file containing a raw NEGOEX token")
    parser.add_argument("-debug", action="store_true", help="turn DEBUG output ON")
    options = parser.parse_args()

    logger.init(False, options.debug)

    if options.hex:
        describe(binascii.unhexlify(options.hex.replace(" ", "").replace(":", "")))
    elif options.file:
        with open(options.file, "rb") as f:
            describe(f.read())
    else:
        demo()


if __name__ == "__main__":
    main()
