#!/usr/bin/env python
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
#   TLS helper functions shared across protocol clients.
#

from hashlib import md5, sha256


def tls_server_end_point_channel_binding_from_digest(peer_certificate_digest):
    channel_binding_struct = b'\x00' * 16
    application_data_raw = b'tls-server-end-point:' + peer_certificate_digest
    channel_binding_struct += len(application_data_raw).to_bytes(4, byteorder='little', signed=False)
    channel_binding_struct += application_data_raw
    return md5(channel_binding_struct).digest()


def tls_server_end_point_channel_binding_from_certificate(peer_certificate):
    return tls_server_end_point_channel_binding_from_digest(sha256(peer_certificate).digest())
