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
#   Partial C706.pdf + [MS-RPCE] implementation
#
#   Best way to learn how to use these calls is to grab the protocol standard
#   so you understand what the call does, and then read the test case located
#   at https://github.com/fortra/impacket/tree/master/tests/SMB_RPC
#
# ToDo:
#   [ ] Take out all the security provider stuff out of here (e.g. RPC_C_AUTHN_WINNT)
#       and put it elsewhere. This will make the coder cleaner and easier to add
#       more SSP (e.g. NETLOGON)
# 

import logging
import socket
import sys
from binascii import unhexlify
from Cryptodome.Cipher import ARC4

from impacket import ntlm, LOG
from impacket.structure import Structure,pack,unpack
from impacket.krb5 import kerberosv5, gssapi
from impacket.uuid import uuidtup_to_bin, generate, stringver_to_bin, bin_to_uuidtup, bin_to_string
from impacket.dcerpc.v5.dtypes import UCHAR, ULONG, USHORT
from impacket.dcerpc.v5.ndr import NDRSTRUCT
from impacket import hresult_errors
from threading import Thread

# MS/RPC Constants
MSRPC_REQUEST   = 0x00
MSRPC_PING      = 0x01
MSRPC_RESPONSE  = 0x02
MSRPC_FAULT     = 0x03
MSRPC_WORKING   = 0x04
MSRPC_NOCALL    = 0x05
MSRPC_REJECT    = 0x06
MSRPC_ACK       = 0x07
MSRPC_CL_CANCEL = 0x08
MSRPC_FACK      = 0x09
MSRPC_CANCELACK = 0x0A
MSRPC_BIND      = 0x0B
MSRPC_BINDACK   = 0x0C
MSRPC_BINDNAK   = 0x0D
MSRPC_ALTERCTX  = 0x0E
MSRPC_ALTERCTX_R= 0x0F
MSRPC_AUTH3     = 0x10
MSRPC_SHUTDOWN  = 0x11
MSRPC_CO_CANCEL = 0x12
MSRPC_ORPHANED  = 0x13
MSRPC_RTS       = 0x14

msrpc_message_type = {
    0x00: 'MSRPC REQUEST',
    0x01: 'MSRPC PING',
    0x02: 'MSRPC RESPONSE',
    0x03: 'MSRPC FAULT',
    0x04: 'MSRPC WORKING',
    0x05: 'MSRPC NOCALL',
    0x06: 'MSRPC REJECT',
    0x07: 'MSRPC ACK',
    0x08: 'MSRPC CL CANCEL',
    0x09: 'MSRPC FACK',
    0x0A: 'MSRPC CANCELACK',
    0x0B: 'MSRPC BIND',
    0x0C: 'MSRPC BINDACK',
    0x0D: 'MSRPC BINDNAK',
    0x0E: 'MSRPC ALTERCTX',
    0x0F: 'MSRPC ALTERCTX R',
    0x10: 'MSRPC AUTH3',
    0x11: 'MSRPC SHUTDOWN',
    0x12: 'MSRPC CO CANCEL',
    0x13: 'MSRPC ORPHANED'
}

# MS/RPC Packet Flags
PFC_FIRST_FRAG     = 0x01
PFC_LAST_FRAG      = 0x02

# For PDU types bind, bind_ack, alter_context, and
# alter_context_resp, this flag MUST be interpreted as PFC_SUPPORT_HEADER_SIGN
MSRPC_SUPPORT_SIGN  = 0x04

#For the
#remaining PDU types, this flag MUST be interpreted as PFC_PENDING_CANCEL.
MSRPC_PENDING_CANCEL= 0x04

PFC_RESERVED_1      = 0x08
PFC_CONC_MPX        = 0x10
PFC_DID_NOT_EXECUTE = 0x20
PFC_MAYBE           = 0x40
PFC_OBJECT_UUID     = 0x80

# Auth Types - Security Providers
RPC_C_AUTHN_NONE          = 0x00
RPC_C_AUTHN_GSS_NEGOTIATE = 0x09
RPC_C_AUTHN_WINNT         = 0x0A
RPC_C_AUTHN_GSS_SCHANNEL  = 0x0E
RPC_C_AUTHN_GSS_KERBEROS  = 0x10
RPC_C_AUTHN_NETLOGON      = 0x44
RPC_C_AUTHN_DEFAULT       = 0xFF

# Auth Levels
RPC_C_AUTHN_LEVEL_NONE          = 1
RPC_C_AUTHN_LEVEL_CONNECT       = 2
RPC_C_AUTHN_LEVEL_CALL          = 3
RPC_C_AUTHN_LEVEL_PKT           = 4
RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 5
RPC_C_AUTHN_LEVEL_PKT_PRIVACY   = 6

#Reasons for rejection of a context element, included in bind_ack result reason
rpc_provider_reason = {
    0       : 'reason_not_specified',
    1       : 'abstract_syntax_not_supported',
    2       : 'proposed_transfer_syntaxes_not_supported',
    3       : 'local_limit_exceeded',
    4       : 'protocol_version_not_specified',
    8       : 'authentication_type_not_recognized',
    9       : 'invalid_checksum'
}

MSRPC_CONT_RESULT_ACCEPT = 0
MSRPC_CONT_RESULT_USER_REJECT = 1
MSRPC_CONT_RESULT_PROV_REJECT = 2
MSRPC_CONT_RESULT_NEGOTIATE_ACK = 3

#Results of a presentation context negotiation
rpc_cont_def_result = {
    0       : 'acceptance',
    1       : 'user_rejection',
    2       : 'provider_rejection'
}

#status codes, references:
#https://docs.microsoft.com/windows/desktop/Rpc/rpc-return-values
#https://msdn.microsoft.com/library/default.asp?url=/library/en-us/randz/protocol/common_return_values.asp
#winerror.h
#https://www.opengroup.org/onlinepubs/9629399/apdxn.htm

rpc_status_codes = {
    0x00000005 : 'rpc_s_access_denied',
    0x00000008 : 'Authentication type not recognized',
    0x000006D8 : 'rpc_fault_cant_perform', 
    0x000006C6 : 'rpc_x_invalid_bound',                # the arrays bound are invalid
    0x000006E4 : 'rpc_s_cannot_support: The requested operation is not supported.',               # some operation is not supported
    0x000006F7 : 'rpc_x_bad_stub_data',                # the stub data is invalid, doesn't match with the IDL definition
    0x1C010001 : 'nca_s_comm_failure',                 # unable to get response from server:
    0x1C010002 : 'nca_s_op_rng_error',                 # bad operation number in call
    0x1C010003 : 'nca_s_unk_if',                       # unknown interface
    0x1C010006 : 'nca_s_wrong_boot_time',              # client passed server wrong server boot time
    0x1C010009 : 'nca_s_you_crashed',                  # a restarted server called back a client
    0x1C01000B : 'nca_s_proto_error',                  # someone messed up the protocol
    0x1C010013 : 'nca_s_out_args_too_big ',            # output args too big
    0x1C010014 : 'nca_s_server_too_busy',              # server is too busy to handle call
    0x1C010015 : 'nca_s_fault_string_too_long',        # string argument longer than declared max len
    0x1C010017 : 'nca_s_unsupported_type ',            # no implementation of generic operation for object
    0x1C000001 : 'nca_s_fault_int_div_by_zero',
    0x1C000002 : 'nca_s_fault_addr_error ',
    0x1C000003 : 'nca_s_fault_fp_div_zero',
    0x1C000004 : 'nca_s_fault_fp_underflow',
    0x1C000005 : 'nca_s_fault_fp_overflow',
    0x1C000006 : 'nca_s_fault_invalid_tag',
    0x1C000007 : 'nca_s_fault_invalid_bound ',
    0x1C000008 : 'nca_s_rpc_version_mismatch',
    0x1C000009 : 'nca_s_unspec_reject ',
    0x1C00000A : 'nca_s_bad_actid',
    0x1C00000B : 'nca_s_who_are_you_failed',
    0x1C00000C : 'nca_s_manager_not_entered ',
    0x1C00000D : 'nca_s_fault_cancel',
    0x1C00000E : 'nca_s_fault_ill_inst',
    0x1C00000F : 'nca_s_fault_fp_error',
    0x1C000010 : 'nca_s_fault_int_overflow',
    0x1C000012 : 'nca_s_fault_unspec',
    0x1C000013 : 'nca_s_fault_remote_comm_failure ',
    0x1C000014 : 'nca_s_fault_pipe_empty ',
    0x1C000015 : 'nca_s_fault_pipe_closed',
    0x1C000016 : 'nca_s_fault_pipe_order ',
    0x1C000017 : 'nca_s_fault_pipe_discipline',
    0x1C000018 : 'nca_s_fault_pipe_comm_error',
    0x1C000019 : 'nca_s_fault_pipe_memory',
    0x1C00001A : 'nca_s_fault_context_mismatch ',
    0x1C00001B : 'nca_s_fault_remote_no_memory ',
    0x1C00001C : 'nca_s_invalid_pres_context_id',
    0x1C00001D : 'nca_s_unsupported_authn_level',
    0x1C00001F : 'nca_s_invalid_checksum ',
    0x1C000020 : 'nca_s_invalid_crc',
    0x1C000021 : 'nca_s_fault_user_defined',
    0x1C000022 : 'nca_s_fault_tx_open_failed',
    0x1C000023 : 'nca_s_fault_codeset_conv_error',
    0x1C000024 : 'nca_s_fault_object_not_found ',
    0x1C000025 : 'nca_s_fault_no_client_stub',
    0x16c9a000 : "rpc_s_mod",
    0x16c9a001 : "rpc_s_op_rng_error",
    0x16c9a002 : "rpc_s_cant_create_socket",
    0x16c9a003 : "rpc_s_cant_bind_socket",
    0x16c9a004 : "rpc_s_not_in_call",
    0x16c9a005 : "rpc_s_no_port",
    0x16c9a006 : "rpc_s_wrong_boot_time",
    0x16c9a007 : "rpc_s_too_many_sockets",
    0x16c9a008 : "rpc_s_illegal_register",
    0x16c9a009 : "rpc_s_cant_recv",
    0x16c9a00a : "rpc_s_bad_pkt",
    0x16c9a00b : "rpc_s_unbound_handle",
    0x16c9a00c : "rpc_s_addr_in_use",
    0x16c9a00d : "rpc_s_in_args_too_big",
    0x16c9a00e : "rpc_s_string_too_long",
    0x16c9a00f : "rpc_s_too_many_objects",
    0x16c9a010 : "rpc_s_binding_has_no_auth",
    0x16c9a011 : "rpc_s_unknown_authn_service",
    0x16c9a012 : "rpc_s_no_memory",
    0x16c9a013 : "rpc_s_cant_nmalloc",
    0x16c9a014 : "rpc_s_call_faulted",
    0x16c9a015 : "rpc_s_call_failed",
    0x16c9a016 : "rpc_s_comm_failure",
    0x16c9a017 : "rpc_s_rpcd_comm_failure",
    0x16c9a018 : "rpc_s_illegal_family_rebind",
    0x16c9a019 : "rpc_s_invalid_handle",
    0x16c9a01a : "rpc_s_coding_error",
    0x16c9a01b : "rpc_s_object_not_found",
    0x16c9a01c : "rpc_s_cthread_not_found",
    0x16c9a01d : "rpc_s_invalid_binding",
    0x16c9a01e : "rpc_s_already_registered",
    0x16c9a01f : "rpc_s_endpoint_not_found",
    0x16c9a020 : "rpc_s_invalid_rpc_protseq",
    0x16c9a021 : "rpc_s_desc_not_registered",
    0x16c9a022 : "rpc_s_already_listening",
    0x16c9a023 : "rpc_s_no_protseqs",
    0x16c9a024 : "rpc_s_no_protseqs_registered",
    0x16c9a025 : "rpc_s_no_bindings",
    0x16c9a026 : "rpc_s_max_descs_exceeded",
    0x16c9a027 : "rpc_s_no_interfaces",
    0x16c9a028 : "rpc_s_invalid_timeout",
    0x16c9a029 : "rpc_s_cant_inq_socket",
    0x16c9a02a : "rpc_s_invalid_naf_id",
    0x16c9a02b : "rpc_s_inval_net_addr",
    0x16c9a02c : "rpc_s_unknown_if",
    0x16c9a02d : "rpc_s_unsupported_type",
    0x16c9a02e : "rpc_s_invalid_call_opt",
    0x16c9a02f : "rpc_s_no_fault",
    0x16c9a030 : "rpc_s_cancel_timeout",
    0x16c9a031 : "rpc_s_call_cancelled",
    0x16c9a032 : "rpc_s_invalid_call_handle",
    0x16c9a033 : "rpc_s_cannot_alloc_assoc",
    0x16c9a034 : "rpc_s_cannot_connect",
    0x16c9a035 : "rpc_s_connection_aborted",
    0x16c9a036 : "rpc_s_connection_closed",
    0x16c9a037 : "rpc_s_cannot_accept",
    0x16c9a038 : "rpc_s_assoc_grp_not_found",
    0x16c9a039 : "rpc_s_stub_interface_error",
    0x16c9a03a : "rpc_s_invalid_object",
    0x16c9a03b : "rpc_s_invalid_type",
    0x16c9a03c : "rpc_s_invalid_if_opnum",
    0x16c9a03d : "rpc_s_different_server_instance",
    0x16c9a03e : "rpc_s_protocol_error",
    0x16c9a03f : "rpc_s_cant_recvmsg",
    0x16c9a040 : "rpc_s_invalid_string_binding",
    0x16c9a041 : "rpc_s_connect_timed_out",
    0x16c9a042 : "rpc_s_connect_rejected",
    0x16c9a043 : "rpc_s_network_unreachable",
    0x16c9a044 : "rpc_s_connect_no_resources",
    0x16c9a045 : "rpc_s_rem_network_shutdown",
    0x16c9a046 : "rpc_s_too_many_rem_connects",
    0x16c9a047 : "rpc_s_no_rem_endpoint",
    0x16c9a048 : "rpc_s_rem_host_down",
    0x16c9a049 : "rpc_s_host_unreachable",
    0x16c9a04a : "rpc_s_access_control_info_inv",
    0x16c9a04b : "rpc_s_loc_connect_aborted",
    0x16c9a04c : "rpc_s_connect_closed_by_rem",
    0x16c9a04d : "rpc_s_rem_host_crashed",
    0x16c9a04e : "rpc_s_invalid_endpoint_format",
    0x16c9a04f : "rpc_s_unknown_status_code",
    0x16c9a050 : "rpc_s_unknown_mgr_type",
    0x16c9a051 : "rpc_s_assoc_creation_failed",
    0x16c9a052 : "rpc_s_assoc_grp_max_exceeded",
    0x16c9a053 : "rpc_s_assoc_grp_alloc_failed",
    0x16c9a054 : "rpc_s_sm_invalid_state",
    0x16c9a055 : "rpc_s_assoc_req_rejected",
    0x16c9a056 : "rpc_s_assoc_shutdown",
    0x16c9a057 : "rpc_s_tsyntaxes_unsupported",
    0x16c9a058 : "rpc_s_context_id_not_found",
    0x16c9a059 : "rpc_s_cant_listen_socket",
    0x16c9a05a : "rpc_s_no_addrs",
    0x16c9a05b : "rpc_s_cant_getpeername",
    0x16c9a05c : "rpc_s_cant_get_if_id",
    0x16c9a05d : "rpc_s_protseq_not_supported",
    0x16c9a05e : "rpc_s_call_orphaned",
    0x16c9a05f : "rpc_s_who_are_you_failed",
    0x16c9a060 : "rpc_s_unknown_reject",
    0x16c9a061 : "rpc_s_type_already_registered",
    0x16c9a062 : "rpc_s_stop_listening_disabled",
    0x16c9a063 : "rpc_s_invalid_arg",
    0x16c9a064 : "rpc_s_not_supported",
    0x16c9a065 : "rpc_s_wrong_kind_of_binding",
    0x16c9a066 : "rpc_s_authn_authz_mismatch",
    0x16c9a067 : "rpc_s_call_queued",
    0x16c9a068 : "rpc_s_cannot_set_nodelay",
    0x16c9a069 : "rpc_s_not_rpc_tower",
    0x16c9a06a : "rpc_s_invalid_rpc_protid",
    0x16c9a06b : "rpc_s_invalid_rpc_floor",
    0x16c9a06c : "rpc_s_call_timeout",
    0x16c9a06d : "rpc_s_mgmt_op_disallowed",
    0x16c9a06e : "rpc_s_manager_not_entered",
    0x16c9a06f : "rpc_s_calls_too_large_for_wk_ep",
    0x16c9a070 : "rpc_s_server_too_busy",
    0x16c9a071 : "rpc_s_prot_version_mismatch",
    0x16c9a072 : "rpc_s_rpc_prot_version_mismatch",
    0x16c9a073 : "rpc_s_ss_no_import_cursor",
    0x16c9a074 : "rpc_s_fault_addr_error",
    0x16c9a075 : "rpc_s_fault_context_mismatch",
    0x16c9a076 : "rpc_s_fault_fp_div_by_zero",
    0x16c9a077 : "rpc_s_fault_fp_error",
    0x16c9a078 : "rpc_s_fault_fp_overflow",
    0x16c9a079 : "rpc_s_fault_fp_underflow",
    0x16c9a07a : "rpc_s_fault_ill_inst",
    0x16c9a07b : "rpc_s_fault_int_div_by_zero",
    0x16c9a07c : "rpc_s_fault_int_overflow",
    0x16c9a07d : "rpc_s_fault_invalid_bound",
    0x16c9a07e : "rpc_s_fault_invalid_tag",
    0x16c9a07f : "rpc_s_fault_pipe_closed",
    0x16c9a080 : "rpc_s_fault_pipe_comm_error",
    0x16c9a081 : "rpc_s_fault_pipe_discipline",
    0x16c9a082 : "rpc_s_fault_pipe_empty",
    0x16c9a083 : "rpc_s_fault_pipe_memory",
    0x16c9a084 : "rpc_s_fault_pipe_order",
    0x16c9a085 : "rpc_s_fault_remote_comm_failure",
    0x16c9a086 : "rpc_s_fault_remote_no_memory",
    0x16c9a087 : "rpc_s_fault_unspec",
    0x16c9a088 : "uuid_s_bad_version",
    0x16c9a089 : "uuid_s_socket_failure",
    0x16c9a08a : "uuid_s_getconf_failure",
    0x16c9a08b : "uuid_s_no_address",
    0x16c9a08c : "uuid_s_overrun",
    0x16c9a08d : "uuid_s_internal_error",
    0x16c9a08e : "uuid_s_coding_error",
    0x16c9a08f : "uuid_s_invalid_string_uuid",
    0x16c9a090 : "uuid_s_no_memory",
    0x16c9a091 : "rpc_s_no_more_entries",
    0x16c9a092 : "rpc_s_unknown_ns_error",
    0x16c9a093 : "rpc_s_name_service_unavailable",
    0x16c9a094 : "rpc_s_incomplete_name",
    0x16c9a095 : "rpc_s_group_not_found",
    0x16c9a096 : "rpc_s_invalid_name_syntax",
    0x16c9a097 : "rpc_s_no_more_members",
    0x16c9a098 : "rpc_s_no_more_interfaces",
    0x16c9a099 : "rpc_s_invalid_name_service",
    0x16c9a09a : "rpc_s_no_name_mapping",
    0x16c9a09b : "rpc_s_profile_not_found",
    0x16c9a09c : "rpc_s_not_found",
    0x16c9a09d : "rpc_s_no_updates",
    0x16c9a09e : "rpc_s_update_failed",
    0x16c9a09f : "rpc_s_no_match_exported",
    0x16c9a0a0 : "rpc_s_entry_not_found",
    0x16c9a0a1 : "rpc_s_invalid_inquiry_context",
    0x16c9a0a2 : "rpc_s_interface_not_found",
    0x16c9a0a3 : "rpc_s_group_member_not_found",
    0x16c9a0a4 : "rpc_s_entry_already_exists",
    0x16c9a0a5 : "rpc_s_nsinit_failure",
    0x16c9a0a6 : "rpc_s_unsupported_name_syntax",
    0x16c9a0a7 : "rpc_s_no_more_elements",
    0x16c9a0a8 : "rpc_s_no_ns_permission",
    0x16c9a0a9 : "rpc_s_invalid_inquiry_type",
    0x16c9a0aa : "rpc_s_profile_element_not_found",
    0x16c9a0ab : "rpc_s_profile_element_replaced",
    0x16c9a0ac : "rpc_s_import_already_done",
    0x16c9a0ad : "rpc_s_database_busy",
    0x16c9a0ae : "rpc_s_invalid_import_context",
    0x16c9a0af : "rpc_s_uuid_set_not_found",
    0x16c9a0b0 : "rpc_s_uuid_member_not_found",
    0x16c9a0b1 : "rpc_s_no_interfaces_exported",
    0x16c9a0b2 : "rpc_s_tower_set_not_found",
    0x16c9a0b3 : "rpc_s_tower_member_not_found",
    0x16c9a0b4 : "rpc_s_obj_uuid_not_found",
    0x16c9a0b5 : "rpc_s_no_more_bindings",
    0x16c9a0b6 : "rpc_s_invalid_priority",
    0x16c9a0b7 : "rpc_s_not_rpc_entry",
    0x16c9a0b8 : "rpc_s_invalid_lookup_context",
    0x16c9a0b9 : "rpc_s_binding_vector_full",
    0x16c9a0ba : "rpc_s_cycle_detected",
    0x16c9a0bb : "rpc_s_nothing_to_export",
    0x16c9a0bc : "rpc_s_nothing_to_unexport",
    0x16c9a0bd : "rpc_s_invalid_vers_option",
    0x16c9a0be : "rpc_s_no_rpc_data",
    0x16c9a0bf : "rpc_s_mbr_picked",
    0x16c9a0c0 : "rpc_s_not_all_objs_unexported",
    0x16c9a0c1 : "rpc_s_no_entry_name",
    0x16c9a0c2 : "rpc_s_priority_group_done",
    0x16c9a0c3 : "rpc_s_partial_results",
    0x16c9a0c4 : "rpc_s_no_env_setup",
    0x16c9a0c5 : "twr_s_unknown_sa",
    0x16c9a0c6 : "twr_s_unknown_tower",
    0x16c9a0c7 : "twr_s_not_implemented",
    0x16c9a0c8 : "rpc_s_max_calls_too_small",
    0x16c9a0c9 : "rpc_s_cthread_create_failed",
    0x16c9a0ca : "rpc_s_cthread_pool_exists",
    0x16c9a0cb : "rpc_s_cthread_no_such_pool",
    0x16c9a0cc : "rpc_s_cthread_invoke_disabled",
    0x16c9a0cd : "ept_s_cant_perform_op",
    0x16c9a0ce : "ept_s_no_memory",
    0x16c9a0cf : "ept_s_database_invalid",
    0x16c9a0d0 : "ept_s_cant_create",
    0x16c9a0d1 : "ept_s_cant_access",
    0x16c9a0d2 : "ept_s_database_already_open",
    0x16c9a0d3 : "ept_s_invalid_entry",
    0x16c9a0d4 : "ept_s_update_failed",
    0x16c9a0d5 : "ept_s_invalid_context",
    0x16c9a0d6 : "ept_s_not_registered",
    0x16c9a0d7 : "ept_s_server_unavailable",
    0x16c9a0d8 : "rpc_s_underspecified_name",
    0x16c9a0d9 : "rpc_s_invalid_ns_handle",
    0x16c9a0da : "rpc_s_unknown_error",
    0x16c9a0db : "rpc_s_ss_char_trans_open_fail",
    0x16c9a0dc : "rpc_s_ss_char_trans_short_file",
    0x16c9a0dd : "rpc_s_ss_context_damaged",
    0x16c9a0de : "rpc_s_ss_in_null_context",
    0x16c9a0df : "rpc_s_socket_failure",
    0x16c9a0e0 : "rpc_s_unsupported_protect_level",
    0x16c9a0e1 : "rpc_s_invalid_checksum",
    0x16c9a0e2 : "rpc_s_invalid_credentials",
    0x16c9a0e3 : "rpc_s_credentials_too_large",
    0x16c9a0e4 : "rpc_s_call_id_not_found",
    0x16c9a0e5 : "rpc_s_key_id_not_found",
    0x16c9a0e6 : "rpc_s_auth_bad_integrity",
    0x16c9a0e7 : "rpc_s_auth_tkt_expired",
    0x16c9a0e8 : "rpc_s_auth_tkt_nyv",
    0x16c9a0e9 : "rpc_s_auth_repeat",
    0x16c9a0ea : "rpc_s_auth_not_us",
    0x16c9a0eb : "rpc_s_auth_badmatch",
    0x16c9a0ec : "rpc_s_auth_skew",
    0x16c9a0ed : "rpc_s_auth_badaddr",
    0x16c9a0ee : "rpc_s_auth_badversion",
    0x16c9a0ef : "rpc_s_auth_msg_type",
    0x16c9a0f0 : "rpc_s_auth_modified",
    0x16c9a0f1 : "rpc_s_auth_badorder",
    0x16c9a0f2 : "rpc_s_auth_badkeyver",
    0x16c9a0f3 : "rpc_s_auth_nokey",
    0x16c9a0f4 : "rpc_s_auth_mut_fail",
    0x16c9a0f5 : "rpc_s_auth_baddirection",
    0x16c9a0f6 : "rpc_s_auth_method",
    0x16c9a0f7 : "rpc_s_auth_badseq",
    0x16c9a0f8 : "rpc_s_auth_inapp_cksum",
    0x16c9a0f9 : "rpc_s_auth_field_toolong",
    0x16c9a0fa : "rpc_s_invalid_crc",
    0x16c9a0fb : "rpc_s_binding_incomplete",
    0x16c9a0fc : "rpc_s_key_func_not_allowed",
    0x16c9a0fd : "rpc_s_unknown_stub_rtl_if_vers",
    0x16c9a0fe : "rpc_s_unknown_ifspec_vers",
    0x16c9a0ff : "rpc_s_proto_unsupp_by_auth",
    0x16c9a100 : "rpc_s_authn_challenge_malformed",
    0x16c9a101 : "rpc_s_protect_level_mismatch",
    0x16c9a102 : "rpc_s_no_mepv",
    0x16c9a103 : "rpc_s_stub_protocol_error",
    0x16c9a104 : "rpc_s_class_version_mismatch",
    0x16c9a105 : "rpc_s_helper_not_running",
    0x16c9a106 : "rpc_s_helper_short_read",
    0x16c9a107 : "rpc_s_helper_catatonic",
    0x16c9a108 : "rpc_s_helper_aborted",
    0x16c9a109 : "rpc_s_not_in_kernel",
    0x16c9a10a : "rpc_s_helper_wrong_user",
    0x16c9a10b : "rpc_s_helper_overflow",
    0x16c9a10c : "rpc_s_dg_need_way_auth",
    0x16c9a10d : "rpc_s_unsupported_auth_subtype",
    0x16c9a10e : "rpc_s_wrong_pickle_type",
    0x16c9a10f : "rpc_s_not_listening",
    0x16c9a110 : "rpc_s_ss_bad_buffer",
    0x16c9a111 : "rpc_s_ss_bad_es_action",
    0x16c9a112 : "rpc_s_ss_wrong_es_version",
    0x16c9a113 : "rpc_s_fault_user_defined",
    0x16c9a114 : "rpc_s_ss_incompatible_codesets",
    0x16c9a115 : "rpc_s_tx_not_in_transaction",
    0x16c9a116 : "rpc_s_tx_open_failed",
    0x16c9a117 : "rpc_s_partial_credentials",
    0x16c9a118 : "rpc_s_ss_invalid_codeset_tag",
    0x16c9a119 : "rpc_s_mgmt_bad_type",
    0x16c9a11a : "rpc_s_ss_invalid_char_input",
    0x16c9a11b : "rpc_s_ss_short_conv_buffer",
    0x16c9a11c : "rpc_s_ss_iconv_error",
    0x16c9a11d : "rpc_s_ss_no_compat_codeset",
    0x16c9a11e : "rpc_s_ss_no_compat_charsets",
    0x16c9a11f : "dce_cs_c_ok",
    0x16c9a120 : "dce_cs_c_unknown",
    0x16c9a121 : "dce_cs_c_notfound",
    0x16c9a122 : "dce_cs_c_cannot_open_file",
    0x16c9a123 : "dce_cs_c_cannot_read_file",
    0x16c9a124 : "dce_cs_c_cannot_allocate_memory",
    0x16c9a125 : "rpc_s_ss_cleanup_failed",
    0x16c9a126 : "rpc_svc_desc_general",
    0x16c9a127 : "rpc_svc_desc_mutex",
    0x16c9a128 : "rpc_svc_desc_xmit",
    0x16c9a129 : "rpc_svc_desc_recv",
    0x16c9a12a : "rpc_svc_desc_dg_state",
    0x16c9a12b : "rpc_svc_desc_cancel",
    0x16c9a12c : "rpc_svc_desc_orphan",
    0x16c9a12d : "rpc_svc_desc_cn_state",
    0x16c9a12e : "rpc_svc_desc_cn_pkt",
    0x16c9a12f : "rpc_svc_desc_pkt_quotas",
    0x16c9a130 : "rpc_svc_desc_auth",
    0x16c9a131 : "rpc_svc_desc_source",
    0x16c9a132 : "rpc_svc_desc_stats",
    0x16c9a133 : "rpc_svc_desc_mem",
    0x16c9a134 : "rpc_svc_desc_mem_type",
    0x16c9a135 : "rpc_svc_desc_dg_pktlog",
    0x16c9a136 : "rpc_svc_desc_thread_id",
    0x16c9a137 : "rpc_svc_desc_timestamp",
    0x16c9a138 : "rpc_svc_desc_cn_errors",
    0x16c9a139 : "rpc_svc_desc_conv_thread",
    0x16c9a13a : "rpc_svc_desc_pid",
    0x16c9a13b : "rpc_svc_desc_atfork",
    0x16c9a13c : "rpc_svc_desc_cma_thread",
    0x16c9a13d : "rpc_svc_desc_inherit",
    0x16c9a13e : "rpc_svc_desc_dg_sockets",
    0x16c9a13f : "rpc_svc_desc_timer",
    0x16c9a140 : "rpc_svc_desc_threads",
    0x16c9a141 : "rpc_svc_desc_server_call",
    0x16c9a142 : "rpc_svc_desc_nsi",
    0x16c9a143 : "rpc_svc_desc_dg_pkt",
    0x16c9a144 : "rpc_m_cn_ill_state_trans_sa",
    0x16c9a145 : "rpc_m_cn_ill_state_trans_ca",
    0x16c9a146 : "rpc_m_cn_ill_state_trans_sg",
    0x16c9a147 : "rpc_m_cn_ill_state_trans_cg",
    0x16c9a148 : "rpc_m_cn_ill_state_trans_sr",
    0x16c9a149 : "rpc_m_cn_ill_state_trans_cr",
    0x16c9a14a : "rpc_m_bad_pkt_type",
    0x16c9a14b : "rpc_m_prot_mismatch",
    0x16c9a14c : "rpc_m_frag_toobig",
    0x16c9a14d : "rpc_m_unsupp_stub_rtl_if",
    0x16c9a14e : "rpc_m_unhandled_callstate",
    0x16c9a14f : "rpc_m_call_failed",
    0x16c9a150 : "rpc_m_call_failed_no_status",
    0x16c9a151 : "rpc_m_call_failed_errno",
    0x16c9a152 : "rpc_m_call_failed_s",
    0x16c9a153 : "rpc_m_call_failed_c",
    0x16c9a154 : "rpc_m_errmsg_toobig",
    0x16c9a155 : "rpc_m_invalid_srchattr",
    0x16c9a156 : "rpc_m_nts_not_found",
    0x16c9a157 : "rpc_m_invalid_accbytcnt",
    0x16c9a158 : "rpc_m_pre_v2_ifspec",
    0x16c9a159 : "rpc_m_unk_ifspec",
    0x16c9a15a : "rpc_m_recvbuf_toosmall",
    0x16c9a15b : "rpc_m_unalign_authtrl",
    0x16c9a15c : "rpc_m_unexpected_exc",
    0x16c9a15d : "rpc_m_no_stub_data",
    0x16c9a15e : "rpc_m_eventlist_full",
    0x16c9a15f : "rpc_m_unk_sock_type",
    0x16c9a160 : "rpc_m_unimp_call",
    0x16c9a161 : "rpc_m_invalid_seqnum",
    0x16c9a162 : "rpc_m_cant_create_uuid",
    0x16c9a163 : "rpc_m_pre_v2_ss",
    0x16c9a164 : "rpc_m_dgpkt_pool_corrupt",
    0x16c9a165 : "rpc_m_dgpkt_bad_free",
    0x16c9a166 : "rpc_m_lookaside_corrupt",
    0x16c9a167 : "rpc_m_alloc_fail",
    0x16c9a168 : "rpc_m_realloc_fail",
    0x16c9a169 : "rpc_m_cant_open_file",
    0x16c9a16a : "rpc_m_cant_read_addr",
    0x16c9a16b : "rpc_svc_desc_libidl",
    0x16c9a16c : "rpc_m_ctxrundown_nomem",
    0x16c9a16d : "rpc_m_ctxrundown_exc",
    0x16c9a16e : "rpc_s_fault_codeset_conv_error",
    0x16c9a16f : "rpc_s_no_call_active",
    0x16c9a170 : "rpc_s_cannot_support",
    0x16c9a171 : "rpc_s_no_context_available",
}

MSRPC_STATUS_CODE_RPC_S_ACCESS_DENIED = 0X00000005
MSRPC_STATUS_CODE_AUTHENTICATION_TYPE_NOT_RECOGNIZED = 0X00000008
MSRPC_STATUS_CODE_RPC_FAULT_CANT_PERFORM = 0X000006D8
MSRPC_STATUS_CODE_RPC_X_INVALID_BOUND = 0X000006C6
MSRPC_STATUS_CODE_RPC_S_CANNOT_SUPPORT = 0X000006E4
MSRPC_STATUS_CODE_RPC_X_BAD_STUB_DATA = 0X000006F7
MSRPC_STATUS_CODE_NCA_S_COMM_FAILURE = 0X1C010001
MSRPC_STATUS_CODE_NCA_S_OP_RNG_ERROR = 0X1C010002
MSRPC_STATUS_CODE_NCA_S_UNK_IF = 0X1C010003
MSRPC_STATUS_CODE_NCA_S_WRONG_BOOT_TIME = 0X1C010006
MSRPC_STATUS_CODE_NCA_S_YOU_CRASHED = 0X1C010009
MSRPC_STATUS_CODE_NCA_S_PROTO_ERROR = 0X1C01000B
MSRPC_STATUS_CODE_NCA_S_OUT_ARGS_TOO_BIG = 0X1C010013
MSRPC_STATUS_CODE_NCA_S_SERVER_TOO_BUSY = 0X1C010014
MSRPC_STATUS_CODE_NCA_S_FAULT_STRING_TOO_LONG = 0X1C010015
MSRPC_STATUS_CODE_NCA_S_UNSUPPORTED_TYPE = 0X1C010017
MSRPC_STATUS_CODE_NCA_S_FAULT_INT_DIV_BY_ZERO = 0X1C000001
MSRPC_STATUS_CODE_NCA_S_FAULT_ADDR_ERROR = 0X1C000002
MSRPC_STATUS_CODE_NCA_S_FAULT_FP_DIV_ZERO = 0X1C000003
MSRPC_STATUS_CODE_NCA_S_FAULT_FP_UNDERFLOW = 0X1C000004
MSRPC_STATUS_CODE_NCA_S_FAULT_FP_OVERFLOW = 0X1C000005
MSRPC_STATUS_CODE_NCA_S_FAULT_INVALID_TAG = 0X1C000006
MSRPC_STATUS_CODE_NCA_S_FAULT_INVALID_BOUND = 0X1C000007
MSRPC_STATUS_CODE_NCA_S_RPC_VERSION_MISMATCH = 0X1C000008
MSRPC_STATUS_CODE_NCA_S_UNSPEC_REJECT = 0X1C000009
MSRPC_STATUS_CODE_NCA_S_BAD_ACTID = 0X1C00000A
MSRPC_STATUS_CODE_NCA_S_WHO_ARE_YOU_FAILED = 0X1C00000B
MSRPC_STATUS_CODE_NCA_S_MANAGER_NOT_ENTERED = 0X1C00000C
MSRPC_STATUS_CODE_NCA_S_FAULT_CANCEL = 0X1C00000D
MSRPC_STATUS_CODE_NCA_S_FAULT_ILL_INST = 0X1C00000E
MSRPC_STATUS_CODE_NCA_S_FAULT_FP_ERROR = 0X1C00000F
MSRPC_STATUS_CODE_NCA_S_FAULT_INT_OVERFLOW = 0X1C000010
MSRPC_STATUS_CODE_NCA_S_FAULT_UNSPEC = 0X1C000012
MSRPC_STATUS_CODE_NCA_S_FAULT_REMOTE_COMM_FAILURE = 0X1C000013
MSRPC_STATUS_CODE_NCA_S_FAULT_PIPE_EMPTY = 0X1C000014
MSRPC_STATUS_CODE_NCA_S_FAULT_PIPE_CLOSED = 0X1C000015
MSRPC_STATUS_CODE_NCA_S_FAULT_PIPE_ORDER = 0X1C000016
MSRPC_STATUS_CODE_NCA_S_FAULT_PIPE_DISCIPLINE = 0X1C000017
MSRPC_STATUS_CODE_NCA_S_FAULT_PIPE_COMM_ERROR = 0X1C000018
MSRPC_STATUS_CODE_NCA_S_FAULT_PIPE_MEMORY = 0X1C000019
MSRPC_STATUS_CODE_NCA_S_FAULT_CONTEXT_MISMATCH = 0X1C00001A
MSRPC_STATUS_CODE_NCA_S_FAULT_REMOTE_NO_MEMORY = 0X1C00001B
MSRPC_STATUS_CODE_NCA_S_INVALID_PRES_CONTEXT_ID = 0X1C00001C
MSRPC_STATUS_CODE_NCA_S_UNSUPPORTED_AUTHN_LEVEL = 0X1C00001D
MSRPC_STATUS_CODE_NCA_S_INVALID_CHECKSUM = 0X1C00001F
MSRPC_STATUS_CODE_NCA_S_INVALID_CRC = 0X1C000020
MSRPC_STATUS_CODE_NCA_S_FAULT_USER_DEFINED = 0X1C000021
MSRPC_STATUS_CODE_NCA_S_FAULT_TX_OPEN_FAILED = 0X1C000022
MSRPC_STATUS_CODE_NCA_S_FAULT_CODESET_CONV_ERROR = 0X1C000023
MSRPC_STATUS_CODE_NCA_S_FAULT_OBJECT_NOT_FOUND = 0X1C000024
MSRPC_STATUS_CODE_NCA_S_FAULT_NO_CLIENT_STUB = 0X1C000025
MSRPC_STATUS_CODE_RPC_S_MOD = 0X16C9A000
MSRPC_STATUS_CODE_RPC_S_OP_RNG_ERROR = 0X16C9A001
MSRPC_STATUS_CODE_RPC_S_CANT_CREATE_SOCKET = 0X16C9A002
MSRPC_STATUS_CODE_RPC_S_CANT_BIND_SOCKET = 0X16C9A003
MSRPC_STATUS_CODE_RPC_S_NOT_IN_CALL = 0X16C9A004
MSRPC_STATUS_CODE_RPC_S_NO_PORT = 0X16C9A005
MSRPC_STATUS_CODE_RPC_S_WRONG_BOOT_TIME = 0X16C9A006
MSRPC_STATUS_CODE_RPC_S_TOO_MANY_SOCKETS = 0X16C9A007
MSRPC_STATUS_CODE_RPC_S_ILLEGAL_REGISTER = 0X16C9A008
MSRPC_STATUS_CODE_RPC_S_CANT_RECV = 0X16C9A009
MSRPC_STATUS_CODE_RPC_S_BAD_PKT = 0X16C9A00A
MSRPC_STATUS_CODE_RPC_S_UNBOUND_HANDLE = 0X16C9A00B
MSRPC_STATUS_CODE_RPC_S_ADDR_IN_USE = 0X16C9A00C
MSRPC_STATUS_CODE_RPC_S_IN_ARGS_TOO_BIG = 0X16C9A00D
MSRPC_STATUS_CODE_RPC_S_STRING_TOO_LONG = 0X16C9A00E
MSRPC_STATUS_CODE_RPC_S_TOO_MANY_OBJECTS = 0X16C9A00F
MSRPC_STATUS_CODE_RPC_S_BINDING_HAS_NO_AUTH = 0X16C9A010
MSRPC_STATUS_CODE_RPC_S_UNKNOWN_AUTHN_SERVICE = 0X16C9A011
MSRPC_STATUS_CODE_RPC_S_NO_MEMORY = 0X16C9A012
MSRPC_STATUS_CODE_RPC_S_CANT_NMALLOC = 0X16C9A013
MSRPC_STATUS_CODE_RPC_S_CALL_FAULTED = 0X16C9A014
MSRPC_STATUS_CODE_RPC_S_CALL_FAILED = 0X16C9A015
MSRPC_STATUS_CODE_RPC_S_COMM_FAILURE = 0X16C9A016
MSRPC_STATUS_CODE_RPC_S_RPCD_COMM_FAILURE = 0X16C9A017
MSRPC_STATUS_CODE_RPC_S_ILLEGAL_FAMILY_REBIND = 0X16C9A018
MSRPC_STATUS_CODE_RPC_S_INVALID_HANDLE = 0X16C9A019
MSRPC_STATUS_CODE_RPC_S_CODING_ERROR = 0X16C9A01A
MSRPC_STATUS_CODE_RPC_S_OBJECT_NOT_FOUND = 0X16C9A01B
MSRPC_STATUS_CODE_RPC_S_CTHREAD_NOT_FOUND = 0X16C9A01C
MSRPC_STATUS_CODE_RPC_S_INVALID_BINDING = 0X16C9A01D
MSRPC_STATUS_CODE_RPC_S_ALREADY_REGISTERED = 0X16C9A01E
MSRPC_STATUS_CODE_RPC_S_ENDPOINT_NOT_FOUND = 0X16C9A01F
MSRPC_STATUS_CODE_RPC_S_INVALID_RPC_PROTSEQ = 0X16C9A020
MSRPC_STATUS_CODE_RPC_S_DESC_NOT_REGISTERED = 0X16C9A021
MSRPC_STATUS_CODE_RPC_S_ALREADY_LISTENING = 0X16C9A022
MSRPC_STATUS_CODE_RPC_S_NO_PROTSEQS = 0X16C9A023
MSRPC_STATUS_CODE_RPC_S_NO_PROTSEQS_REGISTERED = 0X16C9A024
MSRPC_STATUS_CODE_RPC_S_NO_BINDINGS = 0X16C9A025
MSRPC_STATUS_CODE_RPC_S_MAX_DESCS_EXCEEDED = 0X16C9A026
MSRPC_STATUS_CODE_RPC_S_NO_INTERFACES = 0X16C9A027
MSRPC_STATUS_CODE_RPC_S_INVALID_TIMEOUT = 0X16C9A028
MSRPC_STATUS_CODE_RPC_S_CANT_INQ_SOCKET = 0X16C9A029
MSRPC_STATUS_CODE_RPC_S_INVALID_NAF_ID = 0X16C9A02A
MSRPC_STATUS_CODE_RPC_S_INVAL_NET_ADDR = 0X16C9A02B
MSRPC_STATUS_CODE_RPC_S_UNKNOWN_IF = 0X16C9A02C
MSRPC_STATUS_CODE_RPC_S_UNSUPPORTED_TYPE = 0X16C9A02D
MSRPC_STATUS_CODE_RPC_S_INVALID_CALL_OPT = 0X16C9A02E
MSRPC_STATUS_CODE_RPC_S_NO_FAULT = 0X16C9A02F
MSRPC_STATUS_CODE_RPC_S_CANCEL_TIMEOUT = 0X16C9A030
MSRPC_STATUS_CODE_RPC_S_CALL_CANCELLED = 0X16C9A031
MSRPC_STATUS_CODE_RPC_S_INVALID_CALL_HANDLE = 0X16C9A032
MSRPC_STATUS_CODE_RPC_S_CANNOT_ALLOC_ASSOC = 0X16C9A033
MSRPC_STATUS_CODE_RPC_S_CANNOT_CONNECT = 0X16C9A034
MSRPC_STATUS_CODE_RPC_S_CONNECTION_ABORTED = 0X16C9A035
MSRPC_STATUS_CODE_RPC_S_CONNECTION_CLOSED = 0X16C9A036
MSRPC_STATUS_CODE_RPC_S_CANNOT_ACCEPT = 0X16C9A037
MSRPC_STATUS_CODE_RPC_S_ASSOC_GRP_NOT_FOUND = 0X16C9A038
MSRPC_STATUS_CODE_RPC_S_STUB_INTERFACE_ERROR = 0X16C9A039
MSRPC_STATUS_CODE_RPC_S_INVALID_OBJECT = 0X16C9A03A
MSRPC_STATUS_CODE_RPC_S_INVALID_TYPE = 0X16C9A03B
MSRPC_STATUS_CODE_RPC_S_INVALID_IF_OPNUM = 0X16C9A03C
MSRPC_STATUS_CODE_RPC_S_DIFFERENT_SERVER_INSTANCE = 0X16C9A03D
MSRPC_STATUS_CODE_RPC_S_PROTOCOL_ERROR = 0X16C9A03E
MSRPC_STATUS_CODE_RPC_S_CANT_RECVMSG = 0X16C9A03F
MSRPC_STATUS_CODE_RPC_S_INVALID_STRING_BINDING = 0X16C9A040
MSRPC_STATUS_CODE_RPC_S_CONNECT_TIMED_OUT = 0X16C9A041
MSRPC_STATUS_CODE_RPC_S_CONNECT_REJECTED = 0X16C9A042
MSRPC_STATUS_CODE_RPC_S_NETWORK_UNREACHABLE = 0X16C9A043
MSRPC_STATUS_CODE_RPC_S_CONNECT_NO_RESOURCES = 0X16C9A044
MSRPC_STATUS_CODE_RPC_S_REM_NETWORK_SHUTDOWN = 0X16C9A045
MSRPC_STATUS_CODE_RPC_S_TOO_MANY_REM_CONNECTS = 0X16C9A046
MSRPC_STATUS_CODE_RPC_S_NO_REM_ENDPOINT = 0X16C9A047
MSRPC_STATUS_CODE_RPC_S_REM_HOST_DOWN = 0X16C9A048
MSRPC_STATUS_CODE_RPC_S_HOST_UNREACHABLE = 0X16C9A049
MSRPC_STATUS_CODE_RPC_S_ACCESS_CONTROL_INFO_INV = 0X16C9A04A
MSRPC_STATUS_CODE_RPC_S_LOC_CONNECT_ABORTED = 0X16C9A04B
MSRPC_STATUS_CODE_RPC_S_CONNECT_CLOSED_BY_REM = 0X16C9A04C
MSRPC_STATUS_CODE_RPC_S_REM_HOST_CRASHED = 0X16C9A04D
MSRPC_STATUS_CODE_RPC_S_INVALID_ENDPOINT_FORMAT = 0X16C9A04E
MSRPC_STATUS_CODE_RPC_S_UNKNOWN_STATUS_CODE = 0X16C9A04F
MSRPC_STATUS_CODE_RPC_S_UNKNOWN_MGR_TYPE = 0X16C9A050
MSRPC_STATUS_CODE_RPC_S_ASSOC_CREATION_FAILED = 0X16C9A051
MSRPC_STATUS_CODE_RPC_S_ASSOC_GRP_MAX_EXCEEDED = 0X16C9A052
MSRPC_STATUS_CODE_RPC_S_ASSOC_GRP_ALLOC_FAILED = 0X16C9A053
MSRPC_STATUS_CODE_RPC_S_SM_INVALID_STATE = 0X16C9A054
MSRPC_STATUS_CODE_RPC_S_ASSOC_REQ_REJECTED = 0X16C9A055
MSRPC_STATUS_CODE_RPC_S_ASSOC_SHUTDOWN = 0X16C9A056
MSRPC_STATUS_CODE_RPC_S_TSYNTAXES_UNSUPPORTED = 0X16C9A057
MSRPC_STATUS_CODE_RPC_S_CONTEXT_ID_NOT_FOUND = 0X16C9A058
MSRPC_STATUS_CODE_RPC_S_CANT_LISTEN_SOCKET = 0X16C9A059
MSRPC_STATUS_CODE_RPC_S_NO_ADDRS = 0X16C9A05A
MSRPC_STATUS_CODE_RPC_S_CANT_GETPEERNAME = 0X16C9A05B
MSRPC_STATUS_CODE_RPC_S_CANT_GET_IF_ID = 0X16C9A05C
MSRPC_STATUS_CODE_RPC_S_PROTSEQ_NOT_SUPPORTED = 0X16C9A05D
MSRPC_STATUS_CODE_RPC_S_CALL_ORPHANED = 0X16C9A05E
MSRPC_STATUS_CODE_RPC_S_WHO_ARE_YOU_FAILED = 0X16C9A05F
MSRPC_STATUS_CODE_RPC_S_UNKNOWN_REJECT = 0X16C9A060
MSRPC_STATUS_CODE_RPC_S_TYPE_ALREADY_REGISTERED = 0X16C9A061
MSRPC_STATUS_CODE_RPC_S_STOP_LISTENING_DISABLED = 0X16C9A062
MSRPC_STATUS_CODE_RPC_S_INVALID_ARG = 0X16C9A063
MSRPC_STATUS_CODE_RPC_S_NOT_SUPPORTED = 0X16C9A064
MSRPC_STATUS_CODE_RPC_S_WRONG_KIND_OF_BINDING = 0X16C9A065
MSRPC_STATUS_CODE_RPC_S_AUTHN_AUTHZ_MISMATCH = 0X16C9A066
MSRPC_STATUS_CODE_RPC_S_CALL_QUEUED = 0X16C9A067
MSRPC_STATUS_CODE_RPC_S_CANNOT_SET_NODELAY = 0X16C9A068
MSRPC_STATUS_CODE_RPC_S_NOT_RPC_TOWER = 0X16C9A069
MSRPC_STATUS_CODE_RPC_S_INVALID_RPC_PROTID = 0X16C9A06A
MSRPC_STATUS_CODE_RPC_S_INVALID_RPC_FLOOR = 0X16C9A06B
MSRPC_STATUS_CODE_RPC_S_CALL_TIMEOUT = 0X16C9A06C
MSRPC_STATUS_CODE_RPC_S_MGMT_OP_DISALLOWED = 0X16C9A06D
MSRPC_STATUS_CODE_RPC_S_MANAGER_NOT_ENTERED = 0X16C9A06E
MSRPC_STATUS_CODE_RPC_S_CALLS_TOO_LARGE_FOR_WK_EP = 0X16C9A06F
MSRPC_STATUS_CODE_RPC_S_SERVER_TOO_BUSY = 0X16C9A070
MSRPC_STATUS_CODE_RPC_S_PROT_VERSION_MISMATCH = 0X16C9A071
MSRPC_STATUS_CODE_RPC_S_RPC_PROT_VERSION_MISMATCH = 0X16C9A072
MSRPC_STATUS_CODE_RPC_S_SS_NO_IMPORT_CURSOR = 0X16C9A073
MSRPC_STATUS_CODE_RPC_S_FAULT_ADDR_ERROR = 0X16C9A074
MSRPC_STATUS_CODE_RPC_S_FAULT_CONTEXT_MISMATCH = 0X16C9A075
MSRPC_STATUS_CODE_RPC_S_FAULT_FP_DIV_BY_ZERO = 0X16C9A076
MSRPC_STATUS_CODE_RPC_S_FAULT_FP_ERROR = 0X16C9A077
MSRPC_STATUS_CODE_RPC_S_FAULT_FP_OVERFLOW = 0X16C9A078
MSRPC_STATUS_CODE_RPC_S_FAULT_FP_UNDERFLOW = 0X16C9A079
MSRPC_STATUS_CODE_RPC_S_FAULT_ILL_INST = 0X16C9A07A
MSRPC_STATUS_CODE_RPC_S_FAULT_INT_DIV_BY_ZERO = 0X16C9A07B
MSRPC_STATUS_CODE_RPC_S_FAULT_INT_OVERFLOW = 0X16C9A07C
MSRPC_STATUS_CODE_RPC_S_FAULT_INVALID_BOUND = 0X16C9A07D
MSRPC_STATUS_CODE_RPC_S_FAULT_INVALID_TAG = 0X16C9A07E
MSRPC_STATUS_CODE_RPC_S_FAULT_PIPE_CLOSED = 0X16C9A07F
MSRPC_STATUS_CODE_RPC_S_FAULT_PIPE_COMM_ERROR = 0X16C9A080
MSRPC_STATUS_CODE_RPC_S_FAULT_PIPE_DISCIPLINE = 0X16C9A081
MSRPC_STATUS_CODE_RPC_S_FAULT_PIPE_EMPTY = 0X16C9A082
MSRPC_STATUS_CODE_RPC_S_FAULT_PIPE_MEMORY = 0X16C9A083
MSRPC_STATUS_CODE_RPC_S_FAULT_PIPE_ORDER = 0X16C9A084
MSRPC_STATUS_CODE_RPC_S_FAULT_REMOTE_COMM_FAILURE = 0X16C9A085
MSRPC_STATUS_CODE_RPC_S_FAULT_REMOTE_NO_MEMORY = 0X16C9A086
MSRPC_STATUS_CODE_RPC_S_FAULT_UNSPEC = 0X16C9A087
MSRPC_STATUS_CODE_UUID_S_BAD_VERSION = 0X16C9A088
MSRPC_STATUS_CODE_UUID_S_SOCKET_FAILURE = 0X16C9A089
MSRPC_STATUS_CODE_UUID_S_GETCONF_FAILURE = 0X16C9A08A
MSRPC_STATUS_CODE_UUID_S_NO_ADDRESS = 0X16C9A08B
MSRPC_STATUS_CODE_UUID_S_OVERRUN = 0X16C9A08C
MSRPC_STATUS_CODE_UUID_S_INTERNAL_ERROR = 0X16C9A08D
MSRPC_STATUS_CODE_UUID_S_CODING_ERROR = 0X16C9A08E
MSRPC_STATUS_CODE_UUID_S_INVALID_STRING_UUID = 0X16C9A08F
MSRPC_STATUS_CODE_UUID_S_NO_MEMORY = 0X16C9A090
MSRPC_STATUS_CODE_RPC_S_NO_MORE_ENTRIES = 0X16C9A091
MSRPC_STATUS_CODE_RPC_S_UNKNOWN_NS_ERROR = 0X16C9A092
MSRPC_STATUS_CODE_RPC_S_NAME_SERVICE_UNAVAILABLE = 0X16C9A093
MSRPC_STATUS_CODE_RPC_S_INCOMPLETE_NAME = 0X16C9A094
MSRPC_STATUS_CODE_RPC_S_GROUP_NOT_FOUND = 0X16C9A095
MSRPC_STATUS_CODE_RPC_S_INVALID_NAME_SYNTAX = 0X16C9A096
MSRPC_STATUS_CODE_RPC_S_NO_MORE_MEMBERS = 0X16C9A097
MSRPC_STATUS_CODE_RPC_S_NO_MORE_INTERFACES = 0X16C9A098
MSRPC_STATUS_CODE_RPC_S_INVALID_NAME_SERVICE = 0X16C9A099
MSRPC_STATUS_CODE_RPC_S_NO_NAME_MAPPING = 0X16C9A09A
MSRPC_STATUS_CODE_RPC_S_PROFILE_NOT_FOUND = 0X16C9A09B
MSRPC_STATUS_CODE_RPC_S_NOT_FOUND = 0X16C9A09C
MSRPC_STATUS_CODE_RPC_S_NO_UPDATES = 0X16C9A09D
MSRPC_STATUS_CODE_RPC_S_UPDATE_FAILED = 0X16C9A09E
MSRPC_STATUS_CODE_RPC_S_NO_MATCH_EXPORTED = 0X16C9A09F
MSRPC_STATUS_CODE_RPC_S_ENTRY_NOT_FOUND = 0X16C9A0A0
MSRPC_STATUS_CODE_RPC_S_INVALID_INQUIRY_CONTEXT = 0X16C9A0A1
MSRPC_STATUS_CODE_RPC_S_INTERFACE_NOT_FOUND = 0X16C9A0A2
MSRPC_STATUS_CODE_RPC_S_GROUP_MEMBER_NOT_FOUND = 0X16C9A0A3
MSRPC_STATUS_CODE_RPC_S_ENTRY_ALREADY_EXISTS = 0X16C9A0A4
MSRPC_STATUS_CODE_RPC_S_NSINIT_FAILURE = 0X16C9A0A5
MSRPC_STATUS_CODE_RPC_S_UNSUPPORTED_NAME_SYNTAX = 0X16C9A0A6
MSRPC_STATUS_CODE_RPC_S_NO_MORE_ELEMENTS = 0X16C9A0A7
MSRPC_STATUS_CODE_RPC_S_NO_NS_PERMISSION = 0X16C9A0A8
MSRPC_STATUS_CODE_RPC_S_INVALID_INQUIRY_TYPE = 0X16C9A0A9
MSRPC_STATUS_CODE_RPC_S_PROFILE_ELEMENT_NOT_FOUND = 0X16C9A0AA
MSRPC_STATUS_CODE_RPC_S_PROFILE_ELEMENT_REPLACED = 0X16C9A0AB
MSRPC_STATUS_CODE_RPC_S_IMPORT_ALREADY_DONE = 0X16C9A0AC
MSRPC_STATUS_CODE_RPC_S_DATABASE_BUSY = 0X16C9A0AD
MSRPC_STATUS_CODE_RPC_S_INVALID_IMPORT_CONTEXT = 0X16C9A0AE
MSRPC_STATUS_CODE_RPC_S_UUID_SET_NOT_FOUND = 0X16C9A0AF
MSRPC_STATUS_CODE_RPC_S_UUID_MEMBER_NOT_FOUND = 0X16C9A0B0
MSRPC_STATUS_CODE_RPC_S_NO_INTERFACES_EXPORTED = 0X16C9A0B1
MSRPC_STATUS_CODE_RPC_S_TOWER_SET_NOT_FOUND = 0X16C9A0B2
MSRPC_STATUS_CODE_RPC_S_TOWER_MEMBER_NOT_FOUND = 0X16C9A0B3
MSRPC_STATUS_CODE_RPC_S_OBJ_UUID_NOT_FOUND = 0X16C9A0B4
MSRPC_STATUS_CODE_RPC_S_NO_MORE_BINDINGS = 0X16C9A0B5
MSRPC_STATUS_CODE_RPC_S_INVALID_PRIORITY = 0X16C9A0B6
MSRPC_STATUS_CODE_RPC_S_NOT_RPC_ENTRY = 0X16C9A0B7
MSRPC_STATUS_CODE_RPC_S_INVALID_LOOKUP_CONTEXT = 0X16C9A0B8
MSRPC_STATUS_CODE_RPC_S_BINDING_VECTOR_FULL = 0X16C9A0B9
MSRPC_STATUS_CODE_RPC_S_CYCLE_DETECTED = 0X16C9A0BA
MSRPC_STATUS_CODE_RPC_S_NOTHING_TO_EXPORT = 0X16C9A0BB
MSRPC_STATUS_CODE_RPC_S_NOTHING_TO_UNEXPORT = 0X16C9A0BC
MSRPC_STATUS_CODE_RPC_S_INVALID_VERS_OPTION = 0X16C9A0BD
MSRPC_STATUS_CODE_RPC_S_NO_RPC_DATA = 0X16C9A0BE
MSRPC_STATUS_CODE_RPC_S_MBR_PICKED = 0X16C9A0BF
MSRPC_STATUS_CODE_RPC_S_NOT_ALL_OBJS_UNEXPORTED = 0X16C9A0C0
MSRPC_STATUS_CODE_RPC_S_NO_ENTRY_NAME = 0X16C9A0C1
MSRPC_STATUS_CODE_RPC_S_PRIORITY_GROUP_DONE = 0X16C9A0C2
MSRPC_STATUS_CODE_RPC_S_PARTIAL_RESULTS = 0X16C9A0C3
MSRPC_STATUS_CODE_RPC_S_NO_ENV_SETUP = 0X16C9A0C4
MSRPC_STATUS_CODE_TWR_S_UNKNOWN_SA = 0X16C9A0C5
MSRPC_STATUS_CODE_TWR_S_UNKNOWN_TOWER = 0X16C9A0C6
MSRPC_STATUS_CODE_TWR_S_NOT_IMPLEMENTED = 0X16C9A0C7
MSRPC_STATUS_CODE_RPC_S_MAX_CALLS_TOO_SMALL = 0X16C9A0C8
MSRPC_STATUS_CODE_RPC_S_CTHREAD_CREATE_FAILED = 0X16C9A0C9
MSRPC_STATUS_CODE_RPC_S_CTHREAD_POOL_EXISTS = 0X16C9A0CA
MSRPC_STATUS_CODE_RPC_S_CTHREAD_NO_SUCH_POOL = 0X16C9A0CB
MSRPC_STATUS_CODE_RPC_S_CTHREAD_INVOKE_DISABLED = 0X16C9A0CC
MSRPC_STATUS_CODE_EPT_S_CANT_PERFORM_OP = 0X16C9A0CD
MSRPC_STATUS_CODE_EPT_S_NO_MEMORY = 0X16C9A0CE
MSRPC_STATUS_CODE_EPT_S_DATABASE_INVALID = 0X16C9A0CF
MSRPC_STATUS_CODE_EPT_S_CANT_CREATE = 0X16C9A0D0
MSRPC_STATUS_CODE_EPT_S_CANT_ACCESS = 0X16C9A0D1
MSRPC_STATUS_CODE_EPT_S_DATABASE_ALREADY_OPEN = 0X16C9A0D2
MSRPC_STATUS_CODE_EPT_S_INVALID_ENTRY = 0X16C9A0D3
MSRPC_STATUS_CODE_EPT_S_UPDATE_FAILED = 0X16C9A0D4
MSRPC_STATUS_CODE_EPT_S_INVALID_CONTEXT = 0X16C9A0D5
MSRPC_STATUS_CODE_EPT_S_NOT_REGISTERED = 0X16C9A0D6
MSRPC_STATUS_CODE_EPT_S_SERVER_UNAVAILABLE = 0X16C9A0D7
MSRPC_STATUS_CODE_RPC_S_UNDERSPECIFIED_NAME = 0X16C9A0D8
MSRPC_STATUS_CODE_RPC_S_INVALID_NS_HANDLE = 0X16C9A0D9
MSRPC_STATUS_CODE_RPC_S_UNKNOWN_ERROR = 0X16C9A0DA
MSRPC_STATUS_CODE_RPC_S_SS_CHAR_TRANS_OPEN_FAIL = 0X16C9A0DB
MSRPC_STATUS_CODE_RPC_S_SS_CHAR_TRANS_SHORT_FILE = 0X16C9A0DC
MSRPC_STATUS_CODE_RPC_S_SS_CONTEXT_DAMAGED = 0X16C9A0DD
MSRPC_STATUS_CODE_RPC_S_SS_IN_NULL_CONTEXT = 0X16C9A0DE
MSRPC_STATUS_CODE_RPC_S_SOCKET_FAILURE = 0X16C9A0DF
MSRPC_STATUS_CODE_RPC_S_UNSUPPORTED_PROTECT_LEVEL = 0X16C9A0E0
MSRPC_STATUS_CODE_RPC_S_INVALID_CHECKSUM = 0X16C9A0E1
MSRPC_STATUS_CODE_RPC_S_INVALID_CREDENTIALS = 0X16C9A0E2
MSRPC_STATUS_CODE_RPC_S_CREDENTIALS_TOO_LARGE = 0X16C9A0E3
MSRPC_STATUS_CODE_RPC_S_CALL_ID_NOT_FOUND = 0X16C9A0E4
MSRPC_STATUS_CODE_RPC_S_KEY_ID_NOT_FOUND = 0X16C9A0E5
MSRPC_STATUS_CODE_RPC_S_AUTH_BAD_INTEGRITY = 0X16C9A0E6
MSRPC_STATUS_CODE_RPC_S_AUTH_TKT_EXPIRED = 0X16C9A0E7
MSRPC_STATUS_CODE_RPC_S_AUTH_TKT_NYV = 0X16C9A0E8
MSRPC_STATUS_CODE_RPC_S_AUTH_REPEAT = 0X16C9A0E9
MSRPC_STATUS_CODE_RPC_S_AUTH_NOT_US = 0X16C9A0EA
MSRPC_STATUS_CODE_RPC_S_AUTH_BADMATCH = 0X16C9A0EB
MSRPC_STATUS_CODE_RPC_S_AUTH_SKEW = 0X16C9A0EC
MSRPC_STATUS_CODE_RPC_S_AUTH_BADADDR = 0X16C9A0ED
MSRPC_STATUS_CODE_RPC_S_AUTH_BADVERSION = 0X16C9A0EE
MSRPC_STATUS_CODE_RPC_S_AUTH_MSG_TYPE = 0X16C9A0EF
MSRPC_STATUS_CODE_RPC_S_AUTH_MODIFIED = 0X16C9A0F0
MSRPC_STATUS_CODE_RPC_S_AUTH_BADORDER = 0X16C9A0F1
MSRPC_STATUS_CODE_RPC_S_AUTH_BADKEYVER = 0X16C9A0F2
MSRPC_STATUS_CODE_RPC_S_AUTH_NOKEY = 0X16C9A0F3
MSRPC_STATUS_CODE_RPC_S_AUTH_MUT_FAIL = 0X16C9A0F4
MSRPC_STATUS_CODE_RPC_S_AUTH_BADDIRECTION = 0X16C9A0F5
MSRPC_STATUS_CODE_RPC_S_AUTH_METHOD = 0X16C9A0F6
MSRPC_STATUS_CODE_RPC_S_AUTH_BADSEQ = 0X16C9A0F7
MSRPC_STATUS_CODE_RPC_S_AUTH_INAPP_CKSUM = 0X16C9A0F8
MSRPC_STATUS_CODE_RPC_S_AUTH_FIELD_TOOLONG = 0X16C9A0F9
MSRPC_STATUS_CODE_RPC_S_INVALID_CRC = 0X16C9A0FA
MSRPC_STATUS_CODE_RPC_S_BINDING_INCOMPLETE = 0X16C9A0FB
MSRPC_STATUS_CODE_RPC_S_KEY_FUNC_NOT_ALLOWED = 0X16C9A0FC
MSRPC_STATUS_CODE_RPC_S_UNKNOWN_STUB_RTL_IF_VERS = 0X16C9A0FD
MSRPC_STATUS_CODE_RPC_S_UNKNOWN_IFSPEC_VERS = 0X16C9A0FE
MSRPC_STATUS_CODE_RPC_S_PROTO_UNSUPP_BY_AUTH = 0X16C9A0FF
MSRPC_STATUS_CODE_RPC_S_AUTHN_CHALLENGE_MALFORMED = 0X16C9A100
MSRPC_STATUS_CODE_RPC_S_PROTECT_LEVEL_MISMATCH = 0X16C9A101
MSRPC_STATUS_CODE_RPC_S_NO_MEPV = 0X16C9A102
MSRPC_STATUS_CODE_RPC_S_STUB_PROTOCOL_ERROR = 0X16C9A103
MSRPC_STATUS_CODE_RPC_S_CLASS_VERSION_MISMATCH = 0X16C9A104
MSRPC_STATUS_CODE_RPC_S_HELPER_NOT_RUNNING = 0X16C9A105
MSRPC_STATUS_CODE_RPC_S_HELPER_SHORT_READ = 0X16C9A106
MSRPC_STATUS_CODE_RPC_S_HELPER_CATATONIC = 0X16C9A107
MSRPC_STATUS_CODE_RPC_S_HELPER_ABORTED = 0X16C9A108
MSRPC_STATUS_CODE_RPC_S_NOT_IN_KERNEL = 0X16C9A109
MSRPC_STATUS_CODE_RPC_S_HELPER_WRONG_USER = 0X16C9A10A
MSRPC_STATUS_CODE_RPC_S_HELPER_OVERFLOW = 0X16C9A10B
MSRPC_STATUS_CODE_RPC_S_DG_NEED_WAY_AUTH = 0X16C9A10C
MSRPC_STATUS_CODE_RPC_S_UNSUPPORTED_AUTH_SUBTYPE = 0X16C9A10D
MSRPC_STATUS_CODE_RPC_S_WRONG_PICKLE_TYPE = 0X16C9A10E
MSRPC_STATUS_CODE_RPC_S_NOT_LISTENING = 0X16C9A10F
MSRPC_STATUS_CODE_RPC_S_SS_BAD_BUFFER = 0X16C9A110
MSRPC_STATUS_CODE_RPC_S_SS_BAD_ES_ACTION = 0X16C9A111
MSRPC_STATUS_CODE_RPC_S_SS_WRONG_ES_VERSION = 0X16C9A112
MSRPC_STATUS_CODE_RPC_S_FAULT_USER_DEFINED = 0X16C9A113
MSRPC_STATUS_CODE_RPC_S_SS_INCOMPATIBLE_CODESETS = 0X16C9A114
MSRPC_STATUS_CODE_RPC_S_TX_NOT_IN_TRANSACTION = 0X16C9A115
MSRPC_STATUS_CODE_RPC_S_TX_OPEN_FAILED = 0X16C9A116
MSRPC_STATUS_CODE_RPC_S_PARTIAL_CREDENTIALS = 0X16C9A117
MSRPC_STATUS_CODE_RPC_S_SS_INVALID_CODESET_TAG = 0X16C9A118
MSRPC_STATUS_CODE_RPC_S_MGMT_BAD_TYPE = 0X16C9A119
MSRPC_STATUS_CODE_RPC_S_SS_INVALID_CHAR_INPUT = 0X16C9A11A
MSRPC_STATUS_CODE_RPC_S_SS_SHORT_CONV_BUFFER = 0X16C9A11B
MSRPC_STATUS_CODE_RPC_S_SS_ICONV_ERROR = 0X16C9A11C
MSRPC_STATUS_CODE_RPC_S_SS_NO_COMPAT_CODESET = 0X16C9A11D
MSRPC_STATUS_CODE_RPC_S_SS_NO_COMPAT_CHARSETS = 0X16C9A11E
MSRPC_STATUS_CODE_DCE_CS_C_OK = 0X16C9A11F
MSRPC_STATUS_CODE_DCE_CS_C_UNKNOWN = 0X16C9A120
MSRPC_STATUS_CODE_DCE_CS_C_NOTFOUND = 0X16C9A121
MSRPC_STATUS_CODE_DCE_CS_C_CANNOT_OPEN_FILE = 0X16C9A122
MSRPC_STATUS_CODE_DCE_CS_C_CANNOT_READ_FILE = 0X16C9A123
MSRPC_STATUS_CODE_DCE_CS_C_CANNOT_ALLOCATE_MEMORY = 0X16C9A124
MSRPC_STATUS_CODE_RPC_S_SS_CLEANUP_FAILED = 0X16C9A125
MSRPC_STATUS_CODE_RPC_SVC_DESC_GENERAL = 0X16C9A126
MSRPC_STATUS_CODE_RPC_SVC_DESC_MUTEX = 0X16C9A127
MSRPC_STATUS_CODE_RPC_SVC_DESC_XMIT = 0X16C9A128
MSRPC_STATUS_CODE_RPC_SVC_DESC_RECV = 0X16C9A129
MSRPC_STATUS_CODE_RPC_SVC_DESC_DG_STATE = 0X16C9A12A
MSRPC_STATUS_CODE_RPC_SVC_DESC_CANCEL = 0X16C9A12B
MSRPC_STATUS_CODE_RPC_SVC_DESC_ORPHAN = 0X16C9A12C
MSRPC_STATUS_CODE_RPC_SVC_DESC_CN_STATE = 0X16C9A12D
MSRPC_STATUS_CODE_RPC_SVC_DESC_CN_PKT = 0X16C9A12E
MSRPC_STATUS_CODE_RPC_SVC_DESC_PKT_QUOTAS = 0X16C9A12F
MSRPC_STATUS_CODE_RPC_SVC_DESC_AUTH = 0X16C9A130
MSRPC_STATUS_CODE_RPC_SVC_DESC_SOURCE = 0X16C9A131
MSRPC_STATUS_CODE_RPC_SVC_DESC_STATS = 0X16C9A132
MSRPC_STATUS_CODE_RPC_SVC_DESC_MEM = 0X16C9A133
MSRPC_STATUS_CODE_RPC_SVC_DESC_MEM_TYPE = 0X16C9A134
MSRPC_STATUS_CODE_RPC_SVC_DESC_DG_PKTLOG = 0X16C9A135
MSRPC_STATUS_CODE_RPC_SVC_DESC_THREAD_ID = 0X16C9A136
MSRPC_STATUS_CODE_RPC_SVC_DESC_TIMESTAMP = 0X16C9A137
MSRPC_STATUS_CODE_RPC_SVC_DESC_CN_ERRORS = 0X16C9A138
MSRPC_STATUS_CODE_RPC_SVC_DESC_CONV_THREAD = 0X16C9A139
MSRPC_STATUS_CODE_RPC_SVC_DESC_PID = 0X16C9A13A
MSRPC_STATUS_CODE_RPC_SVC_DESC_ATFORK = 0X16C9A13B
MSRPC_STATUS_CODE_RPC_SVC_DESC_CMA_THREAD = 0X16C9A13C
MSRPC_STATUS_CODE_RPC_SVC_DESC_INHERIT = 0X16C9A13D
MSRPC_STATUS_CODE_RPC_SVC_DESC_DG_SOCKETS = 0X16C9A13E
MSRPC_STATUS_CODE_RPC_SVC_DESC_TIMER = 0X16C9A13F
MSRPC_STATUS_CODE_RPC_SVC_DESC_THREADS = 0X16C9A140
MSRPC_STATUS_CODE_RPC_SVC_DESC_SERVER_CALL = 0X16C9A141
MSRPC_STATUS_CODE_RPC_SVC_DESC_NSI = 0X16C9A142
MSRPC_STATUS_CODE_RPC_SVC_DESC_DG_PKT = 0X16C9A143
MSRPC_STATUS_CODE_RPC_M_CN_ILL_STATE_TRANS_SA = 0X16C9A144
MSRPC_STATUS_CODE_RPC_M_CN_ILL_STATE_TRANS_CA = 0X16C9A145
MSRPC_STATUS_CODE_RPC_M_CN_ILL_STATE_TRANS_SG = 0X16C9A146
MSRPC_STATUS_CODE_RPC_M_CN_ILL_STATE_TRANS_CG = 0X16C9A147
MSRPC_STATUS_CODE_RPC_M_CN_ILL_STATE_TRANS_SR = 0X16C9A148
MSRPC_STATUS_CODE_RPC_M_CN_ILL_STATE_TRANS_CR = 0X16C9A149
MSRPC_STATUS_CODE_RPC_M_BAD_PKT_TYPE = 0X16C9A14A
MSRPC_STATUS_CODE_RPC_M_PROT_MISMATCH = 0X16C9A14B
MSRPC_STATUS_CODE_RPC_M_FRAG_TOOBIG = 0X16C9A14C
MSRPC_STATUS_CODE_RPC_M_UNSUPP_STUB_RTL_IF = 0X16C9A14D
MSRPC_STATUS_CODE_RPC_M_UNHANDLED_CALLSTATE = 0X16C9A14E
MSRPC_STATUS_CODE_RPC_M_CALL_FAILED = 0X16C9A14F
MSRPC_STATUS_CODE_RPC_M_CALL_FAILED_NO_STATUS = 0X16C9A150
MSRPC_STATUS_CODE_RPC_M_CALL_FAILED_ERRNO = 0X16C9A151
MSRPC_STATUS_CODE_RPC_M_CALL_FAILED_S = 0X16C9A152
MSRPC_STATUS_CODE_RPC_M_CALL_FAILED_C = 0X16C9A153
MSRPC_STATUS_CODE_RPC_M_ERRMSG_TOOBIG = 0X16C9A154
MSRPC_STATUS_CODE_RPC_M_INVALID_SRCHATTR = 0X16C9A155
MSRPC_STATUS_CODE_RPC_M_NTS_NOT_FOUND = 0X16C9A156
MSRPC_STATUS_CODE_RPC_M_INVALID_ACCBYTCNT = 0X16C9A157
MSRPC_STATUS_CODE_RPC_M_PRE_V2_IFSPEC = 0X16C9A158
MSRPC_STATUS_CODE_RPC_M_UNK_IFSPEC = 0X16C9A159
MSRPC_STATUS_CODE_RPC_M_RECVBUF_TOOSMALL = 0X16C9A15A
MSRPC_STATUS_CODE_RPC_M_UNALIGN_AUTHTRL = 0X16C9A15B
MSRPC_STATUS_CODE_RPC_M_UNEXPECTED_EXC = 0X16C9A15C
MSRPC_STATUS_CODE_RPC_M_NO_STUB_DATA = 0X16C9A15D
MSRPC_STATUS_CODE_RPC_M_EVENTLIST_FULL = 0X16C9A15E
MSRPC_STATUS_CODE_RPC_M_UNK_SOCK_TYPE = 0X16C9A15F
MSRPC_STATUS_CODE_RPC_M_UNIMP_CALL = 0X16C9A160
MSRPC_STATUS_CODE_RPC_M_INVALID_SEQNUM = 0X16C9A161
MSRPC_STATUS_CODE_RPC_M_CANT_CREATE_UUID = 0X16C9A162
MSRPC_STATUS_CODE_RPC_M_PRE_V2_SS = 0X16C9A163
MSRPC_STATUS_CODE_RPC_M_DGPKT_POOL_CORRUPT = 0X16C9A164
MSRPC_STATUS_CODE_RPC_M_DGPKT_BAD_FREE = 0X16C9A165
MSRPC_STATUS_CODE_RPC_M_LOOKASIDE_CORRUPT = 0X16C9A166
MSRPC_STATUS_CODE_RPC_M_ALLOC_FAIL = 0X16C9A167
MSRPC_STATUS_CODE_RPC_M_REALLOC_FAIL = 0X16C9A168
MSRPC_STATUS_CODE_RPC_M_CANT_OPEN_FILE = 0X16C9A169
MSRPC_STATUS_CODE_RPC_M_CANT_READ_ADDR = 0X16C9A16A
MSRPC_STATUS_CODE_RPC_SVC_DESC_LIBIDL = 0X16C9A16B
MSRPC_STATUS_CODE_RPC_M_CTXRUNDOWN_NOMEM = 0X16C9A16C
MSRPC_STATUS_CODE_RPC_M_CTXRUNDOWN_EXC = 0X16C9A16D
MSRPC_STATUS_CODE_RPC_S_FAULT_CODESET_CONV_ERROR = 0X16C9A16E
MSRPC_STATUS_CODE_RPC_S_NO_CALL_ACTIVE = 0X16C9A16F
MSRPC_STATUS_CODE_RPC_S_CANNOT_SUPPORT = 0X16C9A170
MSRPC_STATUS_CODE_RPC_S_NO_CONTEXT_AVAILABLE = 0X16C9A171

# Bind Time Feature Negotiation:
# [MS-RPCE] 3.3.1.5.3
MSRPC_BIND_TIME_FEATURE_NEGOTIATION_PREFIX = "6CB71C2C-9812-4540-"
MSRPC_BIND_TIME_FEATURE_NEGOTIATION_SECURITY_CONTEXT_MULTIPLEXING_SUPPORTED_BITMASK = 0x01
MSRPC_BIND_TIME_FEATURE_NEGOTIATION_KEEP_CONNECTION_ON_ORPHAN_SUPPORTED_BITMASK = 0x02

MSRPC_STANDARD_NDR_SYNTAX = ('8A885D04-1CEB-11C9-9FE8-08002B104860', '2.0')

class DCERPCException(Exception):
    """
    This is the exception every client should catch regardless of the underlying
    DCERPC Transport used.
    """
    def __init__(self, error_string=None, error_code=None, packet=None):
        """
        :param string error_string: A string you want to show explaining the exception. Otherwise the default ones will be used
        :param integer error_code: the error_code if we're using a dictionary with error's descriptions
        :param NDR packet: if successfully decoded, the NDR packet of the response call. This could probably have useful
        information
        """
        Exception.__init__(self)
        self.packet = packet
        self.error_string = error_string
        if packet is not None:
            try:
                self.error_code = packet['ErrorCode']
            except:
                self.error_code = error_code
        else:
            self.error_code = error_code

    def get_error_code( self ):
        return self.error_code
 
    def get_packet( self ):
        return self.packet

    def __str__( self ):
        key = self.error_code
        if self.error_string is not None:
            return self.error_string
        if key in rpc_status_codes:
            error_msg_short = rpc_status_codes[key]
            return 'DCERPC Runtime Error: code: 0x%x - %s ' % (self.error_code, error_msg_short)
        else:
            return 'DCERPC Runtime Error: unknown error code: 0x%x' % self.error_code

# Context Item
class CtxItem(Structure):
    structure = (
        ('ContextID','<H=0'),
        ('TransItems','B=0'),
        ('Pad','B=0'),
        ('AbstractSyntax','20s=""'),
        ('TransferSyntax','20s=""'),
    )

class CtxItemResult(Structure):
    structure = (
        ('Result','<H=0'),
        ('Reason','<H=0'),
        ('TransferSyntax','20s=""'),
    )

class SEC_TRAILER(Structure):
    commonHdr = (
        ('auth_type', 'B=10'),
        ('auth_level','B=0'),
        ('auth_pad_len','B=0'),
        ('auth_rsvrd','B=0'),
        ('auth_ctx_id','<L=747920'),
    )

class MSRPCHeader(Structure):
    _SIZE = 16
    commonHdr = ( 
        ('ver_major','B=5'),                              # 0
        ('ver_minor','B=0'),                              # 1
        ('type','B=0'),                                   # 2
        ('flags','B=0'),                                  # 3
        ('representation','<L=0x10'),                     # 4
        ('frag_len','<H=self._SIZE+len(auth_data)+(16 if (self["flags"] & 0x80) > 0 else 0)+len(pduData)+len(pad)+len(sec_trailer)'),  # 8
        ('auth_len','<H=len(auth_data)'),                 # 10
        ('call_id','<L=1'),                               # 12    <-- Common up to here (including this)
    )

    structure = ( 
        ('dataLen','_-pduData','self["frag_len"]-self["auth_len"]-self._SIZE-(8 if self["auth_len"] > 0 else 0)'),
        ('pduData',':'),                                
        ('_pad', '_-pad','(4 - ((self._SIZE + (16 if (self["flags"] & 0x80) > 0 else 0) + len(self["pduData"])) & 3) & 3)'),
        ('pad', ':'),
        ('_sec_trailer', '_-sec_trailer', '8 if self["auth_len"] > 0 else 0'),
        ('sec_trailer',':'),
        ('auth_dataLen','_-auth_data','self["auth_len"]'),
        ('auth_data',':'),
    )

    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self,data, alignment)
        if data is None:
            self['ver_major'] = 5
            self['ver_minor'] = 0
            self['flags'] = PFC_FIRST_FRAG | PFC_LAST_FRAG
            self['type'] = MSRPC_REQUEST
            self.__frag_len_set = 0
            self['auth_len'] = 0
            self['pduData'] = b''
            self['auth_data'] = b''
            self['sec_trailer'] = b''
            self['pad'] = b''

    def get_header_size(self):
        return self._SIZE + (16 if (self["flags"] & PFC_OBJECT_UUID) > 0 else 0)

    def get_packet(self):
        if self['auth_data'] != b'':
            self['auth_len'] = len(self['auth_data'])
        # The sec_trailer structure MUST be 4-byte aligned with respect to 
        # the beginning of the PDU. Padding octets MUST be used to align the 
        # sec_trailer structure if its natural beginning is not already 4-byte aligned
        ##self['pad'] = '\xAA' * (4 - ((self._SIZE + len(self['pduData'])) & 3) & 3)

        return self.getData()

class MSRPCRequestHeader(MSRPCHeader):
    _SIZE = 24
    commonHdr = MSRPCHeader.commonHdr + ( 
        ('alloc_hint','<L=0'),                            # 16
        ('ctx_id','<H=0'),                                # 20
        ('op_num','<H=0'),                                # 22
        ('_uuid','_-uuid','16 if self["flags"] & 0x80 > 0 else 0' ), # 22
        ('uuid',':'),                                # 22
    )

    def __init__(self, data = None, alignment = 0):
        MSRPCHeader.__init__(self, data, alignment)
        if data is None:
           self['type'] = MSRPC_REQUEST
           self['ctx_id'] = 0
           self['uuid'] = b''

class MSRPCRespHeader(MSRPCHeader):
    _SIZE = 24
    commonHdr = MSRPCHeader.commonHdr + ( 
        ('alloc_hint','<L=0'),                          # 16   
        ('ctx_id','<H=0'),                              # 20
        ('cancel_count','<B=0'),                        # 22
        ('padding','<B=0'),                             # 23
    )

    def __init__(self, aBuffer = None, alignment = 0):
        MSRPCHeader.__init__(self, aBuffer, alignment)
        if aBuffer is None:
            self['type'] = MSRPC_RESPONSE
            self['ctx_id'] = 0

class MSRPCBind(Structure):
    _CTX_ITEM_LEN = len(CtxItem())
    structure = (
        ('max_tfrag', '<H=4280'),
        ('max_rfrag', '<H=4280'),
        ('assoc_group', '<L=0'),
        ('ctx_num', 'B=0'),
        ('Reserved', 'B=0'),
        ('Reserved2', '<H=0'),
        ('_ctx_items', '_-ctx_items', 'self["ctx_num"]*self._CTX_ITEM_LEN'),
        ('ctx_items', ':'),
    )

    def __init__(self, data=None, alignment=0):
        Structure.__init__(self, data, alignment)
        if data is None:
            self['max_tfrag'] = 4280
            self['max_rfrag'] = 4280
            self['assoc_group'] = 0
            self['ctx_num'] = 1
            self['ctx_items'] = b''
        self.__ctx_items = []

    def addCtxItem(self, item):
        self.__ctx_items.append(item)

    def getCtxItems(self):
        return self.__ctx_items

    def getCtxItem(self, index):
        return self.__ctx_items[index - 1]

    def getData(self):
        self['ctx_num'] = len(self.__ctx_items)
        for i in self.__ctx_items:
            self['ctx_items'] += i.getData()
        return Structure.getData(self)


class MSRPCRelayBind(Structure):
    _CTX_ITEM_LEN = len(CtxItem())
    structure = ( 
        ('max_tfrag','<H=4280'),
        ('max_rfrag','<H=4280'),
        ('assoc_group','<L=0'),
        ('ctx_num','B=0'),
        ('Reserved','B=0'),
        ('Reserved2','<H=0'),
        ('_ctx_items', '_-ctx_items', 'self["ctx_num"]*self._CTX_ITEM_LEN'),
        ('ctx_items',':'),
    )
 
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self, data, alignment)
        if data is None:
            self['max_tfrag'] = 4280
            self['max_rfrag'] = 4280
            self['assoc_group'] = 0
            self['ctx_num'] = 1
            self['ctx_items'] = b''
        self.__ctx_items = []
        ctx_items_data = self["ctx_items"]
        for i in range(int(self["_ctx_items"] / self._CTX_ITEM_LEN)):
            self.__ctx_items.append(CtxItem(ctx_items_data))
            ctx_items_data = ctx_items_data[self._CTX_ITEM_LEN:]

    def addCtxItem(self, item):
        self.__ctx_items.append(item)
    
    def getCtxItems(self):
        return self.__ctx_items

    def getCtxItem(self,index):
        return self.__ctx_items[index-1]

    def getData(self):
        self['ctx_num'] = len(self.__ctx_items)
        for i in self.__ctx_items:
            self['ctx_items'] += i.getData()
        return Structure.getData(self)

class MSRPCBindAck(MSRPCHeader):
    _SIZE = 26 # Up to SecondaryAddr
    _CTX_ITEM_LEN = len(CtxItemResult())
    structure = ( 
        ('max_tfrag','<H=0'),
        ('max_rfrag','<H=0'),
        ('assoc_group','<L=0'),
        ('SecondaryAddrLen','<H&SecondaryAddr'), 
        ('SecondaryAddr','z'),                          # Optional if SecondaryAddrLen == 0
        ('PadLen','_-Pad','(4-((self["SecondaryAddrLen"]+self._SIZE) % 4))%4'),
        ('Pad',':'),
        ('ctx_num','B=0'),
        ('Reserved','B=0'),
        ('Reserved2','<H=0'),
        ('_ctx_items','_-ctx_items','self["ctx_num"]*self._CTX_ITEM_LEN'),
        ('ctx_items',':'),
        ('_sec_trailer', '_-sec_trailer', '8 if self["auth_len"] > 0 else 0'),
        ('sec_trailer',':'),
        ('auth_dataLen','_-auth_data','self["auth_len"]'),
        ('auth_data',':'),
    )
    def __init__(self, data = None, alignment = 0):
        self.__ctx_items = []
        MSRPCHeader.__init__(self,data,alignment)
        if data is None:
            self['Pad'] = b''
            self['ctx_items'] = b''
            self['sec_trailer'] = b''
            self['auth_data'] = b''

    def getCtxItems(self):
        return self.__ctx_items

    def getCtxItem(self,index):
        return self.__ctx_items[index-1]

    def fromString(self, data):
        Structure.fromString(self,data)
        # Parse the ctx_items
        data = self['ctx_items']
        for i in range(self['ctx_num']):
            item = CtxItemResult(data)
            self.__ctx_items.append(item)
            data = data[len(item):]
            
class MSRPCRelayBindAck(Structure):
    _SIZE = 26 # Up to SecondaryAddr
    _CTX_ITEM_LEN = len(CtxItemResult())
    structure = ( 
        ('max_tfrag','<H=0'),
        ('max_rfrag','<H=0'),
        ('assoc_group','<L=0'),
        ('SecondaryAddrLen','<H&SecondaryAddr'), 
        ('SecondaryAddr','z'),                          # Optional if SecondaryAddrLen == 0
        ('PadLen','_-Pad','(4-((self["SecondaryAddrLen"]+self._SIZE) % 4))%4'),
        ('Pad',':'),
        ('ctx_num','B=0'),
        ('Reserved','B=0'),
        ('Reserved2','<H=0'),
        ('_ctx_items','_-ctx_items','self["ctx_num"]*self._CTX_ITEM_LEN'),
        ('ctx_items',':'),
    )
    def __init__(self, data = None, alignment = 0):
        self.__ctx_items = []
        Structure.__init__(self,data,alignment)
        if data is None:
            self['Pad'] = b''
            self['ctx_items'] = b''
            self['ctx_num'] = 0

    def getCtxItems(self):
        return self.__ctx_items

    def getCtxItem(self,index):
        return self.__ctx_items[index-1]

    def addCtxItem(self, item):
        self.__ctx_items.append(item)

    def fromString(self, data):
        Structure.fromString(self,data)
        # Parse the ctx_items
        data = self['ctx_items']
        for i in range(self['ctx_num']):
            item = CtxItemResult(data)
            self.__ctx_items.append(item)
            data = data[len(item):]

    def getData(self):
        self['SecondaryAddrLen'] = len(self["SecondaryAddr"])+1
        self['Pad'] = '\x00'*((4-((self["SecondaryAddrLen"]+self._SIZE) % 4)) % 4)
        self['ctx_num'] = len(self.__ctx_items)
        for i in self.__ctx_items:
            self['ctx_items'] += i.getData()
        return Structure.getData(self)

class MSRPCBindNak(Structure):
    structure = ( 
        ('RejectedReason','<H=0'),
        ('SupportedVersions',':'),
    )
    def __init__(self, data = None, alignment = 0):
        Structure.__init__(self,data,alignment)
        if data is None:
            self['SupportedVersions'] = b''

class DCERPC:
    # Standard NDR Representation
    NDRSyntax   = uuidtup_to_bin(('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'))
    # NDR 64
    NDR64Syntax = uuidtup_to_bin(('71710533-BEBA-4937-8319-B5DBEF9CCC36', '1.0'))
    transfer_syntax =  NDRSyntax

    def __init__(self,transport):
        self._transport = transport
        self.set_ctx_id(0)
        self._max_user_frag = None
        self.set_default_max_fragment_size()
        self._ctx = None

    def get_rpc_transport(self):
        return self._transport

    def set_ctx_id(self, ctx_id):
        self._ctx = ctx_id

    def connect(self):
        return self._transport.connect()

    def disconnect(self):
        return self._transport.disconnect()

    def set_max_fragment_size(self, fragment_size):
        # -1 is default fragment size: 0 for v5, 1300 y pico for v4
        #  0 is don't fragment
        #    other values are max fragment size
        if fragment_size == -1:
            self.set_default_max_fragment_size()
        else:
            self._max_user_frag = fragment_size

    def set_default_max_fragment_size(self):
        # default is 0: don'fragment. v4 will override this method
        self._max_user_frag = 0

    def send(self, data):
        raise RuntimeError ('virtual method. Not implemented in subclass')

    def recv(self):
        raise RuntimeError ('virtual method. Not implemented in subclass')

    def alter_ctx(self, newUID, bogus_binds=''):
        raise RuntimeError ('virtual method. Not implemented in subclass')

    def set_credentials(self, username, password, domain='', lmhash='', nthash='', aesKey='', TGT=None, TGS=None):
        pass

    def set_auth_level(self, auth_level):
        pass

    def set_auth_type(self, auth_type, callback=None):
        pass

    def get_idempotent(self):
        return 0

    def set_idempotent(self, flag):
        pass

    def call(self, function, body, uuid=None):
        if hasattr(body, 'getData'):
            return self.send(DCERPC_RawCall(function, body.getData(), uuid))
        else:
            return self.send(DCERPC_RawCall(function, body, uuid))

    def request(self, request, uuid=None, checkError=True):
        if self.transfer_syntax == self.NDR64Syntax:
            request.changeTransferSyntax(self.NDR64Syntax)
            isNDR64 = True
        else:
            isNDR64 = False

        self.call(request.opnum, request, uuid)
        answer = self.recv()

        __import__(request.__module__)
        module = sys.modules[request.__module__]
        respClass = getattr(module, request.__class__.__name__ + 'Response')

        if  answer[-4:] != b'\x00\x00\x00\x00' and checkError is True:
            error_code = unpack('<L', answer[-4:])[0]
            if error_code in rpc_status_codes:
                # This is an error we can handle
                exception = DCERPCException(error_code = error_code)
            else:    
                sessionErrorClass = getattr(module, 'DCERPCSessionError')
                try:
                    # Try to unpack the answer, even if it is an error, it works most of the times
                    response =  respClass(answer, isNDR64 = isNDR64)
                except:
                    # No luck :(
                    exception = sessionErrorClass(error_code = error_code)
                else:
                    exception = sessionErrorClass(packet = response, error_code = error_code)
            raise exception
        else:
            response =  respClass(answer, isNDR64 = isNDR64)
            return response

class DCERPC_v4(DCERPC):
    pass

class DCERPC_v5(DCERPC):
    def __init__(self, transport):
        DCERPC.__init__(self, transport)
        self.__auth_level = RPC_C_AUTHN_LEVEL_NONE
        self.__auth_type = RPC_C_AUTHN_WINNT
        self.__auth_type_callback = None
        # Flags of the authenticated session. We will need them throughout the connection
        self.__auth_flags = 0
        self.__username = None
        self.__password = None
        self.__domain = ''
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = ''
        self.__TGT    = None
        self.__TGS    = None

        self.__aesNegociated = False
        self.__clientSigningKey = b''
        self.__serverSigningKey = b''
        self.__clientSealingKey = b''
        self.__clientSealingHandle = b''
        self.__serverSealingKey = b''
        self.__serverSealingHandle = b''
        self.__sequence = 0   

        self.transfer_syntax = uuidtup_to_bin(('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0'))
        self.__callid = 1
        self._ctx = 0
        self.__sessionKey = None
        self.__max_xmit_size  = 0
        self.__flags = 0
        self.__cipher = None
        self.__confounder = b''
        self.__gss = None

    def set_aes(self, is_aes):
        self.__aesNegociated = is_aes

    def set_session_key(self, session_key):
        self.__sessionKey = session_key

    def get_session_key(self):
        return self.__sessionKey

    def set_auth_level(self, auth_level):
        self.__auth_level = auth_level

    def set_auth_type(self, auth_type, callback = None):
        self.__auth_type = auth_type
        self.__auth_type_callback = callback

    def get_auth_type(self):
        return self.__auth_type

    def set_max_tfrag(self, size):
        self.__max_xmit_size = size
    
    def get_credentials(self):
        return self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, self.__TGT, self.__TGS

    def set_credentials(self, username, password, domain = '', lmhash = '', nthash = '', aesKey = '', TGT = None, TGS = None):
        self.set_auth_level(RPC_C_AUTHN_LEVEL_CONNECT)
        self.__username = username
        self.__password = password
        self.__domain   = domain
        self.__aesKey   = aesKey
        self.__TGT      = TGT
        self.__TGS      = TGS
        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:
                lmhash = '0%s' % lmhash
            if len(nthash) % 2:
                nthash = '0%s' % nthash
            try: # just in case they were converted already
                self.__lmhash = unhexlify(lmhash)
                self.__nthash = unhexlify(nthash)
            except:
                self.__lmhash = lmhash
                self.__nthash = nthash
                pass

    def bind(self, iface_uuid, alter = 0, bogus_binds = 0, transfer_syntax = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')):
        bind = MSRPCBind()
        #item['TransferSyntax']['Version'] = 1
        ctx = self._ctx
        for i in range(bogus_binds):
            item = CtxItem()
            item['ContextID'] = ctx
            item['TransItems'] = 1
            item['ContextID'] = ctx
            # We generate random UUIDs for bogus binds
            item['AbstractSyntax'] = generate() + stringver_to_bin('2.0')
            item['TransferSyntax'] = uuidtup_to_bin(transfer_syntax)
            bind.addCtxItem(item)
            self._ctx += 1
            ctx += 1

        # The true one :)
        item = CtxItem()
        item['AbstractSyntax'] = iface_uuid
        item['TransferSyntax'] = uuidtup_to_bin(transfer_syntax)
        item['ContextID'] = ctx
        item['TransItems'] = 1
        bind.addCtxItem(item)

        packet = MSRPCHeader()
        packet['type'] = MSRPC_BIND
        packet['pduData'] = bind.getData()
        packet['call_id'] = self.__callid

        if alter:
            packet['type'] = MSRPC_ALTERCTX

        if self.__auth_level != RPC_C_AUTHN_LEVEL_NONE:
            if (self.__username is None) or (self.__password is None):
                self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, self.__aesKey, self.__TGT, self.__TGS = self._transport.get_credentials()

            if self.__auth_type == RPC_C_AUTHN_WINNT:
                auth = ntlm.getNTLMSSPType1('', '', signingRequired=True,
                                            use_ntlmv2=self._transport.doesSupportNTLMv2())
            elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                from impacket.dcerpc.v5 import nrpc
                auth = nrpc.getSSPType1(self.__username[:-1], self.__domain, signingRequired=True)
            elif self.__auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                self.__cipher, self.__sessionKey, auth = kerberosv5.getKerberosType1(self.__username, self.__password,
                                                                                     self.__domain, self.__lmhash,
                                                                                     self.__nthash, self.__aesKey,
                                                                                     self.__TGT, self.__TGS,
                                                                                     self._transport.getRemoteName(),
                                                                                     self._transport.get_kdcHost())
            else:
                raise DCERPCException('Unsupported auth_type 0x%x' % self.__auth_type)

            sec_trailer = SEC_TRAILER()
            sec_trailer['auth_type']   = self.__auth_type
            sec_trailer['auth_level']  = self.__auth_level
            sec_trailer['auth_ctx_id'] = self._ctx + 79231 

            pad = (4 - (len(packet.get_packet()) % 4)) % 4
            if pad != 0:
               packet['pduData'] += b'\xFF'*pad
               sec_trailer['auth_pad_len']=pad

            packet['sec_trailer'] = sec_trailer
            packet['auth_data'] = auth

        self._transport.send(packet.get_packet())

        s = self._transport.recv()

        if s != 0:
            resp = MSRPCHeader(s)
        else:
            return 0 #mmm why not None?

        if resp['type'] == MSRPC_BINDACK or resp['type'] == MSRPC_ALTERCTX_R:
            bindResp = MSRPCBindAck(resp.getData())
        elif resp['type'] == MSRPC_BINDNAK or resp['type'] == MSRPC_FAULT:
            if resp['type'] == MSRPC_FAULT:
                resp = MSRPCRespHeader(resp.getData())
                status_code = unpack('<L', resp['pduData'][:4])[0]
            else:
                resp = MSRPCBindNak(resp['pduData'])
                status_code = resp['RejectedReason']
            if status_code in rpc_status_codes:
                raise DCERPCException(error_code = status_code)
            elif status_code in rpc_provider_reason:
                raise DCERPCException("Bind context rejected: %s" % rpc_provider_reason[status_code])
            else:
                raise DCERPCException('Unknown DCE RPC fault status code: %.8x' % status_code)
        else:
            raise DCERPCException('Unknown DCE RPC packet type received: %d' % resp['type'])

        # check ack results for each context, except for the bogus ones
        for ctx in range(bogus_binds+1,bindResp['ctx_num']+1):
            ctxItems = bindResp.getCtxItem(ctx)
            if ctxItems['Result'] != 0:
                msg = "Bind context %d rejected: " % ctx
                msg += rpc_cont_def_result.get(ctxItems['Result'], 'Unknown DCE RPC context result code: %.4x' % ctxItems['Result'])
                msg += "; "
                reason = bindResp.getCtxItem(ctx)['Reason']
                msg += rpc_provider_reason.get(reason, 'Unknown reason code: %.4x' % reason)
                if (ctxItems['Result'], reason) == (2, 1): # provider_rejection, abstract syntax not supported
                    msg += " (this usually means the interface isn't listening on the given endpoint)"
                raise DCERPCException(msg)

            # Save the transfer syntax for later use
            self.transfer_syntax = ctxItems['TransferSyntax'] 

        # The received transmit size becomes the client's receive size, and the received receive size becomes the client's transmit size.
        self.__max_xmit_size = bindResp['max_rfrag']

        if self.__auth_level != RPC_C_AUTHN_LEVEL_NONE:
            if self.__auth_type == RPC_C_AUTHN_WINNT:
                response, self.__sessionKey = ntlm.getNTLMSSPType3(auth, bindResp['auth_data'], self.__username,
                                                                   self.__password, self.__domain, self.__lmhash,
                                                                   self.__nthash,
                                                                   use_ntlmv2=self._transport.doesSupportNTLMv2())
                self.__flags = response['flags']
            elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                response = None
            elif self.__auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                self.__cipher, self.__sessionKey, response = kerberosv5.getKerberosType3(self.__cipher,
                                                                                         self.__sessionKey,
                                                                                         bindResp['auth_data'])

            self.__sequence = 0

            if self.__auth_level in (RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY):
                if self.__auth_type == RPC_C_AUTHN_WINNT:
                    if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                        self.__clientSigningKey = ntlm.SIGNKEY(self.__flags, self.__sessionKey)
                        self.__serverSigningKey = ntlm.SIGNKEY(self.__flags, self.__sessionKey,b"Server")
                        self.__clientSealingKey = ntlm.SEALKEY(self.__flags, self.__sessionKey)
                        self.__serverSealingKey = ntlm.SEALKEY(self.__flags, self.__sessionKey,b"Server")
                        # Preparing the keys handle states
                        cipher3 = ARC4.new(self.__clientSealingKey)
                        self.__clientSealingHandle = cipher3.encrypt
                        cipher4 = ARC4.new(self.__serverSealingKey)
                        self.__serverSealingHandle = cipher4.encrypt
                    else:
                        # Same key for everything
                        self.__clientSigningKey = self.__sessionKey
                        self.__serverSigningKey = self.__sessionKey
                        self.__clientSealingKey = self.__sessionKey
                        self.__serverSealingKey = self.__sessionKey
                        cipher = ARC4.new(self.__clientSigningKey)
                        self.__clientSealingHandle = cipher.encrypt
                        self.__serverSealingHandle = cipher.encrypt
                elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                    if self.__auth_level == RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
                        self.__confounder = b''
                    else:
                        self.__confounder = b'12345678'

            sec_trailer = SEC_TRAILER()
            sec_trailer['auth_type'] = self.__auth_type
            sec_trailer['auth_level'] = self.__auth_level
            sec_trailer['auth_ctx_id'] = self._ctx + 79231 

            if response is not None:
                if self.__auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                    alter_ctx = MSRPCHeader()
                    alter_ctx['type'] = MSRPC_ALTERCTX
                    alter_ctx['pduData'] = bind.getData()
                    alter_ctx['sec_trailer'] = sec_trailer
                    alter_ctx['auth_data'] = response
                    self._transport.send(alter_ctx.get_packet(), forceWriteAndx = 1)
                    self.__gss = gssapi.GSSAPI(self.__cipher)
                    self.__sequence = 0
                    self.recv()
                    self.__sequence = 0
                else:
                    auth3 = MSRPCHeader()
                    auth3['type'] = MSRPC_AUTH3
                    # pad (4 bytes): Can be set to any arbitrary value when set and MUST be 
                    # ignored on receipt. The pad field MUST be immediately followed by a 
                    # sec_trailer structure whose layout, location, and alignment are as 
                    # specified in section 2.2.2.11
                    auth3['pduData'] = b'    '
                    auth3['sec_trailer'] = sec_trailer
                    auth3['auth_data'] = response.getData()

                    # Use the same call_id
                    self.__callid = resp['call_id']
                    auth3['call_id'] = self.__callid
                    self._transport.send(auth3.get_packet(), forceWriteAndx = 1)

            self.__callid += 1

        return resp     # means packet is signed, if verifier is wrong it fails

    def _transport_send(self, rpc_packet, forceWriteAndx = 0, forceRecv = 0):
        rpc_packet['ctx_id'] = self._ctx
        rpc_packet['sec_trailer'] = b''
        rpc_packet['auth_data'] = b''

        if self.__auth_level in [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY]:
            # Dummy verifier, just for the calculations
            sec_trailer = SEC_TRAILER()
            sec_trailer['auth_type'] = self.__auth_type
            sec_trailer['auth_level'] = self.__auth_level
            sec_trailer['auth_pad_len'] = 0
            sec_trailer['auth_ctx_id'] = self._ctx + 79231 

            pad = (4 - (len(rpc_packet.get_packet()) % 4)) % 4
            if pad != 0:
                rpc_packet['pduData'] += b'\xBB'*pad
                sec_trailer['auth_pad_len']=pad

            rpc_packet['sec_trailer'] = sec_trailer.getData()
            rpc_packet['auth_data'] = b' '*16

            plain_data = rpc_packet['pduData']
            if self.__auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
                if self.__auth_type == RPC_C_AUTHN_WINNT:
                    if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                        # When NTLM2 is on, we sign the whole pdu, but encrypt just
                        # the data, not the dcerpc header. Weird..
                        sealedMessage, signature =  ntlm.SEAL(self.__flags, 
                               self.__clientSigningKey, 
                               self.__clientSealingKey,  
                               rpc_packet.get_packet()[:-16], 
                               plain_data, 
                               self.__sequence, 
                               self.__clientSealingHandle)
                    else:
                        sealedMessage, signature =  ntlm.SEAL(self.__flags, 
                               self.__clientSigningKey, 
                               self.__clientSealingKey,  
                               plain_data, 
                               plain_data, 
                               self.__sequence, 
                               self.__clientSealingHandle)
                elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                    from impacket.dcerpc.v5 import nrpc
                    sealedMessage, signature = nrpc.SEAL(plain_data, self.__confounder, self.__sequence, self.__sessionKey, self.__aesNegociated)
                elif self.__auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                    sealedMessage, signature = self.__gss.GSS_Wrap(self.__sessionKey, plain_data, self.__sequence)

                rpc_packet['pduData'] = sealedMessage
            elif self.__auth_level == RPC_C_AUTHN_LEVEL_PKT_INTEGRITY: 
                if self.__auth_type == RPC_C_AUTHN_WINNT:
                    if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                        # Interesting thing.. with NTLM2, what is is signed is the 
                        # whole PDU, not just the data
                        signature =  ntlm.SIGN(self.__flags,
                               self.__clientSigningKey, 
                               rpc_packet.get_packet()[:-16], 
                               self.__sequence, 
                               self.__clientSealingHandle)
                    else:
                        signature =  ntlm.SIGN(self.__flags, 
                               self.__clientSigningKey, 
                               plain_data, 
                               self.__sequence, 
                               self.__clientSealingHandle)
                elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                    from impacket.dcerpc.v5 import nrpc
                    signature = nrpc.SIGN(plain_data, 
                           self.__confounder, 
                           self.__sequence, 
                           self.__sessionKey, 
                           self.__aesNegociated)
                elif self.__auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                    signature = self.__gss.GSS_GetMIC(self.__sessionKey, plain_data, self.__sequence)

            rpc_packet['sec_trailer'] = sec_trailer.getData()
            rpc_packet['auth_data'] = signature

            self.__sequence += 1

        self._transport.send(rpc_packet.get_packet(), forceWriteAndx = forceWriteAndx, forceRecv = forceRecv)

    def send(self, data):
        if isinstance(data, MSRPCHeader) is not True:
            # Must be an Impacket, transform to structure
            data = DCERPC_RawCall(data.OP_NUM, data.get_packet())

        try:
            if data['uuid'] != b'':
                data['flags'] |= PFC_OBJECT_UUID
        except:
            # Structure doesn't have uuid
            pass
        data['ctx_id'] = self._ctx
        data['call_id'] = self.__callid
        data['alloc_hint'] = len(data['pduData'])
        # We should fragment PDUs if:
        # 1) Payload exceeds __max_xmit_size received during BIND response
        # 2) We'e explicitly fragmenting packets with lower values
        should_fragment = False

        # Let's decide what will drive fragmentation for this request
        if self._max_user_frag > 0:
            # User set a frag size, let's compare it with the max transmit size agreed when binding the interface
            fragment_size = min(self._max_user_frag, self.__max_xmit_size)
        else:
            fragment_size = self.__max_xmit_size

        # Sanity check. Fragmentation can't be too low, otherwise sec_trailer won't fit

        if self.__auth_level in [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY]:
            if fragment_size <= 8:
                # Minimum pdu fragment size is 8, important when doing PKT_INTEGRITY/PRIVACY. We need a minimum size of 8
                # (Kerberos)
                fragment_size = 8

        # ToDo: Better calculate the size needed. Now I'm setting a number that surely is enough for Kerberos and NTLM
        # ToDo: trailers, both for INTEGRITY and PRIVACY. This means we're not truly honoring the user's frag request.
        if len(data['pduData']) + 128 > fragment_size:
            should_fragment = True
            if fragment_size+128 > self.__max_xmit_size:
                fragment_size = self.__max_xmit_size - 128

        if should_fragment:
            packet = data['pduData']
            offset = 0

            while 1:
                toSend = packet[offset:offset+fragment_size]
                if not toSend:
                    break
                if offset == 0:
                    data['flags'] |= PFC_FIRST_FRAG
                else:
                    data['flags'] &= (~PFC_FIRST_FRAG)
                offset += len(toSend)
                if offset >= len(packet):
                    data['flags'] |= PFC_LAST_FRAG
                else:
                    data['flags'] &= (~PFC_LAST_FRAG)
                data['pduData'] = toSend
                self._transport_send(data, forceWriteAndx = 1, forceRecv =data['flags'] & PFC_LAST_FRAG)
        else:
            self._transport_send(data)
        self.__callid += 1

    def recv(self):
        finished = False
        forceRecv = 0
        retAnswer = b''
        while not finished:
            # At least give me the MSRPCRespHeader, especially important for 
            # TCP/UDP Transports
            response_data = self._transport.recv(forceRecv, count=MSRPCRespHeader._SIZE)
            response_header = MSRPCRespHeader(response_data)
            # Ok, there might be situation, especially with large packets, that 
            # the transport layer didn't send us the full packet's contents
            # So we gotta check we received it all
            while len(response_data) < response_header['frag_len']:
               response_data += self._transport.recv(forceRecv, count=(response_header['frag_len']-len(response_data)))

            off = response_header.get_header_size()

            if response_header['type'] == MSRPC_FAULT and response_header['frag_len'] >= off+4:
                status_code = unpack("<L",response_data[off:off+4])[0]
                if status_code in rpc_status_codes:
                    raise DCERPCException(rpc_status_codes[status_code])
                elif status_code & 0xffff in rpc_status_codes:
                    raise DCERPCException(rpc_status_codes[status_code & 0xffff])
                else:
                    if status_code in hresult_errors.ERROR_MESSAGES:
                        error_msg_short = hresult_errors.ERROR_MESSAGES[status_code][0]
                        error_msg_verbose = hresult_errors.ERROR_MESSAGES[status_code][1] 
                        raise DCERPCException('%s - %s' % (error_msg_short, error_msg_verbose))
                    else:
                        raise DCERPCException('Unknown DCE RPC fault status code: %.8x' % status_code)

            if response_header['flags'] & PFC_LAST_FRAG:
                # No need to reassembly DCERPC
                finished = True
            else:
                # Forcing Read Recv, we need more packets!
                forceRecv = 1

            answer = response_data[off:]
            auth_len = response_header['auth_len']
            if auth_len:
                auth_len += 8
                auth_data = answer[-auth_len:]
                sec_trailer = SEC_TRAILER(data = auth_data)
                answer = answer[:-auth_len]

                if sec_trailer['auth_level'] == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
                    if self.__auth_type == RPC_C_AUTHN_WINNT:
                        if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                            # TODO: FIX THIS, it's not calculating the signature well
                            # Since I'm not testing it we don't care... yet
                            answer, signature =  ntlm.SEAL(self.__flags, 
                                    self.__serverSigningKey, 
                                    self.__serverSealingKey,  
                                    answer, 
                                    answer, 
                                    self.__sequence, 
                                    self.__serverSealingHandle)
                        else:
                            answer, signature = ntlm.SEAL(self.__flags, 
                                    self.__serverSigningKey, 
                                    self.__serverSealingKey, 
                                    answer, 
                                    answer, 
                                    self.__sequence, 
                                    self.__serverSealingHandle)
                            self.__sequence += 1
                    elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                        from impacket.dcerpc.v5 import nrpc
                        answer, cfounder = nrpc.UNSEAL(answer, 
                               auth_data[len(sec_trailer):],
                               self.__sessionKey, 
                               self.__aesNegociated)
                        self.__sequence += 1
                    elif self.__auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                        if self.__sequence > 0:
                            answer, cfounder = self.__gss.GSS_Unwrap(self.__sessionKey, answer, self.__sequence,
                                                                     direction='init', authData=auth_data)

                elif sec_trailer['auth_level'] == RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
                    if self.__auth_type == RPC_C_AUTHN_WINNT:
                        ntlmssp = auth_data[12:]
                        if self.__flags & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                            signature =  ntlm.SIGN(self.__flags, 
                                    self.__serverSigningKey, 
                                    answer, 
                                    self.__sequence, 
                                    self.__serverSealingHandle)
                        else:
                            signature = ntlm.SIGN(self.__flags, 
                                    self.__serverSigningKey, 
                                    ntlmssp, 
                                    self.__sequence, 
                                    self.__serverSealingHandle)
                            # Yes.. NTLM2 doesn't increment sequence when receiving
                            # the packet :P
                            self.__sequence += 1
                    elif self.__auth_type == RPC_C_AUTHN_NETLOGON:
                        from impacket.dcerpc.v5 import nrpc
                        ntlmssp = auth_data[12:]
                        signature = nrpc.SIGN(ntlmssp, 
                               self.__confounder, 
                               self.__sequence, 
                               self.__sessionKey, 
                               self.__aesNegociated)
                        self.__sequence += 1
                    elif self.__auth_type == RPC_C_AUTHN_GSS_NEGOTIATE:
                        # Do NOT increment the sequence number when Signing Kerberos
                        #self.__sequence += 1
                        pass

                
                if sec_trailer['auth_pad_len']:
                    answer = answer[:-sec_trailer['auth_pad_len']]
              
            retAnswer += answer
        return retAnswer

    def alter_ctx(self, newUID, bogus_binds = 0):
        answer = self.__class__(self._transport)

        answer.set_credentials(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                               self.__aesKey, self.__TGT, self.__TGS)
        answer.set_auth_type(self.__auth_type)
        answer.set_auth_level(self.__auth_level)

        answer.set_ctx_id(self._ctx+1)
        answer.__callid = self.__callid
        answer.bind(newUID, alter = 1, bogus_binds = bogus_binds, transfer_syntax = bin_to_uuidtup(self.transfer_syntax))
        return answer

class DCERPC_RawCall(MSRPCRequestHeader):
    def __init__(self, op_num, data = b'', uuid=None):
        MSRPCRequestHeader.__init__(self)
        self['op_num'] = op_num
        self['pduData'] = data
        if uuid is not None:
            self['flags'] |= PFC_OBJECT_UUID
            self['uuid'] = uuid

    def setData(self, data):
        self['pduData'] = data

# 2.2.6 Type Serialization Version 1
class CommonHeader(NDRSTRUCT):
    structure = (
        ('Version', UCHAR),
        ('Endianness', UCHAR),
        ('CommonHeaderLength', USHORT),
        ('Filler', ULONG),
    )
    def __init__(self, data = None,isNDR64 = False):
        NDRSTRUCT.__init__(self, data, isNDR64)
        if data is None:
            self['Version'] = 1
            self['Endianness'] = 0x10
            self['CommonHeaderLength'] = 8
            self['Filler'] = 0xcccccccc

class PrivateHeader(NDRSTRUCT):
    structure = (
        ('ObjectBufferLength', ULONG),
        ('Filler', ULONG),
    )
    def __init__(self, data = None,isNDR64 = False):
        NDRSTRUCT.__init__(self, data, isNDR64)
        if data is None:
            self['Filler'] = 0xcccccccc

class TypeSerialization1(NDRSTRUCT):
    commonHdr = (
        ('CommonHeader', CommonHeader),
        ('PrivateHeader', PrivateHeader),
    )
    def getData(self, soFar = 0):
        self['PrivateHeader']['ObjectBufferLength'] = len(NDRSTRUCT.getData(self, soFar)) + len(
            NDRSTRUCT.getDataReferents(self, soFar)) - len(self['CommonHeader']) - len(self['PrivateHeader'])
        return NDRSTRUCT.getData(self, soFar)

class DCERPCServer(Thread):
    """
    A minimalistic DCERPC Server, mainly used by the smbserver, for now. Might be useful
    for other purposes in the future, but we should do it way stronger.
    If you want to implement a DCE Interface Server, use this class as the base class
    """
    #constructor to use with rpcrelayserver
    def __init__(self, client_socket=None):
        if client_socket:
            self._clientSock = client_socket
            self._listenUUIDS = {}
            self._boundUUID = b''
            self._callid = 1
            self._max_frag = None
            self._max_xmit_size = 4280
            self.__log = LOG
        else:
            Thread.__init__(self)
            self._listenPort    = 0
            self._listenAddress = '127.0.0.1'
            self._listenUUIDS   = {}
            self._boundUUID     = b''
            self._sock          = None
            self._clientSock    = None
            self._callid        = 1
            self._max_frag       = None
            self._max_xmit_size = 4280
            self.__log = LOG
            self._sock = socket.socket()
            self._sock.bind((self._listenAddress,self._listenPort))

    def set_client_socket(self, client_socket):
        self._clientSock =client_socket

    def log(self, msg, level=logging.INFO):
        self.__log.log(level,msg)

    def addCallbacks(self, ifaceUUID, secondaryAddr, callbacks):
        """
        adds a call back to a UUID/opnum call
        
        :param uuid ifaceUUID: the interface UUID
        :param string secondaryAddr: the secondary address to answer as part of the bind request (e.g. \\\\PIPE\\\\srvsvc)
        :param dict callbacks: the callbacks for each opnum. Format is [opnum] = callback
        """
        self._listenUUIDS[uuidtup_to_bin(ifaceUUID)] = {}
        self._listenUUIDS[uuidtup_to_bin(ifaceUUID)]['SecondaryAddr'] = secondaryAddr
        self._listenUUIDS[uuidtup_to_bin(ifaceUUID)]['CallBacks'] = callbacks
        self.log("Callback added for UUID %s V:%s" % ifaceUUID)

    def setListenAddress(self,addr):
        self._listenAddress=addr
        self._sock = socket.socket()
        self._sock.bind((self._listenAddress, self._listenPort))

    def setListenPort(self, portNum):
        self._listenPort = portNum
        self._sock = socket.socket()
        self._sock.bind((self._listenAddress,self._listenPort))

    def getListenPort(self):
        return self._sock.getsockname()[1]

    def recv(self):
        finished = False
        retAnswer = b''
        response_data = b''
        while not finished:
            # At least give me the MSRPCRespHeader, especially important for TCP/UDP Transports
            response_data = self._clientSock.recv(MSRPCRespHeader._SIZE)
            # No data?, connection might have closed
            if response_data == b'':
                return None
            response_header = MSRPCRespHeader(response_data)
            # Ok, there might be situation, especially with large packets, 
            # that the transport layer didn't send us the full packet's contents
            # So we gotta check we received it all
            while len(response_data) < response_header['frag_len']:
               response_data += self._clientSock.recv(response_header['frag_len']-len(response_data))
            response_header = MSRPCRespHeader(response_data)
            if response_header['flags'] & PFC_LAST_FRAG:
                # No need to reassembly DCERPC
                finished = True
            answer = response_header['pduData']
            auth_len = response_header['auth_len']
            if auth_len:
                auth_len += 8
                auth_data = answer[-auth_len:]
                sec_trailer = SEC_TRAILER(data = auth_data)
                answer = answer[:-auth_len]
                if sec_trailer['auth_pad_len']:
                    answer = answer[:-sec_trailer['auth_pad_len']]
              
            retAnswer += answer
        return response_data
    
    def run(self):
        self._sock.listen(10)
        while True:
            self._clientSock, address = self._sock.accept()
            try:
                while True:
                    data = self.recv()
                    if data is None:
                        # No data.. connection closed
                        break
                    answer = self.processRequest(data)
                    if answer is not None:
                        self.send(answer)
            except Exception:
                #import traceback
                #traceback.print_exc()
                pass
            self._clientSock.close()

    def send(self, data):
        max_frag       = self._max_frag
        if len(data['pduData']) > self._max_xmit_size - 32:
            max_frag   = self._max_xmit_size - 32    # XXX: 32 is a safe margin for auth data

        if self._max_frag:
            max_frag   = min(max_frag, self._max_frag)
        if max_frag and len(data['pduData']) > 0:
            packet     = data['pduData']
            offset     = 0
            while 1:
                toSend = packet[offset:offset+max_frag]
                if not toSend:
                    break
                flags  = 0
                if offset == 0:
                    flags |= PFC_FIRST_FRAG
                offset += len(toSend)
                if offset == len(packet):
                    flags |= PFC_LAST_FRAG
                data['flags']   = flags
                data['pduData'] = toSend
                self._clientSock.send(data.get_packet())
        else:
            self._clientSock.send(data.get_packet())
        self._callid += 1

    def bind(self,packet, bind):
        # Standard NDR Representation
        NDRSyntax   = ('8a885d04-1ceb-11c9-9fe8-08002b104860', '2.0')
        resp = MSRPCBindAck()

        resp['type']             = MSRPC_BINDACK
        resp['flags']            = packet['flags']
        resp['frag_len']         = 0
        resp['auth_len']         = 0
        resp['auth_data']        = b''
        resp['call_id']          = packet['call_id'] 
        resp['max_tfrag']        = bind['max_tfrag']
        resp['max_rfrag']        = bind['max_rfrag']
        resp['assoc_group']      = 0x1234
        resp['ctx_num']          = 0

        data      = bind['ctx_items']
        ctx_items = b''
        resp['SecondaryAddrLen'] = 0
        for i in range(bind['ctx_num']):
            result = MSRPC_CONT_RESULT_USER_REJECT
            item   = CtxItem(data)
            data   = data[len(item):]

            # First we check the Transfer Syntax is NDR32, what we support
            if item['TransferSyntax'] == uuidtup_to_bin(NDRSyntax):
                # Now Check if the interface is what we listen
                reason = 1 # Default, Abstract Syntax not supported
                for j in self._listenUUIDS:
                    if item['AbstractSyntax'] == j:
                        # Match, we accept the bind request
                        resp['SecondaryAddr']    = self._listenUUIDS[item['AbstractSyntax']]['SecondaryAddr']
                        resp['SecondaryAddrLen'] = len(resp['SecondaryAddr'])+1
                        reason           = 0
                        self._boundUUID = j
            else:
                # Fail the bind request for this context
                reason = 2 # Transfer Syntax not supported
            if reason == 0:
               result = MSRPC_CONT_RESULT_ACCEPT
            if reason == 1:
                LOG.error('Bind request for an unsupported interface %s' % bin_to_string(item['AbstractSyntax']))

            resp['ctx_num']             += 1
            itemResult                   = CtxItemResult()
            itemResult['Result']         = result
            itemResult['Reason']         = reason
            itemResult['TransferSyntax'] = uuidtup_to_bin(NDRSyntax)
            ctx_items                   += itemResult.getData()

        resp['Pad']              ='A'*((4-((resp["SecondaryAddrLen"]+MSRPCBindAck._SIZE) % 4))%4)
        resp['ctx_items'] = ctx_items
        resp['frag_len']  = len(resp.getData())

        self._clientSock.send(resp.getData())
        return None

    def processRequest(self,data):
        packet = MSRPCHeader(data)
        if packet['type'] == MSRPC_BIND:
            bind   = MSRPCBind(packet['pduData'])
            self.bind(packet, bind)
            packet = None
        elif packet['type'] == MSRPC_REQUEST and not self._listenUUIDS.get(self._boundUUID) is None:
            request          = MSRPCRequestHeader(data)
            response         = MSRPCRespHeader(data)
            response['type'] = MSRPC_RESPONSE
            # Serve the opnum requested, if not, fails
            if request['op_num'] in self._listenUUIDS[self._boundUUID]['CallBacks']:
                # Call the function 
                returnData          = self._listenUUIDS[self._boundUUID]['CallBacks'][request['op_num']](request['pduData'])
                response['pduData'] = returnData
            else:
                LOG.error('Unsupported DCERPC opnum %d called for interface %s' % (request['op_num'], bin_to_uuidtup(self._boundUUID)))
                response['type']    = MSRPC_FAULT
                response['pduData'] = pack('<L',0x000006E4)
            response['frag_len'] = len(response)
            return response
        else:
            # Defaults to a fault
            packet         = MSRPCRespHeader(data)
            packet['type'] = MSRPC_FAULT

        return packet
