#!/usr/bin/env python
"""opdump - scan for operations on a given DCERPC interface

Usage: opdump.py hostname port interface version

This binds to the given hostname:port and DCERPC interface. Then, it tries to
call each of the first 256 operation numbers in turn and reports the outcome
of each call.

This will generate a burst of TCP connections to the given host:port!

Example:
$ ./opdump.py 10.0.0.30 135 99FCFEC4-5260-101B-BBCB-00AA0021347A 0.0
op 0 (0x00): rpc_x_bad_stub_data
op 1 (0x01): rpc_x_bad_stub_data
op 2 (0x02): rpc_x_bad_stub_data
op 3 (0x03): success
op 4 (0x04): rpc_x_bad_stub_data
ops 5-255: nca_s_op_rng_error

rpc_x_bad_stub_data, rpc_s_access_denied, and success generally means there's an
operation at that number.

Author: Catalin Patulea <cat@vv.carleton.ca>
"""
import sys

from impacket.examples import logger
from impacket import uuid
from impacket.dcerpc.v5 import transport


def main(args):
  if len(args) != 4:
    print "usage: opdump.py hostname port interface version"
    return 1

  host, port, interface, version = args[0],  int(args[1]), args[2], args[3]

  stringbinding = "ncacn_ip_tcp:%s" % host
  trans = transport.DCERPCTransportFactory(stringbinding)
  trans.set_dport(port)

  results = []
  for i in range(256):
    dce = trans.get_dce_rpc()
    dce.connect()

    iid = uuid.uuidtup_to_bin((interface, version))
    dce.bind(iid)

    dce.call(i, "")
    try:
      dce.recv()
    except Exception, e:
      result = str(e)
    else:
      result = "success"

    dce.disconnect()

    results.append(result)

  # trim duplicate suffixes from the back
  suffix = results[-1]
  while results and results[-1] == suffix:
    results.pop()

  for i, result in enumerate(results):
    print "op %d (0x%02x): %s" % (i, i, result)

  print "ops %d-%d: %s" % (len(results), 255, suffix)

if __name__ == "__main__":
  # Init the example's logger theme
  logger.init()
  sys.exit(main(sys.argv[1:]))
