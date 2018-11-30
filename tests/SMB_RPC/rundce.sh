#!/bin/bash
separator='======================================================================'

export PYTHONPATH=../../:$PYTHONPATH
if [ $# -gt 0 ]
then
	# Only run coverage when called by tox
	RUN="coverage run --append --rcfile=../coveragerc "
else
	RUN=python
fi

$RUN test_rpcrt.py
$RUN test_scmr.py
$RUN test_epm.py
$RUN test_samr.py
$RUN test_wkst.py
$RUN test_srvs.py
$RUN test_lsad.py
$RUN test_lsat.py
$RUN test_rrp.py
$RUN test_mgmt.py
$RUN test_ndr.py
$RUN test_drsuapi.py
$RUN test_wmi.py
$RUN test_dcomrt.py
$RUN test_even6.py
$RUN test_bkrp.py
$RUN test_tsch.py
$RUN test_dhcpm.py
$RUN test_secretsdump.py
$RUN test_rprn.py
