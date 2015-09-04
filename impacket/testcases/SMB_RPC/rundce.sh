#!/bin/bash
separator='======================================================================'
#ls *.py | xargs -I{} --max-args=1 bash -c "echo -e '$separator\nExecuting: {}\n';python {}"
#ls *.py | xargs --max-args=1 python

export PYTHONPATH=../../..:$PYTHONPATH

python test_rpcrt.py
python test_scmr.py
python test_epm.py
python test_samr.py
python test_wkst.py
python test_srvs.py
python test_lsad.py
python test_lsat.py
python test_rrp.py
python test_mgmt.py
python test_ndr.py
python test_drsuapi.py
python test_wmi.py
python test_dcomrt.py
