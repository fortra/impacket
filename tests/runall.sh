#!/bin/sh
if [ $# -gt 0 ]
then
	SUFFIX=$1
	# Only run coverage when called by tox
	RUN="python -m coverage run --append --rcfile=../coveragerc "
	RUNLOCAL="python -m coverage run --append --rcfile=./coveragerc "
	COVERAGE=true
else
	SUFFIX=XX
	RUN=python
	RUNLOCAL=python
	COVERAGE=
fi

export PYTHONPATH=../:$PYTHONPATH

OUTPUTFILE=/tmp/impacketoutput$SUFFIX.txt
# Let's remove the OUTPUTFILE in case it exists
rm -f $OUTPUTFILE

# Start running the tests

echo Walking modules
$RUNLOCAL ./walkmodules.py

echo Running __main__ on some important files
$RUNLOCAL -m impacket.crypto __main__
$RUNLOCAL -m impacket.krb5.crypto __main__
$RUNLOCAL -m impacket.structure __main__
$RUNLOCAL -m impacket.dns __main__ 
$RUNLOCAL -m impacket.IP6_Address __main__
$RUNLOCAL -m impacket.dcerpc.v5.ndr __main__

echo Testing ImpactPacket
cd ImpactPacket
./runalltestcases.sh  $COVERAGE 2>&1 1>/dev/null | tee -a $OUTPUTFILE

echo Testing dot11
cd ../dot11
./runalltestcases.sh $COVERAGE 2>&1 1>/dev/null | tee -a $OUTPUTFILE

# In some environments we don't have a Windows 2012 R2 Domain Controller,
# so skip these tests.
cd ../SMB_RPC
echo test_spnego.py
$RUN test_spnego.py 2>&1 1>/dev/null | tee -a $OUTPUTFILE
echo test_ntlm.py
$RUN test_ntlm.py 2>&1 1>/dev/null | tee -a $OUTPUTFILE

if [ -z "$NO_REMOTE" ]; then
    echo Testing SMB RPC/LDAP
    export PYTHONPATH=../../:$PYTHONPATH
    echo test_smb.py
    $RUN test_smb.py 2>&1 1>/dev/null | tee -a $OUTPUTFILE
    echo test_ldap.py
    $RUN test_ldap.py 2>&1 1>/dev/null | tee -a $OUTPUTFILE
    echo test_nmb.py
    $RUN test_nmb.py 2>&1 1>/dev/null | tee -a $OUTPUTFILE
    ./rundce.sh $COVERAGE 2>&1 1>/dev/null | tee -a $OUTPUTFILE
fi
cd ..

echo Testing MISC
cd misc
export PYTHONPATH=../../:$PYTHONPATH
echo test_dpapi.py
$RUN test_dpapi.py 2>&1 1>/dev/null | tee -a $OUTPUTFILE
cd ..

if [ $COVERAGE ]
then
	# Combine coverage and produce report
	echo "Combining coverage data"
	mv .coverage .coveragetmp
	coverage combine .coveragetmp ImpactPacket/.coverage dot11/.coverage SMB_RPC/.coverage misc/.coverage
	coverage html -i
	coverage erase
	rm -f ImpactPacket/.coverage dot11/.coverage SMB_RPC/.coverage misc/.coverage
fi

if grep -q ERROR $OUTPUTFILE;
then
        echo "ERRORS found, look at $OUTPUTFILE"
        exit 1
else
	echo "NO ERRORS found, congrats!"
	rm $OUTPUTFILE
	exit 0
fi

echo ================================================================================
echo IMPORTANT: Dont forget to remove all the .coverage files from tests/* and subdirs
echo if you want newly freshed coverage stats
echo ================================================================================
