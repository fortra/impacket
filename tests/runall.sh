#!/bin/sh
if [ $# -gt 0 ]
then
	SUFFIX=$1
	# Only run coverage when called by tox
	RUN="coverage run --append --rcfile=../coveragerc "
	RUNLOCAL="coverage run --append --rcfile=./coveragerc "
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

echo Testing SMB RPC/LDAP
cd ../SMB_RPC
export PYTHONPATH=../../:$PYTHONPATH
$RUN test_smb.py 2>&1 1>/dev/null | tee -a $OUTPUTFILE
$RUN test_spnego.py 2>&1 1>/dev/null | tee -a $OUTPUTFILE
$RUN test_ldap.py 2>&1 1>/dev/null | tee -a $OUTPUTFILE
$RUN test_nmb.py 2>&1 1>/dev/null | tee -a $OUTPUTFILE
$RUN test_ntlm.py 2>&1 1>/dev/null | tee -a $OUTPUTFILE
./rundce.sh $COVERAGE 2>&1 1>/dev/null | tee -a $OUTPUTFILE
cd ..

if [ $COVERAGE ]
then
	# Combine coverage and produce report
	echo "Combining coverage data"
	mv .coverage .coveragetmp
	coverage combine .coveragetmp ImpactPacket/.coverage dot11/.coverage SMB_RPC/.coverage
	coverage html -i
	coverage erase
	rm -f ImpactPacket/.coverage dot11/.coverage SMB_RPC/.coverage
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
