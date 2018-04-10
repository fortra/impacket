#!/bin/sh
if [ $# -gt 0 ]
then
	SUFFIX=$1
else
	SUFFIX=XX
fi

OUTPUTFILE=/tmp/impacketoutput$SUFFIX.txt
# Let's remove the OUTPUTFILE in case it exists
rm -f $OUTPUTFILE

# Start running the tests
cd ImpactPacket
./runalltestcases.sh  2>&1 1>/dev/null | tee -a $OUTPUTFILE
cd ../dot11
./runalltestcases.sh 2>&1 1>/dev/null | tee -a $OUTPUTFILE
cd ../SMB_RPC
python test_smb.py 2>&1 1>/dev/null | tee -a $OUTPUTFILE
python test_spnego.py 2>&1 1>/dev/null | tee -a $OUTPUTFILE
#python test_ldap.py 2>&1 1>/dev/null | tee -a $OUTPUTFILE
python test_nmb.py 2>&1 1>/dev/null | tee -a $OUTPUTFILE
python test_ntlm.py 2>&1 1>/dev/null | tee -a $OUTPUTFILE
./rundce.sh  2>&1 1>/dev/null | tee -a $OUTPUTFILE
cd ..

if grep -q ERROR $OUTPUTFILE;
then
        echo "ERRORS found, look at $OUTPUTFILE"
        exit 1
else
	echo "NO ERRORS found, congrats!"
	rm $OUTPUTFILE
	exit 0
fi
