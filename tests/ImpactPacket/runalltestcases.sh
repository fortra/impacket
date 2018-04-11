#!/bin/bash
separator='======================================================================'

export PYTHONPATH=../..:$PYTHONPATH

if [ $# -gt 0 ]
then
	# Only run coverage when called by tox
	RUN="coverage run --append --rcfile=../coveragerc "
else
	RUN=python
fi

total=0
ok=0
failed=0
for file in `ls *.py` ; do
	echo $separator
	echo Executing $RUN $file
	latest=$(
		$RUN $file 2>&1 | {
		while read line; do
			echo " $line" 1>&2
			latest="$line"
		done
		echo $latest
		} 
	)
	#echo Latest ${latest} 
	result=${latest:0:6}
	if [ "$result" = "FAILED" ]
	then
		(( failed++ ))
	elif [ "$result" = "OK" ]
	then
		(( ok++ ))
	fi

	(( total++ ))
done
echo $separator
echo Summary:
echo " OK $ok/$total"
echo " $failed FAILED"
