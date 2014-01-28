#!/bin/bash
separator='======================================================================'
#ls *.py | xargs -I{} --max-args=1 bash -c "echo -e '$separator\nExecuting: {}\n';python {}"
#ls *.py | xargs --max-args=1 python

export PYTHONPATH=../../..:$PYTHONPATH

total=0
ok=0
failed=0
for file in `ls *.py` ; do
	echo $separator
	echo Executing $file
	latest=$(
		python $file 2>&1 | {
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
	else
    		echo "WARNING: Unknown result!!!!!"
		(( failed++ ))
	fi

	(( total++ ))
done
echo $separator
echo Summary:
echo " OK $ok/$total"
echo " $failed FAILED"
