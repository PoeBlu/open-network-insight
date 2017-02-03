#!/bin/bash
#running ml_ops with different groups having different values of topic number, multiple replicates for each
for i in 5 10 15 20 30 50 100
do
	echo "Modifying the TOPIC_COUNT in ml_ops2.sh (a copy of ml_ops.sh)"
	cp ml_ops.sh ml_ops2.sh
	sed -c -i "s/TOPIC_COUNT=20/TOPIC_COUNT=$i/g" /home/duxbury/ml/ml_ops2.sh
	chmod +x ml_ops2.sh

	for j in {1..10}
	do
		echo "Running ML"
		./ml_ops2.sh 20170104 dns 1 50
		echo "Topic: $i , relicate: $j"
		echo "Saving csv file"
		mkdir /home/duxbury/brandon_results/multirun_results/dir_dns_spark_${i}_${j}
		hive -e "INSERT OVERWRITE LOCAL DIRECTORY '/home/duxbury/brandon_results/multirun_results/dir_dns_spark_${i}_${j}' ROW FORMAT DELIMITED FIELDS TERMINATED BY ',' SELECT * FROM brandon_dns_spark;"
		echo "csv file saved"
		echo "now merging csv files into one"
		cat /home/duxbury/brandon_results/multirun_results/dir_dns_spark_${i}_${j}/* > /home/duxbury/brandon_results/multirun_results/dns_spark_${i}_${j}.csv
	done
done
