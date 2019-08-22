#!/bin/bash

cd bin/
./DroidNative-ACFG.exe 0 70 whatever files_to_check_02_960_partition_0.txt sig_temp_02 virus_samples.txt.training.dat.ACFG > results_02_960_partition_0.txt 2> timing_02_960_partition_0.csv &
./DroidNative-ACFG.exe 0 70 whatever files_to_check_02_960_partition_1.txt sig_temp_02 virus_samples.txt.training.dat.ACFG > results_02_960_partition_1.txt 2> timing_02_960_partition_1.csv &
./DroidNative-ACFG.exe 0 70 whatever files_to_check_02_960_partition_2.txt sig_temp_02 virus_samples.txt.training.dat.ACFG > results_02_960_partition_2.txt 2> timing_02_960_partition_2.csv &
./DroidNative-ACFG.exe 0 70 whatever files_to_check_02_960_partition_3.txt sig_temp_02 virus_samples.txt.training.dat.ACFG > results_02_960_partition_3.txt 2> timing_02_960_partition_3.csv

