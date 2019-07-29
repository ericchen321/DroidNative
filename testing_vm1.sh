#!/bin/bash
# testing on VT 2018 & 2019

cd bin/
./DroidNative-ACFG_vm1.exe 0 70 whatever files_to_check_02.txt sig_temp_02 virus_samples.txt.training.dat.ACFG > results_02.txt 2> timing_02.csv
./DroidNative-ACFG_vm1.exe 0 70 whatever files_to_check_03.txt sig_temp_03 virus_samples.txt.training.dat.ACFG > results_03.txt 2> timing_03.csv
