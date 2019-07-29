#!/bin/bash
# testing on VT 2018 & 2019

cd bin/
./DroidNative-ACFG_vm0.exe 0 70 whatever files_to_check_00.txt sig_temp_00 virus_samples.txt.training.dat.ACFG > results_00.txt 2> timing_00.csv
./DroidNative-ACFG_vm0.exe 0 70 whatever files_to_check_01.txt sig_temp_01 virus_samples.txt.training.dat.ACFG > results_01.txt 2> timing_01.csv
