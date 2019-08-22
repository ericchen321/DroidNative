#!/bin/bash
cd bin
# 4b, 4c, 4d
./DroidNative-ACFG.exe 0 70 whatever files_to_check_04_cabe0.txt sig_temp_04 virus_samples.txt.training.dat.ACFG > results_04_cabe0.txt 2>timing_04_cabe0.csv
./DroidNative-ACFG.exe 0 70 whatever files_to_check_04_a5f52.txt sig_temp_04 virus_samples.txt.training.dat.ACFG > results_04_a5f52.txt 2>timing_04_a5f52.csv
./DroidNative-ACFG.exe 0 70 whatever files_to_check_04_d3459.txt sig_temp_04 virus_samples.txt.training.dat.ACFG > results_04_d3459.txt 2>timing_04_d3459.csv 
