#!/usr/bin/python3
# Author: Guanxiong Chen
# Python script to run DroidNative to do
# 1) Feature Extraction or
# 2) Testing
# Requires the following files to be present under DroidNative/bin/:
# benign_samples.txt
# malware_samples.txt
# virus_samples_<partition_index>.txt
# files_to_check_<partition_index>.txt
# Usage:
# run-cross-validation_ACFG.py <n> <file_name_DroidNative> <build_sig_only=0/1> <threshold_for_malware_graph_matching> <feature_extraction_parallel_count>
# Example:
# run-cross-validation_ACFG.py.pl 10 ./DroidNative-ACFG.exe 1 70 20

import sys
import os
from multiprocessing import Pool
import itertools

# build signatures of samples specified in <prefix>_parallel_<process_index>.txt,
# eg. malware_samples_parallel_01.txt
def run_droidnative_build_sigs_only(process_index, droidnative_exe_path, prefix):
    samples_name = prefix + '_parallel_' + ('%02d' % process_index) + '.txt'
    os.system(droidnative_exe_path + " 0 " + samples_name)

# run testing on a fold
def test_per_fold(virus_samples_name, files_to_check_name, result_name, threshold, droidnative_exe_path):
    os.system(droidnative_exe_path + ' 0 ' + str(threshold) + ' ' + virus_samples_name + ' ' + files_to_check_name + ' > ' + result_name)

def main():
    # check input arguments
    if(len(sys.argv) != 6):
        print('Wrong arguments, please check out comments for usage')
        sys.exit(1)
    num_fold = int(sys.argv[1])
    droidnative_exe_path = sys.argv[2]
    build_sig_only = bool(int(sys.argv[3]))
    threshold = int(sys.argv[4])
    num_parallel = int(sys.argv[5])

    # check if input files required are present
    print('Checking if all required input files are present...')
    if not os.path.exists('./benign_samples.txt'):
        print('Error: missing find benign_samples.txt, exiting...')
        sys.exit(1)
    if not os.path.exists('./malware_samples.txt'):
        print('Error: missing malware_samples.txt, exiting...')
        sys.exit(1)
    for fold_count in range(0, num_fold):
        virus_samples_name = './virus_samples_' + ('%02d' % fold_count) + '.txt'
        if not os.path.exists(virus_samples_name):
            print('Error: missing ' + virus_samples_name + ', exiting...')
            sys.exit(1)
        files_to_check_name = './files_to_check_' + ('%02d' % fold_count) + '.txt'
        if not os.path.exists(files_to_check_name):
            print('Error: missing ' + files_to_check_name + ', exiting...')
            sys.exit(1)
    for parallel_count in range(0, num_parallel):
        malware_samples_parallel_name = './malware_samples_parallel_' + ('%02d' % parallel_count) + '.txt'
        if not os.path.exists(malware_samples_parallel_name):
            print('Error: missing ' + malware_samples_parallel_name + ', exiting')
            sys.exit(1)
        benign_samples_parallel_name = './benign_samples_parallel_' + ('%02d' % parallel_count) + '.txt'
        if not os.path.exists(benign_samples_parallel_name):
            print('Error: missing ' + benign_samples_parallel_name + ', exiting')
            sys.exit(1)
    print('Input files checking done.')

    if build_sig_only:
        pool = Pool(num_parallel)
        print('Running DroidNative-ACFG in feature extraction mode...')
        print('Generating signatures from benign samples...')
        pool.starmap(run_droidnative_build_sigs_only, itertools.product(range(0, num_parallel), [droidnative_exe_path], ['benign_samples']))
        print('Benign samples signature generation done.')
        print('Generating signatures from malware samples...')
        pool = Pool(20)
        pool.starmap(run_droidnative_build_sigs_only, itertools.product(range(0, num_parallel), [droidnative_exe_path], ['malware_samples']))
        print('Malware samples signature generation done.')
    else:
        print('Running DroidNative-ACFG in testing mode...')
        pool = Pool(num_fold)
        test_per_fold_inputs = []
        for fold_count in range(0, num_fold):
            virus_samples_name = 'virus_samples_' + ('%02d' % fold_count) + '.txt'
            files_to_check_name = 'files_to_check_' + ('%02d' % fold_count) + '.txt'
            result_name = 'results_' + ('%02d' % fold_count) + '.txt'
            test_per_fold_input = (virus_samples_name, files_to_check_name, result_name, threshold, droidnative_exe_path)
            test_per_fold_inputs.append(test_per_fold_input)
        # do testing per fold in parallel; number of parallel processes = num_fold
        pool.starmap(test_per_fold, test_per_fold_inputs)

if __name__ == '__main__':
    main()