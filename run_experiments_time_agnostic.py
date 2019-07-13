# Author: Guanxiong Chen
# Python 3 script to parse given .csv file that describes time-agnostic
# experiment setups, then prepare files required for DroidNative's testing:
#   malware_samples.txt                         (all malware samples from all folds)
#   benign_samples.txt                          (all benign samples from all folds)
#   malware_samples_<partition_index>           (all malware samples in a fold)
#   virus_samples_<partition_index>.txt         (all malware samples not in a fold)
#   benign_samples_<partition_index>            (all benign samples in a fold)
#   benign_samples_<partition_index>.txt        (all benign samples not in a fold)
#   files_to_check_<partition_index>.txt        (malware_samples_<partition_index> Union benign_samples_<partition_index>)
# Requires Python 3.5
# Requires signature files ready
# Usage:
# 1st param: path to .csv file
# 2nd param: path to directory where signature files are stored, eg.
#            /nfs/home2/guanxiong/signatures

import csv
import sys
import os
import subprocess
from multiprocessing import Pool
from itertools import product

# split a path to individual parts
# from https://www.oreilly.com/library/view/python-cookbook/0596001673/ch04s16.html
def split_path(path):
    allparts = []
    while 1:
        parts = os.path.split(path)
        if parts[0] == path:  # sentinel for absolute paths
            allparts.insert(0, parts[0])
            break
        elif parts[1] == path: # sentinel for relative paths
            allparts.insert(0, parts[1])
            break
        else:
            path = parts[0]
            allparts.insert(0, parts[1])
    return allparts

# given path to experiment setup csv file, modifies given lists so that
# each becomes list of txt files containing path to apk files
def parse_setup_file(csv_path, folds_benign_test, folds_malware_test, folds_benign_train, folds_malware_train):
    csv_file = open(csv_path, 'r')
    csv_reader = csv.reader(csv_file, delimiter=',')
    line_count = 0
    for row in csv_reader:
        if line_count >= 1:
            folds_benign_test.append(row[4])
            folds_malware_test.append(row[5])
            folds_benign_train.append(row[2])
            folds_malware_train.append(row[3])
        line_count += 1

# generate list of samples for each fold
# @param folds_test: list of paths to txt files that store testing/training samples' paths
# @param dir_droidnative_bin: path to DroidNative/bin
# @param dir_sig: path to signature files directory
# @param prefix: prefix to generated file. 
#                Usually like 'malware_samples' or 'benign_samples'
# @param extension: like .txt or empty string
def gen_list_of_sigs(folds, dir_droidnative_bin, dir_sig, prefix, extension):
    num_fold = len(folds)
    for fold_count in range(int(0), num_fold):
        fold_i = folds[fold_count]
        samples_i = prefix + "_" + ("%02d" % fold_count)
        if extension != "":
            samples_i += ("." + extension)
        os.system("rm " + dir_droidnative_bin + "/" + samples_i)
        samples_i_file = open(dir_droidnative_bin + "/" + samples_i, 'w')
        fold_benign_test_i_file = open(fold_i, 'r')
        for line in fold_benign_test_i_file:
            apk_path = line.rstrip('\n')
            apk_name = os.path.basename(apk_path)
            year = split_path(apk_path)[6]
            sig_folder_prefix = 'benign'
            if "Malware" in split_path(apk_path)[5]:
                sig_folder_prefix = 'malware'
            txt_path = dir_sig + '/' + year + '/' + sig_folder_prefix + '_sig/' + apk_name + '.dex.txt.training.dat.ACFG.zip'
            samples_i_file.write(txt_path + '\n')
        samples_i_file.close()

# combine <malware/benign>_samples_<partition_index> of all indicies
# into one file; prefix is usually 'benign_samples' or 'malware_samples'
def combine_samples(num_fold, dir_droidnative_bin, prefix):
    samples_file_path = dir_droidnative_bin + "/" + prefix + '.txt'
    os.system("rm " + samples_file_path)
    os.system("touch " + samples_file_path)
    for fold_count in range(0, num_fold):
        os.system("cat " + dir_droidnative_bin + ("/" + prefix + ("_%02d" % fold_count)) + " >> " + samples_file_path)

# run droidnative given fold count
# requires in droidnative's bin dir;
# requires virus_samples_<fold_count>.txt, files_to_check_<fold_count>.txt present in bin dir
def run_droidnative_testing(fold_count):
    threshold = 70
    virus_samples_name = 'virus_samples_' + ('%02d' % fold_count) + '.txt'
    files_to_check_name = 'files_to_check_' + ('%02d' % fold_count) + '.txt'
    sig_temp_dir = 'sig_temp_' + ('%02d' % fold_count)
    result_name = 'results_' + ('%02d' % fold_count) + '.txt'
    timing_name = 'timing_' + ('%02d' % fold_count) + '.txt'
    os.system('mkdir ' + sig_temp_dir)
    os.system("./DroidNative-ACFG.exe" + ' 0 ' + str(threshold) + ' ' + virus_samples_name + ' ' + files_to_check_name + ' ' + sig_temp_dir + ' > ' + result_name + ' 2>' + timing_name)
    os.system('rm -rf ' + sig_temp_dir)

def main():
    if len(sys.argv) != 3:
        print("Wrong arguments, please check comments in the script for usage")
        sys.exit(1)
    csv_path = sys.argv[1]
    dir_sig = sys.argv[2]
    dir_droidnative_bin = os.getcwd() + '/bin'

    # get experiment setup info
    folds_benign_test = []
    folds_malware_test = []
    folds_benign_train = []
    folds_malware_train = []
    parse_setup_file(csv_path, folds_benign_test, folds_malware_test, folds_benign_train, folds_malware_train)
    num_fold = len(list(folds_benign_test))

    # generate benign_samples_<partition_index> and malware_samples_<partition_index>
    gen_list_of_sigs(folds_benign_test, dir_droidnative_bin, dir_sig, 'benign_samples', '')
    gen_list_of_sigs(folds_malware_test, dir_droidnative_bin, dir_sig, 'malware_samples', '')

    # generate benign_samples.txt and malware_samples.txt
    combine_samples(num_fold, dir_droidnative_bin, 'benign_samples')
    combine_samples(num_fold, dir_droidnative_bin, 'malware_samples')

    # generate virus_samples_<partition_index>.txt
    for fold_count in range(int(0), num_fold):
        gen_list_of_sigs(folds_malware_train, dir_droidnative_bin, dir_sig, 'virus_samples', 'txt')

    # generate files_to_check_<partition_index>.txt
    for fold_count in range(int(0), num_fold):
        file_to_check_i_path = dir_droidnative_bin + "/files_to_check_" + ("%02d" % fold_count) + ".txt"
        os.system("rm " + file_to_check_i_path)
        os.system("touch " + file_to_check_i_path)
        os.system("cat " + dir_droidnative_bin + "/malware_samples_" + ("%02d" % fold_count) + " >> " + file_to_check_i_path)
        os.system("cat " + dir_droidnative_bin + "/benign_samples_" + ("%02d" % fold_count) + " >> " + file_to_check_i_path)
    
    # run DroidNative testing
    os.chdir(dir_droidnative_bin)
    pool = Pool(num_fold)
    pool.map(run_droidnative_testing, range(int(0), num_fold))
    
if __name__ == "__main__":
    main()
