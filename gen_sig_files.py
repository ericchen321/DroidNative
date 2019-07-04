# Use DroidNative to generate signature files
# Usage:
# 1st param: path to (zipped) txt directory
# 2nd param: path to (zipped) signature file directory
# 3rd param: path to feature extraction log directory
# 4th param: path to DroidNative/bin
# 5th param: number of processes to do feature extraction in parallel
# 6th param: (optional) txt file with list of (zipped) txt files to be excluded. Requires paths
#            matching paths of txt files in 1st param's directory

import sys
import os
import subprocess
import glob
from multiprocessing import Pool
import itertools
import re

# Yield successive n-sized chunks from list
def partition_list(list, n):
    for i in range(0, len(list), n):
        yield list[i:i + n]

# identify errors from siggen.log file and record in <log_path>/siggen_error.log
def identify_errors(per_apk_log_file_path, log_path):
    error_log_file = open(log_path + '/siggen_error.log', 'a+')
    per_apk_error_log_file = open(per_apk_log_file_path, 'r')
    apk_path = os.path.basename(per_apk_log_file_path).rstrip('.siggen.log')
    for line in per_apk_error_log_file:
        if re.search('Error:SimilarityDetector::GenerateSignatures: Cannot open the file', line):
            error_log_file.write('File ' + apk_path + ' signature generation failed due to C++ I/O error')
            break
    per_apk_error_log_file.close()
    error_log_file.close()

# build signatures of given sample, write to file, and generate log file
def run_droidnative_build_sigs_only(zipped_txt_path, dir_droidnative_bin, sig_dir, log_dir):
    log_file_path = log_dir + "/" + os.path.basename(zipped_txt_path).rstrip('.dex.txt.zip') + ".siggen.log"
    print("Command: " + "./DroidNative-ACFG.exe" + " 0 " + sig_dir + " " + zipped_txt_path + " 2>&1 | tee " + log_file_path)
    os.system("./DroidNative-ACFG.exe" + " 0 " + sig_dir + " " + zipped_txt_path + " 2>&1 | tee " + log_file_path)
    identify_errors(log_file_path, log_dir)

txt_dir = sys.argv[1]
sig_dir = sys.argv[2]
log_dir = sys.argv[3]
dir_droidnative_bin = sys.argv[4]
parallel_count = int(sys.argv[5])
exclusion_txts_path = ""
if len(sys.argv) == 7:
    print("exclusion file noted.")
    exclusion_txts_path = sys.argv[6]
else:
    print("no exclusion file given. Will feature-extract all files.")

# partition samples
samples = glob.glob(txt_dir + '/*.zip')
if exclusion_txts_path != "":
    exclusion_file = open(exclusion_txts_path, 'r')
    for excluded_txt in exclusion_file:
        excluded_txt = excluded_txt.rstrip('\n')
        for sample in samples:
            if excluded_txt == sample:
                samples.remove(sample)
                print("Sample " + sample + " has been removed from feature extraction.")
    exclusion_file.close()
partitions = list(partition_list(samples, parallel_count))

# run DroidNative
os.chdir(dir_droidnative_bin)
pool = Pool(parallel_count)
for partition in partitions:
    pool.starmap(run_droidnative_build_sigs_only, itertools.product(partition, [dir_droidnative_bin], [sig_dir], [log_dir]))