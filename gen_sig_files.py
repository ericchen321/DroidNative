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

# build signatures of samples specified in <prefix>_parallel_<process_index>.txt,
# eg. malware_samples_parallel_01.txt
def run_droidnative_build_sigs_only(process_index, dir_droidnative_bin, sig_dir, log_dir, prefix):
    samples_name = prefix + '_parallel_' + ('%02d' % process_index) + '.txt'
    print("command: " + "./DroidNative-ACFG.exe" + " 0 " + samples_name)
    os.system("./DroidNative-ACFG.exe" + " 0 " + sig_dir + " " + samples_name + " 2>&1 | tee " + log_dir + "/" + samples_name + ".siggen.log")

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

# remove existing sample lists
os.chdir(dir_droidnative_bin)
os.system("rm " + dir_droidnative_bin + "/" + "preprocessed_samples" + "_parallel_*")

# count num of processes actually needed
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
samples_per_partition = int(len(samples) // int(parallel_count))
sample_count = 0
for sample_path in samples:
    sample_count += 1
processes_needed = len(samples) // samples_per_partition
if len(samples) % samples_per_partition != int(0):
    processes_needed += 1
print("Given number of processes: " + str(parallel_count) + "; actual number of processes: " + str(processes_needed) + ".")

# produce sample lists
sample_count = 0
for process_index in range(0, processes_needed):
    sample_file_name = 'preprocessed_samples' + '_parallel_' + ('%02d' % process_index) + '.txt'
    sample_file = open(sample_file_name, 'w')
    file_count = 0
    for file_count in range(0, samples_per_partition):
        if(sample_count < len(samples)):
            sample_file.write(samples[sample_count] + '\n')
            sample_count += 1
    sample_file.close()

pool = Pool(processes_needed)
pool.starmap(run_droidnative_build_sigs_only, itertools.product(range(0, processes_needed), [dir_droidnative_bin], [sig_dir], [log_dir], ['preprocessed_samples']))