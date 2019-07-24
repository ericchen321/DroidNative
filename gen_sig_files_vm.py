# Use DroidNative to generate signature files
# Usage:
# 1st param: txt file containing paths to txt files on the host
# 2nd param: path to (zipped) signature file directory on the host
# 3rd param: path to feature extraction log directory on the host
# 4th param: number of processes to do feature extraction in parallel
# 5th param: ip address of the host
# 6th param: (optional) txt file with list of (zipped) txt files to be excluded. Requires paths
#            matching paths of txt files in 1st param's directory

import sys
import os
import subprocess
import glob
from multiprocessing import Pool
import itertools
import re

# identify errors from siggen.log file and record in <log_path>/siggen_error.log
def identify_errors(per_apk_log_file_path, log_path):
    error_log_file = open(log_path + '/siggen_error.log', 'a+')
    per_apk_error_log_file = open(per_apk_log_file_path, 'r')
    apk_path = os.path.basename(per_apk_log_file_path).rstrip('.siggen.log')
    for line in per_apk_error_log_file:
        if re.search('Error:SimilarityDetector::GenerateSignatures: Cannot open the file', line):
            error_log_file.write('File ' + apk_path + ' signature generation failed due to C++ I/O error\n')
            break
    per_apk_error_log_file.close()
    error_log_file.close()

# build signatures of given sample, write to file, and generate log file
def run_droidnative_build_sigs_only(zipped_txt_name, sig_dir, log_dir):
    log_file_path = log_dir + "/" + zipped_txt_name.rstrip('.dex.txt.zip') + ".siggen.log"
    print("Command: " + "./DroidNative-ACFG.exe" + " 0 " + sig_dir + " " + zipped_txt_name + " 2>&1 | tee " + log_file_path)
    os.system("./DroidNative-ACFG.exe" + " 0 " + sig_dir + " " + zipped_txt_name + " 2>&1 | tee " + log_file_path)
    identify_errors(log_file_path, log_dir)

txt_file_path = sys.argv[1]
sig_dir = sys.argv[2]
log_dir = sys.argv[3]
parallel_count = int(sys.argv[4])
ip_host = sys.argv[5]
exclusion_txts_path = ""
if len(sys.argv) == 7:
    print("exclusion file noted.")
    exclusion_txts_path = sys.argv[6]
else:
    print("no exclusion file given. Will feature-extract all files.")

txt_file = open(txt_file_path, 'r')
os.chdir('./bin')
for zipped_txt_path_on_host in txt_file:
    # copy remote disassembly file to current directory
    zipped_txt_path_on_host = zipped_txt_path_on_host.rstrip('\n')
    print("Downloading txt sample from host: " + zipped_txt_path_on_host)
    subprocess.run('sshpass -p "hooBUFF3!" scp ' + 'i0y0b@' + ip_host + ':' + zipped_txt_path_on_host + ' ./', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    print("Downloading completed. Starting feature extraction...")
    # run DN and produce: sig files, sig gen logs
    zipped_txt_name = os.path.basename(zipped_txt_path_on_host)
    run_droidnative_build_sigs_only('./' + zipped_txt_name, '.', '.')
    # upload files to host
    zipped_training_sig_name = zipped_txt_name.rstrip('.zip') + '.training.dat.ACFG.zip'
    training_log_name = zipped_txt_name.rstrip('.dex.txt.zip') + ".siggen.log"
    subprocess.run('sshpass -p "hooBUFF3!" scp ' + zipped_training_sig_name + ' i0y0b@' + ip_host + ':' + sig_dir + '/' + zipped_training_sig_name, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    subprocess.run('sshpass -p "hooBUFF3!" scp ' + training_log_name + ' i0y0b@' + ip_host + ':' + log_dir + '/' + training_log_name, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    print("Conversion and vm->host uploading completed.")
    # remove files left in the VM
    print("Removing files: zipped txt file, zipped training sig file, training log file")
    subprocess.run('rm ' + zipped_txt_name, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    subprocess.run('rm ' + zipped_training_sig_name, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    subprocess.run('rm ' + training_log_name, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)

subprocess.run('sshpass -p "hooBUFF3!" scp ' + 'siggen_error.log' + ' i0y0b@' + ip_host + ':' + log_dir + '/siggen_error.log', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)