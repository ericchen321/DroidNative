# Author: Guanxiong Chen
# Script to convert apk samples to txt using Android emulator
# Requires Python 3.5
# Requires running emulator
# Requires adb set up properly
# Script usage:
# 1st param: path to apk directory
# 2nd param: path to output directory for txts
# 3rd param: path to output directory for logs
# 4th param: number of samples to be converted. 0 means all
# 5th param: number of processes to do preprocessing in parallel
# 6th param: name of running emulator (eg. emulator-5554)

import sys
import os
import glob
import subprocess
import re
from multiprocessing import Pool
from itertools import product
import itertools

# Yield successive n-sized chunks from list
def partition_list(list, n):
    for i in range(0, len(list), n):
        yield list[i:i + n]

# extract SDK version info of given apk file
def extract_sdk_version(apk_name):
    # run aapt
    aapt_results = subprocess.run('aapt list -a ' + apk_name + ' | grep "SdkVersion"', stdout = subprocess.PIPE, shell = True).stdout.decode()
    # search minSdkVersion
    search_min_sdk = re.search(r'(minSdkVersion.+=\(type.+\))(.+)', aapt_results)
    if search_min_sdk:
        print('minSdkVersion is ' + str(int(search_min_sdk.group(2), 0)))
    search_target_sdk = re.search(r'(targetSdkVersion.+=\(type.+\))(.+)', aapt_results)
    if search_target_sdk:
        print('targetSdkVersion is ' + str(int(search_target_sdk.group(2), 0)))
    search_max_sdk = re.search(r'(maxSdkVersion.+=\(type.+\))(.+)', aapt_results)
    if search_max_sdk:
        print('maxSdkVersion is ' + str(int(search_max_sdk.group(2), 0)))

# identify given apk's verification errors and lock errors from 
# dex2oat's terminal message. Returns 1 if got any errors
def identify_errors(apk_path, log_path):
    apk_name = os.path.basename(apk_path)
    log_file_dex2oat = open(log_path + '/' + apk_name + '.dex2oat.log', 'r')
    verification_error = False
    lock_verification_error = False
    oat_file_gen_error = False

    # search only first 100 lines
    line_count = 0
    for line in log_file_dex2oat.readlines():
        if (not verification_error) and re.search('verification error', line, re.IGNORECASE):
            print("File " + apk_path + " got verification error")
            verification_error = True
        if (not lock_verification_error) and re.search('failed lock verification', line, re.IGNORECASE):
            print("File " + apk_path + " got lock verification error")
            lock_verification_error = True
        if (not oat_file_gen_error) and re.search('Failed to open', line, re.IGNORECASE):
            print("File " + apk_path + " failed to have its oat and txt file produced")
            oat_file_gen_error = True
        line_count += 1
        if line_count >= 100:
            break

    return (verification_error or lock_verification_error or oat_file_gen_error)

# Convert given apk file to txt file stored in out_path; 
# store terminal log to <apk_name>.dex2oat.log under log_path; 
# generate error messages if errors occured during conversion; 
# print out SDK version info of apk with conversion error
def convert_file(apk_path, out_path, log_path, emulator_name):
    apk_name = os.path.basename(apk_path)
    apk_path_on_device = "/sdcard/" + apk_name
    os.system("cp " + apk_path + " ./" + apk_name)

    log_file_dex2oat = open(log_path + '/' + apk_name + '.dex2oat.log', 'w')
    os.system("adb -s " + emulator_name + " push " + apk_path + " /sdcard/")
    os.system("adb -s " + emulator_name + " logcat -c")
    subprocess.run("adb -s " + emulator_name + " shell dex2oat --runtime-arg -classpath --runtime-arg " + apk_path_on_device + " --instruction-set=x86 " + "--runtime-arg " + "-Xrelocate " + " --dex-file=" + apk_path_on_device + " --oat-file=" + apk_path_on_device + ".dex", stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, shell=True)
    subprocess.run("adb -s " + emulator_name + " logcat -b main -d", stdout=log_file_dex2oat, stderr=log_file_dex2oat, universal_newlines=True, shell=True)
    subprocess.run("adb -s " + emulator_name + " shell oatdump --oat-file=" + apk_path_on_device + ".dex" + " --instruction-set=x86" + " --output=" + apk_path_on_device + ".dex.txt", stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, shell=True)
    log_file_dex2oat.close()
    if identify_errors(apk_path, log_path):
        extract_sdk_version(apk_name)
    os.system("adb -s " + emulator_name + " pull " + apk_path_on_device + ".dex.txt " + out_path + "/" + apk_name + ".dex.txt")
    os.system("adb -s " + emulator_name + " shell rm " + apk_path_on_device)
    os.system("adb -s " + emulator_name + " shell rm " + apk_path_on_device + ".dex")
    os.system("adb -s " + emulator_name + " shell rm " + apk_path_on_device + ".vdex")
    os.system("adb -s " + emulator_name + " shell rm " + apk_path_on_device + ".dex.txt")

# Convert apk files in in_path to txt files stroed in out_path; store terminal log
# to log_path
def convert_files(in_path, out_path, log_path, emulator_name, sample_count, parallel_count):
    pool = Pool(int(parallel_count))
    samples = glob.glob(in_path + "/*.apk")
    if int(sample_count) != 0:
        samples = samples[:int(sample_count)]
    partitions = list(partition_list(samples, int(parallel_count)))
    for partition in partitions:
        pool.starmap(convert_file, itertools.product(partition, [out_path], [log_path], [emulator_name]))

# Convert apk files in in_path to txt files stroed in out_path; store terminal log
# to log_path. This function takes a file containing all apk files' paths as input
def convert_files_alternative(txt_file_with_apk_paths, out_path, log_path, BOOT_IMAGE, sample_count, parallel_count):
    pool = Pool(int(parallel_count))
    samples_with_nl = []
    samples = []
    with open(txt_file_with_apk_paths, 'r') as txt_file:
        samples_with_nl = txt_file.readlines()
    for sample in samples_with_nl:
        samples.append(sample.rstrip('\n'))
    if int(sample_count) != 0:
        samples = samples[:int(sample_count)]
    partitions = list(partition_list(samples, int(parallel_count)))
    for partition in partitions:
        pool.starmap(convert_file, itertools.product(partition, [out_path], [log_path], [BOOT_IMAGE]))

def main():
    if(len(sys.argv)!=7):
        print("Wrong arguments, please check comments in the script for usage")
        sys.exit(1)

    dir_in = sys.argv[1]
    dir_out = sys.argv[2]
    dir_log = sys.argv[3]
    sample_count = int(sys.argv[4])
    parallel_count = int(sys.argv[5])
    emulator_name = sys.argv[6]

    convert_files(dir_in, dir_out, dir_log, emulator_name, sample_count, parallel_count)

if __name__ == '__main__':
    main()