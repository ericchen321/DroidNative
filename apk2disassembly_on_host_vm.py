# Author: Guanxiong Chen
#         Ryan Riley
# Requires Python 3.5
# Requires to be run on Ubuntu 14.04/16.04 VM
# Requires aapt and sshpass command runnable
# Requires host machine already in ~/.ssh/known_hosts
# Tested with Android 5.1.1_r4 on Ubuntu 14.04 VM
# Batch-producing ARM disassembly files from apk files. This script was modified based
# on the original shell script from Ryan Riley: https://gist.github.com/rriley/a0b5eb36a093a66e86a8
# Also referenced: https://stackoverflow.com/questions/29291270/threading-in-python-processing-multiple-large-files-concurrently
#                  https://stackoverflow.com/questions/41094707/setting-timeout-when-using-os-system-function
#                  https://stackoverflow.com/questions/5442910/python-multiprocessing-pool-map-for-multiple-arguments
# How to use ART to get ARM disassembly files on-host:
# - Setup before running the script:
# 1. Get source code according to https://source.android.com/source/downloading.html
# 2. (for Android 5.1) Install OpenJDK 1.7 and set up PATH
# 3. Change to source code directory
# 4. (for Ubuntu 16.04) cp /usr/bin/ld.gold prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.11-4.6/x86_64-linux/bin/ld
# 5. source build/envsetup.sh
# 6. mm build-art
# 7. (for Ubuntu 16.04) make update-api
# 8. Build the full android image for aosp_arm-eng
#   (Follow the directions at https://source.android.com/source/building.html)
# 9. Run this script
# - Script usage:
# 1st param: path to text file on host, with paths to apks
# 2nd param: path to host output directory where txts are stored
# 3rd param: path to host output directory where running log files are stored
# 4th param: number of samples to be converted. 0 means all
# 5th param: (deprecated) number of processes to do preprocessing in parallel
# 6th param: path to VM Android directory (example: ~/android_5.1.1_r4)
# 7th param: ip upload address of the host (vm -> host xfer)
# 8th param: ip download address of the host (host -> vm xfer)

import sys
import os
import glob
import subprocess
import re
from itertools import product
import itertools
import base64

# Yield successive n-sized chunks from list
def partition_list(list, n):
    for i in range(0, len(list), n):
        yield list[i:i + n]

# extract SDK version info of given apk file
def extract_sdk_version(apk_name):
    error_log_file = open('conversion_error.log', "a+")
    # run aapt
    aapt_results = subprocess.run('aapt list -a ' + apk_name + ' | grep "SdkVersion"', stdout = subprocess.PIPE, shell = True).stdout.decode()
    # search minSdkVersion
    search_min_sdk = re.search(r'(minSdkVersion.+=\(type.+\))(.+)', aapt_results)
    if search_min_sdk:
        error_log_file.write('minSdkVersion is ' + str(int(search_min_sdk.group(2), 0)) + '\n')
        print('minSdkVersion is ' + str(int(search_min_sdk.group(2), 0)))
    search_target_sdk = re.search(r'(targetSdkVersion.+=\(type.+\))(.+)', aapt_results)
    if search_target_sdk:
        error_log_file.write('targetSdkVersion is ' + str(int(search_target_sdk.group(2), 0)) + '\n')
        print('targetSdkVersion is ' + str(int(search_target_sdk.group(2), 0)))
    search_max_sdk = re.search(r'(maxSdkVersion.+=\(type.+\))(.+)', aapt_results)
    if search_max_sdk:
        error_log_file.write('maxSdkVersion is ' + str(int(search_max_sdk.group(2), 0)) + '\n')
        print('maxSdkVersion is ' + str(int(search_max_sdk.group(2), 0)))
    error_log_file.close()

# identify given apk's verification errors and lock errors from 
# dex2oat and oatdump's terminal message. Returns 1 if got any errors
def identify_errors(apk_path):
    apk_name = os.path.basename(apk_path)
    log_file_dex2oat = open(apk_name + '.dex2oat.log', 'r')
    error_log_file = open('conversion_error.log', "a+")
    verification_error = False
    lock_verification_error = False
    oat_file_gen_error = False

    # search only first 100 lines
    line_count = 0
    for line in log_file_dex2oat.readlines():
        if (not verification_error) and re.search('verification error', line, re.IGNORECASE):
            error_log_file.write("File " + apk_path + " got verification error" + "\n")
            print("File " + apk_path + " got verification error")
            verification_error = True
        if (not lock_verification_error) and re.search('failed lock verification', line, re.IGNORECASE):
            error_log_file.write("File " + apk_path + " got lock verification error" + "\n")
            print("File " + apk_path + " got lock verification error")
            lock_verification_error = True
        if (not oat_file_gen_error) and re.search('Failed to open', line, re.IGNORECASE):
            error_log_file.write("File " + apk_path + " failed to have its oat and txt file produced" + "\n")
            print("File " + apk_path + " failed to have its oat and txt file produced")
            oat_file_gen_error = True
        line_count += 1
        if line_count >= 100:
            break
    log_file_dex2oat.close()
    error_log_file.close()

    return (verification_error or lock_verification_error or oat_file_gen_error)

# Requires apk_path being './<apk filename>'
# Convert given apk file to txt file stored in out_path; store
# terminal log to <apk_name>.dex2oat.log and <apk name>.oatdump.log
# under log_path; generate error messages if errors occured during
# conversion; print out SDK version info of apk with conversion error
def convert_file(apk_path, out_path, log_path, BOOT_IMAGE, ip_host_up):
    apk_name = os.path.basename(apk_path)

    log_file_dex2oat = open(apk_name + '.dex2oat.log', 'w')
    log_file_oatdump = open(apk_name + '.oatdump.log', 'w')
    log_file_compression = open(apk_name + '.compression.log', 'w')
    subprocess.run("out/host/linux-x86/bin/dex2oat --runtime-arg -classpath --runtime-arg " + apk_name + " --instruction-set=arm " + "--runtime-arg " + "-Xrelocate " + "--host " + "--boot-image=" + BOOT_IMAGE + " --dex-file=" + apk_name + " --oat-file=" + apk_name + ".dex", stdout=log_file_dex2oat, stderr=log_file_dex2oat, universal_newlines=True, shell=True)
    subprocess.run("out/host/linux-x86/bin/oatdump --oat-file=" + apk_name + ".dex" + " --instruction-set=arm" + " --output=" + apk_name + ".dex" + ".txt", stdout=log_file_oatdump, stderr=log_file_oatdump, universal_newlines=True, shell=True)
    subprocess.run('zip ' + apk_name + '.dex.txt.zip ' + apk_name + '.dex.txt', stdout=log_file_compression, stderr=log_file_compression, shell=True)
    log_file_dex2oat.close()
    log_file_oatdump.close()
    log_file_compression.close()
    if identify_errors(apk_path):
        extract_sdk_version(apk_name)

    print("Uploading zip file and log files from vm to host...")
    # copy zip file, three error log files
    subprocess.run('sshpass -p "hooBUFF3!" scp ' + apk_name + '.dex.txt.zip ' + 'i0y0b@' + ip_host_up + ':' + out_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    subprocess.run('sshpass -p "hooBUFF3!" scp ' + apk_name + '.compression.log ' + 'i0y0b@' + ip_host_up + ':' + log_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    subprocess.run('sshpass -p "hooBUFF3!" scp ' + apk_name + '.dex2oat.log ' + 'i0y0b@' + ip_host_up + ':' + log_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    subprocess.run('sshpass -p "hooBUFF3!" scp ' + apk_name + '.oatdump.log ' + 'i0y0b@' + ip_host_up + ':' + log_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    print("Uploading zip file and log files done.")

    # remove temp files
    os.system("rm " + apk_name)
    os.system("rm " + apk_name + ".dex")
    os.system('rm ' + apk_name + '.dex.txt')
    os.system('rm ' + apk_name + '.dex.txt.zip')
    os.system('rm ' + apk_name + '.compression.log')
    os.system('rm ' + apk_name + '.dex2oat.log')
    os.system('rm ' + apk_name + '.oatdump.log')

# Convert apk files listed in txt_file to txt files stroed in out_path; store terminal log
# to log_path
def convert_files(txt_file_with_apk_paths, out_path, log_path, BOOT_IMAGE, sample_count, ip_host_up, ip_host_down):
    samples_with_nl = []
    samples = []
    with open(txt_file_with_apk_paths, 'r') as txt_file:
        samples_with_nl = txt_file.readlines()
    for sample in samples_with_nl:
        samples.append(sample.rstrip('\n'))

    for apk_path_on_host in samples:
        # copy remote apk file to current directory
        print("Downloading apk sample from host: " + apk_path_on_host)
        subprocess.run('sshpass -p "hooBUFF3!" scp ' + 'i0y0b@' + ip_host_down + ':' + apk_path_on_host + ' ./', stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
        apk_name = os.path.basename(apk_path_on_host)
        print("Downloading completed. Starting conversion...")
        convert_file('./'+apk_name, out_path, log_path, BOOT_IMAGE, ip_host_up)
        print("Conversion and vm->host uploading completed.")
    
    # copy conversion_error.log to host, then delete it
    print("Uploading conversion_error.log to host...")
    subprocess.run('sshpass -p "hooBUFF3!" scp ' + 'conversion_error.log ' + 'i0y0b@' + ip_host_up + ':' + log_path, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)
    os.system('rm conversion_error.log')
    print("conversion_error.log uploading completed.")

def main():
    if(len(sys.argv)!=9):
        print("Wrong arguments, please check comments in the script for usage")
        sys.exit(1)

    path_to_samples_txt = sys.argv[1]
    dir_out = sys.argv[2]
    dir_log = sys.argv[3]
    sample_count = int(sys.argv[4])
    parallel_count = int(sys.argv[5])
    AOSP_DIR = sys.argv[6]
    ip_host_up = sys.argv[7]
    ip_host_down = sys.argv[8]

    ANDROID_DATA = AOSP_DIR + "/out/host/datadir/dalvik-cache/x86_64"
    ANDROID_ROOT = AOSP_DIR + "/out/host/linux-x86"
    BOOT_IMAGE = AOSP_DIR + "/out/target/product/generic/system/framework/boot.art"
    os.environ["ANDROID_DATA"] = ANDROID_DATA
    os.environ["ANDROID_ROOT"] = ANDROID_ROOT
    os.system("mkdir -p " + ANDROID_DATA)
    os.chdir(AOSP_DIR)
    convert_files(path_to_samples_txt, dir_out, dir_log, BOOT_IMAGE, sample_count, ip_host_up, ip_host_down)

if __name__ == '__main__':
    main()