# Author: Guanxiong Chen
#         Ryan Riley
# Requires Python 3.5
# Requires to be run on Zeus
# Tested with Android 5.1.1_r4 and Android 7
# Batch-producing ARM disassembly files from apk files. This script was modified based
# on the original shell script from Ryan Riley: https://gist.github.com/rriley/a0b5eb36a093a66e86a8
# Also referenced: https://stackoverflow.com/questions/29291270/threading-in-python-processing-multiple-large-files-concurrently
#                  https://stackoverflow.com/questions/41094707/setting-timeout-when-using-os-system-function
#                  https://stackoverflow.com/questions/5442910/python-multiprocessing-pool-map-for-multiple-arguments
# How to use ART to get ARM disassembly files on-host:
# - Setup before running the script:
# 1. Get source code according to https://source.android.com/source/downloading.html
# 2. Install OpenJDK 1.7 and set up PATH (required for using Android 5.1)
# 3. Change to source code directory
# 4. cp /usr/bin/ld.gold prebuilts/gcc/linux-x86/host/x86_64-linux-glibc2.11-4.6/x86_64-linux/bin/ld
# 5. source build/envsetup.sh
# 6. mm build-art
# 7. make update-api
# 8. Build the full android image for aosp_arm-eng
#   (Follow the directions at https://source.android.com/source/building.html)
# 9. Run this script
# - Script usage:
# first param: path to directory where apks are stored
# 2nd param: path to output directory where txts are stored
# 3rd param: path to output directory where running log files are stored
# 4th param (optional): path to Android directory (example: /data/guanxiong/android_source). If not provided then use Android 7 build

import sys
import os
import glob
import subprocess
import re
from multiprocessing import Pool
from itertools import product
import itertools

AOSP_DIR = None
ANDROID_DATA = None
ANDROID_ROOT = None
BOOT_IMAGE = None

# Yield successive n-sized chunks from list
def partition_list(list, n):
    for i in range(0, len(list), n):
        yield list[i:i + n]

# extract SDK version info of given apk file
def extract_sdk_version(apk_name):
    versionInfo = None
    subprocess.run("aapt dump badging " + apk_name + " | grep sdkVersion", stdout=versionInfo, universal_newlines=True, shell=True)
    if versionInfo is not None:
        print("    " + apk_name + versionInfo)
    subprocess.run("aapt dump badging " + apk_name + " | grep minSdkVersion", stdout=versionInfo, universal_newlines=True, shell=True)
    if versionInfo is not None:
        print("    " + apk_name + versionInfo)
    subprocess.run("aapt dump badging " + apk_name + " | grep targetSdkVersion", stdout=versionInfo, universal_newlines=True, shell=True)
    if versionInfo is not None:
        print("    " + apk_name + versionInfo)

# identify given apk's verification errors and lock errors from 
# dex2oat and oatdump's terminal message. Returns 1 if got any errors
def identify_errors(apk_path, log_path):
    apk_name = os.path.basename(apk_path)
    log_file_dex2oat = open(log_path + '/' + apk_name + '.dex2oat.log', 'r')
    log_file_oatdump = open(log_path + '/' + apk_name + '.oatdump.log', 'r')
    error = 0

    # search only first 100 lines
    line_count = 0
    for line in log_file_dex2oat.readlines():
        if re.search('verification error', line, re.IGNORECASE):
            print("File " + apk_path + " got verification error")
            error = 1
            break
        line_count += 1
        if line_count >= 100:
            break
    line_count = 0
    for line in log_file_dex2oat.readlines():
        if re.search('lock', line, re.IGNORECASE):
            print("File " + apk_path + " got lock error")
            error = 1
            break
        line_count += 1
        if line_count >= 100:
            break
    line_count = 0
    for line in log_file_oatdump.readlines():
        if re.search('too short', line, re.IGNORECASE):
            print("File " + apk_path + " failed to have its oat and txt file produced")
            error = 1
            break
        line_count += 1
        if line_count >= 100:
            break
    return error

# Convert given apk file to txt file stored in out_path; store
# terminal log to <apk_name>.dex2oat.log and <apk name>.oatdump.log
# under log_path; generate error messages if errors occured during
# conversion; print out SDK version info of apk with conversion error
def convert_file(apk_path, out_path, log_path):
    apk_name = os.path.basename(apk_path)
    os.system("cp " + apk_path + " ./" + apk_name)

    log_file_dex2oat = open(log_path + '/' + apk_name + '.dex2oat.log', 'w')
    log_file_oatdump = open(log_path + '/' + apk_name + '.oatdump.log', 'w')
    subprocess.run("out/host/linux-x86/bin/dex2oat --runtime-arg -classpath --runtime-arg " + apk_name + " --instruction-set=arm " + "--runtime-arg " + "-Xrelocate " + "--host " + "--boot-image=" + BOOT_IMAGE + " --dex-file=" + apk_name + " --oat-file=" + apk_name + ".dex", stdout=log_file_dex2oat, stderr=log_file_dex2oat, universal_newlines=True, shell=True)
    subprocess.run("out/host/linux-x86/bin/oatdump --oat-file=" + apk_name + ".dex" + " --instruction-set=arm" + " --output=" + out_path + "/" + apk_name + ".dex" + ".txt", stdout=log_file_oatdump, stderr=log_file_oatdump, universal_newlines=True, shell=True)
    log_file_dex2oat.close()
    log_file_oatdump.close()
    if identify_errors(apk_path, log_path):
        extract_sdk_version(apk_name)
    os.system("rm " + apk_name)
    os.system("rm " + apk_name + ".dex")

# Convert apk files in in_path to txt files stroed in out_path; store terminal log
# to log_path
def convert_files(in_path, out_path, log_path):
    parallel_count = 10
    pool = Pool(parallel_count)
    samples = glob.glob(in_path + "/*.apk")
    partitions = list(partition_list(samples, parallel_count))
    for partition in partitions:
        pool.starmap(convert_file, itertools.product(partition, [out_path], [log_path]))

if(len(sys.argv)!=4 and len(sys.argv)!=5):
	print("Wrong arguments, please check comments in the script for usage")
	sys.exit(1)

dir_in = sys.argv[1]
dir_out = sys.argv[2]
dir_log = sys.argv[3]
if(len(sys.argv)==5):
    AOSP_DIR = sys.argv[4]
else:
    AOSP_DIR = "/data/guanxiong/android_source_7" # by default uses Android 7

ANDROID_DATA = AOSP_DIR + "/out/host/datadir/dalvik-cache/x86_64"
ANDROID_ROOT = AOSP_DIR + "/out/host/linux-x86"
BOOT_IMAGE = AOSP_DIR + "/out/target/product/generic/system/framework/boot.art"
os.environ["ANDROID_DATA"] = ANDROID_DATA
os.environ["ANDROID_ROOT"] = ANDROID_ROOT
os.system("mkdir -p " + ANDROID_DATA)
os.chdir(AOSP_DIR)
convert_files(dir_in, dir_out, dir_log)