# Python 3 script to parse given .csv file that describes experiment setups,
# then convert given apk files to txt format, then prepare the following
# files for DroidNative:
#   malware_samples.txt                         (all malware samples from all folds)
#   benign_samples.txt                          (all benign samples from all folds)
#   malware_samples_<partition_index>           (all malware samples in a fold)
#   malware_samples_<partition_index>.txt       (all malware samples not in a fold)
#   virus_samples_<partition_index>.txt         (identical to malware_sample_<partition_index>.txt)
#   benign_samples_<partition_index>            (all benign samples in a fold)
#   benign_samples_<partition_index>.txt        (all benign samples not in a fold)
#   files_to_check_<partition_index>.txt        (malware_samples_<partition_index> Union benign_samples_<partition_index>)
# Requires Python 3.5
# Usage:
#   first param: path to .csv file
#   2nd param:   path to directory where txt files will be stored
#   3rd param:   path to output directory where running log files are stored
#   4th param:   path to Android directory (example: /data/guanxiong/android_source_7)

import csv
import sys
import os
import apk2disassembly_on_host

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

def main():
    if len(sys.argv) != 5:
        print("Wrong arguments, please check comments in the script for usage")
        sys.exit(1)
    csv_path = sys.argv[1]
    dir_out_disassembly = sys.argv[2]
    dir_out_log = sys.argv[3]
    AOSP_DIR = sys.argv[4]
    dir_droidnative_bin = os.getcwd() + '/bin'

    # get experiment setup info
    folds_benign_test = []
    folds_malware_test = []
    folds_benign_train = []
    folds_malware_train = []
    parse_setup_file(csv_path, folds_benign_test, folds_malware_test, folds_benign_train, folds_malware_train)
    num_fold = len(list(folds_benign_test))

    # set up ART env vars
    ANDROID_DATA = AOSP_DIR + "/out/host/datadir/dalvik-cache/x86_64"
    ANDROID_ROOT = AOSP_DIR + "/out/host/linux-x86"
    BOOT_IMAGE = AOSP_DIR + "/out/target/product/generic/system/framework/boot.art"
    os.environ["ANDROID_DATA"] = ANDROID_DATA
    os.environ["ANDROID_ROOT"] = ANDROID_ROOT
    os.system("mkdir -p " + ANDROID_DATA)
    os.chdir(AOSP_DIR)

    # apk to disassembly conversion
    fold_count = 0
    for fold_count in range(0, num_fold):
        apk2disassembly_on_host.convert_files_alternative(folds_benign_test[fold_count], dir_out_disassembly, dir_out_log, BOOT_IMAGE, 0)
        apk2disassembly_on_host.convert_files_alternative(folds_malware_test[fold_count], dir_out_disassembly, dir_out_log, BOOT_IMAGE, 0)

if __name__ == "__main__":
    main()
