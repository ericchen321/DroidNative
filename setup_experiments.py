# Python 3 script to parse given .csv file that describes experiment setups,
# then convert given apk files to txt format, then prepare the following
# files for DroidNative:
#   malware_samples.txt                         (all malware samples from all folds)
#   benign_samples.txt                          (all benign samples from all folds)
#   malware_samples_<partition_index>           (all malware samples in a fold)
#   malware_samples_<partition_index>.txt       (all malware samples not in a fold) TODO
#   virus_samples_<partition_index>.txt         (identical to malware_sample_<partition_index>.txt)
#   benign_samples_<partition_index>            (all benign samples in a fold)
#   benign_samples_<partition_index>.txt        (all benign samples not in a fold) TODO
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

# generate list of samples for each fold
# @param folds_test: list of paths to txt files that store testing/training samples' paths
# @param dir_droidnative_bin: path to DroidNative/bin
# @param dir_out_disassembly: path to disassembly file directory
# @param prefix: prefix to generated file. 
#                Usually like 'malware_samples' or 'benign_samples'
# @param extension: like .txt or empty string
def gen_list_of_txt_samples(folds, dir_droidnative_bin, dir_out_disassembly, prefix, extension):
    num_fold = len(folds)
    for fold_count in range(int(0), num_fold):
        fold_i = folds[fold_count]
        samples_i = prefix + "_" + ("%02d" % fold_count)
        if extension != "":
            samples_i += ("." + extension)
        os.system("touch " + dir_droidnative_bin + "/" + samples_i)
        samples_i_file = open(dir_droidnative_bin + "/" + samples_i, 'w')
        fold_benign_test_i_file = open(fold_i, 'r')
        for line in fold_benign_test_i_file:
            apk_path = line.rstrip('\n')
            apk_name = os.path.basename(apk_path)
            txt_path = dir_out_disassembly + '/' + apk_name + '.dex.txt'
            samples_i_file.write(txt_path + '\n')
        samples_i_file.close()

# combine <malware/benign>_samples_<partition_index> of all indicies
# into one file; prefix is usually 'benign_samples' or 'malware_samples'
def combine_samples(num_fold, dir_droidnative_bin, prefix):
    samples_file_path = dir_droidnative_bin + "/" + prefix + '.txt'
    os.system("touch " + samples_file_path)
    for fold_count in range(0, num_fold):
        os.system("cat " + dir_droidnative_bin + ("/" + prefix + ("_%02d" % fold_count)) + " >> " + samples_file_path)

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
    for fold_count in range(int(0), num_fold):
        apk2disassembly_on_host.convert_files_alternative(folds_benign_test[fold_count], dir_out_disassembly, dir_out_log, BOOT_IMAGE, 0)
        apk2disassembly_on_host.convert_files_alternative(folds_malware_test[fold_count], dir_out_disassembly, dir_out_log, BOOT_IMAGE, 0)

    # generate benign_samples_<partition_index> and malware_samples_<partition_index>
    gen_list_of_txt_samples(folds_benign_test, dir_droidnative_bin, dir_out_disassembly, 'benign_samples', '')
    gen_list_of_txt_samples(folds_malware_test, dir_droidnative_bin, dir_out_disassembly, 'malware_samples', '')

    # generate benign_samples.txt and malware_samples.txt
    combine_samples(num_fold, dir_droidnative_bin, 'benign_samples')
    combine_samples(num_fold, dir_droidnative_bin, 'malware_samples')

    # generate virus_samples_<partition_index>.txt
    for fold_count in range(int(0), num_fold):
        gen_list_of_txt_samples(folds_malware_train, dir_droidnative_bin, dir_out_disassembly, 'virus_samples', 'txt')

    # generate files_to_check_<partition_index>.txt
    for fold_count in range(int(0), num_fold):
        file_to_check_i_path = dir_droidnative_bin + "/files_to_check_" + ("%02d" % fold_count) + ".txt"
        os.system("touch " + file_to_check_i_path)
        os.system("cat " + dir_droidnative_bin + "/malware_samples_" + ("%02d" % fold_count) + " >> " + file_to_check_i_path)
        os.system("cat " + dir_droidnative_bin + "/benign_samples_" + ("%02d" % fold_count) + " >> " + file_to_check_i_path)

if __name__ == "__main__":
    main()
