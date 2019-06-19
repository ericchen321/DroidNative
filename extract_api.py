# Script to extract API Level of apk samples
# Author: Guanxiong Chen
#         Junbin Zhang
# Usage: 
# 1st param: path to directory where apk samples are stored
# 2nd param: path to file where file-minSdk-targetSdk table is to be stored
# 3rd param: path to file where target api-count table is to be stored
# 4th param: path to file where min api-count table is to be stored

import sys
import glob
import os
import subprocess
import re

source_dir = sys.argv[1]
result_file_path = sys.argv[2]
target_stat_file_path = sys.argv[3]
min_stat_file_path = sys.argv[4]

samples = glob.glob(os.path.join(source_dir, '*.apk'))
min_sdk_hist = []
target_sdk_hist = []

with open(result_file_path, "w") as result_file:
    result_file.write('apk Path, minSdkVersion, targetSdkVersion\n')
    for filename in samples:
        log_results = filename + ','
        # run aapt
        aapt_results = subprocess.run('aapt list -a ' + filename + ' | grep "SdkVersion"', stdout = subprocess.PIPE, shell = True).stdout.decode()
        # search minSdkVersion
        search_min_sdk = re.search(r'(minSdkVersion.+=\(type.+\))(.+)', aapt_results)
        if search_min_sdk:
            log_results += str(int(search_min_sdk.group(2), 0)) + ","
            min_sdk_ver = int(str(int(search_min_sdk.group(2), 0)))
            has_entry = False
            for entry in min_sdk_hist:
                if entry.get('api') == min_sdk_ver:
                    entry['count'] = entry.get('count') + 1
                    has_entry = True
            if not has_entry:
                min_sdk_entry = {'api': min_sdk_ver, 'count': int(1)}
                min_sdk_hist.append(min_sdk_entry) 
        else:
            log_results += ", "
        # search targetSdkVersion
        search_target_sdk = re.search(r'(targetSdkVersion.+=\(type.+\))(.+)', aapt_results)
        if search_target_sdk:
            log_results += str(int(search_target_sdk.group(2), 0)) + ","
            target_sdk_ver = int(str(int(search_target_sdk.group(2), 0)))
            has_entry = False
            for entry in target_sdk_hist:
                if entry.get('api') == target_sdk_ver:
                    entry['count'] = entry.get('count') + 1
                    has_entry = True
            if not has_entry:
                target_sdk_entry = {'api': target_sdk_ver, 'count': int(1)}
                target_sdk_hist.append(target_sdk_entry) 
        else:
            log_results += ","
        result_file.write(log_results + '\n')

target_sdk_hist = sorted(target_sdk_hist, key = lambda i: i['api'])
min_sdk_hist = sorted(min_sdk_hist, key = lambda i: i['api'])

with open(target_stat_file_path, "w") as target_stat_file:
    target_stat_file.write('Target API Level, Count\n')
    for entry in target_sdk_hist:
        target_stat_file.write(str(entry.get('api')) + ',' + str(entry.get('count')) + '\n')

with open(min_stat_file_path, "w") as min_stat_file:
    min_stat_file.write('Min API Level, Count\n')
    for entry in min_sdk_hist:
        min_stat_file.write(str(entry.get('api')) + ',' + str(entry.get('count')) + '\n')
