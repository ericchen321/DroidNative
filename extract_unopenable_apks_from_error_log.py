# Usage:
# first param: error log file
# 2nd param: path to look for apks
# 3rd param: output txt file with path to apks with errors

import sys
import os

log_file_path = sys.argv[1]
dir_in = sys.argv[2]
out_txt_path = sys.argv[3]

log_file = open(log_file_path, 'r')
failed_apk_names = []
for line in log_file:
    if "failed to have its oat and txt file produced" in line:
        words = line.split()
        for word in words:
            if "apk" in word:
                apk_name = os.path.basename(word)
                failed_apk_names.append(apk_name)
log_file.close()

out_file = open(out_txt_path, 'w')
for failed_apk_name in failed_apk_names:
    out_file.write(dir_in + '/' + failed_apk_name + '\n')
out_file.close()