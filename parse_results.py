# Usage:
# 1st param: path to result file
# 2nd param: path to parsed csv result file path
# 3rd param: if all samples are benign, then True, otherwise False

import sys

result_file_path = sys.argv[1]
parsed_result_file_path = sys.argv[2]
are_all_benign = sys.argv[3]

parsed_result_file = open(parsed_result_file_path, 'w')
result_file = open(result_file_path, 'r')
sample_count = 0
malware_count = 0
for line in result_file:
    if (('File /nfs/home2/guanxiong/signatures' in line) or ('File /home/ubuntu/i0y0b/signatures' in line) or ('File ~/signatures' in line)):
        sample_count += 1
        if ('is/contain malware' in line):
            malware_count += 1
        
result_file.close()

print("Result file analyzed: " + result_file_path)
print("Total sample count: " + str(sample_count))
benign_count = sample_count - malware_count
print("Samples classified as benign: " + str(benign_count))
print("Samples classified as malware: " + str(malware_count))
if are_all_benign == 'True':
    print("As user defined, all samples are benign. So set target class: Benign")
else:
    print("As user defined, all samples are malware. So set target class: Malware")
    m_tpr = float(malware_count) / sample_count
    m_fnr = float(benign_count) / sample_count
    m_recall = float(malware_count) / sample_count
    print("M_Recall: " + str(m_recall))