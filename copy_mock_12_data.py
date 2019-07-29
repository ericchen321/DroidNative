import os

training = open('bin/virus_samples_00.txt', 'r')
for line in training:
    zipped_sig_path = line.rstrip('\n')
    os.system('sshpass -p "hooBUFF3!" scp ' + zipped_sig_path + " ubuntu@192.168.122.182:~/mock_11_sigs/malware")
training.close()

testing_malware = open('bin/files_to_check_00.txt', 'r')
for line in testing_malware:
    zipped_sig_path = line.rstrip('\n')
    os.system('sshpass -p "hooBUFF3!" scp ' + zipped_sig_path + " ubuntu@192.168.122.182:~/mock_11_sigs/malware")
testing_malware.close()

testing_benign = open('bin/files_to_check_01.txt', 'r')
for line in testing_benign:
    zipped_sig_path = line.rstrip('\n')
    os.system('sshpass -p "hooBUFF3!" scp ' + zipped_sig_path + " ubuntu@192.168.122.182:~/mock_11_sigs/benign")
testing_benign.close()