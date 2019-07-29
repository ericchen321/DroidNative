import os

dir_droidnative_bin = os.getcwd() + '/bin'

mock_11_apk_path_benign_test = '/data/guanxiong/mock_11_all_data/apk_benign_test'
mock_11_txt_path_benign_test = '/data/guanxiong/mock_11_all_data/txt_benign_test'
os.system('mkdir -p ' + mock_11_apk_path_benign_test)
os.system('mkdir -p ' + mock_11_txt_path_benign_test)
benign_test_sigs_file = open(dir_droidnative_bin + '/files_to_check_01.txt', 'r')
for zipped_sig_file in benign_test_sigs_file:
    apk_name = os.path.basename(zipped_sig_file.rstrip('.dex.txt.training.dat.ACFG.zip\n'))
    apk_path = '/nfs/home/DatasetsForTools/DatasetsForTools/GeneralBenign/2017/' + apk_name
    os.system('cp ' + apk_path + ' ' + mock_11_apk_path_benign_test + '/' + apk_name)
    os.system('unzip -j /nfs/home2/guanxiong/disassembly/2017/benign_txt/' + apk_name + '.dex.txt.zip -d ' + mock_11_txt_path_benign_test)
benign_test_sigs_file.close()

mock_11_apk_path_malware_test = '/data/guanxiong/mock_11_all_data/apk_malware_test'
mock_11_txt_path_malware_test = '/data/guanxiong/mock_11_all_data/txt_malware_test'
os.system('mkdir -p ' + mock_11_apk_path_malware_test)
os.system('mkdir -p ' + mock_11_txt_path_malware_test)
malware_test_sigs_file = open(dir_droidnative_bin + '/files_to_check_00.txt', 'r')
for zipped_sig_file in malware_test_sigs_file:
    apk_name = os.path.basename(zipped_sig_file.rstrip('.dex.txt.training.dat.ACFG.zip\n'))
    apk_path = '/nfs/home/DatasetsForTools/DatasetsForTools/GeneralMalware/2017/' + apk_name
    os.system('cp ' + apk_path + ' ' + mock_11_apk_path_malware_test + '/' + apk_name)
    os.system('unzip -j /nfs/home2/guanxiong/disassembly/2017/malware_txt/' + apk_name + '.dex.txt.zip -d ' + mock_11_txt_path_malware_test)
malware_test_sigs_file.close()

mock_11_apk_path_malware_train = '/data/guanxiong/mock_11_all_data/apk_malware_train'
mock_11_txt_path_malware_train = '/data/guanxiong/mock_11_all_data/txt_malware_train'
os.system('mkdir -p ' + mock_11_apk_path_malware_train)
os.system('mkdir -p ' + mock_11_txt_path_malware_train)
malware_train_sigs_file = open(dir_droidnative_bin + '/virus_samples_00.txt', 'r')
for zipped_sig_file in malware_train_sigs_file:
    apk_name = os.path.basename(zipped_sig_file.rstrip('.dex.txt.training.dat.ACFG.zip\n'))
    apk_path = '/nfs/home/DatasetsForTools/DatasetsForTools/GeneralMalware/2016/' + apk_name
    os.system('cp ' + apk_path + ' ' + mock_11_apk_path_malware_train + '/' + apk_name)
    os.system('unzip -j /nfs/home2/guanxiong/disassembly/2016/malware_txt/' + apk_name + '.dex.txt.zip -d ' + mock_11_txt_path_malware_train)
malware_train_sigs_file.close()
