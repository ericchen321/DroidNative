#!/bin/bash
# extract features of 2017 and 2019 malware samples
python3 gen_sig_files.py /nfs/home2/guanxiong/disassembly/malware/2017_txt /nfs/home2/guanxiong/disassembly/malware/2017_sig /nfs/home2/guanxiong/disassembly/malware/2017_log /data/guanxiong/DroidNative/bin 20 /data/guanxiong/DroidNative/excluded_malware_2017.txt
python3 gen_sig_files.py /nfs/home2/guanxiong/disassembly/malware/2019_txt /nfs/home2/guanxiong/disassembly/malware/2019_sig /nfs/home2/guanxiong/disassembly/malware/2019_log /data/guanxiong/DroidNative/bin 20
# extract features of 2017 and 2019 benign samples
python3 gen_sig_files.py /nfs/home2/guanxiong/disassembly/benign/2017_txt /nfs/home2/guanxiong/disassembly/benign/2017_sig /nfs/home2/guanxiong/disassembly/benign/2017_log /data/guanxiong/DroidNative/bin 20
python3 gen_sig_files.py /nfs/home2/guanxiong/disassembly/benign/2019_txt /nfs/home2/guanxiong/disassembly/benign/2019_sig /nfs/home2/guanxiong/disassembly/benign/2019_log /data/guanxiong/DroidNative/bin 20