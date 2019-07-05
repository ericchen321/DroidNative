#!/bin/bash
# feature-extract 2016 and 2018 malware samples
python3 gen_sig_files.py /nfs/home2/guanxiong/disassembly/malware/2016_txt /nfs/home2/guanxiong/disassembly/malware/2016_sig /nfs/home2/guanxiong/disassembly/malware/2016_log /data/guanxiong/DroidNative/bin 20 /data/guanxiong/DroidNative/excluded_malware_2016.txt
python3 gen_sig_files.py /nfs/home2/guanxiong/disassembly/malware/2018_txt /nfs/home2/guanxiong/disassembly/malware/2018_sig /nfs/home2/guanxiong/disassembly/malware/2018_log /data/guanxiong/DroidNative/bin 20 /data/guanxiong/DroidNative/excluded_malware_2018.txt 
# feature-extract 2016 and 2018 benign samples
python3 gen_sig_files.py /nfs/home2/guanxiong/disassembly/benign/2016_txt /nfs/home2/guanxiong/disassembly/benign/2016_sig /nfs/home2/guanxiong/disassembly/benign/2016_log /data/guanxiong/DroidNative/bin 20
python3 gen_sig_files.py /nfs/home2/guanxiong/disassembly/benign/2018_txt /nfs/home2/guanxiong/disassembly/benign/2018_sig /nfs/home2/guanxiong/disassembly/benign/2018_log /data/guanxiong/DroidNative/bin 20
