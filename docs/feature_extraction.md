------------------------------------------------
# README file for using DroidNative to Extract Features from APK Samples
------------------------------------------------

Author:
- Guanxiong Chen chenguanxiong@alumni.ubc.ca

This documentation explains where our already-produced signatures files are stored, and procedure to produce signature files.

## ALREADY-PRODUCED SIGNATURE FILES (Updated by Aug 23, 2019)

The signature file for each sample from our datasets is under ``` /nfs/home2/guanxiong/signatures ``` which you can access from Zeus or Galileo. Within the subdirectory for each year, ``` benign_sig ``` contains all benign signatures from ANdroZoo; ``` malware_sig ``` contains all malware signatures from VirusTotal; ``` gp_internal_sig ``` and ``` gp_additional_15_sig ``` contains signatures from Google Play malware 2018/2019 dataset, and the signatures of the additional 15 samples Michael updated on Aug 18, respectively.  

For the DroidNative experiments, we also have put signatures from the testing dataset in ``` az_experiments ``` (from AndroZoo) and ``` gp_experiments ``` (from Google Play).

## PROCEDURE TO PRODUCE SIGNATURE FILES

Unlike training and testing, DroidNative's feature extraction does not require VM. To batch-produce signature files, run script ``` gen_sig_files.py ```. Instructions on how to use the script is in the script itself. To produce the signature file for a specific sample, please read Section 1 under "Running" in the README file for building and running DroidNative.