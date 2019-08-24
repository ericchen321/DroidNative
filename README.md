------------------------------------------------
# README file for building and running DroidNative
------------------------------------------------

Authors: 
- Shahid Alam alam_shahid@yahoo.com
- Guanxiong Chen chenguanxiong@alumni.ubc.ca

Malware writers are applying stealthy mutations (obfuscations) to create malware variants, that are difficult to detect statically by current signature based detectors. DroidNative uses specific control flow patterns to reduce the effect of obfuscations, provides automation and platform independence, and unlike other Android anti-malwares, operates at the Android native code level, allowing it to detect malware embedded in both native code and bytecode.

## A very high level overview of DroidNative:

The native (binary) code is disassembled and translated into MAIL (Malware Analysis Intermediate Language) [1] code, which is processed using ACFG (Anotated Control Flow Weight) [2] and SWOD (Sliding Window of Difference) [3] in order to produce a behavioral signature.  Next, the similarity detector uses this signature and detects the presence of malware in the application using the malware templates previously discovered during a training phase. A simple binary classifier (decision tree) is used for this purpose. If the application being analyzed matches a malware template (within a given threshold), then the app is tagged as malware and its signature become part of the malware templates used for further detection. Please read the paper for more details.

DroidNative is written in C/C++ (50,000+ lines of code including comments) and requires perl, GNU make, gcc and g++ (with stdlib) for building. It is build and tested on Windows (cygwin) and Linux (Ubuntu) systems.

DroidNative analyzes samples in either native binary format or disassembled human-readable text format. So you need to preprocess your apk samples first. This documentation explains only using DroidNative analyze preprocessed samples.  

## Directories and files:

- ````bin ````               - DIR:  DroidNative binaries (DroidNative-ACFG, DroidNative-SWOD and DroidNative-Only-MAIL), perl scripts for running them, training models, experiment results

- ```` lib ````               - DIR:  The library required to build and run DroidNative

- ```` source ````             - DIR:  Source of DroidNative
- ```` build.pl ````          - FILE: Perl script to build DroidNative
- ```` Makefile-ACFG ````     - FILE: Makefile for ACFG
- ```` Makefile-SWOD ````      - FILE: Makefile for SWOD
- ```` Makefile-Only-MAIL ```` - FILE: Makefile that produces a binary to generate only MAIL-CFG to be used in other algorithms for malware detection
- ```` README ````            - FILE: This file


## BUILDING:

The build.pl script will build DroidNative binaries in the bin DIR. For our paper since we are only using DroidNative-ACFG, we are not building DroidNative-SWOD.
- Usage:
   ```` 
  perl build.pl
  ````


## RUNNING:

For running DroidNative change to the ````bin```` DIR, then run the ````DroidNative-ACFG.exe```` executable. Our DroidNative-ACFG provides the following running modes:

1. Generating ACFG signature file for one sample
- USAGE:
  ```` 
  ./DroidNative-ACFG.exe 0 <directory to store signatures> <path to compressed oat-txt file (must be in the bin directory)> > <path to signature generation log file>
  ````

- EXAMPLE:
  ```` 
  ./DroidNative-ACFG.exe 0 /nfs/home2/guanxiong/signatures/2018/malware_sig /data/guanxiong/DroidNative/bin/sample_malware.apk.dex.txt.zip > sample_malware.apk.siggen.log
  ````
- NOTE: After program execution a compressed signature file will be produced under the ````bin```` directory. The file contains all CFGs extracted from the given sample. After running the example command you should see the file ````sample_malware.apk.dex.txt.training.dat.ACFG.zip```` being produced. In this directory you should also see ```` sample_malware.apk.siggen.log ```` which contains information on if unzipping was successfull, number of CFGs extracted, etc.

2. Generating ACFG signature file (training model) from multiple malware samples
- USAGE:
  ```` 
  ./DroidNative-ACFG.exe 0 <name of the training model file> <path to text file with list of per sample compressed signatures> <directory where signatures are decompressed to> > <path to training result file> 2><path to timing information file> 
  ````

- EXAMPLE:
  ```` 
  ./DroidNative-ACFG.exe 0 virus_samples.txt.training.dat.ACFG virus_samples.txt sig_temp > training_result.txt 2>training_timing.csv
  ````
- NOTE: In the example above, ```` virus_samples.txt ```` contains a list of signature files generated from each oat-txt sample. Its content looks like this:
  ````
  /nfs/home2/guanxiong/signatures/2018/malware_sig/sample_0.apk.dex.txt.training.dat.ACFG.zip
  /nfs/home2/guanxiong/signatures/2018/malware_sig/sample_1.apk.dex.txt.training.dat.ACFG.zip

  ```` 
  If you want to make this file yourself, make sure each line ends with a new-line character. You should see the training model file, ````virus_samples.txt.training.dat.ACFG```` under ````bin```` DIR after program execution. The directory where signature files are decompressed to, ````sig_temp```` in this example should be created before executing the command. You can pick a different directory though. We need this parameter because if we were running multiple DroidNative-ACFG threads in the same ````bin```` directory without a decompression space for each, and they happened to decompress the same signature file, they would try overwrite each other's decompressed files. The file ````training_result.txt```` contains information of whether each sample's signature file is loaded successfully, number of CFGs loaded from each sample, etc. ```` training_timing.csv ```` lists the time it takes to load CFGs per sample, and the size of each signature file.

3. Testing
- NOTE: Two ways to do testing: a) loading in a pre-existing training model, then test or b) building a training model from multiple samples first, then test. Using b) is not recommended because it does not produce a training model after training is done. So if a testing thread crashes, the training progress would be lost.
  
- USAGE (Method 3a):
  ````
  ./DroidNative-ACFG.exe 0 <threshold> <doesn't matter what you put in here> <path to text file with list of samples' signatures to test> <directory where signatures are decompressed to> <path to training model file> > <path to testing result file> 2><path to timing information file>  
  ````
- EXAMPLE:
  ````
  ./DroidNative-ACFG.exe 0 70 whatever files_to_check.txt sig_temp virus_samples.txt.training.dat.ACFG > testing_results.txt 2>testing_timing.csv
  ````

- NOTE: In the example above, DroidNative-ACFG will load all CFGs from ```` virus_samples.txt.training.dat.ACFG ````, then test CFGs of each sample in ```` files_to_check.txt```` against CFGs loaded from the training sample, and write if the sample is benign/malicious and its similarity score in ````testing_results.txt````. Format of ````files_to_check.txt```` is the same as ````virus_samples.txt```` from the command example in Section 2, except this time the samples listed are to be tested.

For any questions or feedback, please contact chenguanxiong@alumni.ubc.ca.


## MISCELLANOUS:

The following scripts are useful for batch production:

1. ``` move_output_files.sh ``` moves output files from ``` bin/ ```to another folder.
- USAGE:
  ```` 
  ./move_output_files.sh ~/training_set_0_result/ 
  ````

2. ``` remove_output_files.sh ``` deletes all output files from ``` bin/ ```.
- USAGE:
  ``` 
  ./remove_output_files.sh 
  ``` 

3. ``` gen_sig_files.py ``` automates signature generation per sample. Please check the script itself for usage.

## REFERENCES:
[1] MAIL: Malware Analysis Intermediate Language - A Step Towards Automating and Optimizing Malware Detection. In Proceedings of the Sixth ACM International Conference on Security of Information and Networks, SIN 2013.
[2] Sliding Window and Control Flow Weight for Metamorphic Malware Detection. Journal of Computer Virology and Hacking Techniques, Springer Computer Science, 2015.
[3] Annotated Control Flow Graph for Metamorphic Malware Detection. The Computer Journal - Section D: Security in Computer Systems and Networks, 2014.
