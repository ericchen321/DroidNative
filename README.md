------------------------------------------------
# README file for building and running DroidNative
------------------------------------------------

Malware writers are applying stealthy mutations (obfuscations) to create malware variants, that are difficult to detect statically by current signature based detectors. DroidNative uses specific control flow patterns to reduce the effect of obfuscations, provides automation and platform independence, and unlike other Android anti-malwares, operates at the Android native code level, allowing it to detect malware embedded in both native code and bytecode.

## A very high level overview of DroidNative:

The native (binary) code is disassembled and translated into MAIL (Malware Analysis Intermediate Language) [1] code, which is processed using ACFG (Anotated Control Flow Weight) [2] and SWOD (Sliding Window of Difference) [3] in order to produce a behavioral signature.  Next, the similarity detector uses this signature and detects the presence of malware in the application using the malware templates previously discovered during a training phase. A simple binary classifier (decision tree) is used for this purpose. If the application being analyzed matches a malware template (within a given threshold), then the app is tagged as malware and its signature become part of the malware templates used for further detection. Please read the paper for more details.

DroidNative is written in C/C++ (50,000+ lines of code including comments) and requires perl, GNU make, gcc and g++ (with stdlib) for building. It is build and tested on Windows (cygwin) and Linux (Ubuntu) systems.


## Directories and files:

- ````bin ````               - DIR:  DroidNative binaries (DroidNative-ACFG, DroidNative-SWOD and DroidNative-Only-MAIL) and perl scripts for running them
- ```` lib ````               - DIR:  The library required to build and run DroidNative
- ```` run ````               - DIR:  Sub-directories to run DroidNative for different sizes of dataset
- ```` samples ````            - DIR:  Malware and benign samples. These are real malware samples, therefore exclude this DIR from AV scanning for testing
- ```` source ````             - DIR:  Source of DroidNative
- ```` build.pl ````          - FILE: Perl script to build DroidNative
- ```` Makefile-ACFG ````     - FILE: Makefile for ACFG
- ```` Makefile-SWOD ````      - FILE: Makefile for SWOD
- ```` Makefile-Only-MAIL ```` - FILE: Makefile that produces a binary to generate only MAIL-CFG to be used in other algorithms for malware detection
- ```` README ````            - FILE: This file


## BUILDING:

The build.pl script will build DroidNative binaries in the bin DIR.


## RUNNING:

For running DroidNative change to the run DIR and then to the respective sub-DIR, such as dataset-40-40 for running with the dataset of 40 malware and 40 benign samples. Use the following scripts to run the respective binary for n-fold cross validation and building ROC and timings for the respective run.

1. run-cross-validation_ACFG.pl
- USAGE:
```` 
run-cross-validation.pl <max_threads> <n> <file_name_benign_samples> <file_name_malware_samples> <file_name_DroidNative> <build_roc=0/1> <THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING> 
````
build_roc = 0 Just run once
build_roc = 1 Run more than once, from THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING - 100 for building ROC
- EXAMPLE:
```` 
run-cross-validation.pl 1 10 benign_samples.txt malware_samples.txt DroidNative.exe 1 1 
````
- NOTE:
- DroidNative saves the training data to a file ```` <file_name_malware_samples>.training.dat ```` to save time. Next time when it is run with the same file name ```` <file_name_malware_samples> ```` it will try to load the saved training data from the file ```` <file_name_malware_samples>.training.dat ```` and if the file is not present only then it's going to train the data. DroidNative distinguishes the saved training data by the filename. If your training data does not change, then use the same file name that was used when building the training data. But if your training data has changed then you need to use a file with different name.
For the input files, each line must end with the new-line character.

2. run-cross-validation_SWOD.pl
- USAGE:
```` 
run-cross-validation.pl <n> <file_name_benign_samples> <file_name_malware_samples> <file_name_DroidNative> <find_best_value=0/1/2> <VWOD> <HWOD> <VSD> <HSD> 
````
find_best_value = 0 for generating ROC,
find_best_value = 1 for one run,
find_best_value = 2 For finding the best values.
- EXAMPLE:
```` 
run-cross-validation.pl 10 benign_samples.txt malware_samples.txt DroidNative.exe 1 3 50 25 50 
````
- NOTE:
For the input files, each line must end with the new-line character.

3. build-ROC.pl
- USAGE:
```` 
build-ROC.pl <path to result files> <n> <range> 
````

4. getTime.pl
- USAGE:
```` 
getTime.pl <path to result files> <n> <range> 
````

For example, to carry out 5-fold cross validation with the dataset of 40 malware and 40 benign samples using ACFG technique:
````
$ cd run/dataset-40-40
$ run-cross-validation.pl 1 10 benign_samples.txt malware_samples.txt DroidNative-ACFG.exe 1 1 
````

This will create all the output files with results in the current DIR and the folowing commands can be used to build the ROC and get timings from these result files.
````
$ build-ROC.pl ./ 5 1-100
$ getTime.pl ./ 5 1-100
````
For any questions or feedback, please contact alam_shahid@yahoo.com.


## REFERENCES:
[1] MAIL: Malware Analysis Intermediate Language - A Step Towards Automating and Optimizing Malware Detection. In Proceedings of the Sixth ACM International Conference on Security of Information and Networks, SIN 2013.
[2] Sliding Window and Control Flow Weight for Metamorphic Malware Detection. Journal of Computer Virology and Hacking Techniques, Springer Computer Science, 2015.
[3] Annotated Control Flow Graph for Metamorphic Malware Detection. The Computer Journal - Section D: Security in Computer Systems and Networks, 2014.
