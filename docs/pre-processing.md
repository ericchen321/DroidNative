------------------------------------------------
# README file for pre-processing APK samples 
------------------------------------------------

Author:
- Guanxiong Chen chenguanxiong@alumni.ubc.ca

DroidNative does not process apk samples directly; instead it requires ART (Android Runtime) to convert dex files in an apk sample to a single oat-txt file first, then build signatures of the sample using the oat-txt file. This document explains how to convert apk samples to oat-txt format on our servers.

ART is part of an Android Operation System, so you can use ART by either running an Android emulator (on-device), or building Android from source (on-host). Either way, the conversion process is divided into two steps: 1. using ART tool ```` dex2oat ```` to convert an apk sample to non-human-readable oat file; 2. using ART tool ```` oatdump ```` to convert the output file from the previous step to a human-readable text file.

From a script provided by Ryan Riley, one of DroidNative's authors (https://gist.github.com/rriley/a0b5eb36a093a66e86a8) and a post by the same person (https://groups.google.com/forum/#!msg/android-platform/NpD_OZ-dCZk/e8Izo2k4CAAJ), we found two things:
- They used the on-host option for batch production;
- They used ART in Android 5.1.1_r4 to convert their samples
  
So we also used the on-host option with Android 5.1.1_r4 for preprocessing.

This documentation explains where our already-produced oat-txt files are produced, and procedure to produce oat-txt files.

## ALREADY-PRODUCED OAT-TXT FILES (Updated by Aug 23, 2019)

The preprocessed files are under ``` /nfs/home2/guanxiong/disassembly ``` which you can access from Zeus or Galileo. Within the subdirectory for each year, ``` benign_txt ``` folder has all oat-txt files from AndroZoo, ``` malware_txt ``` has all oat-txt files from VirusTotal. Folder ``` gp_internal_txt ``` contains oat-txt files from GooglePlay. Folder ``` *_log ``` contains terminal outputs from ```dex2oat ``` and ``` oatdump ``` for each sample.

## PROCEDURE TO PRODUCE OAT-TXT FILES   

1. Set up a VM (virtual machine): You need a VM running Ubuntu 14.04 to build Android. You can use VirtualBox or Virsh to set up and manage the VM. On Galileo we have a Virsh VM named ``` ericAndroid5Build ``` with Android 5.1.1_r4 built. If you want to use this VM, move to Step 3.

2. Build Android: Follow the instructions provided in the following links in sequence to build Android:
   -  https://source.android.com/setup/build/initializing
   -  https://source.android.com/setup/build/downloading
   -  https://source.android.com/setup/build/building
  

3. Mount directories: mount host directories where ``` DroidNative ``` is stored, directories with apks, and directories where you want to store oat-txt files to the VM. Using ``` sshfs ``` to mount directories is very easy.

4. Convert files: If you are using VM ``` ericAndroid5Build ```, and it was shutdown, then after booting it up you need to run the following commands:
   ````
   cd android_5.1.1_r4
   source build/envsetup.sh
   set_stuff_for_environment
   ````
   These steps set up some environmental variables necessary for our scripts. To verify the build environment has been set up properly, run
   ```
   emulator -no-window
   ```
   and see if the Android emulator starts. Then inside the VM, change to the ``` DroidNative ``` directory, and run script ``` apk2disassembly_on_host.py ``` for batch production. You can look into the script for its usage.