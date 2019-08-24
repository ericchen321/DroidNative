------------------------------------------------
# README file for using DroidNative to Test Samples
------------------------------------------------

Author:
- Guanxiong Chen chenguanxiong@alumni.ubc.ca

This documentation explains our testing infrastructure, where our results so far are stored, and how to set up DroidNative for testing.

## TESTING INFRASTRUCTURE
We run DroidNative's testing threads insides virtual machines (VMs). The reason is sometimes DroidNative were unable to unzip compressed signature files. The failure happens randomly, but running each testing thread inside a VM, as opposed to running multiple threads simultaneously and natively on our servers, reduces the frequency of such failure.

The table below lists the VMs currently available on our machines as well as on Pleiades (Mieszko's machine) that could be used for testing:

| VM Name        | On Which Machine?           | Front-end Management Tool  |
| ------------- |:-------------:| -----:|
| ericAndroid5Build      | Galileo | Virsh |
| moscow      | Thanos      |   Virsh |
| leningrad | Thanos      |    Virsh |
| stalingrad | Thanos      |    Virsh |
| kursk | Thanos      |    Virsh |
| midway | Thanos      |    Virsh |
| pearlHarbor | Thanos      |    Virsh |
| saipan | Thanos      |    Virsh |
| guadalcanal | Thanos      |    Virsh |
| tatooine | Zeus      |    VirtualBox |
| alderaan | Zeus      |    VirtualBox |
| naboo | Zeus      |    VirtualBox |
| bespin | Zeus      |    VirtualBox |
| kashyyyk | Zeus      |    VirtualBox |
| anubis | Pleiades      |    VirtualBox |
| horus | Pleiades      |    VirtualBox |
| osiris | Pleiades      |    VirtualBox |

You can also use them for training. Each VM has Ubuntu 14.04 installed. To make programs running in a VM access files on its host, you can either use the VM's front-end's built-in utilities to mount a directory to the VM, or use ``` sshfs ``` to mount a directory.

## TESTING RESULTS (Updated by Aug 19, 2019)

There are eight DroidNative testing experiments. You can see the details of each in ``` DroidNative_experiment_status.xlsx ```. All results so far has been stored in ``` /nfs/home2/guanxiong/results_for_analysis_testing_result_for_each_sample_(aug_19_backup) ``` which you can access from Zeus or Galileo. The result files were named after the convention ``` results_<experiment number>_<time>_<month>_<date>.txt ```. 

## PROCEDURE TO SET UP DROIDNATIVE FOR TESTING

1. Set up VMs. You can use VirtualBox or Virsh (with virt-manager being its GUI management tool) to create new VMs. VirtualBox utilizes KVM, and some Android emulators also use KVM, so you may not run them together on a host. In that case you will have to use Vish. Once you have started a VM, ssh into it.

2. Mount host directories with DroidNative executable, signature files to the VMs.

3. Run DroidNative in testing mode. To be safe put only one testing thread in each VM. For commands to run DroidNative in testing mode, please read Section 3 under "Running" in the README file for building and running DroidNative.