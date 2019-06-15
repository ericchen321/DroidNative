#!/bin/bash
# this script moves partitioning, training, and testing data from bin to somewhere else
# Usage : param - folder where you want to store training data

mkdir -p $1
mv bin/benign_samples* $1
mv bin/malware_samples* $1
mv bin/virus_samples* $1
mv bin/files_to_check* $1
mv bin/results* $1
mv bin/*.dat* $1
mv bin/*.gle $1