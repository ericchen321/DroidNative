#!/bin/bash
# this script moves training data from bin to somewhere else
# Usage : param - folder where you want to store training data

mv bin/benign_samples* $1
mv bin/malware_samples* $1
mv bin/*.dat* $1
mv bin/*.gle $1
mv bin/*.txt $1