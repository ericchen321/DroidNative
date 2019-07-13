# This script generates a text file with list of filepaths in given directory
# Usage:
# first param: input directory
# second param: path to output file
# 3rd param: number of samples wanted. 0 means all

import glob
import sys
import random

in_dir = sys.argv[1]
txt_file_path = sys.argv[2]
num_samples = int(sys.argv[3])

samples = glob.glob(in_dir + '/*')
if num_samples != 0:
  samples = random.sample(samples, num_samples)

outFile = open(txt_file_path, 'w')
for line in samples:
  line = line.replace(' ', '\ ')
  outFile.write(line)
  outFile.write('\n')
outFile.close()