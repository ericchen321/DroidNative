# This script generates a text file with list of filepaths in given directory
# Usage:
# first param: input directory
# second param: path to output file

import glob
import sys

in_dir = sys.argv[1]
txt_file_path = sys.argv[2]

samples = glob.glob(in_dir + '/*.apk')
outFile = open(txt_file_path, 'w')

for line in samples:
  outFile.write(line)
  outFile.write('\n')

outFile.close()