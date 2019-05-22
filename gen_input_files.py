# This script generates the two input files to DroidNative, benign_samples.txt and malware.txt,
# and places them in the given directory.
# Usage:
# first param: directory where benign samples are stored, do not end with slash
# second param: directory where malware samples are stored, do not end with slash
# 3rd param: number of benign samples wanted; "all" means all samples
# 4th param: number of malware samples wanted; "all" means all samples
# 5th param: directory where output files are stored, do not end with slash

import glob
import sys

if(len(sys.argv)!=6):
	print "Wrong arguments, please check comments in the script for usage"
	sys.exit(1)

benignInDir = sys.argv[1] + '/*'
malwareInDir = sys.argv[2] + '/*'
benignSamples = glob.glob(benignInDir)
malwareSamples = glob.glob(malwareInDir)

benignOut = sys.argv[5] + '/benign_samples.txt'
malwareOut = sys.argv[5] + '/malware_samples.txt'

outFile = open(benignOut, 'w')
if(sys.argv[3] == 'all'):
  for line in benignSamples:
    outFile.write(line)
    outFile.write("\n")
else:
  count = 0
  for line in benignSamples:
    outFile.write(line)
    outFile.write("\n")
    count += 1
    if(count == int(sys.argv[3])):
      break
outFile.close()

outFile = open(malwareOut, 'w')
if(sys.argv[4] == 'all'):
  for line in malwareSamples:
    outFile.write(line)
    outFile.write("\n")
else:
  count = 0
  for line in malwareSamples:
    outFile.write(line)
    outFile.write("\n")
    count += 1
    if(count == int(sys.argv[4])):
      break
outFile.close()
