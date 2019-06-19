# copy n randomly selected samples from source to destination folder
# Usage:
# 1st param: path to source folder
# 2nd param: path to dest folder
# 3rd param: n (number of samples)

import sys
import glob
import random
import os
import shutil
SAMPLE_COUNT = 40

source_dir = sys.argv[1]
dest_dir = sys.argv[2]
num_samples = int(sys.argv[3])

samples = glob.glob(os.path.join(source_dir, '*.apk'))
samples = random.sample(samples, num_samples)

os.system('rm ' + dest_dir + '/*')

for filename in samples:
    shutil.copy(filename, dest_dir)