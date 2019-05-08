#!/usr/bin/perl
#
# Author: Shahid Alam
# Dated: January 14, 2015
# E-mail: salam@qu.edu.qa / alam_shahid@yahoo.com
#
# Prepares data (files) for n-fold cross validation.
# Takes a number, to be used as n, two files benign and
# malware to generate files for testing SAMAD, a tool for
# malware detection, and exe of the tool SAMAD.
#
# In n-fold cross validation the original sample is divided
# into n equal size subsamples. One of the samples is used for
# testing and the remaining n-1 samples are used for training.
# The cross validation process is then repeated n times with
# each of the n subsamples used exactly once for validation.
# The overall performance results are obtained by averaging
# the results obtained in the n different runs.
#
# It can also be used to find the following parameters by running
# several iterations of n-fold cross validation for a dataset:
# VWOD and HWOD
# VSD and HSD
#
# Make sure
# number of files listed / n = integer, to generate
# complete files, otherwise the program exits with error.
# AND
# files are listed with full path.
# AND
# full path name of the tool SAMAD
# Assumption - n is less than 100.
#
# Example files:
#
# --- benign_samples.txt ---
# -  -  -  -  -  -  -
# samples/benign/binary/subsystem_ramdump
# samad/samples/benign/binary/make_ext4fs
# samad/samples/benign/binary/bcc
# -  -  -  -  -  -  -
#
# --- malware_samples.txt ---
# -  -  -  -  -  -  -
# samples/malware/binary/contagiominidump.blogspot.com/Mac_flashback_39
# samad/samples/malware/binary/contagiominidump.blogspot.com/DroidPak_flashmx32.xtl_
# samples/malware/binary/contagiominidump.blogspot.com/CarrierIQ_iqd
# -  -  -  -  -  -  -
#
# Usage:
# run-cross-validation.pl <n> <file_name_benign_samples> <file_name_malware_samples> <file_name_SAMAD>
# Example:
# run-cross-validation.pl 10 benign_samples.txt malware_samples.txt SAMAD.exe
#

use strict;
use warnings;
use threads;

my $num_args = $#ARGV + 1;
if ($num_args != 9)
{
	die "Usage:\nrun-cross-validation.pl <n> <file_name_benign_samples> <file_name_malware_samples> <file_name_SAMAD> <find_best_value=0/1/2> <VWOD> <HWOD> <VSD> <HSD>\nfind_best_value = 0 For generating ROC\nfind_best_value = 1 For one run\nfind_best_value = 2 For finding the best values\n\nExample:\nrun-cross-validation.pl 10 benign_samples.txt malware_samples.txt SAMAD.exe 1 3 50 25 50\n";
}

my $N = $ARGV[0];
my $BENIGN_FILE = $ARGV[1];
my $MALWARE_FILE = $ARGV[2];
my $SAMAD_full_path = $ARGV[3];
my $FINDING_BEST_VALUES = $ARGV[4];
my $VWOD = $ARGV[5];
my $HWOD = $ARGV[6];
my $VSD = $ARGV[7];
my $HSD = $ARGV[8];
print "n = $N\nbenign_file = $BENIGN_FILE\nmalware_file = $MALWARE_FILE\n";
print "VWOD = $VWOD HWOD = $HWOD\nVSD = $VSD HSD = $HSD\n";

my $BENIGN_FILE_SIZE = 0;
open(my $FH,"$BENIGN_FILE") or die "ERROR - Cannot open $BENIGN_FILE . . .";
while (<$FH>) { $BENIGN_FILE_SIZE++ if  !/^\s+?$/;}
close $FH;
my $BENIGN_sub_samples = $BENIGN_FILE_SIZE / $N;

my $MALWARE_FILE_SIZE = 0;
open($FH,"$MALWARE_FILE") or die "ERROR - Cannot open $MALWARE_FILE . . .";
while (<$FH>) { $MALWARE_FILE_SIZE++ if  !/^\s+?$/;}
close $FH;
my $MALWARE_sub_samples = $MALWARE_FILE_SIZE / $N;

print "benign_sub_samples = $BENIGN_sub_samples\nmalware_sub_samples = $MALWARE_sub_samples\n";
my $OUTPUT_FILE = sprintf ("best_values_SWOD_run-cross-validation_%d_%d.txt", $BENIGN_FILE_SIZE, $MALWARE_FILE_SIZE);
print "\n";

#
# Geneating true random locations for picking files randomly from the benign file.
# Each random location is unique.
#
my @files_locations_benign;
my $global_count = 0;
my $GLOBAL_LIMIT = 1000 * ($BENIGN_FILE_SIZE + $MALWARE_FILE_SIZE);
my @already_selected;
for (my $s = 0; $s < $BENIGN_FILE_SIZE; $s++)
{
	$already_selected[$s] = 0;
}
for (my $i = 0; $i < $N; $i++)
{
	for (my $s = 0; $s < $BENIGN_sub_samples; $s++)
	{
		$files_locations_benign[$i][$s] = 0;
	}
	for (my $s = 0; $s < $BENIGN_sub_samples; )
	{
		my $random_number = int(rand($BENIGN_FILE_SIZE));
		if ($already_selected[$random_number] == 0)
		{
			$files_locations_benign[$i][$s] = $random_number;
			$already_selected[$random_number] = 1;
			$s++;
		}
		$global_count++;
		if ($global_count > $GLOBAL_LIMIT)
		{
			die "SYSTEM ERROR 1: $s Generating random numbers $global_count > $GLOBAL_LIMIT . . .\nPlease try again . . .\n";
		}
	}
}
#
# Checking the randomness of the locations.
#
for (my $s = 0; $s < $BENIGN_FILE_SIZE; $s++)
{
	if ($already_selected[$s] == 0)
	{
		print "FAILED THE TEST: already_selected is '0' @ $s\n";
		die "SYSTEM ERROR 1: Generating random numbers . . .\nPlease try again . . .\n";
	}
}
#
# Geneating true random locations for picking files randomly from the malware file.
# Each random location is unique.
#
my @files_locations_malware;
$global_count = 0;
$GLOBAL_LIMIT = 1000 * ($BENIGN_FILE_SIZE + $MALWARE_FILE_SIZE);
for (my $s = 0; $s < $MALWARE_FILE_SIZE; $s++)
{
	$already_selected[$s] = 0;
}
for (my $i = 0; $i < $N; $i++)
{
	for (my $s = 0; $s < $MALWARE_sub_samples; $s++)
	{
		$files_locations_malware[$i][$s] = 0;
	}
	for (my $s = 0; $s < $MALWARE_sub_samples; )
	{
		my $random_number = int(rand($MALWARE_FILE_SIZE));
		if ($already_selected[$random_number] == 0)
		{
			$files_locations_malware[$i][$s] = $random_number;
			$already_selected[$random_number] = 1;
			$s++;
		}
		$global_count++;
		if ($global_count > $GLOBAL_LIMIT)
		{
			die "SYSTEM ERROR 2: $s Generating random numbers $global_count > $GLOBAL_LIMIT . . .\nPlease try again . . .\n";
		}
	}
}
#
# Checking the randomness of the locations.
#
for (my $s = 0; $s < $BENIGN_FILE_SIZE; $s++)
{
	if ($already_selected[$s] == 0)
	{
		print "FAILED THE TEST: already_selected is '0' @ $s\n";
		die "SYSTEM ERROR 2: Generating random numbers . . .\nPlease try again . . .\n";
	}
}

#
# Generating benign files to be used latter
#
open($FH,"$BENIGN_FILE") or die "ERROR - Cannot open $BENIGN_FILE . . .";
my @benign_lines = <$FH>;
for (my $i = 0; $i < $N; $i++)
{
	my $file_name = sprintf("benign_samples_%02d", $i);
	print "Generating $file_name\n";
	open(my $FH_file,'>', "$file_name") or die "ERROR - Cannot open $file_name . . .";
	for (my $s = 0; $s < $BENIGN_sub_samples; $s++)
	{
		my $location = $files_locations_benign[$i][$s];
		my $benign_file = $benign_lines[$location];
		print $FH_file "$benign_file";
	}
	close $FH_file;
}
close $FH;

#
# Generating malware files to be used latter
#
open($FH,"$MALWARE_FILE") or die "ERROR - Cannot open $MALWARE_FILE . . .";
my @malware_lines = <$FH>;
for (my $i = 0; $i < $N; $i++)
{
	my $file_name = sprintf("malware_samples_%02d", $i);
	print "Generating $file_name\n";
	open(my $FH_file,'>', "$file_name") or die "ERROR - Cannot open $file_name . . .";
	for (my $s = 0; $s < $MALWARE_sub_samples; $s++)
	{
		my $location = $files_locations_malware[$i][$s];
		my $malware_file = $malware_lines[$location];
		print $FH_file "$malware_file";
	}
	close $FH_file;
}
close $FH;

#
# Generating other files for testing
#
print "\n";
for (my $i = 0; $i < $N; $i++)
{
	my $cmd = sprintf("cat malware_samples_%02d benign_samples_%02d > files_to_check_%02d.txt", $i, $i, $i);
	print "Running $cmd\n";
	system ($cmd);

	$cmd = "cat ";
	for (my $s = 0; $s < $N; $s++)
	{
		if ($s != $i)
		{
			$cmd = $cmd . sprintf("malware_samples_%02d ", $s);
		}
	}
	if ($cmd ne "cat ")
	{
		$cmd = $cmd . sprintf("> malware_samples_%02d.txt", $i);
		print "Running $cmd\n";
		system ($cmd);
	}
	else
	{
		$cmd = $cmd . sprintf("malware_samples_%02d > malware_samples_%02d.txt", $i, $i);
		print "Running $cmd\n";
		system ($cmd);
	}

	$cmd = sprintf("cat malware_samples_%02d.txt > virus_samples_%02d.txt", $i, $i);;
	print "Running $cmd\n";
	system ($cmd);

	$cmd = "cat ";
	for (my $s = 0; $s < $N; $s++)
	{
		if ($s != $i)
		{
			$cmd = $cmd . sprintf("benign_samples_%02d ", $s);
		}
	}
	if ($cmd ne "cat ")
	{
		$cmd = $cmd . sprintf("> benign_samples_%02d.txt", $i);
		print "Running $cmd\n\n";
		system ($cmd);
	}
	else
	{
		$cmd = $cmd . sprintf("benign_samples_%02d > benign_samples_%02d.txt", $i, $i);
		print "Running $cmd\n";
		system ($cmd);
	}
}

my $max_threads = 1;
if ($FINDING_BEST_VALUES == 0)
{
	#
	# Running the tool SAMAD with appropriate command line parameters
	# for n-fold cross validation using the files generated above.
	# It runs it completely for COUNT iterations to create an ROC.
	# Generate the result files (results_xxx_xx.txt) for buidling the ROC.
	#
	my $COUNT = 100;
	my $jump = 1;
	my $STARTING = 1;
	for (my $hsd_count = $STARTING; $hsd_count <= $COUNT; $hsd_count += $jump)
	{
		$HSD = $hsd_count;
		my @threads;
		for (my $i = 0; $i < $N; $i++)
		{
			my $cmd = sprintf("%s %d %.02f %.02f 1.00 1.00 %.02f %.02f malware_samples_%02d.txt benign_samples_%02d.txt virus_samples_%02d.txt files_to_check_%02d.txt > results_%03d_%02d.txt", $SAMAD_full_path, $max_threads, $VWOD, $HWOD, $VSD, $HSD, $i, $i, $i, $i, $hsd_count, $i);
			$threads[$i] = threads->create('thr_func', $cmd);
		}
		for (my $i = 0; $i < $N; $i++)
		{
			$threads[$i]->join();
		}
	}
}
elsif ($FINDING_BEST_VALUES == 1)
{
	#
	# Running the tool SAMAD with appropriate command line parameters
	# for n-fold cross validation using the files generated above.
	#
	my @threads;
	for (my $i = 0; $i < $N; $i++)
	{
		my $cmd = sprintf("%s %d %.02f %.02f 1.00 1.00 %.02f %.02f malware_samples_%02d.txt benign_samples_%02d.txt virus_samples_%02d.txt files_to_check_%02d.txt > results_%02d.txt", $SAMAD_full_path, $max_threads, $VWOD, $HWOD, $VSD, $HSD, $i, $i, $i, $i, $i);
		$threads[$i] = threads->create('thr_func', $cmd);
	}
	for (my $i = 0; $i < $N; $i++)
	{
		$threads[$i]->join();
	}
}
elsif ($FINDING_BEST_VALUES == 2)
{
	#
	# Just run one of the sets (the first one) from n-folds.
	#
	my $ORIGINAL_N = $N;
	$N = 1;
	# Open the output file to store the results
	open(my $OUTPUT, ' > ', "$OUTPUT_FILE") or die "ERROR - Cannot open $OUTPUT_FILE . . .";
	#
	# Here the program finds the best values for VWOD, HWOD, VSD and HSD.
	# It runs different iterations of the test ofr finding these values.
	#
	#
	# Running the tool SAMAD with appropriate command line parameters
	# for n-fold cross validation using the files generated above.
	# Changing the values of VSD and HSD.
	#
	my $V_COUNT = 50;
	my $H_COUNT = 100;
	my $jump_vsd = 2;
	my $jump_hsd = 5;
	my $STARTING_VSD = $VSD;
	my $STARTING_HSD = $HSD;
	for (my $vsd_count = $STARTING_VSD; $vsd_count <= $V_COUNT; $vsd_count += $jump_vsd)
	{
		my $THREADS_COUNT = 0;
		my @threads;
		for (my $hsd_count = $STARTING_HSD; $hsd_count <= $H_COUNT; $hsd_count += $jump_hsd)
		{
			$VSD = $vsd_count;
			$HSD = $hsd_count;
			for (my $i = 0; $i < $N; $i++)
			{
				my $cmd = sprintf("%s %d %.02f %.02f 1.00 1.00 %.02f %.02f malware_samples_%02d.txt benign_samples_%02d.txt virus_samples_%02d.txt files_to_check_%02d.txt > ./VSD_HSD/results_%02d_%03d_%02d.txt", $SAMAD_full_path, $max_threads, $VWOD, $HWOD, $VSD, $HSD, $i, $i, $i, $i, $vsd_count, $hsd_count, $i);
				$threads[$THREADS_COUNT] = threads->create('thr_func', $cmd);
				$THREADS_COUNT++;
			}
			if ($THREADS_COUNT >= $ORIGINAL_N)
			{
				for (my $i = 0; $i < $THREADS_COUNT; $i++)
				{
					$threads[$i]->join();
				}
				$THREADS_COUNT = 0;
			}
		}
	}

	#
	# Find the file containing the best results, and then get the VSD and HSD from that file to be used latter
	#
	my $global_count = -1;
	my $max_count = 0;
	my $file_max_count = "";
	for (my $vsd_count = $STARTING_VSD; $vsd_count <= $V_COUNT; $vsd_count += $jump_vsd)
	{
		for (my $hsd_count = $STARTING_HSD; $hsd_count <= $H_COUNT; $hsd_count += $jump_hsd)
		{
			$VSD = $vsd_count;
			$HSD = $hsd_count;
			my $file = sprintf("./VSD_HSD/results_%02d_%03d", $vsd_count, $hsd_count);
			my $cmd = sprintf("grep 'samples.*malware.*   0\$' %s* | wc | awk '{print \$1;}'", $file);
			print "\nRunning $cmd\n";
			open(my $EXEC, '-|', $cmd);
			my $line = <$EXEC>;
			close ($EXEC);
			chomp $line;
			my $count_zeros = $line;
			$cmd = sprintf("grep 'samples.*benign.*   1\$' %s* | wc | awk '{print \$1;}'", $file);
			print "\nRunning $cmd\n";
			open($EXEC, '-|', $cmd);
			$line = <$EXEC>;
			close ($EXEC);
			chomp $line;
			my $count_ones = $line;
			print "VSD_HSD - count_zeros: $count_zeros\n";
			print "VSD_HSD - count_ones: $count_ones\n";

			my $max_count_zeros = $count_zeros;
			my $max_count_ones = $count_ones;
			if (($max_count_zeros + $max_count_ones) > $max_count)
			{
				$max_count = $max_count_zeros + $max_count_ones;
				$file_max_count = "$file";
				$global_count++;
			}
		}
	}

	#
	# If we are able to compute the values
	#
	if ($global_count > 0)
	{
		my $file = "$file_max_count" . "_00.txt";
		print "FILE with Best VSD and HSD size: $file";

		my $cmd = sprintf("grep 'VSD' %s | sed 's/VSD = //'", $file);
		print "\nRunning $cmd\n";
		open(my $EXEC, '-|', $cmd);
		my $line_vsd = <$EXEC>;
		close ($EXEC);
		chomp $line_vsd;
		$VSD = $line_vsd;
		if ($VSD <= 0)
		{
			die "Error in computing VSD\n";
		}

		$cmd = sprintf("grep 'HSD' %s | sed 's/HSD = //'", $file);
		print "\nRunning $cmd\n";
		open($EXEC, '-|', $cmd);
		my $line_hsd = <$EXEC>;
		close ($EXEC);
		chomp $line_hsd;
		$HSD = $line_hsd;
		if ($HSD <= 0)
		{
			die "Error in computing HSD\n";
		}
	}
	#
	# If not then assign default values 25 and 70
	#
	else
	{
		$VSD = 25;
		$HSD = 70;
	}

	print $OUTPUT "VSD: $VSD\nHSD: $HSD\n";
	print "VSD: $VSD\nHSD: $HSD\n";

	#
	# Running the tool SAMAD with appropriate command line parameters
	# for n-fold cross validation using the files generated above.
	# Changing the values of VWOD and HWOD.
	#
	#
	$V_COUNT = 10;
	$H_COUNT = 100;
	my $jump_vwod = 1;
	my $jump_hwod = 5;
#	my $STARTING_VWOD = $VWOD;
#	my $STARTING_HWOD = $HWOD;
	my $STARTING_VWOD = 1; # by default start from here
	my $STARTING_HWOD = 5; # by default start from here
	for (my $vwod_count = $STARTING_VWOD; $vwod_count <= $V_COUNT; $vwod_count += $jump_vwod)
	{
		my $THREADS_COUNT = 0;
		my @threads;
		for (my $hwod_count = $STARTING_HWOD; $hwod_count <= $H_COUNT; $hwod_count += $jump_hwod)
		{
			$VWOD = $vwod_count;
			$HWOD = $hwod_count;
			for (my $i = 0; $i < $N; $i++)
			{
				my $cmd = sprintf("%s %d %.02f %.02f 1.00 1.00 %.02f %.02f malware_samples_%02d.txt benign_samples_%02d.txt virus_samples_%02d.txt files_to_check_%02d.txt > ./VWOD_HWOD/results_%02d_%03d_%02d.txt", $SAMAD_full_path, $max_threads, $VWOD, $HWOD, $VSD, $HSD, $i, $i, $i, $i, $vwod_count, $hwod_count, $i);
				$threads[$THREADS_COUNT] = threads->create('thr_func', $cmd);
				$THREADS_COUNT++;
			}
			if ($THREADS_COUNT >= $ORIGINAL_N)
			{
				for (my $i = 0; $i < $THREADS_COUNT; $i++)
				{
					$threads[$i]->join();
				}
				$THREADS_COUNT = 0;
			}
		}
	}

	#
	# Find the file containing the best results, and then get the VWOD and HWOD from that file to be used latter
	#
	$global_count = -1;
	$max_count = 0;
	$file_max_count = "";
	for (my $vwod_count = $STARTING_VWOD; $vwod_count <= $V_COUNT; $vwod_count += $jump_vwod)
	{
		for (my $hwod_count = $STARTING_HWOD; $hwod_count <= $H_COUNT; $hwod_count += $jump_hwod)
		{
			$VWOD = $vwod_count;
			$HWOD = $hwod_count;
			my $file = sprintf("./VWOD_HWOD/results_%02d_%03d", $vwod_count, $hwod_count);
			my $cmd = sprintf("grep 'samples.*malware.*   0\$' %s* | wc | awk '{print \$1;}'", $file);
			print "\nRunning $cmd\n";
			open(my $EXEC, '-|', $cmd);
			my $line = <$EXEC>;
			close ($EXEC);
			chomp $line;
			my $count_zeros = $line;
			$cmd = sprintf("grep 'samples.*benign.*   1\$' %s* | wc | awk '{print \$1;}'", $file);
			print "\nRunning $cmd\n";
			open($EXEC, '-|', $cmd);
			$line = <$EXEC>;
			close ($EXEC);
			chomp $line;
			my $count_ones = $line;
			print "VWOD_HWOD - count_zeros: $count_zeros\n";
			print "VWOD_HWOD - count_ones: $count_ones\n";

			my $max_count_zeros = $count_zeros;
			my $max_count_ones = $count_ones;
			if (($max_count_zeros + $max_count_ones) > $max_count)
			{
				$max_count = $max_count_zeros + $max_count_ones;
				$file_max_count = "$file";
				$global_count++;
			}
		}
	}

	#
	# If we are able to compute the values
	#
	if ($global_count > 0)
	{
		my $file = "$file_max_count" . "_00.txt";
		print "FILE with Best VWOD and HWOD size: $file";

		my $cmd = sprintf("grep 'VWOD' %s | sed 's/VWOD = //'", $file);
		print "\nRunning $cmd\n";
		open(my $EXEC, '-|', $cmd);
		my $line_vwod = <$EXEC>;
		close ($EXEC);
		chomp $line_vwod;
		$VWOD = $line_vwod;
		if ($VWOD <= 0)
		{
			die "Error in computing VWOD\n";
		}

		$cmd = sprintf("grep 'HWOD' %s | sed 's/HWOD = //'", $file);
		print "\nRunning $cmd\n";
		open($EXEC, '-|', $cmd);
		my $line_hwod = <$EXEC>;
		close ($EXEC);
		chomp $line_hwod;
		$HWOD = $line_hwod;
		if ($HWOD <= 0)
		{
			die "Error in computing HWOD\n";
		}
	}
	#
	# If not then assign default values 1 and 25
	#
	else
	{
		$VWOD = 1.0;
		$HWOD = 25.0;
	}

	print $OUTPUT "VWOD: $VWOD\nHWOD: $HWOD\n";
	print "VWOD: $VWOD\nHWOD: $HWOD\n";


	my $cmd = sprintf("cat %s", $OUTPUT_FILE);
	print "\nRunning $cmd\n";
	system($cmd);
	close ($OUTPUT);
}
else
{
	die "Usage:\nrun-cross-validation.pl <n> <file_name_benign_samples> <file_name_malware_samples> <file_name_SAMAD> <find_best_value=0/1/2> <VWOD> <HWOD> <VSD> <HSD>\nfind_best_value = 0 For generating ROC\nfind_best_value = 1 For one run\nfind_best_value = 2 For finding the best values\n\nExample:\nrun-cross-validation.pl 10 benign_samples.txt malware_samples.txt SAMAD.exe 1 3 50 25 50\n";
}

print "\nExiting\n";

sub thr_func
{
	my $tid = threads->tid();
	my $cmd = shift;

	print "\nThread $tid Running $cmd\n";
	system ($cmd);
	print "\nThread $tid Finished Running $cmd\n";
}
