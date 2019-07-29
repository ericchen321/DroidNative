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
if ($num_args != 7)
{
	die "Usage:\nrun-cross-validation.pl <max_threads> <n> <file_name_benign_samples> <file_name_malware_samples> <file_name_SAMAD> <build_roc=0/1> <THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING>\nbuild_roc = 0 Just run once\nbuild_roc = 1 Run more than once, from THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING - 100 for building ROC\n\nExample:\nrun-cross-validation.pl 1 10 benign_samples.txt malware_samples.txt SAMAD.exe 1 1\n";
}

my $max_threads = $ARGV[0];
my $N = $ARGV[1];
my $BENIGN_FILE = $ARGV[2];
my $MALWARE_FILE = $ARGV[3];
my $SAMAD_full_path = $ARGV[4];
my $BUILD_ROC = $ARGV[5];
my $THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING = $ARGV[6];
print "n = $N\nbenign_file = $BENIGN_FILE\nmalware_file = $MALWARE_FILE\n";
print "THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING = $THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING\n";

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

if ($BUILD_ROC == 1)
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
	for (my $count = $STARTING; $count <= $COUNT; $count += $jump)
	{
		$THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING = $count;
		my @threads;
		for (my $i = 0; $i < $N; $i++)
		{
			my $cmd = sprintf("%s %d %.02f virus_samples_%02d.txt files_to_check_%02d.txt > results_%03d_%02d.txt", $SAMAD_full_path, $max_threads, $THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING, $i, $i, $count, $i);
			$threads[$i] = threads->create('thr_func', $cmd);
		}
		for (my $i = 0; $i < $N; $i++)
		{
			$threads[$i]->join();
		}
	}
}
elsif ($BUILD_ROC == 0)
{
	#
	# Running the tool SAMAD with appropriate command line parameters
	# for n-fold cross validation using the files generated above.
	#
	my @threads;
	for (my $i = 0; $i < $N; $i++)
	{
		my $cmd = sprintf("%s %d %.02f virus_samples_%02d.txt files_to_check_%02d.txt > results_%02d.txt", $SAMAD_full_path, $max_threads, $THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING, $i, $i, $i);
		$threads[$i] = threads->create('thr_func', $cmd);
	}
	for (my $i = 0; $i < $N; $i++)
	{
		$threads[$i]->join();
	}
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
