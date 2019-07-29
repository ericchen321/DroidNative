#!/usr/bin/perl
#
# Author: Shahid Alam
# Dated: February 14, 2015
# E-mail: alam_shahid@yahoo.com
#
# Get the timings information from the files generated by build-ROC.pl
#
# First paramter:   The name (with full path) of the directory where the result files are stored.
# Second parameter: The number n in the n-fold cross validation.
# Third parameter:  The range of the runs, e.g, 1-100, 10-90, etc, with no spacing in between.
#
# e.g: getTime.pl c:\results 5 1-100
#
# It will atuomatically start procesing the following files
# c:\results\results_001_00.txt
# c:\results\results_001_01.txt
# c:\results\results_001_02.txt
# c:\results\results_001_03.txt
# c:\results\results_001_04.txt
# c:\results\results_002_00.txt
# c:\results\results_002_01.txt
# c:\results\results_002_02.txt
# c:\results\results_002_03.txt
# c:\results\results_002_04.txt
# -  -  -  -  -  -  -  -  -  -
# -  -  -  -  -  -  -  -  -  -
# -  -  -  -  -  -  -  -  -  -
# c:\results\results_100_00.txt
# c:\results\results_100_01.txt
# c:\results\results_100_02.txt
# c:\results\results_100_03.txt
# c:\results\results_100_04.txt
#
#
# It uses the first file to compute different parametrs, such as:
# The VWOD, HWOD and VSD,
# and assumes that all other files will contain the same number of these samples.
#
# The name of the output file contains n, VWOD, HWOD, VSD and range of HSD as follows:
# ROC-<n>-<VWOD>-<HWOD>-<VSD>-<[START_HSD-END_HSD]>.tim
# e.g, ROC-5-1-25-5-[1-100].tim
#
#
# Example result file:
#
# --- results_001_00.txt ---
# -  -  -  -  -  -  -  -  --  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -
# -  -  -  -  -  -  -  -  --  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -
# -  -  -  -  -  -  -  -  --  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -  -
#                                                                                                                                              Filename  Number Benign
#                                    c:/samples/malware/oat/GENOME/DroidKungFu4/data_DroidKungFu4@app@com.safett.butler-1@base.apk@classes.dex.dump.txt       0     0
#                                    c:/samples/malware/oat/GENOME/DroidKungFu2/data_DroidKungFu2@app@com.allen.txtjjsz-1@base.apk@classes.dex.dump.txt       1     0
#                                    c:/samples/malware/oat/GENOME/DroidKungFu3/data_DroidKungFu3@app@com.mogo.animalkeeper-1@base.apk@classes.dump.txt       2     0
#                                   c:/samples/malware/oat/GENOME/DroidKungFu4/data_DroidKungFu4@app@com.safesys.myvpn2-1@base.apk@classes.dex.dump.txt       3     0
#                                      c:/samples/malware/oat/GENOME/DroidKungFu2/data_DroidKungFu2@app@com.allen.txtdz-1@base.apk@classes.dex.dump.txt       4     0
#                                 c:/samples/malware/oat/GENOME/DroidKungFu2/data_DroidKungFu2@app@com.tutusw.onekeyvpn-1@base.apk@classes.dex.dump.txt       5     0
#                             c:/samples/malware/oat/GENOME/DroidKungFu2/data_DroidKungFu2@app@com.mediagroup.wcms.view-1@base.apk@classes.dex.dump.txt       6     0
#                                      c:/samples/malware/oat/GENOME/DroidKungFu3/data_DroidKungFu3@app@com.mogo.shuiguollk-1@base.apk@classes.dump.txt       7     0
#                                                      c:/samples/benign/oat/system@priv-app@SettingsProvider@SettingsProvider.apk@classes.dex.dump.txt       8     0
#                                                    c:/samples/benign/oat/system@priv-app@TelephonyProvider@TelephonyProvider.apk@classes.dex.dump.txt       9     0
#                                                                                                            c:/samples/benign/binary/libEnjemailuri.so      10     1
#                                                          c:/samples/benign/oat/system@priv-app@GoogleFeedback@GoogleFeedback.apk@classes.dex.dump.txt      11     0
#                                                                                                          c:/samples/benign/binary/libstagefrighthw.so      12     1
#                                                                                                                    c:/samples/benign/binary/screencap      13     1
#                                                                                                                     c:/samples/benign/binary/qseecomd      14     1
#                                                                                                            c:/samples/benign/binary/libeffectproxy.so      15     1
#
# Size of SWOD:
# VWOD = 1.00000
# HWOD = 25.00000
# VSD = 5.00000
# HSD = 34.00000
# Total Assigning Weights time:                                            34.55400 second(s)
# Total Training (building all signatures) time:                           30.84000 second(s)
# Total Testing (matching each signature with all signatures) time:        11.80900 second(s)
#
#
#
# Usage:
# getTime.pl <path to result files> <n> <range>
# Example:
# getTime.pl c:\results 5 1-100
#

use strict;
use warnings;

my $num_args = $#ARGV + 1;
if ($num_args != 3)
{
	die "Usage:\ngetTime.pl <path to result files> <n> <range>\n\nExample:\ngetTime.pl c:\\results 5 1-100\n";
}

my $PATH = $ARGV[0];
my $N = $ARGV[1];
my $RANGE = $ARGV[2];

#
# Parse the range to get the number of files to process
#
my @token = split('-', $RANGE);
my $token_size = $#token + 1;
if ($token_size != 2)
{
	die "Usage:\ngetTime.pl <path to result files> <n> <range>\n\nExample:\ngetTime.pl c:\\results 5 1-100\n";
}

my $VWOD = 0;
my $HWOD = 0;
my $VSD = 0;
my $START_HSD = $token[0] + 0;
my $END_HSD = $token[1] + 0;
my $end_char = substr($PATH, -1);
if ($end_char ne '/' && $end_char ne '\\')
{
	die "Usage:\ngetTime.pl <path to result files> <n> <range>\n\nExample:\ngetTime.pl c:\\results 5 1-100\nPlease provide full path to the result files . . .";
}
my $filename = $PATH . sprintf("results_%03d_%02d.txt", $START_HSD, "00");
open(my $FILE,"$filename") or die "ERROR - Cannot open $filename . . .";
my @lines = <$FILE>;
for (@lines)
{
	if ($_ =~ m/VWOD = /i)
	{
		@token = split("=", $_);
		$token_size = $#token + 1;
		if ($token_size != 2)
		{
			die "File $filename missing VWOD value, quitting . . .\n";
		}
		$VWOD = $token[1] + 0;
	}
	elsif ($_ =~ m/HWOD = /i)
	{
		@token = split("=", $_);
		$token_size = $#token + 1;
		if ($token_size != 2)
		{
			die "File $filename missing HWOD value, quitting . . .\n";
		}
		$HWOD = $token[1] + 0;
	}
	elsif ($_ =~ m/VSD = /i)
	{
		@token = split("=", $_);
		$token_size = $#token + 1;
		if ($token_size != 2)
		{
			die "File $filename missing HWOD value, quitting . . .\n";
		}
		$VSD = $token[1] + 0;
	}
}
close ($FILE);

my $OUTPUT_FILE = "ROC-$N-$VWOD-$HWOD-$VSD-[$START_HSD-$END_HSD].tim";
open(my $OUTPUT, ' > ', "$OUTPUT_FILE") or die "ERROR - Cannot open $OUTPUT_FILE . . .";
print "Path to result files = $PATH\nn-folds = $N\nTime file = $OUTPUT_FILE\n";
print "VWOD = $VWOD HWOD = $HWOD\nVSD = $VSD START_HSD = $START_HSD END_HSD = $END_HSD\n";

#-----------------------------------------------------------------
# Computing average values over the n-fold cross validation
#-----------------------------------------------------------------

my @AssignWeightTime = 0.0; # Assigning Weights Time;
my @TrainingTime = 0.0;     # Training (building all signatures) time
my @TestingTime = 0.0;      # Testing (matching each signature with all signatures) time
my $string_to_print = sprintf ("Count Assigning Weights Time     Training Time     Testing Time\n");
$filename = "";
my $time_unit = "";
for (my $hsd_count = $START_HSD; $hsd_count <= $END_HSD; $hsd_count++)
{
	$AssignWeightTime[$hsd_count-$START_HSD] = 0.0;
	$TrainingTime[$hsd_count-$START_HSD] = 0.0;
	$TestingTime[$hsd_count-$START_HSD] = 0.0;
	for (my $n_fold_count = 0; $n_fold_count < $N; $n_fold_count++)
	{
		$filename = $PATH . sprintf("results_%03d_%02d.txt", $hsd_count, $n_fold_count);
		open($FILE,"$filename") or die "ERROR - Cannot open $filename . . .";
		my @lines = <$FILE>;
		for (@lines)
		{
			my $line = $_;
			if ($line =~ m/^Total.* Assigning.* Weights.* time.* second/i)
			{
				@token = split(":", $line);
				$token_size = $#token + 1;
				if ($token_size != 2)
				{
					die "File $filename missing Assigning Weights time value, quitting . . .\n";
				}
				$line = $token[1];
				( $line ) = $line =~ m{(\d+\.\d+)};
				my $temp = $line + 0.0;
				$AssignWeightTime[$hsd_count-$START_HSD] = $AssignWeightTime[$hsd_count-$START_HSD] + $temp;
			}
			elsif ($line =~ m/^Total.* Training.* time.* second/i)
			{
				@token = split(":", $line);
				$token_size = $#token + 1;
				if ($token_size != 2)
				{
					die "File $filename missing Training time value, quitting . . .\n";
				}
				$line = $token[1];
				( $line ) = $line =~ m{(\d+\.\d+)};
				my $temp = $line + 0.0;
				$TrainingTime[$hsd_count-$START_HSD] = $TrainingTime[$hsd_count-$START_HSD] + $temp;
			}
			elsif ($line =~ m/^Total.* Testing.* time.* second/i)
			{
				@token = split(":", $line);
				$token_size = $#token + 1;
				if ($token_size != 2)
				{
					die "File $filename missing Testing time value, quitting . . .\n";
				}
				$line = $token[1];
				$time_unit = $line;
				( $line ) = $line =~ m{(\d+\.\d+)};
				my $temp = $line + 0.0;
				$TestingTime[$hsd_count-$START_HSD] = $TestingTime[$hsd_count-$START_HSD] + $temp;
			}
		}
		close ($FILE);
	}
	$AssignWeightTime[$hsd_count-$START_HSD] = $AssignWeightTime[$hsd_count-$START_HSD] / $N;
	$TrainingTime[$hsd_count-$START_HSD] = $TrainingTime[$hsd_count-$START_HSD] / $N;
	$TestingTime[$hsd_count-$START_HSD] = $TestingTime[$hsd_count-$START_HSD] / $N;
	$string_to_print = $string_to_print . sprintf ("%3d   %20.03f   %15.03f    %13.03f\n", $hsd_count, $AssignWeightTime[$hsd_count-$START_HSD], $TrainingTime[$hsd_count-$START_HSD], $TestingTime[$hsd_count-$START_HSD]);
}
#
# Computing the time unit value (milli seconds / seconds / minutes / hours)
#
chomp $time_unit;
@token = split(" ", $time_unit);
$token_size = $#token + 1;
if ($token_size != 2)
{
	print "Warning: Missing time unit value . . .\n";
	$time_unit = "";
}
else
{
	$time_unit = $token[1];
	chomp $time_unit;
}

#------------------------------------------------------
# Computing average values over the total range
#------------------------------------------------------

my $ATAWT = 0.0;
my $ATRT = 0.0;
my $ATET = 0.0;
my $total_count = $END_HSD - $START_HSD + 1;
for (my $hsd_count = 0; $hsd_count < $total_count; $hsd_count++)
{
	$ATAWT = $ATAWT + $AssignWeightTime[$hsd_count-$START_HSD];
	$ATRT = $ATRT + $TrainingTime[$hsd_count-$START_HSD];
	$ATET = $ATET + $TestingTime[$hsd_count-$START_HSD];
}
$string_to_print = $string_to_print . "---------------------------------------------------------------\n";
$string_to_print = $string_to_print . sprintf ("Total %20.03f   %15.03f    %13.03f\n", $ATAWT, $ATET, $ATET);
print $OUTPUT "$string_to_print\n";

my $ATAWT_ = $ATAWT / $total_count;
my $ATRT_ = $ATRT / $total_count;
my $ATET_ = $ATET / $total_count;

$string_to_print = "";
$string_to_print = $string_to_print . sprintf ("Average Assign Weight Time  = %12.03f / %03d = %12.03f %s\n", $ATAWT, $total_count, $ATAWT_, $time_unit);
$string_to_print = $string_to_print . sprintf ("Average Training Time       = %12.03f / %03d = %12.03f %s\n", $ATRT, $total_count, $ATRT_, $time_unit);
$string_to_print = $string_to_print . sprintf ("Average Testing Time        = %12.03f / %03d = %12.03f %s\n\n", $ATET, $total_count, $ATET_, $time_unit);
$string_to_print = $string_to_print . sprintf ("Total Average Training Time = %12.03f %s\n", $ATAWT_ + $ATRT_, $time_unit);
$string_to_print = $string_to_print . sprintf ("Total Average Testing Time  = %12.03f %s\n", $ATET_, $time_unit);
print $OUTPUT "$string_to_print\n";

print "$string_to_print\n";

close ($OUTPUT);
print "\nExiting\n";
