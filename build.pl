#!/usr/bin/perl
#
# Author: Shahid Alam
# Dated: May 29, 2015
# E-mail: alam_shahid@yahoo.com
#
# Build DroidNative
#

use strict;
use warnings;
use Config;
use Cwd;
use File::Copy;

my $CURRENT_DIR = cwd();
my $CAPSTONE_DIR = "$CURRENT_DIR/lib/capstone-3.0";
my $LIBS_DIR = "$CURRENT_DIR/lib";
my $OS = "$Config{osname}";
print "Running on $OS\n";

chdir $CAPSTONE_DIR;
my $cmd = sprintf("chmod 755 make.sh \n ./make.sh");
print "------------------------------\n";
print "Building the library\n\n";
system ($cmd);
chdir $CURRENT_DIR;

if ( $OS =~ m/.*cygwin.*/i )
{
   my $lib_file = "$CAPSTONE_DIR/capstone.lib";
   if (-e $lib_file)
   {
      copy ($lib_file, $LIBS_DIR);
      my $cmd = sprintf("make -s -f Makefile-ACFG clean_all \n make -s -f Makefile-ACFG all");
      print "------------------------------\n";
      print "Building DroidNative-ACFG\n\n";
      system ($cmd);
      $cmd = sprintf("make -s -f Makefile-SWOD clean_all \n make -s -f Makefile-SWOD all");
      print "------------------------------\n";
      print "Building DroidNative-SWOD\n\n";
      system ($cmd);
      $cmd = sprintf("make -s -f Makefile-Only-MAIL clean_all \n make -s -f Makefile-Only-MAIL all");
      print "------------------------------\n";
      print "Building DroidNative-SWOD\n\n";
      system ($cmd);
      print "------------------------------\n";
   }
   else
   {
      print "Error building the library\n";
   }
}
elsif ( $OS =~ m/.*linux.*/i )
{
   my $lib_file = "$CAPSTONE_DIR/libcapstone.a";
   if (-e $lib_file)
   {
      copy ($lib_file, $LIBS_DIR);
      my $cmd = sprintf("make -s -f Makefile-ACFG clean_all \n make -s -f Makefile-ACFG all");
      print "------------------------------\n";
      print "Building DroidNative-ACFG\n\n";
      system ($cmd);
      $cmd = sprintf("make -s -f Makefile-SWOD clean_all \n make -s -f Makefile-SWOD all");
      print "------------------------------\n";
      print "Building DroidNative-SWOD\n\n";
      system ($cmd);
      $cmd = sprintf("make -s -f Makefile-Only-MAIL clean_all \n make -s -f Makefile-Only-MAIL all");
      print "------------------------------\n";
      print "Building DroidNative-SWOD\n\n";
      system ($cmd);
      print "------------------------------\n";
   }
   else
   {
      print "Error building the library\n";
   }
}
else
{
   print "Platform '$OS' not supported\n";
}
