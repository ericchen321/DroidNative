#!/bin/bash
# this script converts all apk files in given directory to disassembly
# usage:
# first param: path to directory where apks are stored
# 2nd param: path to output directory where txts are stored
# 3rd param: path to output directory where dex2oat logs are stored
# 4th param: name of running emulator

if [ "$#" -ne 4 ]; then
    echo "You are not using it the right way. Please read the comments in script"
    exit 1
fi

in_dir="$1"
out_txt_dir="$2"
out_log_dir="$3"
emulator="$4"

mkdir -p $out_txt_dir
mkdir -p $out_log_dir
cd $in_dir

for APK in  $(ls $in_dir/*.apk |sort -R); do
	adb -s $emulator push ${APK} /sdcard/
	adb -s $emulator logcat -c
	adb -s $emulator shell dex2oat --runtime-arg -classpath --runtime-arg $(basename "$APK" ) --instruction-set=x86 --runtime-arg -Xrelocate --dex-file=/sdcard/$(basename "$APK" ) --oat-file=/sdcard/$(basename "$APK" ).oat
	adb -s $emulator logcat -b main -d > $out_log_dir/$(basename "$APK" ).dex2oat.log
	adb -s $emulator shell oatdump --oat-file=/sdcard/$(basename "$APK" ).oat --output=/sdcard/$(basename "$APK" ).oat.txt
	adb -s $emulator pull /sdcard/$(basename "$APK" ).oat.txt $out_txt_dir/
	adb -s $emulator shell rm /sdcard/$(basename "$APK" )
	adb -s $emulator shell rm /sdcard/$(basename "$APK" ).vdex
	adb -s $emulator shell rm /sdcard/$(basename "$APK" ).oat
	adb -s $emulator shell rm /sdcard/$(basename "$APK" ).oat.txt
done