#!/bin/bash
# this script converts all apk files in given directory to disassembly
# usage:
# first param: path to directory where benign apks are stored
# 2nd param: path to directory where malware apks are stored
# 3rd param: name of running emulator
# 4th param: path to output directory where benign txts are stored
# 5th param: path to output directory where malware txts are stored

convert () {
	if [ "$1" = "benign" ]; then
		in_dir="$in_dir_benign"
		out_dir="$out_dir_benign"
		temp="benign_temp"
	elif [ "$1" = "malware" ]; then
		in_dir="$in_dir_mal"
		out_dir="$out_dir_mal"
		temp="malware_temp"
	else
		echo "Error"
		exit 1
	fi

	# FIXME: now assume each apk has only one dex file; should add ability to
	# handle multiple dex files later
	for APK in  $(ls $in_dir/*.apk |sort -R); do
		mkdir ./$temp/
		unzip -o ${APK} classes.dex -d ./$temp/
		adb -s $emulator shell mkdir /sdcard/$temp
		adb -s $emulator push ./$temp/classes.dex /sdcard/$temp
		adb -s $emulator shell dex2oat --dex-file=/sdcard/$temp/classes.dex --oat-file=/sdcard/$temp/classes.dex.oat --instruction-set-features=div
		adb -s $emulator shell oatdump --oat-file=/sdcard/$temp/classes.dex.oat --output=/sdcard/$temp/$(basename "$APK" .apk).dex.oat.txt
		adb -s $emulator pull /sdcard/$temp/$(basename "$APK" .apk).dex.oat.txt $out_dir/
		adb -s $emulator shell rm -rf /sdcard/$temp
		rm -rf ./$temp/
	done
}

if [ "$#" -ne 5 ]; then
    echo "You are not using it the right way. Please read the comments in script"
    exit 1
fi

in_dir_benign="$1"
in_dir_mal="$2"
emulator="$3"
out_dir_benign="$4"
out_dir_mal="$5"

convert "malware" &
convert "benign" &
wait