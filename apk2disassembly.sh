#!/bin/bash
# this script converts all apk files in given directory to disassembly
# usage:
# first param: path to directory where apk files are stored
# second param: name of running emulator
# 3rd param: path to output directory

if [ "$#" -ne 3 ]; then
    echo "You are not using it the right way"
    exit 1
fi

# FIXME: now assume each apk has only one dex file; should add ability to
# handle multiple dex files later
for APK in  $(ls $1/*.apk |sort -R); do
	mkdir ./temp/
	unzip -o ${APK} classes.dex -d ./temp/
	adb -s $2 push ./temp/classes.dex /sdcard/
	adb -s $2 shell dex2oat --dex-file=/sdcard/classes.dex --oat-file=/sdcard/classes.dex.oat --instruction-set-features=div
	adb -s $2 shell oatdump --oat-file=/sdcard/classes.dex.oat --output=/sdcard/$(basename "$APK" .apk).dex.oat.txt
	adb -s $2 pull /sdcard/$(basename "$APK" .apk).dex.oat.txt ${3}/
	adb -s $2 shell rm /sdcard/classes.dex
	adb -s $2 shell rm /sdcard/classes.dex.oat
	adb -s $2 shell rm /sdcard/$(basename "$APK" .apk).dex.oat.txt
	rm -r ./temp/
done