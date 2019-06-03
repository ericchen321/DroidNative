#!/bin/bash
# author: Ryan Riley
#         Eric Chen
# this script converts all apk files in given directory to disassembly
# using on-host conversion
# usage:
# first param: path to directory where benign apks are stored
# 2nd param: path to directory where malware apks are stored
# 3rd param: path to output directory where benign txts are stored
# 4th param: path to output directory where malware txts are stored

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

	for APK in  $(ls $in_dir/*.apk |sort -R); do
		cp $in_dir/$(basename "$APK" ) ./$(basename "$APK" )
        
		timeout 15s ${AOSP_DIR}/out/host/linux-x86/bin/dex2oat --runtime-arg -classpath --runtime-arg $(basename "$APK" ) --instruction-set=arm --runtime-arg -Xrelocate --host --boot-image=$BOOT_IMAGE --dex-file=$(basename "$APK" ) --oat-file=$(basename "$APK" ).dex
        exit_status=$?
		if [ $exit_status -ne 124 ] && [ $exit_status -ne 125 ] && [ $exit_status -ne 126 ] && [ $exit_status -ne 127 ] && [ $exit_status -ne 137 ]; then
    		timeout 15s ${AOSP_DIR}/out/host/linux-x86/bin/oatdump --oat-file=$(basename "$APK" ).dex --instruction-set=arm --output=$out_dir/$(basename "$APK" ).dex.txt
			exit_status=$?
			if [[ $exit_status -eq 124 ]]; then
				echo "running oatdump on $(basename "$APK" ) timed out"
				rm $out_dir/$(basename "$APK" ).dex.txt
			fi
		else
			echo "running dex2oat on $(basename "$APK" ) timed out"
		fi
		rm $(basename "$APK" )
		rm $(basename "$APK" ).dex
	done
}

if [ "$#" -ne 4 ]; then
    echo "You are not using it the right way. Please read the comments in script"
    exit 1
fi

in_dir_benign="$1"
in_dir_mal="$2"
out_dir_benign="$3"
out_dir_mal="$4"

AOSP_DIR="/data/guanxiong/android_source"
export ANDROID_DATA="${AOSP_DIR}/out/host/datadir/dalvik-cache/x86_64"
export ANDROID_ROOT="${AOSP_DIR}/out/host/linux-x86"
BOOT_IMAGE="${AOSP_DIR}/out/target/product/generic/system/framework/boot.art"
mkdir -p $ANDROID_DATA
cd $AOSP_DIR
convert "malware"
convert "benign"