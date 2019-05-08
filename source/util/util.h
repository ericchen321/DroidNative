/**
 * Copyright (C) 2015 Shahid Alam

 * This program is free software: you can redistribute it and/or modify it under the terms of the GNU General
 * Public License as published by the Free Software Foundation, either version 3 of the License, or (at your 
 * option) any later version. This program is distributed in the hope that it will be useful, but WITHOUT ANY 
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the 
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along with this program. If not, see 
 * http://www.gnu.org/licenses/.

 * For any questions, please contact me @ alam_shahid@yahoo.com.
 */

#ifndef __UTIL_H__
#define __UTIL_H__

#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <stdio.h>
#include <stdint.h>
#include <math.h>

#include "../include/common.h"

using namespace std;

/**
 * <p>
 * This class implements the Util class.
 * It provides different utilities.
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since April 22, 2012
 *
 */
class Util
{
public:
	static void flipHex(char *hex, unsigned int size);
	static string removeWhiteSpaces(string str);
	static bool isNumeric(string str);

	static bool isHex(char c);
	static bool isHexString(string s);
	vector<int64_t> readHexNumbers(const char *str, unsigned int size);
	static uint8_t CharHex(unsigned char ch1, unsigned char ch2);
	static int64_t hexStringToInt(string hexString);

	static int8_t ReadByte(unsigned int from, const char *buffer);
	static int16_t ReadShort(unsigned int from, const char *buffer);
	static int32_t ReadInt(unsigned int from, const char *buffer);
	static int64_t ReadLong(unsigned int from, const char *buffer);

	static void WriteByte(int8_t new_int, unsigned int from, char *buffer);
	static void WriteShort(int16_t new_int, unsigned int from, char *buffer);
	static void WriteInt(int32_t new_int, unsigned int from, char *buffer);
	static void WriteLong(int64_t new_int, unsigned int from, char *buffer);
	static void PrintData(_data *data);
	static void PrintCode(_code *code, bool IS_X86);
};

#endif // __UTIL_H__
