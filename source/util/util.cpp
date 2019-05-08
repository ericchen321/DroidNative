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

#include "util.h"
#include <iomanip>

/*
 * General purpose (works for different sizes) hex flipping function to store hex.
 * The hex string can also start with '0x'.
 */
void Util::flipHex(char *hex, unsigned int size)
{
#ifdef __DEBUG__
	printf("Original hex: %s\n", hex);
#endif
	if (size%2 > 0)
		cout << "Error:Util::flipHex: Not a hex number\n";
	else
	{
		char temp[2];
		int s = 0, e = size - 1;
		if (hex[0] == '0' && hex[1] == 'x')
		{
			s = 2;
			size = size - 2;
		}
		for ( ; s < size/2; s += 2,e -= 2)
		{
			temp[0] = hex[e-1];
			temp[1] = hex[e];
			hex[e-1] = hex[s];
			hex[e] = hex[s+1];
			hex[s] = temp[0];
			hex[s+1] = temp[1];
		}
	}
#ifdef __DEBUG__
	printf("Flipped hex: %s\n", hex);
#endif
}

/*
 *
 * Read hex numbers from a string of characters and
 * returns them in a vector of 64 bit integers
 * e.g:
 *    "QWORD [RAX*8+0x600e28+0x2003af]"
 * returned as:
 *    { 600e28, 2003af }
 *
 */
vector<int64_t> Util::readHexNumbers(const char *str, unsigned int size)
{
	vector<int64_t> numbers;
	uint16_t i = 0;
	while (str[i] != '\0' && i < (size - 1))
	{
		if (str[i] == '0' && str[i+1] == 'x')
		{
			uint16_t j = i + 2;
			string nums;
			while (str[j] != '\0' && j < size)
			{
				if (isHex(str[j])) { nums += str[j]; }
				else { j--; break; }
				j++;
			}
			if (nums.size() > 0)
			{
				int64_t num;
				stringstream ss;
				ss << nums;
				ss >> hex >> num;
				numbers.push_back(num);
				nums.assign("");
			}
			i = j;
		}
		i++;
	}

	return (numbers);
}

/*
 * Removing white spaces from front and back
 */
string Util::removeWhiteSpaces(string str)
{
	string s;
	int space = str.find_first_not_of(' ');
	str = str.erase(0, space);
	space = str.find_last_not_of(' ');
	s = str.erase(space+1, str.size());
	return s;
}

/*
 * Only decimal numbers
 */
bool Util::isNumeric(string str)
{
	for (int i = 0; i < str.size(); i++)
		if (isalpha(str[i]))
			return false;
	return true;
}

/*
 * Only hex numbers
 */
bool Util::isHex(char c)
{
	bool ishex = false;
	if (isdigit(c))
		return true;

	switch(c)
	{
	case 'a': ishex = true; break; case 'A': ishex = true; break;
	case 'b': ishex = true; break; case 'B': ishex = true; break;
	case 'c': ishex = true; break; case 'C': ishex = true; break;
	case 'd': ishex = true; break; case 'D': ishex = true; break;
	case 'e': ishex = true; break; case 'E': ishex = true; break;
	case 'f': ishex = true; break; case 'F': ishex = true; break;
	}

	return ishex;
}

/*
 * Only hex numbers, it assumes that there are no
 * empty spaces in the beginning of the string
 */
bool Util::isHexString(string s)
{
	int i = 0;
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
		i = 2;
	for ( ; i < s.size(); i++)
	{
		if (!isHex(s[i]))
			return false;
	}

	return true;
}

/*
 *
 * Take two ASCII values of characters.
 * Translate them to hex:
 * e.g: 0xA -> 'A'
 *      0xa -> 'A'
 *      0x0 -> '0'
 * And return a character with both values
 * concatenated using little endian format.
 * ch = ch_msb + ch_lsb
 *
 */
uint8_t Util::CharHex(unsigned char ch_msb, unsigned char ch_lsb)
{
	if (ch_msb >= '0' && ch_msb <= '9')
		ch_msb = ch_msb + 48;
	else if (ch_msb >= 'A' && ch_msb <= 'F')
		ch_msb = ch_msb + 55;
	else if (ch_msb >= 'a' && ch_msb <= 'f')
		ch_msb = ch_msb + 89;
	else
		cerr << "Error::Util::CharHex: Wrong hex character " << ch_msb << "\n";
	if (ch_lsb >= '0' && ch_lsb <= '9')
		ch_lsb = ch_lsb + 48;
	else if (ch_lsb >= 'A' && ch_lsb <= 'F')
		ch_lsb = ch_lsb + 55;
	else if (ch_lsb >= 'a' && ch_lsb <= 'f')
		ch_lsb = ch_lsb + 89;
	else
		cerr << "Error::Util::CharHex: Wrong hex character " << ch_lsb << "\n";

	uint8_t ch = ((ch_msb << 4) & 0xF0) | (ch_lsb & 0x0F);
	return ch;
}

/*
 * Converting hex string to int
 * e.g: a00(hex) = 2560(int)
 */
int64_t Util::hexStringToInt(string hexString)
{
	char hexString_local[128];
	int len = sprintf(hexString_local, "%s", hexString.c_str());
#ifdef __DEBUG__
	printf("hexString: %s ", hexString_local);
#endif
	int64_t hex = 0;
	for (int i = len-1,n = 0; i >= 0;i--,n++)
	{
		if (hexString_local[i] == 'a')
			hex += pow(16, n) * 10;
		else if (hexString_local[i] == 'b')
			hex += pow(16, n) * 11;
		else if (hexString_local[i] == 'c')
			hex += pow(16, n) * 12;
		else if (hexString_local[i] == 'd')
			hex += pow(16, n) * 13;
		else if (hexString_local[i] == 'e')
			hex += pow(16, n) * 14;
		else if (hexString_local[i] == 'f')
			hex += pow(16, n) * 15;
		else if (isdigit(hexString_local[i]))
			hex += pow(16, n) * (hexString[i] - '0');
		else
			return -1;
	}
#ifdef __DEBUG__
	printf("converted to: %x", (int)hex);
#endif
	return hex;
}

/*
 *  Read 1 byte from buffer start @ from (Little endian format)
 */
int8_t Util::ReadByte(unsigned int from, const char *buffer)
{
	int8_t b = buffer[from];
	return b;
}

/*
 *  Read 2 bytes from buffer start @ from (Little endian format)
 */
int16_t Util::ReadShort(unsigned int from, const char *buffer)
{
	int8_t b1 = buffer[from++]; int8_t b2 = buffer[from++];
	int16_t result = (int32_t)( (b1&0x00FF) | ((b2&0x00FF) << 8) );
	return result;
}

/*
 *  Read 4 bytes from buffer start @ from (Little endian format)
 */
int32_t Util::ReadInt(unsigned int from, const char *buffer)
{
	int8_t b1 = buffer[from++]; int8_t b2 = buffer[from++];
	int8_t b3 = buffer[from++]; int8_t b4 = buffer[from++];
	int32_t result = (int32_t)( (b1&0x000000FF) | ((b2&0x000000FF) << 8)
								| ((b3&0x000000FF) << 16) | ((b4&0x000000FF) << 24) );
	return result;
}

/*
 *  Read 8 bytes from buffer start @ from (Little endian format)
 */
int64_t Util::ReadLong(unsigned int from, const char *buffer)
{
	int8_t b1 = buffer[from++]; int8_t b2 = buffer[from++];
	int8_t b3 = buffer[from++]; int8_t b4 = buffer[from++];
	int8_t b5 = buffer[from++]; int8_t b6 = buffer[from++];
	int8_t b7 = buffer[from++]; int8_t b8 = buffer[from++];
	int64_t result = (int64_t)(b1&0x00000000000000FF) | ((int64_t)(b2&0x00000000000000FF) << 8)
						| ((int64_t)(b3&0x00000000000000FF) << 16) | ((int64_t)(b4&0x00000000000000FF) << 24)
						| ((int64_t)(b5&0x00000000000000FF) << 32) | ((int64_t)(b6&0x00000000000000FF) << 40)
						| ((int64_t)(b7&0x00000000000000FF) << 48) | ((int64_t)(b8&0x00000000000000FF) << 56);
	return result;
}

/*
 *  Write 1 byte data to buffer starting @ from (Little endian format)
 */
void Util::WriteByte(int8_t new_int, unsigned int from, char *buffer)
{
	buffer[from] = new_int;
}

/*
 *  Write 2 bytes data to buffer starting @ from (Little endian format)
 */
void Util::WriteShort(int16_t new_int, unsigned int from, char *buffer)
{
	int8_t b1 = (int8_t)( new_int & 0x00FF );
	int8_t b2 = (int8_t)( (new_int >> 8) & 0x00FF );
	buffer[from++] = b1; buffer[from++] = b2;
}

/*
 *  Write 4 bytes data to buffer starting @ from (Little endian format)
 */
void Util::WriteInt(int32_t new_int, unsigned int from, char *buffer)
{
	int8_t b1 = (int8_t)( new_int & 0x000000FF );
	int8_t b2 = (int8_t)( (new_int >> 8) & 0x000000FF );
	int8_t b3 = (int8_t)( (new_int >> 16) & 0x000000FF );
	int8_t b4 = (int8_t)( (new_int >> 24) & 0x000000FF );
	buffer[from++] = b1; buffer[from++] = b2;
	buffer[from++] = b3; buffer[from++] = b4;
}

/*
 *  Write 8 bytes data to buffer starting @ from (Little endian format)
 */
void Util::WriteLong(int64_t new_int, unsigned int from, char *buffer)
{
	int8_t b1 = (int8_t)( new_int & 0x00000000000000FF );
	int8_t b2 = (int8_t)( (new_int >> 8) & 0x00000000000000FF );
	int8_t b3 = (int8_t)( (new_int >> 16) & 0x00000000000000FF );
	int8_t b4 = (int8_t)( (new_int >> 24) & 0x00000000000000FF );
	int8_t b5 = (int8_t)( (new_int >> 32) & 0x00000000000000FF );
	int8_t b6 = (int8_t)( (new_int >> 40) & 0x00000000000000FF );
	int8_t b7 = (int8_t)( (new_int >> 48) & 0x00000000000000FF );
	int8_t b8 = (int8_t)( (new_int >> 56) & 0x00000000000000FF );
	buffer[from++] = b1; buffer[from++] = b2;
	buffer[from++] = b3; buffer[from++] = b4;
	buffer[from++] = b5; buffer[from++] = b6;
	buffer[from++] = b7; buffer[from++] = b8;
}

/**
 * <p>
 * Prints the data from the data Sections
 * </p>
 */
void Util::PrintData(_data *data)
{
	cout << "\n-------------------------------------------------" << endl;
	cout << "     Printing [data] Section: " << data->name;
	cout << "\n-------------------------------------------------" << endl;
	printf ("Size: %8d\n", (int)data->data_size);
	uint64_t offset = data->offset;
	printf ("%12x   ", (unsigned int)offset);
	for (unsigned int i = 1; i <= data->data_size; i++)
	{
		printf ("%02x ", data->buffer[i-1]);
		if ((i % 10) == 0)
		{
			cout << "\n";
			printf ("%12x   ", (unsigned int)(offset += 10));
		}
	}
	cout << "\n";
}

/**
 * <p>
 * Prints the code from the code Sections
 * </p>
 */
void Util::PrintCode(_code *code, bool IS_X86)
{
	cout << "\n-------------------------------------------------" << endl;
	cout << "     Printing [code] Section: " << code->name;
	cout << "\n-------------------------------------------------" << endl;
	printf ("Size: %8d\n", (int)code->buffer_size);
	for (unsigned int i = 0; i < code->code_size; i++)
	{
		if (IS_X86)
		{
			int size = code->decoded->size;
			cout << right << dec << setw(8) << i << " ";
			cout << right << hex << setw(8) << setfill('0') << code->decoded[i].offset << " ";
			cout << left << setw(2) << "(" << setfill('0') << size << ") ";
			cout << setfill(' ');
			for (int c = 0 ; c < (2*size); )
			{
				cout << code->decoded[i].instructionHex.p[c++];
				cout << code->decoded[i].instructionHex.p[c++] << " ";
			}
			size = 48 - (2*size+size);
			cout << setw(size) << " ";
			cout << "(" << setw(2) << setfill('0') << code->decoded[i].operands.length << ")   ";
			cout << setw(12) << setfill(' ') << (char*)code->decoded[i].mnemonic.p << " ";
			cout << (char*)code->decoded[i].operands.p << "\n";
		}
		else if (code->instructions->size > 0)
		{
			printf("0x%x:\t%s\t\t%s\n", (int)code->instructions[i].address, code->instructions[i].mnemonic, code->instructions[i].op_str);
		}
	}

	if (code->buffer_size > 1)
	{
		printf ("\nPrinting Code buffer: Size: %8d\n", (int)code->buffer_size);
		uint64_t offset = code->offset;
		printf ("%12x   ", (unsigned int)offset);
		for (unsigned int i = 1; i <= code->buffer_size; i++)
		{
			printf ("%02x ", code->buffer[i-1]);
			if ((i % 10) == 0)
			{
				cout << "\n";
				printf ("%12x   ", (unsigned int)(offset += 10));
			}
		}
		cout << "\n";
	}
}
