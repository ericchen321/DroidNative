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

#include "sectionHeaderPE.h"

SectionHeaderPE::SectionHeaderPE()
{
	length               = 40;  // 40 bytes
	alignment            = 0;
	Name[0]              = 0;
	VirtualSize          = 0;
	VirtualAddress       = 0;
	SizeOfRawData        = 0;
	PointerToRawData     = 0;
	PointerToRelocations = 0;
	PointerToLinenumbers = 0;
	NumberOfRelocations  = 0;
	NumberOfLinenumbers  = 0;
	Characteristics      = 0;
	buffer               = 0;
}

bool SectionHeaderPE::IsTextBss()
{
	bool res = false;
	if (Name != 0)
	{
		res = (Name[0] == (uint8_t)('.'))
				&& (Name[1] == (uint8_t)('t'))
				&& (Name[2] == (uint8_t)('e'))
				&& (Name[3] == (uint8_t)('x'))
				&& (Name[4] == (uint8_t)('t'))
				&& (Name[5] == (uint8_t)('b'))
				&& (Name[6] == (uint8_t)('s'))
				&& (Name[7] == (uint8_t)('s'));
	}
	return res;
}

bool SectionHeaderPE::IsText()
{
	bool res = false;
	if (Name != 0)
	{
		res = (Name[0] == (uint8_t)('.'))
				&& (Name[1] == (uint8_t)('t'))
				&& (Name[2] == (uint8_t)('e'))
				&& (Name[3] == (uint8_t)('x'))
				&& (Name[4] == (uint8_t)('t'));
	}
	return res;
}

bool SectionHeaderPE::IsData()
{
	bool res = false;
	if (Name != 0)
	{
		res = (Name[0] == (uint8_t)('.'))
			&& (Name[1] == (uint8_t)('d'))
			&& (Name[2] == (uint8_t)('a'))
			&& (Name[3] == (uint8_t)('t'))
			&& (Name[4] == (uint8_t)('a'));
	}
	return res;
}

bool SectionHeaderPE::IsRData()
{
	bool res = false;
	if (Name != 0)
	{
		res = (Name[0] == (uint8_t)('.'))
			&& (Name[1] == (uint8_t)('r'))
			&& (Name[2] == (uint8_t)('d'))
			&& (Name[3] == (uint8_t)('a'))
			&& (Name[4] == (uint8_t)('t'))
			&& (Name[5] == (uint8_t)('a'));
	}
	return res;
}

bool SectionHeaderPE::IsPData()
{
	bool res = false;
	if (Name != 0)
	{
		res = (Name[0] == (uint8_t)('.'))
			&& (Name[1] == (uint8_t)('p'))
			&& (Name[2] == (uint8_t)('d'))
			&& (Name[3] == (uint8_t)('a'))
			&& (Name[4] == (uint8_t)('t'))
			&& (Name[5] == (uint8_t)('a'));
	}
	return res;
}

bool SectionHeaderPE::IsReloc()
{
	bool res = false;
	if (Name != 0)
	{
		res = (Name[0] == (uint8_t)('.'))
			&& (Name[1] == (uint8_t)('r'))
			&& (Name[2] == (uint8_t)('e'))
			&& (Name[3] == (uint8_t)('l'))
			&& (Name[4] == (uint8_t)('o'))
			&& (Name[5] == (uint8_t)('c'));
	}
	return res;
}

bool SectionHeaderPE::IsRsrc()
{
	bool res = false;
	if (Name != 0)
	{
		res = (Name[0] == (uint8_t)('.'))
			&& (Name[1] == (uint8_t)('r'))
			&& (Name[2] == (uint8_t)('s'))
			&& (Name[3] == (uint8_t)('r'))
			&& (Name[4] == (uint8_t)('c'));
	}
	return res;
}

bool SectionHeaderPE::IsExe()
{
	if (Characteristics & IMAGE_SCN_CNT_CODE)
		return true;
	else if (IsText())
		return true;
	return false;
}

bool SectionHeaderPE::IsInitData()
{
	if (Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
		return true;
	return false;
}

bool SectionHeaderPE::IsUninitData()
{
	if (Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
		return true;
	return false;
}

void SectionHeaderPE::Print(bool printBuffer)
{
	if (Name != 0)
		cout << "   Name = " << Name << "\n";
	printf ("   VirtualSize = 0x%X\n", VirtualSize);
	printf ("   VirtualAddress = 0x%X\n", VirtualAddress);
	printf ("   SizeOfRawData = 0x%X\n", SizeOfRawData);
	printf ("   PointerToRawData = 0x%X\n", PointerToRawData);
	printf ("   PointerToRelocations = 0x%X\n", PointerToRelocations);
	printf ("   PointerToLinenumbers = 0x%X\n", PointerToLinenumbers);
	printf ("   NumberOfRelocations = 0x%X\n", NumberOfRelocations);
	printf ("   NumberOfLinenumbers = 0x%X\n", NumberOfLinenumbers);
	printf ("   Characteristics = 0x%X\n", Characteristics);
	if (printBuffer && (buffer != 0))
	{
		for (uint64_t i = 1; i <= buffer_len; i++)
		{
			printf ("%X ", buffer[i-1]);
			if ((i % 10) == 0)
				cout << "\n";
		}
	}
	cout <<  "\n";
}
