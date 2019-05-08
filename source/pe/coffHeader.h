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

#ifndef __COFF_HEADER_H__
#define __COFF_HEADER_H__

#include <stdio.h>
#include <iostream>
#include <stdint.h>

using namespace std;

/*
 * Flags
 */
#define IMAGE_FILE_RELOCS_STRIPPED			0x0001	// Image only, Windows CE, and Windows NT® and later. This indicates
													// that the file does not contain base relocations and must therefore be
													// loaded at its preferred base address. If the base address is not available,
													// the loader reports an error. The default behavior of the linker is to strip
													// base relocations from executable (EXE) files.
#define IMAGE_FILE_EXECUTABLE_IMAGE			0x0002	// Image only. This indicates that the image file is valid and can be run. If
													// this flag is not set, it indicates a linker error.
#define IMAGE_FILE_LINE_NUMS_STRIPPED		0x0004	// COFF line numbers have been removed. This flag is deprecated and should be zero.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED		0x0008	// COFF symbol table entries for local symbols have been removed. This flag is
													// deprecated and should be zero.
#define IMAGE_FILE_AGGRESSIVE_WS_TRIM		0x0010	// Obsolete. Aggressively trim working set. This flag is deprecated for Windows
													// 2000 and later and must be zero.
#define IMAGE_FILE_LARGE_ADDRESS_AWARE		0x0020	// Application can handle > 2GB addresses.
#define IMAGE_FILE_FUTURE_USE				0x0040	// This flag is reserved for future use.
#define IMAGE_FILE_BYTES_REVERSED_LO		0x0080	// Little endian: the least significant bit (LSB) precedes the most significant
													// bit (MSB) in memory. This flag is deprecated and should be zero.
#define IMAGE_FILE_32BIT_MACHINE			0x0100	// Machine is based on a 32-bit-word architecture.
#define IMAGE_FILE_DEBUG_STRIPPED			0x0200	// Debugging information is removed from the image file.
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP	0x0400	// If the image is on removable media, fully load it and copy it to the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP		0x0800	// If the image is on network media, fully load it and copy it to the swap file.
#define IMAGE_FILE_SYSTEM					0x1000	// The image file is a system file, not a user program.
#define IMAGE_FILE_DLL						0x2000	// The image file is a dynamic-link library (DLL). Such files are considered
													// executable files for almost all purposes, although they cannot be directly run.
#define IMAGE_FILE_UP_SYSTEM_ONLY			0x4000	// The file should be run only on a uniprocessor machine.
#define IMAGE_FILE_BYTES_REVERSED_HI		0x8000	// Big endian: the MSB precedes the LSB in memory. This flag is deprecated and
													// should be zero

/**
 * <p>
 * This class implements the CoffHeader class.
 * It stores the COFF header as defined in:
 * http://msdn.microsoft.com/en-us/windows/hardware/gg463119.aspx
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since March 04, 2013
 *
 */
class CoffHeader
{
public:
	uint32_t length;
	uint16_t Machine;                  // 2 bytes The type of target machine
	uint16_t NumberOfSections;         // 2 bytes This indicates the size of the section table, which immediately follows the headers.
	uint32_t TimeDateStamp;            // 4 bytes The low 32 bits of the number of seconds since 00:00 January 1, 1970 (a C run-time time_t value), that indicates when the file was created.
	uint32_t PointerToSymbolTable;     // 4 bytes The file offset of the COFF symbol table, or zero if no COFF symbol table is present. This value should be zero for an image because COFF debugging information is deprecated.
	uint32_t NumberOfSymbols;          // 4 bytes The number of entries in the symbol table. This data can be used to locate the string table, which immediately follows the symbol table. This value should be zero for an image because COFF debugging information is deprecated.
	uint16_t SizeOfOptionalHeader;     // 2 bytes The size of the optional header, which is required for executable files but not for object files. This value should be zero for an object file.
	uint16_t Characteristics;          // 2 bytes The flags;

	CoffHeader()
	{
		length               = 20;  // 20 bytes
		Machine              = 0;
		NumberOfSections     = 0;
		TimeDateStamp        = 0;
		PointerToSymbolTable = 0;
		NumberOfSymbols      = 0;
		SizeOfOptionalHeader = 0;
		Characteristics      = 0;
	}

	bool isEXE()
	{
		if (Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
			return (true);
		return false;
	}

	bool isDLL()
	{
		if (Characteristics & IMAGE_FILE_DLL)
			return (true);
		return false;
	}

	bool isLittleEndian()
	{
		if (Characteristics & IMAGE_FILE_BYTES_REVERSED_LO)
			return (true);
		return false;
	}
	bool isBigEndian()
	{
		if (Characteristics & IMAGE_FILE_BYTES_REVERSED_HI)
			return (true);
		return false;
	}

	void Print()
	{
		switch(Machine)
		{
		case 0x0:
			printf ("   Machine = Unknown\n");
			break;
		case 0x1d3:
			printf ("   Machine = Matsushita AM33\n");
			break;
		case 0x8664:
			printf ("   Machine = x64\n");
			break;
		case 0x1c0:
			printf ("   Machine = ARM little endian\n");
			break;
		case 0x1c4:
			printf ("   Machine = ARMv7 (or higher) Thumb mode only\n");
			break;
		case 0xaa64:
			printf ("   Machine = ARMv8 in 64-bit mode\n");
			break;
		case 0xebc:
			printf ("   Machine = EFI byte code\n");
			break;
		case 0x14c:
			printf ("   Machine = Intel 386 or later processors and compatible processors\n");
			break;
		case 0x200:
			printf ("   Machine = Intel Itanium processor family\n");
			break;
		case 0x9041:
			printf ("   Machine = Mitsubishi M32R little endian\n");
			break;
		case 0x266:
			printf ("   Machine = MIPS16\n");
			break;
		case 0x366:
			printf ("   Machine = MIPS with FPU\n");
			break;
		case 0x466:
			printf ("   Machine = MIPS16 with FPU\n");
			break;
		case 0x1f0:
			printf ("   Machine = Power PC little endian\n");
			break;
		case 0x1f1:
			printf ("   Machine = Power PC with floating point support\n");
			break;
		case 0x166:
			printf ("   Machine = MIPS little endian\n");
			break;
		case 0x1a2:
			printf ("   Machine = Hitachi SH3\n");
			break;
		case 0x1a3:
			printf ("   Machine = Hitachi SH3 DSP\n");
			break;
		case 0x1a6:
			printf ("   Machine = Hitachi SH4\n");
			break;
		case 0x1a8:
			printf ("   Machine = Hitachi SH5\n");
			break;
		case 0x1c2:
			printf ("   Machine = ARM or Thumb ('interworking')\n");
			break;
		case 0x169:
			printf ("   Machine = MIPS little-endian WCE v2\n");
			break;
		}

		printf ("   NumberOfSections = %d\n", NumberOfSections);
		printf ("   TimeDateStamp = 0x%X\n", TimeDateStamp);
		printf ("   PointerToSymbolTable = 0x%X\n", PointerToSymbolTable);
		printf ("   NumberOfSymbols = %d\n", NumberOfSymbols);
		printf ("   SizeOfOptionalHeader = %d\n", SizeOfOptionalHeader);
		printf ("   Characteristics = 0x%X\n", Characteristics);
	}
};

#endif // __COFF_HEADER_H__
