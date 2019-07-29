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

#ifndef __SECTION_HEADER_PE_H__
#define __SECTION_HEADER_PE_H__

#include <stdio.h>
#include <iostream>
#include <stdint.h>

using namespace std;

//#define RESERVED_1								0x00000000	// Reserved for future use.
//#define RESERVED_2								0x00000001	// Reserved for future use.
//#define RESERVED_3								0x00000002	// Reserved for future use.
//#define RESERVED_4								0x00000004	// Reserved for future use.
#define IMAGE_SCN_TYPE_NO_PAD					0x00000008	// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
//#define RESERVED_5								0x00000010	// Reserved for future use.
#define IMAGE_SCN_CNT_CODE						0x00000020	// The section contains executable code.
#define IMAGE_SCN_CNT_INITIALIZED_DATA			0x00000040	// The section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA		0x00000080	// The section contains uninitialized data.
#define IMAGE_SCN_LNK_OTHER						0x00000100	// Reserved for future use.
#define IMAGE_SCN_LNK_INFO						0x00000200	// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
//#define RESERVED_6								0x00000400	// Reserved for future use.
#define IMAGE_SCN_LNK_REMOVE					0x00000800	// The section will not become part of the image. This is valid only for object files.
#define IMAGE_SCN_LNK_COMDAT					0x00001000	// The section contains COMDAT data. For more information, see section 5.5.6, “COMDAT Sections (Object Only).” This is valid only for object files.
#define IMAGE_SCN_GPREL							0x00008000	// The section contains data referenced through the global pointer (GP).
#define IMAGE_SCN_MEM_PURGEABLE					0x00020000	// Reserved for future use.
#define IMAGE_SCN_MEM_16BIT						0x00020000	// For ARM machine types, the section contains Thumb code. Reserved for future use with other machine types.
#define IMAGE_SCN_MEM_LOCKED					0x00040000	// Reserved for future use.
#define IMAGE_SCN_MEM_PRELOAD					0x00080000	// Reserved for future use.
#define IMAGE_SCN_ALIGN_1BYTES					0x00100000	// Align data on a 1-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_2BYTES					0x00200000	// Align data on a 2-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_4BYTES					0x00300000	// Align data on a 4-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_8BYTES					0x00400000	// Align data on an 8-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_16BYTES					0x00500000	// Align data on a 16-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_32BYTES					0x00600000	// Align data on a 32-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_64BYTES					0x00700000	// Align data on a 64-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_128BYTES				0x00800000	// Align data on a 128-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_256BYTES				0x00900000	// Align data on a 256-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_512BYTES				0x00A00000	// Align data on a 512-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_1024BYTES				0x00B00000	// Align data on a 1024-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_2048BYTES				0x00C00000	// Align data on a 2048-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_4096BYTES				0x00D00000	// Align data on a 4096-byte boundary. Valid only for object files.
#define IMAGE_SCN_ALIGN_8192BYTES				0x00E00000	// Align data on an 8192-byte boundary. Valid only for object files.
#define IMAGE_SCN_LNK_NRELOC_OVFL				0x01000000	// The section contains extended relocations.
#define IMAGE_SCN_MEM_DISCARDABLE				0x02000000	// The section can be discarded as needed.
#define IMAGE_SCN_MEM_NOT_CACHED				0x04000000	// The section cannot be cached.
#define IMAGE_SCN_MEM_NOT_PAGED					0x08000000	// The section is not pageable.
#define IMAGE_SCN_MEM_SHARED					0x10000000	// The section can be shared in memory.
#define IMAGE_SCN_MEM_EXECUTE					0x20000000	// The section can be executed as code.
#define IMAGE_SCN_MEM_READ						0x40000000	// The section can be read.
#define IMAGE_SCN_MEM_WRITE						0x80000000	// The section can be written to.

/**
 * <p>
 * This class implements the SectionHeader class.
 * It stores the Section header as defined in:
 * http://msdn.microsoft.com/en-us/windows/hardware/gg463119.aspx
 * The raw data is stored in a buffer
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since Feb 22, 2012
 *
 */
class SectionHeaderPE
{
public:
	uint32_t length;
	uint32_t alignment;
	uint8_t Name[8];                  // 8 bytes An 8-byte, null-padded UTF-8 encoded string. If the string is exactly 8 characters long, there is no terminating null. For longer names, this field contains a slash (/) that is followed by an ASCII representation of a decimal number that is an offset into the string table. Executable images do not use a string table and do not support section names longer than 8 characters. Long names in object files are truncated if they are emitted to an executable file.
	uint32_t VirtualSize;             // 4 bytes The total size of the section when loaded into memory. If this value is greater than SizeOfRawData, the section is zero-padded. This field is valid only for executable images and should be set to zero for object files.
	uint32_t VirtualAddress;          // 4 bytes For executable images, the address of the first byte of the section relative to the image base when the section is loaded into memory. For object files, this field is the address of the first byte before relocation is applied; for simplicity, compilers should set this to zero. Otherwise, it is an arbitrary value that is subtracted from offsets during relocation.
	uint32_t SizeOfRawData;           // 4 bytes The size of the section (for object files) or the size of the initialized data on disk (for image files). For executable images, this must be a multiple of FileAlignment from the optional header. If this is less than VirtualSize, the remainder of the section is zero-filled. Because the SizeOfRawData field is rounded but the VirtualSize field is not, it is possible for SizeOfRawData to be greater than VirtualSize as well. When a section contains only uninitialized data, this field should be zero.
	uint32_t PointerToRawData;        // 4 bytes The file pointer to the first page of the section within the COFF file. For executable images, this must be a multiple of FileAlignment from the optional header. For object files, the value should be aligned on a 4 byte boundary for best performance. When a section contains only uninitialized data, this field should be zero.
	uint32_t PointerToRelocations;    // 4 bytes The file pointer to the beginning of relocation entries for the section. This is set to zero for executable images or if there are no relocations.
	uint32_t PointerToLinenumbers;    // 4 bytes The file pointer to the beginning of line-number entries for the section. This is set to zero if there are no COFF line numbers. This value should be zero for an image because COFF debugging information is deprecated.
	uint16_t NumberOfRelocations;     // 2 bytes The number of relocation entries for the section. This is set to zero for executable images.
	uint16_t NumberOfLinenumbers;     // 2 bytes The number of line-number entries for the section. This value should be zero for an image because COFF debugging information is deprecated.
	uint32_t Characteristics;         // 4 bytes The flags that describe the characteristics of the section.

	uint8_t *buffer;                  // SizeOfRawData bytes
	uint32_t buffer_len;              // Length of the buffer

	SectionHeaderPE();
	bool IsTextBss();
	bool IsText();
	bool IsData();
	bool IsRData();
	bool IsPData();
	bool IsReloc();
	bool IsRsrc();
	bool IsExe();
	bool IsInitData();
	bool IsUninitData();
	void Print(bool printBuffer);
};

#endif // __SECTION_HEADER_PE_H__
