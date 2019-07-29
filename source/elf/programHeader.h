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

#ifndef __PROGRAM_HEADER_H__
#define __PROGRAM_HEADER_H__

#include <stdio.h>
#include <iostream>
#include <stdint.h>

#define PT_NULL                0
#define PT_LOAD                1
#define PT_DYNAMIC             2
#define PT_INTERP              3
#define PT_NOTE                4
#define PT_SHLIB               5
#define PT_PHDR                6

using namespace std;

/**
 * <p>
 * This class implements the SegmentHeader class.
 * It stores the Section header as defined in:
 * downloads.openwatcom.org/ftp/devel/docs/elf-64-gen.pdf
 * The raw data is stored in a buffer
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since December 22, 2012
 *
 */
class ProgramHeader
{
public:
	uint32_t p_type;            // Type of segment
	uint32_t p_flags;           // Segment attributes
	uint64_t p_offset;          // Offset in file
	uint64_t p_vaddr;           // Virtual address in memory
	uint64_t p_paddr;           // Reserved
	uint64_t p_filesz;          // Size of segment in file
	uint64_t p_memsz;           // Size of segment in memory
	uint64_t p_align;           // Alignment of segment

	uint8_t *buffer;            // Size of segment in file
	uint64_t buffer_len;
	bool updated;

	ProgramHeader();
	bool IsText();
	bool IsData();
	bool IsRData();
	bool IsPData();
	bool IsReloc();
	bool IsBss();
	void Print(bool printBuffer);
};

#endif // __PROGRAM_HEADER_H__
