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

#ifndef __PE__FORMAT_H__
#define __PE__FORMAT_H__

#include <iostream>
#include <fstream>
#include <vector>
#include <stdint.h>
#include <map>

#include "coffHeader.h"
#include "optionalHeader.h"
#include "sectionHeaderPE.h"
#include "../include/common.h"

using namespace std;

/**
 * <p>
 * This class implements the PE class.
 * It takes a byte array of a file and parse it.
 * Reads COFF header, Optional header and Section header.
 * Stores and returns the sections in the
 * {@link #pe.SectionHeaderPE} class.
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since March 04, 2013
 */
class PE
{
private:
	bool isEXE, isDLL, isLittleEndian, isBigEndian;
	const static int16_t MAGIC = 0x5A4D;
	uint8_t *data;
	_buffer fileBuffer;
	uint64_t size;
	uint64_t current;
	multimap<uint64_t, uint64_t> bytesWritten;
	uint64_t coff_header_offset;
	uint32_t code_size;
	SectionHeaderPE **sectionHdr;
	CoffHeader coffHdr;
	OptionalHeader optionalHdr;

	void readAt(uint64_t addr, uint8_t readByte[], uint32_t len);
	void read(uint8_t readByte[], uint32_t len);
	uint8_t readByte();
	uint16_t readShort();
	uint32_t readInt();
	uint64_t readLong();
	void writeAt(uint64_t addr, uint8_t writeByte[], uint32_t len);
	void write(uint8_t writeByte[], uint32_t len);
	void writeByte(uint8_t buffer);
	void writeShort(uint16_t buffer);
	void writeInt(uint32_t buffer);
	void writeLong(uint64_t buffer);

public:
	PE(uint8_t *dataPtr, uint64_t size, uint64_t coff_header_offset);
	~PE();
	void ReadCoffHeader();
	void ReadOptionalHeader();
	void ReadSectionHeaders();
	SectionHeaderPE** GetSectionHeaders();
	uint32_t GetNumberOfSections();
	uint64_t GetEntryPointAddress();
	bool Is64();
	void WriteFile(char *filename);
	void Print();
};

#endif // __PE__FORMAT_H__
