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

#ifndef __ELF_H__
#define __ELF_H__

#include <iostream>
#include <fstream>
#include <vector>
#include <map>
#include <iomanip>
#include <stdint.h>
#include <string.h>

#include "elfHeader.h"
#include "programHeader.h"
#include "sectionHeaderELF.h"
#include "dynamicTableELF.h"
#include "symbolTableELF.h"
#include "ehFrameELF.h"
#include "gccExceptTableELF.h"
#include "relocationsELF.h"
#include "../util/util.h"
#include "../include/common.h"

using namespace std;

/**
 * <p>
 * This class implements the ELF class.
 * It takes a byte array of a file and parse it.
 * Reads ELF header, Optional header and Section header.
 * Stores and returns the sections in the
 * {@link #elf.SectionHeaderELF} class.
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since December 22, 2012
 */
class ELF
{
private:
	uint64_t thumb;
	uint8_t *data;
	_buffer fileBuffer;

	uint64_t size;
	uint64_t current;
	uint64_t firstOffsetChanged;
	multimap<uint64_t, uint64_t> bytesWritten;
	uint64_t offsetSectionHeaderTable;
	uint64_t offsetProgramHeaderTable;
	uint32_t numberOfSectionHeaders;
	uint32_t numberOfProgramHeaders;
	uint32_t stringTableIndex;

	ElfHeader elfHdr;
	SectionHeaderELF **sectionHdr;
	ProgramHeader **programHdr;
	DynamicTableELF *dynTable;
	SymbolTableELF *symTable;
	EhFrameELF *ehFrame;
	GccExceptTableELF *gccExceptTable;
	map<char *, RelocationsELF> relocations;

	void readAt(uint64_t addr, uint8_t readByte[], uint32_t len);
	void read(uint8_t readByte[], uint32_t len);
	uint8_t readByte();
	uint16_t readShort();
	uint32_t readInt();
	uint64_t readLong();

	void setArchitecture();
	void setInstructionTypeForSections();
	void readHeader();
	void readProgramHeaders(uint64_t segmentHeaderOffset);
	void readSectionHeaders(uint64_t sectionHeaderOffset, uint16_t stringTableIndex);
	void readSectionBuffers(uint16_t stringTableIndex);
	void readSectionNames(uint64_t stringTableIndex);

	int32_t getProgramHeaderByOffset(uint64_t offset);
	int32_t getSectionHeaderByOffset(uint64_t offset);

public:
	bool is64;
	bool isRel;
	bool isExe;
	bool isDyn;
	bool isCore;
	bool isLittleEndian;
	bool isThumb;
	bool IS_X86;
	bool IS_ARM;


	ELF(uint8_t *dataPtr, uint64_t size, bool isThumb);
	~ELF();

	int32_t GetSectionHeaderByName(const char *name);
	SectionHeaderELF** GetSectionHeaders();
	uint32_t GetNumberOfSections();

	void Print();
};

#endif // __ELF_H__
