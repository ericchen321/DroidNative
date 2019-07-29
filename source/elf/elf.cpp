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

#include "elf.h"

/*
 * <p>
 * Constructor
 * </p>
 */
ELF::ELF(uint8_t *data, uint64_t size, bool isThumb)
{
	this->data = data;
	this->size = size;

	current = 0;
	firstOffsetChanged = 0;
	numberOfSectionHeaders = 0;
	numberOfProgramHeaders = 0;
	offsetProgramHeaderTable = 0;
	offsetSectionHeaderTable = 0;
	stringTableIndex = 0;

	dynTable = 0;
	symTable = 0;
	ehFrame = 0;
	gccExceptTable = 0;

	is64 = false;
	isRel = false;
	isExe = false;
	isDyn = false;
	isCore = false;
	isLittleEndian = false;
	IS_X86 = false;
	IS_ARM = false;
	// If entry contains Thumb instructions
	this->isThumb = isThumb;
	thumb = 0;

	readHeader();

	if (isExe || isDyn)
		readProgramHeaders(elfHdr.e_phoff);
	readSectionHeaders(elfHdr.e_shoff, elfHdr.e_shstrndx);

	/*
	 * If Section name string table exists
	 * read the section names from the table
	 */
	if (elfHdr.e_shstrndx != SHN_UNDEF)
		readSectionNames(elfHdr.e_shstrndx);

	readSectionBuffers(elfHdr.e_shstrndx);
	setArchitecture();
	if (IS_ARM)
		setInstructionTypeForSections();
}

/*
 * <p>
 * Destructor
 * </p>
 */
ELF::~ELF()
{
	for (int p = 0; p < (int)numberOfProgramHeaders; p++)
	{
		if (programHdr[p]->buffer_len > 0)
			delete (programHdr[p]->buffer);
		delete (programHdr[p]);
	}
	if (isExe || isDyn)
		delete (programHdr);
	for (int s = 0; s < (int)numberOfSectionHeaders; s++)
	{
		delete (sectionHdr[s]->buffer);
		delete (sectionHdr[s]);
	}
	delete (sectionHdr);

	if (dynTable != 0)
		delete (dynTable);
	if (symTable != 0)
		delete (symTable);
	if (ehFrame != 0)
		delete (ehFrame);
	if (gccExceptTable != 0)
		delete (gccExceptTable);

	map<char *, RelocationsELF>::iterator it_r;
	for (it_r = relocations.begin(); it_r != relocations.end(); it_r++)
		delete (it_r->second.ElfRelocationsEntry);

	bytesWritten.erase(bytesWritten.begin(), bytesWritten.end());
	relocations.erase(relocations.begin(), relocations.end());
}

/*
 * 0x02 	SPARC
 * 0x03 	x86
 * 0x08 	MIPS
 * 0x14 	PowerPC
 * 0x28 	ARM
 * 0x2A 	SuperH
 * 0x32 	IA-64
 * 0x3E 	x86-64
 * 0xB7 	AArch64
 */
void ELF::setArchitecture()
{
	// x86
	if (elfHdr.e_machine == 0x03 || elfHdr.e_machine == 0x3E)
	{
		IS_X86 = true;
	}
	// ARM
	else if (elfHdr.e_machine == 0x28 || elfHdr.e_machine == 0xB7)
	{
		IS_ARM = true;
	}
	else
		IS_X86 = true;
}

/*
 *
 * There are three ways to differentiate between an ARM and Thumb intruction set.
 * 1. Looking at the entries in the symbol table with $a or $t
 *    This is what I am using in my program
 * 2. Looking at the e_entry address in the ELF header.
 *    The value stored in this field is treated like any other code pointer.
 *    Specifically, if bit[0] is 0b1 then the entry point contains Thumb code;
 *    while bit[1:0] = 0b00 implies that the entry point contains ARM code.
 *    The combination bit[1:0] = 0b10 is reserved.
 * 3. By disassembling each instruction first as Thumb and then ARM. If the instruction
 *    is successfully disassmbled to Thumb then it's a THumb instruction, otherwise
 *    it's (part of) an ARM instruction.
 *
 *
 * Setting the instruction type (ARM / THUMB etc) of a Section.
 *
 * At this time we read the instruction type information from the symbol table
 * embedded by the compiler. A Section in the table is specified as type
 * THUMB ($t), ARM ($a) or/and DATA ($d).
 * The 'name' in the symbol table specify these types.
 * The Sections has been indexed, and these indices are the same as indicated
 * by the 'shndx' in the symbol table.
 *
 * It is possible for one Section to have different types of instructions,
 * i.e, THUMB, ARM and DATA types of instructions can be mixed in one Section.
 * This function does not distinguish between this mixing and will tag the
 * Section as containing the instruction type of the last type mentioned in
 * the symbol table. For example the following symbol table entries:
 *
 * - - - - - - - - - - - - - - - - -
 * - - - - - - - - - - - - - - - - -
 * - - - - - - - - - - - - - - - - -
 * 00 		00 		.text 		00 		800c 		$t
 * - - - - - - - - - - - - - - - - -
 * - - - - - - - - - - - - - - - - -
 * - - - - - - - - - - - - - - - - -
 * 00 		00 		.text 		00 		8094 		$a
 * - - - - - - - - - - - - - - - - -
 * - - - - - - - - - - - - - - - - -
 * - - - - - - - - - - - - - - - - -
 *
 * indicates that the .text Section starting from address 800c contains
 * THUMB instructions, and contains ARM instructions starting from
 * address 8094.
 *
 * Therefore this function will mark all the .text Section as containing ARM
 * instructions.
 *
 * - - -   TO DO   - - -
 * Update the function so that it can mark different parts of a Section with
 * different types of instructions (as shown in the above example) based on the
 * addresses.
 *
 *
 * If the binary does not have a symbol table or this information is not
 * available in the table, then this function will set all the
 * Sections' instruction type as computed from the ELF header table
 * as described above, reading the e_entry field from the ELF header table.
 *
 */
void ELF::setInstructionTypeForSections()
{
#ifdef __DEBUG__
if (symTable != 0)
	symTable->Print();
#endif

	//
	// Set the entry point's instruction type
	//
	if ((thumb & 0x1) == 0)
		isThumb = false;

	for (int sectionIndex = 0; sectionIndex < (int)numberOfSectionHeaders; sectionIndex++)
	{
		if (isThumb)
			sectionHdr[sectionIndex]->IStype = INSTRUCTION_SET_THUMB;
		else
			sectionHdr[sectionIndex]->IStype = INSTRUCTION_SET_ARM;

		if (symTable != 0)
		{
			for (int i = 0; i < (int)symTable->size; i++)
			{
#ifdef __DEBUG__
				cout << "Checking if Symbol table entry " << symTable->ElfSymbolTableEntry[i].shndx << " == Section index " << sectionIndex << endl;
#endif
				if (symTable->ElfSymbolTableEntry[i].shndx == sectionIndex)
				{
					if (strcmp((const char *)symTable->ElfSymbolTableEntry[i].name, "$a") == 0)
					{
						sectionHdr[sectionIndex]->IStype = INSTRUCTION_SET_ARM;
#ifdef __DEBUG__
						printf("Section %s changed to ARM type instructions\n", sectionHdr[sectionIndex]->name);
#endif
					}
					else
						sectionHdr[sectionIndex]->IStype = INSTRUCTION_SET_THUMB;
				}
			}
		}
#ifdef __DEBUG__
		printf("--------------------------------------------------------------------\n\n");
		printf("Checking Section %s which has THUMB type instructions\n", sectionHdr[sectionIndex]->name);
		printf("--------------------------------------------------------------------\n\n");
#endif
	}
}

/*
 * <p>
 * Reads the ELF header starting from 0
 * </p>
 */
void ELF::readHeader()
{
	current = 0;

	ELF::read(elfHdr.e_ident, 16);
	if (elfHdr.e_ident[4] == 0x02)
		is64 = true;
	if (elfHdr.e_ident[5] == 0x01)
		isLittleEndian = true;
	elfHdr.e_type      = ELF::readShort();
	if (elfHdr.e_type == FILE_TYPE_RELOCATABLE)
		isRel = true;
	else if (elfHdr.e_type == FILE_TYPE_EXECUTABLE)
		isExe = true;
	else if (elfHdr.e_type == FILE_TYPE_DYNAMIC)
		isDyn = true;
	else if (elfHdr.e_type == FILE_TYPE_CORE)
		isCore = true;
	elfHdr.e_machine   = ELF::readShort();
	elfHdr.e_version   = ELF::readInt();
	if (is64)
	{
		elfHdr.e_entry     = ELF::readLong();
		if (!isLittleEndian)
			thumb = elfHdr.e_entry >> 63;
		else
			thumb = elfHdr.e_entry;
		elfHdr.e_phoff     = ELF::readLong();
		elfHdr.e_shoff     = ELF::readLong();
		offsetProgramHeaderTable = elfHdr.e_phoff;
		offsetSectionHeaderTable = elfHdr.e_shoff;
	}
	else
	{
		elfHdr.e_entry     = ELF::readInt();
		if (!isLittleEndian)
			thumb = elfHdr.e_entry >> 31;
		else
			thumb = elfHdr.e_entry;
		elfHdr.e_phoff     = ELF::readInt();
		elfHdr.e_shoff     = ELF::readInt();
		offsetProgramHeaderTable = elfHdr.e_phoff;
		offsetSectionHeaderTable = elfHdr.e_shoff;
	}
	elfHdr.e_flags     = ELF::readInt();
	elfHdr.e_ehsize    = ELF::readShort();
	elfHdr.e_phentsize = ELF::readShort();
	elfHdr.e_phnum     = ELF::readShort();
	elfHdr.e_shentsize = ELF::readShort();
	elfHdr.e_shnum     = ELF::readShort();
	elfHdr.e_shstrndx  = ELF::readShort();
#ifdef __DEBUG__
	cout << "\nPrinting ELF Header:\n";
	elfHdr.Print();
#endif

	numberOfProgramHeaders = elfHdr.e_phnum;
	numberOfSectionHeaders = elfHdr.e_shnum;
}

/*
 * <p>
 * Reads the Section headers @ sectionHeaderOffset
 * </p>
 */
void ELF::readProgramHeaders(uint64_t offset_segment_header_table)
{
	current = offset_segment_header_table;
	programHdr = new ProgramHeader*[numberOfProgramHeaders];
	for (uint32_t i = 0; i < numberOfProgramHeaders; i++)
	{
		programHdr[i] = new ProgramHeader();

		if (is64)
		{
			programHdr[i]->p_type       = ELF::readLong();
			programHdr[i]->p_offset     = ELF::readLong();
			programHdr[i]->p_vaddr      = ELF::readLong();
			programHdr[i]->p_paddr      = ELF::readLong();
			programHdr[i]->p_filesz     = ELF::readLong();
			programHdr[i]->p_memsz      = ELF::readLong();
			programHdr[i]->p_flags      = ELF::readLong();
			programHdr[i]->p_align      = ELF::readLong();
		}
		else
		{
			programHdr[i]->p_type       = ELF::readInt();
			programHdr[i]->p_offset     = ELF::readInt();
			programHdr[i]->p_vaddr      = ELF::readInt();
			programHdr[i]->p_paddr      = ELF::readInt();
			programHdr[i]->p_filesz     = ELF::readInt();
			programHdr[i]->p_memsz      = ELF::readInt();
			programHdr[i]->p_flags      = ELF::readInt();
			programHdr[i]->p_align      = ELF::readInt();
		}

		/*
		 * We don't update the program buffer.
		 * The buffers that are updated are
		 * read in section headers.
		 */
//		uint64_t buffer_len = programHdr[i]->p_filesz;
//		programHdr[i]->buffer = new uint8_t[buffer_len+1];
//		programHdr[i]->buffer_len = buffer_len;
//		readAt(programHdr[i]->p_offset, programHdr[i]->buffer, programHdr[i]->buffer_len);
#ifdef __DEBUG__
		cout << "\nPrinting Program Header " << i << ":\n";
		programHdr[i]->Print(true);        // Print the header including the data
#endif
	}
}

/*
 * <p>
 * Reads the Section headers @ sectionHeaderOffset
 * </p>
 */
void ELF::readSectionHeaders(uint64_t offset_section_header_table, uint16_t stringTableIndexSectionName)
{
	current = offset_section_header_table;
	sectionHdr = new SectionHeaderELF*[numberOfSectionHeaders];
	for (uint32_t i = 0; i < numberOfSectionHeaders; i++)
	{
		sectionHdr[i] = new SectionHeaderELF();

		if (is64)
		{
			sectionHdr[i]->sh_name      = ELF::readInt();
			sectionHdr[i]->sh_type      = ELF::readInt();
			sectionHdr[i]->sh_flags     = ELF::readLong();
			sectionHdr[i]->sh_addr      = ELF::readLong();
			sectionHdr[i]->sh_offset    = ELF::readLong();
			sectionHdr[i]->sh_size      = ELF::readLong();
			sectionHdr[i]->sh_link      = ELF::readInt();
			sectionHdr[i]->sh_info      = ELF::readInt();
			sectionHdr[i]->sh_addralign = ELF::readLong();
			sectionHdr[i]->sh_entsize   = ELF::readLong();
		}
		else
		{
			sectionHdr[i]->sh_name      = ELF::readInt();
			sectionHdr[i]->sh_type      = ELF::readInt();
			sectionHdr[i]->sh_flags     = ELF::readInt();
			sectionHdr[i]->sh_addr      = ELF::readInt();
			sectionHdr[i]->sh_offset    = ELF::readInt();
			sectionHdr[i]->sh_size      = ELF::readInt();
			sectionHdr[i]->sh_link      = ELF::readInt();
			sectionHdr[i]->sh_info      = ELF::readInt();
			sectionHdr[i]->sh_addralign = ELF::readInt();
			sectionHdr[i]->sh_entsize   = ELF::readInt();
		}

		/*
		 * Read string table so that the names
		 * of the Sections can be read.
		 */
		if (i == stringTableIndexSectionName)
		{
			sectionHdr[i]->buffer_len = sectionHdr[i]->sh_size;
			sectionHdr[i]->buffer = new uint8_t[sectionHdr[i]->buffer_len+1];
			ELF::readAt(sectionHdr[i]->sh_offset, sectionHdr[i]->buffer, sectionHdr[i]->buffer_len);
		}

#ifdef __DEBUG__
		cout << "\nPrinting Section Header " << i << ":\n";
		sectionHdr[i]->Print(false);        // Print the header excluding the data
#endif
	}
}

/*
 * <p>
 *
 * Read Section buffers excluding the string table
 * Section because it has already been read by the
 * readSectionHeaders function.
 *
 * </p>
 */
void ELF::readSectionBuffers(uint16_t stringTableIndexSectionName)
{
	for (uint32_t i = 0; i < numberOfSectionHeaders; i++)
	{
		if (i != stringTableIndexSectionName)
		{
         sectionHdr[i]->buffer_len = sectionHdr[i]->sh_size;
         sectionHdr[i]->buffer = new uint8_t[sectionHdr[i]->buffer_len+1];
         /*
          * Only read buffer if present
          */
         if (sectionHdr[i]->sh_type != SHT_NOBITS)
        	 ELF::readAt(sectionHdr[i]->sh_offset, sectionHdr[i]->buffer, sectionHdr[i]->buffer_len);

			if (sectionHdr[i]->IsStrtab())
				stringTableIndex = i;
		}
#ifdef __DEBUG__
		cout << "\nPrinting Section Header " << i << ":\n";
		sectionHdr[i]->Print(true);        // Print the header including the data
#endif
	}

	if (stringTableIndex <= 0)
	{
#ifdef __DEBUG__
		cerr << "Warning:ELF::readSectionBuffers: No String Table Found\n";
		cerr << "Using the other string table: Section Number: " << dec << stringTableIndexSectionName << endl;;
#endif
		stringTableIndex = stringTableIndexSectionName;
	}

	for (uint32_t i = 0; i < numberOfSectionHeaders; i++)
	{
		if (sectionHdr[i]->IsDynamic())
			dynTable = new DynamicTableELF(sectionHdr[i]->buffer, sectionHdr[i]->buffer_len);
		else if (sectionHdr[i]->IsSymtab())
			symTable = new SymbolTableELF(sectionHdr[stringTableIndex], sectionHdr[i]->buffer, sectionHdr[i]->buffer_len, is64);
		else if (sectionHdr[i]->IsEhFrameHdr())
		{
			ehFrame = new EhFrameELF();
         ehFrame->ReadHdr(sectionHdr[i]->buffer, sectionHdr[i]->buffer_len, sectionHdr[i]->sh_offset, sectionHdr[i]->sh_addr);
		}
		else if (sectionHdr[i]->IsEhFrame())
		{
		   if (ehFrame != 0)
		   {
            ehFrame->ReadFrame(sectionHdr[i]->buffer, sectionHdr[i]->buffer_len, sectionHdr[i]->sh_offset, sectionHdr[i]->sh_addr);
		   }
         else
		   {
            ehFrame = new EhFrameELF();
            ehFrame->ReadFrame(sectionHdr[i]->buffer, sectionHdr[i]->buffer_len, sectionHdr[i]->sh_offset, sectionHdr[i]->sh_addr);
		   }
		}
		else if (sectionHdr[i]->IsGccExceptTable())
		{
			gccExceptTable = new GccExceptTableELF(sectionHdr[i]->sh_offset, sectionHdr[i]->sh_addr);
         gccExceptTable->Read(sectionHdr[i]->buffer, sectionHdr[i]->buffer_len, false, 0, 0, 0, NULL);
		}
		else if (sectionHdr[i]->IsRela())
		{
			RelocationsELF relf(true, sectionHdr[i]->buffer, sectionHdr[i]->buffer_len);
			relocations.insert(pair<char *, RelocationsELF>((char *)sectionHdr[i]->name, relf));
		}
		/*
		 * We are only doing 64 bit so no need to check for .rel section
		 * which is only available in 32 bit.
		 */
//		else if (sectionHdr[i]->IsRel())
//			relocations = new RelocationsELF(false, sectionHdr[i]->buffer, sectionHdr[i]->buffer_len);
	}
}

/*
 * <p>
 * Reads the Section names from the string table
 * containing the names of the sections.
 * </p>
 */
void ELF::readSectionNames(uint64_t stringTableIndex)
{
	uint8_t *stringTable = sectionHdr[stringTableIndex]->buffer;
	for (uint32_t i = 0; i < numberOfSectionHeaders; i++)
	{
		uint32_t n1 = 0;
		uint32_t n2 = sectionHdr[i]->sh_name;
		while (n1 < MAX_SECTION_NAME && stringTable[n2] != '\0')
			sectionHdr[i]->name[n1++] = stringTable[n2++];
		sectionHdr[i]->name[n1] = '\0';
#ifdef __DEBUG__
      cout << (sectionHdr[stringTableIndex]->sh_offset+sectionHdr[i]->sh_name) << "-- : sectionHdr["<<i<<"]->name: " << sectionHdr[i]->name << ":" << endl;
#endif
	}
}

/*
 * Get the Program header by address
 */
int32_t ELF::getProgramHeaderByOffset(uint64_t offset)
{
	for (uint32_t i = 0; i < numberOfProgramHeaders; i++)
	{
		if (programHdr[i]->p_offset == offset)
			return i;
	}
	return -1;
}

/*
 * Get the Section header by name
 */
int32_t ELF::getSectionHeaderByOffset(uint64_t offset)
{
	for (uint32_t i = 0; i < numberOfSectionHeaders; i++)
	{
		if (sectionHdr[i]->sh_offset == offset)
			return i;
	}
	return -1;
}

/*
 * Get the Section header by name
 */
int32_t ELF::GetSectionHeaderByName(const char *name)
{
	for (uint32_t i = 0; i < numberOfSectionHeaders; i++)
	{
		if (strcmp(name, (const char *)sectionHdr[i]->name) == 0)
			return i;
	}
	return -1;
}

/*
 * Return all the Section headers
 */
SectionHeaderELF** ELF::GetSectionHeaders()
{
	return sectionHdr;
}

uint32_t ELF::GetNumberOfSections()
{
	return numberOfSectionHeaders;
}

/*
 * Read bytes starting from 'addr' of length 'len'
 */
void ELF::readAt(uint64_t addr, uint8_t *readByte, uint32_t len)
{
	uint64_t upto = addr + len;
	if (upto > size)
		cerr << "ELF::readAt: Out of bounds " << upto << " > " << size << endl;
	else
	{
		uint64_t c = 0;
		while (addr < upto)
			readByte[c++] = data[addr++];
	}
}

/*
 * Read bytes of length len starting from current
 */
void ELF::read(uint8_t *readByte, uint32_t len)
{
	uint64_t upto = current + len;
	if (upto > size)
		cerr << "ELF::read: Out of bounds " << upto << " > " << size << endl;
	else
	{
		uint64_t c = 0;
		while (current < upto)
			readByte[c++] = data[current++];
	}
}

/*
 *  Read 1 byte
 */
uint8_t ELF::readByte()
{
	uint8_t b = data[current++];
	return b;
}

/*
 *  Read 2 bytes
 */
uint16_t ELF::readShort()
{
	uint8_t b1 = readByte(); uint8_t b2 = readByte();
	if (isLittleEndian)
	{
		uint16_t result = (uint16_t)( (b1&0x00FF) | ((b2&0x00FF) << 8) );
		return result;
	}
	else
	{
		uint16_t result = (uint16_t)( ((b1&0x00FF) << 8) | (b2&0x00FF) );
		return result;
	}
}

/*
 *  Read 4 bytes
 */
uint32_t ELF::readInt()
{
	uint8_t b1 = readByte(); uint8_t b2 = readByte();
	uint8_t b3 = readByte(); uint8_t b4 = readByte();
	if (isLittleEndian)
	{
		uint32_t result = (uint32_t)( (b1&0x000000FF) | ((b2&0x000000FF) << 8)
									| ((b3&0x000000FF) << 16) | ((b4&0x000000FF) << 24) );
		return result;
	}
	else
	{
		uint32_t result = (uint32_t)( ((b1&0x000000FF) << 24) | ((b2&0x000000FF) << 16)
									| ((b3&0x000000FF) << 8) | (b4&0x000000FF) );
		return result;
	}
}

/*
 *  Read 8 bytes
 */
uint64_t ELF::readLong()
{
	uint8_t b1 = readByte(); uint8_t b2 = readByte();
	uint8_t b3 = readByte(); uint8_t b4 = readByte();
	uint8_t b5 = readByte(); uint8_t b6 = readByte();
	uint8_t b7 = readByte(); uint8_t b8 = readByte();
	if (isLittleEndian)
	{
		uint64_t result = (uint64_t)(b1&0x00000000000000FF) | ((uint64_t)(b2&0x00000000000000FF) << 8)
							| ((uint64_t)(b3&0x00000000000000FF) << 16) | ((uint64_t)(b4&0x00000000000000FF) << 24)
							| ((uint64_t)(b5&0x00000000000000FF) << 32) | ((uint64_t)(b6&0x00000000000000FF) << 40)
							| ((uint64_t)(b7&0x00000000000000FF) << 48) | ((uint64_t)(b8&0x00000000000000FF) << 56);
		return result;
	}
	else
	{
		uint64_t result = ((uint64_t)(b1&0x00000000000000FF) << 56) | ((uint64_t)(b2&0x00000000000000FF) << 48)
							| ((uint64_t)(b3&0x00000000000000FF) << 40) | ((uint64_t)(b4&0x00000000000000FF) << 32)
							| ((uint64_t)(b5&0x00000000000000FF) << 24) | ((uint64_t)(b6&0x00000000000000FF) << 16)
							| ((uint64_t)(b7&0x00000000000000FF) << 8) | (uint64_t)(b8&0x00000000000000FF);
		return result;
	}
}

/**
 * <p>
 * Prints the ELFBuffer in hex 10 bytes per line.
 * </p>
 */
void ELF::Print()
{
	for (uint64_t i = 1; i < size; i++)
	{
		printf ("%X ", data[i-1]);
		if ((i % 10) == 0)
			cout << "\n";
	}
}
