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

#include "symbolTableELF.h"

/*
 * Constructor
 * Reads the symbol table buffer and fill the data structure
 */
SymbolTableELF::SymbolTableELF(SectionHeaderELF *stringTable, uint8_t *buffer, uint64_t len, bool is64)
{
	updated = false;
	buffer_len = len;
	uint32_t size_of_symbol_struct = SIZE_OF_SYMBOL_STRUCT;   // see the header file
	size = len / size_of_symbol_struct;
	ElfSymbolTableEntry = new _Symbol[size];
	uint8_t *stringTableBuffer = stringTable->buffer;
	uint64_t i = 0, ti = 0;

	for ( ; i < (int)len, ti < (int)size; )
	{
		uint32_t n1 = 0;
		uint32_t n2 = Util::ReadInt(i, (const char *)buffer);
		i += sizeof(uint32_t);
		ElfSymbolTableEntry[ti].name_index = n2;
		if (stringTable != 0)
		{
			while (n2 < MAX_SYMBOL_NAME && stringTableBuffer[n2] != '\0')
				ElfSymbolTableEntry[ti].name[n1++] = stringTableBuffer[n2++];
			ElfSymbolTableEntry[ti].name[n1] = '\0';
		}

		if (is64)
		{
			ElfSymbolTableEntry[ti].value = Util::ReadLong(i, (const char *)buffer);
			i += sizeof(uint64_t);
			ElfSymbolTableEntry[ti].size = Util::ReadLong(i, (const char *)buffer);
			i += sizeof(uint64_t);
		}
		else
		{
			ElfSymbolTableEntry[ti].value = Util::ReadInt(i, (const char *)buffer);
			i += sizeof(uint32_t);
			ElfSymbolTableEntry[ti].size = Util::ReadInt(i, (const char *)buffer);
			i += sizeof(uint32_t);
		}

		ElfSymbolTableEntry[ti].info = Util::ReadByte(i, (const char *)buffer);
		i += sizeof(uint8_t);
		ElfSymbolTableEntry[ti].other = Util::ReadByte(i, (const char *)buffer);
		i += sizeof(uint8_t);

		ElfSymbolTableEntry[ti].shndx = Util::ReadShort(i, (const char *)buffer);
		i += sizeof(uint16_t);

		ti++;
	}
}

SymbolTableELF::~SymbolTableELF()
{
	delete (ElfSymbolTableEntry);
}

/*
 * Returns the symbol table as a buffer
 * The size of the table does not change and
 * it's the responsibility of the caller to
 * make sure the buffer has been allocated.
 */
void SymbolTableELF::GetBuffer(uint8_t *buffer, bool is64)
{
	uint64_t i = 0, ti = 0;
	for ( ; i < (int)buffer_len, ti < (int)size; )
	{
		i += sizeof(uint32_t);

		i += sizeof(uint8_t);
		i += sizeof(uint8_t);

		i += sizeof(uint16_t);

		if (is64)
		{
			i += sizeof(uint64_t);
			i += sizeof(uint64_t);
		}
		else
		{
			i += sizeof(uint32_t);
			i += sizeof(uint32_t);
		}

		ti++;
	}
}

void SymbolTableELF::Print()
{
	printf("Info \tOther \tShndx \tSize \tValue \tName\n");
	for (int i = 0; i < (int)size; i++)
		printf("%02x \t\t%02x \t\t%02x \t\t%02x \t\t%02x \t\t%s\n",
							 ElfSymbolTableEntry[i].info,
							 ElfSymbolTableEntry[i].other,
							 ElfSymbolTableEntry[i].shndx,
							 (int)ElfSymbolTableEntry[i].size,
							 (int)ElfSymbolTableEntry[i].value,
							 ElfSymbolTableEntry[i].name);
}
