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

#include "relocationsELF.h"

/*
 * Constructor
 * Reads the relocations buffer and fill the data structure
 */
RelocationsELF::RelocationsELF(bool rela, uint8_t *buffer, uint64_t len)
{
	updated = false;
	buffer_len = len;

	uint32_t size_of_relocations_struct = SIZE_OF_RELOCATIONS_STRUCT_RELA;   // sizeof(_Relocations) = SIZE_OF_RELOCATIONS_STRUCT_RELA --> see the header file
	if (!rela)
		size_of_relocations_struct = SIZE_OF_RELOCATIONS_STRUCT_REL;          // sizeof(_Relocations) = SIZE_OF_RELOCATIONS_STRUCT_REL --> see the header file
	size = len / size_of_relocations_struct;
	ElfRelocationsEntry = new _Relocations[size];

	uint64_t i = 0, ti = 0;
	for ( ; i < len, ti < size; )
	{
		ElfRelocationsEntry[ti].offset = Util::ReadLong(i, (const char *)buffer);
		i += sizeof(uint64_t);
		ElfRelocationsEntry[ti].info = Util::ReadLong(i, (const char *)buffer);
		i += sizeof(uint64_t);
		/*
		 * Examples of relocation sections are:
		 * .rel
		 * .rela
		 * .rela.plt
		 * .rela.dyn
		 * etc
		 *
		 * If .rela i.e with addend
		 */
		if (rela)
		{
			ElfRelocationsEntry[ti].addend = Util::ReadLong(i, (const char *)buffer);
			i += sizeof(int64_t);
		}
		ti++;
	}
	size = ti;
}

RelocationsELF::~RelocationsELF()
{
}

/*
 * Returns the relocations as a buffer
 * The size of the table does not change and
 * it's the responsibility of the caller to
 * make sure the buffer has been allocated.
 */
void RelocationsELF::GetBuffer(bool rela, uint8_t *buffer)
{
	uint64_t i = 0, ti = 0;
	for ( ; i < buffer_len, ti < size; )
	{
		Util::WriteLong(ElfRelocationsEntry[ti].offset, i, (char *)buffer);
		i += sizeof(uint64_t);
		Util::WriteLong(ElfRelocationsEntry[ti].info, i, (char *)buffer);
		i += sizeof(uint64_t);
		if (rela)
		{
			Util::WriteLong(ElfRelocationsEntry[ti].addend, i, (char *)buffer);
			i += sizeof(int64_t);
		}
		ti++;
	}
}

void RelocationsELF::Print()
{
}
