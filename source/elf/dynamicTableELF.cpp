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

#include "dynamicTableELF.h"

/*
 * Constructor
 * Reads the dynamic table buffer and fill the data structure
 */
DynamicTableELF::DynamicTableELF(uint8_t *buffer, uint64_t len)
{
	updated = false;
	buffer_len = len;
	uint32_t size_of_dynamic_struct = SIZE_OF_DYNAMIC_STRUCT;   // see the header file
	size = len / size_of_dynamic_struct;
	ElfDynamicTableEntry = new _Dynamic[size+1];

	uint64_t i = 0, ti = 0;
	for ( ; i < len, ti < size; )
	{
		ElfDynamicTableEntry[ti].type = Util::ReadLong(i, (const char *)buffer);
		i += sizeof(uint64_t);
		if (ElfDynamicTableEntry[ti].type != DT_NULL)
		{
			ElfDynamicTableEntry[ti].value_address = Util::ReadLong(i, (const char *)buffer);
			i += sizeof(uint64_t);
		}
		else
			break;
		ti++;
	}
	size = ti;
}

DynamicTableELF::~DynamicTableELF()
{
	delete (ElfDynamicTableEntry);
}

/*
 * Returns the dynamic table as a buffer
 * The size of the table does not change and
 * it's the responsibility of the caller to
 * make sure the buffer has been allocated.
 */
void DynamicTableELF::GetBuffer(uint8_t *buffer)
{
	uint64_t i = 0, ti = 0;
	for ( ; i < buffer_len, ti < size; )
	{
		Util::WriteLong(ElfDynamicTableEntry[ti].type, i, (char *)buffer);
		i += sizeof(uint64_t);
		if (ti < size && ElfDynamicTableEntry[ti].type != DT_NULL)
		{
			Util::WriteLong(ElfDynamicTableEntry[ti].value_address, i, (char *)buffer);
			i += sizeof(uint64_t);
		}
		else
			break;
		ti++;
	}
}

void DynamicTableELF::Print()
{
}
