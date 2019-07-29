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

#include "programHeader.h"

ProgramHeader::ProgramHeader()
{
	updated    = false;
	p_type     = 0;
	p_flags    = 0;
	p_offset   = 0;
	p_vaddr    = 0;
	p_paddr    = 0;
	p_filesz   = 0;
	p_memsz    = 0;
	p_align    = 0;
	buffer_len = 0;

	buffer     = 0;
}

void ProgramHeader::Print(bool printBuffer)
{
	printf ("   Type = 0x%X\n", p_type);
	printf ("   Flags = 0x%X\n", p_flags);
	printf ("   Offset = 0x%lX\n", p_offset);
	printf ("   Virtual Address = 0x%X\n", (unsigned int)p_vaddr);
	printf ("   Reserved = 0x%X\n", (unsigned int)p_paddr);
	printf ("   Size of segment in file = 0x%lX\n", p_filesz);
	printf ("   Size of segment in memory = 0x%X\n", (unsigned int)p_memsz);
	printf ("   Alignment = 0x%X\n", (unsigned int)p_align);
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
