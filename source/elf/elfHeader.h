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

#ifndef __ELF_HEADER_H__
#define __ELF_HEADER_H__

#include <stdio.h>
#include <iostream>
#include <stdint.h>
#include <string.h>

#define FILE_TYPE_NONE                 0
#define FILE_TYPE_RELOCATABLE          1
#define FILE_TYPE_EXECUTABLE           2
#define FILE_TYPE_DYNAMIC              3
#define FILE_TYPE_CORE                 4

#define ELF_HEADER_IDENT_SIZE  16
#define ELF32_ADDRESS_SIZE     4
#define ELF32_OFFSET_SIZE      4
#define ELF64_ADDRESS_SIZE     8
#define ELF64_OFFSET_SIZE      8

using namespace std;

/**
 * <p>
 * This class implements the ElfHeader class.
 * It stores the ELF header as defined in:
 * downloads.openwatcom.org/ftp/devel/docs/elf-64-gen.pdf
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since Decemebr 22, 2012
 *
 */
class ElfHeader
{
public:
	uint8_t e_ident[ELF_HEADER_IDENT_SIZE];   // ELF identification
	uint16_t e_type;                // Object file type
	uint16_t e_machine;             // Machine type
	uint32_t e_version;             // Object file version
	uint64_t e_entry;               // Entry point address
	                                // If ARM architecture (e_machine) then:
	                                // The value stored in this field is treated like any other code pointer.
	                                // Specifically, if bit[0] is 0b1 then the entry point contains Thumb code;
	                                // while bit[1:0] = 0b00 implies that the entry point contains ARM code.
	                                // The combination bit[1:0] = 0b10 is reserved.
	uint64_t e_phoff;               // Program header offset
	uint64_t e_shoff;               // Section header offset
	uint32_t e_flags;               // Processor-specific flags
	uint16_t e_ehsize;              // ELF header size
	uint16_t e_phentsize;           // Size of program header entry
	uint16_t e_phnum;               // Number of program header entries
	uint16_t e_shentsize;           // Size of section header entry
	uint16_t e_shnum;               // Number of section header entries
	uint16_t e_shstrndx;            // Section name string table index

	uint64_t size;                   // Size of the header

	ElfHeader()
	{
		e_ident[0]  = 0;
		e_type      = 0;
		e_machine   = 0;
		e_version   = 0;
		e_entry     = 0;
		e_phoff     = 0;
		e_shoff     = 0;
		e_flags     = 0;
		e_ehsize    = 0;
		e_phentsize = 0;
		e_phnum     = 0;
		e_shentsize = 0;
		e_shnum     = 0;
		e_shstrndx  = 0;
		size = ELF_HEADER_IDENT_SIZE +
				sizeof(e_type) +
				sizeof(e_machine) +
				sizeof(e_version) +
				sizeof(e_entry) +
				sizeof(e_phoff) +
				sizeof(e_shoff) +
				sizeof(e_flags) +
				sizeof(e_ehsize) +
				sizeof(e_phentsize) +
				sizeof(e_phnum) +
				sizeof(e_shentsize) +
				sizeof(e_shnum) +
				sizeof(e_shstrndx);

	}

	void Print()
	{
		printf ("   e_ident = %X", e_ident[0]);
		printf ("%c", e_ident[1]);
		printf ("%c", e_ident[2]);
		printf ("%c", e_ident[3]);
		printf ("%X", e_ident[4]);
		printf ("%X", e_ident[5]);
		printf ("%X\n", e_ident[6]);
		printf ("   e_type = 0x%X\n", e_type);
		printf ("   e_machine = 0x%X\n", e_machine);
		printf ("   e_version = 0x%X\n", e_version);
		printf ("   e_entry = 0x%lX\n", e_entry);
		printf ("   e_phoff = 0x%lX\n", e_phoff);
		printf ("   e_shoff = 0x%lX\n", e_shoff);
		printf ("   e_flags = 0x%X\n", e_flags);
		printf ("   e_ehsize = %d\n", e_ehsize);
		printf ("   e_phentsize = %d\n", e_phentsize);
		printf ("   e_phnum = %d\n", e_phnum);
		printf ("   e_shentsize = %d\n", e_shentsize);
		printf ("   e_shnum = %d\n", e_shnum);
		printf ("   e_shstrndx = %d\n", e_shstrndx);
	}
};

#endif // __ELF_HEADER_H__
