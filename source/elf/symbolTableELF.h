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

#ifndef __SYMBOL_TABLE_ELF_H__
#define __SYMBOL_TABLE_ELF_H__

#include <stdio.h>
#include <stdint.h>

#include "sectionHeaderELF.h"
#include "../include/common.h"
#include "../util/util.h"

#define SIZE_OF_SYMBOL_STRUCT   sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint64_t) + sizeof(uint64_t)

using namespace std;

/**
 * <p>
 * This class implements the SymbolTableELF class.
 * It stores the symbol table entry structure defined in:
 * downloads.openwatcom.org/ftp/devel/docs/elf-64-gen.pdf
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since May 20, 2012
 *
 */
class SymbolTableELF
{
private:

public:
	struct _Symbol
	{
		uint8_t name[MAX_SYMBOL_NAME+1];       // Symbol name, addition to the structure given in the ELF format for storing the name
		uint32_t name_index;                   // Symbol name index in the string table
		uint64_t value;                        // Symbol value can be an address. If ELF is 32 bit then it's uint32_t
		uint64_t size;                         // Size of object (e.g., common). If ELF is 32 bit then it's uint32_t
		unsigned char info;                    // Type and binding attributes
		unsigned char other;                   // Reserved
		uint16_t shndx;                        // Section table index
		                                       // Section index of the section in which the symbol is “defined.” For undefined
                                               // symbols, this field contains SHN_UNDEF; for absolute symbols, it contains
                                               // SHN_ABS; and for common symbols, it contains SHN_COMMON.
	};

	_Symbol *ElfSymbolTableEntry;
	uint64_t size;
	uint64_t buffer_len;
	bool updated;

	SymbolTableELF(SectionHeaderELF *stringTable, uint8_t *buffer, uint64_t len, bool is64);
	~SymbolTableELF();
	void GetBuffer(uint8_t *buffer, bool is64);
	void Print();
};

#endif // __SYMBOL_TABLE_ELF_H__
