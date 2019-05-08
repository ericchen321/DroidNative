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

#ifndef __DYNAMIC_TABLE_ELF_H__
#define __DYNAMIC_TABLE_ELF_H__

#include <stdio.h>
#include <stdint.h>

#include "../util/util.h"

#define SIZE_OF_DYNAMIC_STRUCT   sizeof(uint64_t) + sizeof(uint64_t)

using namespace std;

/*----------------------------------------------------------------------------------------------------
                                      Dynamic Table Entries
           Name           Value            d_un                  Meaning
----------------------------------------------------------------------------------------------------*/
#define DT_NULL             0           // ignored    Marks the end of the dynamic array
#define DT_NEEDED           1           // d_val      The string table offset of the name of a needed library.
#define DT_PLTRELSZ         2           // d_val      Total size, in bytes, of the relocation entries associated with the procedure linkage table.
#define DT_PLTGOT           3           // d_ptr      Contains an address associated with the linkage table. The specific meaning of this field is processor-dependent.
#define DT_HASH             4           // d_ptr      Address of the symbol hash table.
#define DT_STRTAB           5           // d_ptr      Address of the dynamic string table.
#define DT_SYMTAB           6           // d_ptr      Address of the dynamic symbol table.
#define DT_RELA             7           // d_ptr      Address of a relocation table with Elf64_Rela entries.
#define DT_RELASZ           8           // d_val      Total size, in bytes, of the DT_RELA relocation table.
#define DT_RELAENT          9           // d_val      Size, in bytes, of each DT_RELA relocation entry.
#define DT_STRSZ            10          // d_val      Total size, in bytes, of the string table.
#define DT_SYMENT           11          // d_val      Size, in bytes, of each symbol table entry.
#define DT_INIT             12          // d_ptr      Address of the initialization function.
#define DT_FINI             13          // d_ptr      Address of the termination function.
#define DT_SONAME           14          // d_val      The string table offset of the name of this shared object.
#define DT_RPATH            15          // d_val      The string table offset of a shared library search path string.
#define DT_SYMBOLIC         16          // ignored    The presence of this dynamic table entry modifies the symbol resolution algorithm for references within the library. Symbols defined within the library are used to resolve references before the dynamic linker searches the usual search path.
#define DT_REL              17          // d_ptr      Address of a relocation table with Elf64_Rel entries.
#define DT_RELSZ            18          // d_val      Total size, in bytes, of the DT_REL relocation table.
#define DT_RELENT           19          // d_val      Size, in bytes, of each DT_REL relocation entry.
#define DT_PLTREL           20          // d_val      Type of relocation entry used for the procedure linkage table. The d_val member contains either DT_REL or DT_RELA.
#define DT_DEBUG            21          // d_ptr      Reserved for debugger use.
#define DT_TEXTREL          22          // ignored    The presence of this dynamic table entry signals that the relocation table contains relocations for a non-writable segment.
#define DT_JMPREL           23          // d_ptr      Address of the relocations associated with the procedure linkage table.
#define DT_BIND_NOW         24          // ignored    The presence of this dynamic table entry signals that the dynamic loader should process all relocations for this object before transferring control to the program.
#define DT_INIT_ARRAY       25          // d_ptr      Pointer to an array of pointers to initialization functions.
#define DT_FINI_ARRAY       26          // d_ptr      Pointer to an array of pointers to termination functions.
#define DT_INIT_ARRAYSZ     27          // d_val      Size, in bytes, of the array of initialization functions.
#define DT_FINI_ARRAYSZ     28          // d_val      Size, in bytes, of the array of termination functions.
#define DT_LOOS             0x60000000  // ignored    Defines a range of dynamic table tags that are reserved for environment-specific use.
#define DT_HIOS             0x70000000
#define DT_HIPROC           0x6FFFFFFF  // ignored    Defines a range of dynamic table tags that are reserved for processor-specific use.
#define DT_LOPROC           0x7FFFFFFF

/**
 * <p>
 * This class implements the DynamicTableELF class.
 * It stores the dynamic table entry structure defined in:
 * downloads.openwatcom.org/ftp/devel/docs/elf-64-gen.pdf
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since March 20, 2012
 *
 */
class DynamicTableELF
{
private:

public:
	struct _Dynamic
	{
		int64_t  type;
		uint64_t value_address;
	};

	_Dynamic *ElfDynamicTableEntry;
	uint64_t size;
	uint64_t buffer_len;
	bool updated;

	DynamicTableELF(uint8_t *buffer, uint64_t len);
	~DynamicTableELF();
	void GetBuffer(uint8_t *buffer);
	void Print();
};

#endif // __DYNAMIC_TABLE_ELF_H__
