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

#ifndef __RELOCATIONS_ELF_H__
#define __RELOCATIONS_ELF_H__

#include <stdio.h>
#include <stdint.h>

#include "../util/util.h"

#define SIZE_OF_RELOCATIONS_STRUCT_REL    sizeof(uint64_t) + sizeof(uint64_t)
#define SIZE_OF_RELOCATIONS_STRUCT_RELA   sizeof(uint64_t) + sizeof(uint64_t) + sizeof(int64_t)

using namespace std;

/**
 * <p>
 * This class implements the RelocationsELF class.
 * It stores the relocations entry structure defined in:
 * downloads.openwatcom.org/ftp/devel/docs/elf-64-gen.pdf
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since May 20, 2012
 *
 */
class RelocationsELF
{
private:

public:
   /*
    *
	 * .rel and .rela type
	 *
    *  offset    This member gives the location at which to apply the relocation
    *            action.  For a relocatable file, the value is the byte offset from
    *            the beginning of the section to the storage unit affected by the
    *            relocation.  For an executable file or shared object, the value is
    *            the virtual address of the storage unit affected by the
    *            relocation.
    *
    *  info      This member gives both the symbol table index with respect to
    *            which the relocation must be made and the type of relocation to
    *            apply.  Relocation types are processor specific.  When the text
    *            refers to a relocation entry's relocation type or symbol table
    *            index, it means the result of applying ELF_[32|64]_R_TYPE or
    *            ELF[32|64]_R_SYM, respectively, to the entry's r_info member.
    *
    *  addend    This member specifies a constant addend used to compute the value
    *            to be stored into the relocatable field.
    *
	 */
	struct _Relocations
	{
		uint64_t  offset;
		uint64_t info;
		int64_t addend;      // Constant part of expression only available in .rela type
	};

	_Relocations *ElfRelocationsEntry;
	uint64_t size;
	uint64_t buffer_len;
	bool updated;

	RelocationsELF(bool rela, uint8_t *buffer, uint64_t len);
	~RelocationsELF();
	void GetBuffer(bool rela, uint8_t *buffer);
	void Print();
};

#endif // __RELOCATIONSH_ELF_H__
