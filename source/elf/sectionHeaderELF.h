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

#ifndef __SECTION_HEADER_ELF_H__
#define __SECTION_HEADER_ELF_H__

#include <stdio.h>
#include <iostream>
#include <stdint.h>
#include <string.h>

using namespace std;

#define MAX_SECTION_NAME                            64
#define INSTRUCTION_SET_ARM                         601
#define INSTRUCTION_SET_THUMB                       602

/*
 *         Section type                   Flags             Use                            Section name
 *  #define SHT_NOBITS     0x00000008   // A, W       Uninitialized data                       .bss
 *  #define SHT_PROGBITS   0x00000001   // A, W       Initialized data                         .data
 *  #define SHT_PROGBITS   0x00000001   // A          Read-only data (constants and literals)  .rodata
 *  #define SHT_PROGBITS   0x00000001   // A, X       Executable code                          .text
 *  #define SHT_PROGBITS   0x00000001   // mach. dep. Procedure linkage table                  .plt
 */

/*
 *      Flags                                        Meaning
 */
#define SHF_ALLOC      0x00000002   // (A) Section is allocated in memory image of program
#define SHF_WRITE      0x00000001   // (W) Section contains writable data
#define SHF_EXECINSTR  0x00000004   // (X) Section contains executable instructions

/*
 * Section types
 */
#define SHT_NULL       0          // Marks an unused section header
#define SHT_PROGBITS   1          // Contains information defined by the program
#define SHT_SYMTAB     2          // Contains a linker symbol table
#define SHT_STRTAB     3          // Contains a string table
#define SHT_RELA       4          // Contains "Rela" type relocation entries
#define SHT_HASH       5          // Contains a symbol hash table
#define SHT_DYNAMIC    6          // Contains dynamic linking tables
#define SHT_NOTE       7          // Contains note information
#define SHT_NOBITS     8          // Contains uninitialized space; does'nt occupy any space in the file
#define SHT_REL        9          // Contains "Rel" type relocation entries
#define SHT_SHLIB      10         // Reserved
#define SHT_DYNSYM     11         // Contains a dynamic loader symbol table
#define SHT_LOOS       0x60000000 // Environment-specific use
#define SHT_HIOS       0x6FFFFFFF //
#define SHT_LOPROC     0x70000000 // Processor-specific use
#define SHT_HIPROC     0x7FFFFFFF //
#define SHN_UNDEF      0          // Undefined section reference

/**
 * <p>
 * This class implements the SectionHeaderELF class.
 * It stores the Section header as defined in:
 * downloads.openwatcom.org/ftp/devel/docs/elf-64-gen.pdf
 * The raw data is stored in a buffer
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since December 22, 2012
 *
 */
class SectionHeaderELF
{
public:
	uint8_t name[MAX_SECTION_NAME+1];
	uint32_t sh_name;                // Section name
	uint32_t sh_type;                // Section type
	uint64_t sh_flags;               // Section attributes
	uint64_t sh_addr;                // Virtual address in memory
	uint64_t sh_offset;              // Offset in file
	uint64_t sh_size;                // Size of section
	uint32_t sh_link;                // Link to other section
	uint32_t sh_info;                // Miscellaneous information
	uint64_t sh_addralign;           // Address alignment boundary
	uint64_t sh_entsize;             // Size of entries, if section has table

	uint8_t *buffer;                 // Raw data
	uint64_t buffer_len;             // Size of the buffer
	uint64_t size;                   // Size of the header
	bool updated;
	uint32_t IStype;                 // type of the section instruction set either Thumb or ARM

	SectionHeaderELF();

	bool IsExe();
	bool IsProgramBits();

	bool IsText();
	bool IsInit();
	bool IsFini();
	bool IsRData();
	bool IsPlt();
	bool IsGot();
	bool IsGotPlt();
	bool IsDynamic();
	bool IsReloc();
	bool IsTBss();
	bool IsBss();
	bool IsInterp();
//	bool IsNote();
	bool IsHash();
	bool IsDynsym();
	bool IsDynstr();
	bool IsData();
	bool IsDataRel();
	bool IsComment();
	bool IsSymtab();
	bool IsStrtab();
	bool IsCtors();
	bool IsDtors();
	bool IsRela();
	bool IsRelaDyn();
	bool IsRelaPlt();
	bool IsShstrtab();
	bool IsJcr();
	bool IsEhFrame();
	bool IsEhFrameHdr();
	bool IsNoteABITag();
	bool IsNoteGNUBuildID();
	bool IsGNUHash();
	bool IsGNUVersion();
	bool IsGNUVersionR();
	bool IsGcc();
	bool IsGccExceptTable();
	bool IsLibc();

	void Print(bool printBuffer);
};

#endif // __SECTION_HEADER_ELF_H__
