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

#include "sectionHeaderELF.h"

SectionHeaderELF::SectionHeaderELF()
{
	updated      = false;
	name[0]      = '\0';
	sh_name      = 0;
	sh_type      = 0;
	sh_flags     = 0;
	sh_addr      = 0;
	sh_offset    = 0;
	sh_size      = 0;
	sh_link      = 0;
	sh_info      = 0;
	sh_addralign = 0;
	sh_entsize   = 0;
	buffer       = 0;
	buffer_len   = 0;
	IStype       = INSTRUCTION_SET_THUMB;
	size         = sizeof(sh_name) +
					sizeof(sh_type) +
					sizeof(sh_flags) +
					sizeof(sh_addr) +
					sizeof(sh_offset) +
					sizeof(sh_size) +
					sizeof(sh_link) +
					sizeof(sh_info) +
					sizeof(sh_addralign) +
					sizeof(sh_entsize);
}

bool SectionHeaderELF::IsExe()
{
	if ((sh_flags & SHF_EXECINSTR) == SHF_EXECINSTR)
		return true;

	return false;
}

bool SectionHeaderELF::IsProgramBits()
{
	if (sh_type == SHT_PROGBITS)
		return true;

	return false;
}

bool SectionHeaderELF::IsText()
{
//	if (sh_type == SHT_PROGBITS && sh_flags == (SHF_ALLOC | SHF_EXECINSTR))
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('t'))
			&& (name[2] == (uint8_t)('e'))
			&& (name[3] == (uint8_t)('x'))
			&& (name[4] == (uint8_t)('t'));
	}
	return res;
}
bool SectionHeaderELF::IsInit()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('i'))
			&& (name[2] == (uint8_t)('n'))
			&& (name[3] == (uint8_t)('i'))
			&& (name[4] == (uint8_t)('t'));
	}
	return res;
}
bool SectionHeaderELF::IsFini()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('f'))
			&& (name[2] == (uint8_t)('i'))
			&& (name[3] == (uint8_t)('n'))
			&& (name[4] == (uint8_t)('i'));
	}
	return res;
}
bool SectionHeaderELF::IsRData()
{
//	if (sh_type == SHT_PROGBITS && sh_flags == SHF_ALLOC)
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('r'))
			&& (name[2] == (uint8_t)('o'))
			&& (name[3] == (uint8_t)('d'))
			&& (name[4] == (uint8_t)('a'))
			&& (name[5] == (uint8_t)('t'))
			&& (name[6] == (uint8_t)('a'));
	}
	return res;
}
bool SectionHeaderELF::IsPlt()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('p'))
			&& (name[2] == (uint8_t)('l'))
			&& (name[3] == (uint8_t)('t'));
	}
	return res;
}
bool SectionHeaderELF::IsGot()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('g'))
			&& (name[2] == (uint8_t)('o'))
			&& (name[3] == (uint8_t)('t'));
	}
	return res;
}
bool SectionHeaderELF::IsGotPlt()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('g'))
			&& (name[2] == (uint8_t)('o'))
			&& (name[3] == (uint8_t)('t'))
			&& (name[4] == (uint8_t)('.'))
			&& (name[5] == (uint8_t)('p'))
			&& (name[6] == (uint8_t)('l'))
			&& (name[7] == (uint8_t)('t'));
	}
	return res;
}
bool SectionHeaderELF::IsDynamic()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('d'))
			&& (name[2] == (uint8_t)('y'))
			&& (name[3] == (uint8_t)('n'))
			&& (name[4] == (uint8_t)('a'))
			&& (name[5] == (uint8_t)('m'))
			&& (name[6] == (uint8_t)('i'))
			&& (name[7] == (uint8_t)('c'));
	}
	return res;
}

bool SectionHeaderELF::IsReloc()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('r'))
			&& (name[2] == (uint8_t)('l'))
			&& (name[3] == (uint8_t)('o'))
			&& (name[4] == (uint8_t)('c'));
	}
	return res;
}

bool SectionHeaderELF::IsBss()
{
//	if (sh_type == SHT_NOBITS && sh_flags == (SHF_ALLOC | SHF_WRITE))
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('b'))
			&& (name[2] == (uint8_t)('s'))
			&& (name[3] == (uint8_t)('s'));
	}
	return res;
}

bool SectionHeaderELF::IsTBss()
{
//	if (sh_type == SHT_NOBITS && sh_flags == (SHF_ALLOC | SHF_WRITE))
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('t'))
			&& (name[2] == (uint8_t)('b'))
			&& (name[3] == (uint8_t)('s'))
			&& (name[4] == (uint8_t)('s'));
	}
	return res;
}

bool SectionHeaderELF::IsInterp()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('i'))
			&& (name[2] == (uint8_t)('n'))
			&& (name[3] == (uint8_t)('t'))
			&& (name[4] == (uint8_t)('e'))
			&& (name[5] == (uint8_t)('r'))
			&& (name[6] == (uint8_t)('p'));
	}
	return res;
}

//bool SectionHeaderELF::IsNote()
//{
//	bool res = false;
//	if (name != 0)
//	{
//		res = (name[0] == (uint8_t)('.'))
//			&& (name[1] == (uint8_t)('n'))
//			&& (name[2] == (uint8_t)('o'))
//			&& (name[3] == (uint8_t)('t'))
//			&& (name[4] == (uint8_t)('e'));
//	}
//	return res;
//}

bool SectionHeaderELF::IsHash()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('h'))
			&& (name[2] == (uint8_t)('a'))
			&& (name[3] == (uint8_t)('s'))
			&& (name[4] == (uint8_t)('h'));
	}
	return res;
}

bool SectionHeaderELF::IsDynsym()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('d'))
			&& (name[2] == (uint8_t)('y'))
			&& (name[3] == (uint8_t)('n'))
			&& (name[4] == (uint8_t)('s'))
			&& (name[5] == (uint8_t)('y'))
			&& (name[6] == (uint8_t)('m'));
	}
	return res;
}
bool SectionHeaderELF::IsDynstr()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('d'))
			&& (name[2] == (uint8_t)('y'))
			&& (name[3] == (uint8_t)('n'))
			&& (name[4] == (uint8_t)('s'))
			&& (name[5] == (uint8_t)('t'))
			&& (name[6] == (uint8_t)('r'));
	}
	return res;
}
bool SectionHeaderELF::IsData()
{
//	if (sh_type == SHT_PROGBITS && sh_flags == (SHF_ALLOC | SHF_WRITE))
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('d'))
			&& (name[2] == (uint8_t)('a'))
			&& (name[3] == (uint8_t)('t'))
			&& (name[4] == (uint8_t)('a'));
	}
	return res;
}
bool SectionHeaderELF::IsDataRel()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('d'))
			&& (name[2] == (uint8_t)('a'))
			&& (name[3] == (uint8_t)('t'))
			&& (name[4] == (uint8_t)('a'))
			&& (name[5] == (uint8_t)('.'))
			&& (name[6] == (uint8_t)('r'))
			&& (name[7] == (uint8_t)('e'))
			&& (name[8] == (uint8_t)('l'));
	}
	return res;
}
bool SectionHeaderELF::IsComment()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('c'))
			&& (name[2] == (uint8_t)('o'))
			&& (name[3] == (uint8_t)('m'))
			&& (name[4] == (uint8_t)('m'))
			&& (name[5] == (uint8_t)('e'))
			&& (name[6] == (uint8_t)('n'))
			&& (name[7] == (uint8_t)('t'));
	}
	return res;
}
bool SectionHeaderELF::IsSymtab()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('s'))
			&& (name[2] == (uint8_t)('y'))
			&& (name[3] == (uint8_t)('m'))
			&& (name[4] == (uint8_t)('t'))
			&& (name[5] == (uint8_t)('a'))
			&& (name[6] == (uint8_t)('b'));
	}
	return res;
}
bool SectionHeaderELF::IsStrtab()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('s'))
			&& (name[2] == (uint8_t)('t'))
			&& (name[3] == (uint8_t)('r'))
			&& (name[4] == (uint8_t)('t'))
			&& (name[5] == (uint8_t)('a'))
			&& (name[6] == (uint8_t)('b'));
	}
	return res;
}
bool SectionHeaderELF::IsCtors()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('c'))
			&& (name[2] == (uint8_t)('t'))
			&& (name[3] == (uint8_t)('o'))
			&& (name[4] == (uint8_t)('r'))
			&& (name[5] == (uint8_t)('s'));
	}
	return res;
}
bool SectionHeaderELF::IsDtors()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('d'))
			&& (name[2] == (uint8_t)('t'))
			&& (name[3] == (uint8_t)('o'))
			&& (name[4] == (uint8_t)('r'))
			&& (name[5] == (uint8_t)('s'));
	}
	return res;
}
bool SectionHeaderELF::IsRela()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('r'))
			&& (name[2] == (uint8_t)('e'))
			&& (name[3] == (uint8_t)('l'))
			&& (name[4] == (uint8_t)('a'));
	}
	return res;
}
bool SectionHeaderELF::IsRelaDyn()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('r'))
			&& (name[2] == (uint8_t)('e'))
			&& (name[3] == (uint8_t)('l'))
			&& (name[4] == (uint8_t)('a'))
			&& (name[5] == (uint8_t)('.'))
			&& (name[6] == (uint8_t)('d'))
			&& (name[7] == (uint8_t)('y'))
			&& (name[8] == (uint8_t)('n'));
	}
	return res;
}
bool SectionHeaderELF::IsRelaPlt()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('r'))
			&& (name[2] == (uint8_t)('e'))
			&& (name[3] == (uint8_t)('l'))
			&& (name[4] == (uint8_t)('a'))
			&& (name[5] == (uint8_t)('.'))
			&& (name[6] == (uint8_t)('p'))
			&& (name[7] == (uint8_t)('l'))
			&& (name[8] == (uint8_t)('t'));
	}
	return res;
}
bool SectionHeaderELF::IsShstrtab()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('s'))
			&& (name[2] == (uint8_t)('h'))
			&& (name[3] == (uint8_t)('s'))
			&& (name[4] == (uint8_t)('t'))
			&& (name[5] == (uint8_t)('r'))
			&& (name[6] == (uint8_t)('t'))
			&& (name[7] == (uint8_t)('a'))
			&& (name[8] == (uint8_t)('b'));
	}
	return res;
}
bool SectionHeaderELF::IsJcr()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('j'))
			&& (name[2] == (uint8_t)('c'))
			&& (name[3] == (uint8_t)('r'));
	}
	return res;
}
bool SectionHeaderELF::IsEhFrame()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('e'))
			&& (name[2] == (uint8_t)('h'))
			&& (name[3] == (uint8_t)('_'))
			&& (name[4] == (uint8_t)('f'))
			&& (name[5] == (uint8_t)('r'))
			&& (name[6] == (uint8_t)('a'))
			&& (name[7] == (uint8_t)('m'))
			&& (name[8] == (uint8_t)('e'));
	}
	return res;
}
bool SectionHeaderELF::IsEhFrameHdr()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('e'))
			&& (name[2] == (uint8_t)('h'))
			&& (name[3] == (uint8_t)('_'))
			&& (name[4] == (uint8_t)('f'))
			&& (name[5] == (uint8_t)('r'))
			&& (name[6] == (uint8_t)('a'))
			&& (name[7] == (uint8_t)('m'))
			&& (name[8] == (uint8_t)('e'))
			&& (name[9] == (uint8_t)('_'))
			&& (name[10] == (uint8_t)('h'))
			&& (name[11] == (uint8_t)('d'))
			&& (name[12] == (uint8_t)('r'));
	}
	return res;
}
bool SectionHeaderELF::IsNoteABITag()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('n'))
			&& (name[2] == (uint8_t)('o'))
			&& (name[3] == (uint8_t)('t'))
			&& (name[4] == (uint8_t)('e'))
			&& (name[5] == (uint8_t)('.'))
			&& (name[6] == (uint8_t)('A'))
			&& (name[7] == (uint8_t)('B'))
			&& (name[8] == (uint8_t)('I'))
			&& (name[9] == (uint8_t)('-'))
			&& (name[10] == (uint8_t)('t'))
			&& (name[11] == (uint8_t)('a'))
			&& (name[12] == (uint8_t)('g'));
	}
	return res;
}
bool SectionHeaderELF::IsNoteGNUBuildID()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('n'))
			&& (name[2] == (uint8_t)('o'))
			&& (name[3] == (uint8_t)('t'))
			&& (name[4] == (uint8_t)('e'))
			&& (name[5] == (uint8_t)('.'))
			&& (name[6] == (uint8_t)('g'))
			&& (name[7] == (uint8_t)('n'))
			&& (name[8] == (uint8_t)('u'))
			&& (name[9] == (uint8_t)('.'))
			&& (name[10] == (uint8_t)('b'))
			&& (name[11] == (uint8_t)('u'))
			&& (name[12] == (uint8_t)('i'))
			&& (name[13] == (uint8_t)('l'))
			&& (name[14] == (uint8_t)('d'))
			&& (name[15] == (uint8_t)('-'))
			&& (name[16] == (uint8_t)('i'))
			&& (name[17] == (uint8_t)('d'));
	}
	return res;
}
bool SectionHeaderELF::IsGNUHash()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('g'))
			&& (name[2] == (uint8_t)('n'))
			&& (name[3] == (uint8_t)('u'))
			&& (name[4] == (uint8_t)('.'))
			&& (name[5] == (uint8_t)('h'))
			&& (name[6] == (uint8_t)('a'))
			&& (name[7] == (uint8_t)('s'))
			&& (name[8] == (uint8_t)('h'));
	}
	return res;
}
bool SectionHeaderELF::IsGNUVersion()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('g'))
			&& (name[2] == (uint8_t)('n'))
			&& (name[3] == (uint8_t)('u'))
			&& (name[4] == (uint8_t)('.'))
			&& (name[5] == (uint8_t)('v'))
			&& (name[6] == (uint8_t)('e'))
			&& (name[7] == (uint8_t)('r'))
			&& (name[8] == (uint8_t)('s'))
			&& (name[9] == (uint8_t)('i'))
			&& (name[10] == (uint8_t)('o'))
			&& (name[11] == (uint8_t)('n'));
	}
	return res;
}
bool SectionHeaderELF::IsGNUVersionR()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('g'))
			&& (name[2] == (uint8_t)('n'))
			&& (name[3] == (uint8_t)('u'))
			&& (name[4] == (uint8_t)('.'))
			&& (name[5] == (uint8_t)('v'))
			&& (name[6] == (uint8_t)('e'))
			&& (name[7] == (uint8_t)('r'))
			&& (name[8] == (uint8_t)('s'))
			&& (name[9] == (uint8_t)('i'))
			&& (name[10] == (uint8_t)('o'))
			&& (name[11] == (uint8_t)('n'))
			&& (name[12] == (uint8_t)('_'))
			&& (name[13] == (uint8_t)('r'));
	}
	return res;
}
bool SectionHeaderELF::IsGcc()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('g'))
			&& (name[2] == (uint8_t)('c'))
			&& (name[3] == (uint8_t)('c'));
	}
	return res;
}

bool SectionHeaderELF::IsGccExceptTable()
{
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('.'))
			&& (name[1] == (uint8_t)('g'))
			&& (name[2] == (uint8_t)('c'))
			&& (name[3] == (uint8_t)('c'))
			&& (name[4] == (uint8_t)('_'))
			&& (name[5] == (uint8_t)('e'))
			&& (name[6] == (uint8_t)('x'))
			&& (name[7] == (uint8_t)('c'))
			&& (name[8] == (uint8_t)('e'))
			&& (name[9] == (uint8_t)('p'))
			&& (name[10] == (uint8_t)('t'))
			&& (name[11] == (uint8_t)('_'))
			&& (name[12] == (uint8_t)('t'))
			&& (name[13] == (uint8_t)('a'))
			&& (name[14] == (uint8_t)('b'))
			&& (name[15] == (uint8_t)('l'))
			&& (name[16] == (uint8_t)('e'));
	}
	return res;
}

bool SectionHeaderELF::IsLibc()
{
//	if (sh_type == SHT_NOBITS && sh_flags == (SHF_ALLOC | SHF_WRITE))
	bool res = false;
	if (name != 0)
	{
		res = (name[0] == (uint8_t)('_'))
			&& (name[1] == (uint8_t)('_'))
			&& (name[2] == (uint8_t)('l'))
			&& (name[3] == (uint8_t)('i'))
			&& (name[4] == (uint8_t)('b'))
			&& (name[5] == (uint8_t)('c'));
	}
	return res;
}

void SectionHeaderELF::Print(bool printBuffer)
{
	if (name != 0)
		printf ("   Name = %s\n", name);
	printf ("   Name @ Offset = 0x%X\n", sh_name);
	printf ("   Type = 0x%X\n", sh_type);
	printf ("   Flags = 0x%lX\n", sh_flags);
	printf ("   Address = 0x%X\n", (unsigned int)sh_addr);
	printf ("   Offset = 0x%X\n", (unsigned int)sh_offset);
	printf ("   Size = 0x%lX\n", sh_size);
	printf ("   Link = 0x%X\n", sh_link);
	printf ("   Info = 0x%X\n", sh_info);
	printf ("   Address Align = 0x%lX\n", sh_addralign);
	printf ("   Entries Size = 0x%lX\n", sh_entsize);
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
