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

#ifndef __PARSER_H__
#define __PARSER_H__

#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <exception>

#include "../include/capstone.h"
#include "../include/distorm.h"
#include "../include/common.h"
#include "../pe/pe.h"
#include "../elf/elf.h"
#include "../util/util.h"
#include "../mail/mail.h"
#include "../mail/signature.h"
#include "../cfg/cfg.h"

using namespace std;

#define OAT_X86                0
#define OAT_ARM                1
#define ARCHITECTURE_UNKNOWN   9

#define COPY_TESTING           101
#define PROCEDURE_CALL         102

/**
 * <p>
 * This class implements the Parser class.
 * It parses binary file in PE or ELF format and constructs a CFG.
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since December 04, 2014
 *
 */
class Parser
{
private:
	struct _CodePos
	{
		uint64_t pos;
		uint64_t size;
	};
	string filename;
	uint8_t *buffer;
	uint64_t size;
	bool isPE, isELF, isOAT, dynamic;
	vector<_code> codes;
	vector<_data> datas;
	CFG *cfg;
	vector <CFG *> cfgs;

	bool disassemble(bool is64);
	bool disassembleELF(ELF *elf);
	bool disassemblePE(PE *pe);
	void addCodeWithFunctions(map<string, _code> *codes_m, string name, SectionHeaderELF *sh, uint64_t *Functions_Sorted,
							  uint64_t &nextStartingFunctionIndex, uint64_t totalNumberOfFunctions);
	void addCodeX86ELF(string name, SectionHeaderELF *sh, bool is64);
	void addCodeARMELF(string name, SectionHeaderELF *sh, ELF *elf);
	void addDataELF(string name, SectionHeaderELF *sh);
	void addCodePE(string name, SectionHeaderPE *sh, bool is64);
	void addDataPE(string name, SectionHeaderPE *sh);
	uint8_t parseOAT();
	void copyInstructions (_DecodedInst *destination, _DecodedInst *source, uint64_t decodedInstructionsCount,
						 uint64_t &totalInstructionsCopied);

public:
	MAIL *mail;
	Parser(uint8_t *buffer, uint64_t size);
	~Parser();
	CFG *BuildCFG();
	vector <CFG *> BuildCFGs();
	void Parse(string filename);
	vector<Function> GetFunctionsToProfile();
};

#endif // __PARSER_H__
