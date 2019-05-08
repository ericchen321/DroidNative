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

#include "mail.h"

MAIL::MAIL(int asm_language, uint64_t entryPointAddress, vector<_code> *codes, vector<_data> *datas)
{
	trX86 = NULL;
	trARM = NULL;
	if (codes->size() > 0)
	{
		if (asm_language == X86_ASSEMBLY_LANGUAGE)
		{
			trX86 = new x86AsmToMAIL(codes, datas);
			trX86->Translate(entryPointAddress);
		}
		else if (asm_language == ARM_ASSEMBLY_LANGUAGE)
		{
			trARM = new ArmAsmToMAIL(codes, datas);
			trARM->Translate(entryPointAddress);
		}
	}
}

MAIL::~MAIL()
{
	if (trX86 != NULL)
	{
		delete (trX86);
		trX86 = NULL;
	}
	else if (trARM != NULL)
	{
		delete (trARM);
		trARM = NULL;
	}
}

/*
 * Returns a vector of all the statements
 */
vector<Function *> MAIL::GetFunctions()
{
	vector<Function *> functions;
	if (trX86 != NULL)
		functions = trX86->GetFunctions();
	else if (trARM != NULL)
		functions = trARM->GetFunctions();

	return (functions);
}

/*
 * Returns a vector of all the statements
 */
vector<Statement *> MAIL::GetStatements()
{
	vector <Statement *> stmts;
	if (trX86 != NULL)
		stmts = trX86->GetStatements();
	else if (trARM != NULL)
		stmts = trARM->GetStatements();

	return (stmts);
}

/*
 * Returns a vector of all the blocks
 */
vector<Block *> MAIL::GetBlocks()
{
	vector <Block *> blocks;
	if (trX86 != NULL)
		blocks = trX86->GetBlocks();
	else if (trARM != NULL)
		blocks = trARM->GetBlocks();

	return (blocks);
}

/*
 * Returns a vector of all the back edges
 */
vector<BackEdge *> MAIL::GetBackEdges()
{
	vector<BackEdge *> backEdges;
	if (trX86 != NULL)
		backEdges = trX86->GetBackEdges();
	else if (trARM != NULL)
		backEdges = trARM->GetBackEdges();

	return (backEdges);
}

void MAIL::Print()
{
   if (trX86 != NULL)
      trX86->Print();
   else if (trARM != NULL)
      trARM->Print();
}
