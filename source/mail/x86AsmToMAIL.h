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

#ifndef __x86ASMTOMAIL_H__
#define __x86ASMTOMAIL_H__

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <vector>
#include <map>

#include "patterns.h"
#include "../parser/instruction.h"
#include "../parser/operator.h"
#include "../include/common.h"

#define LIMIT_OF_STATEMENT_ADDED 3

using namespace std;

/**
 * <p>
 * This class implements the x86AsmToMAIL class.
 * It translates a x86 assembly program to the language MAIL.
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since March 09, 2013
 *
 */
class x86AsmToMAIL
{
private:
	vector<Function *> functions;
	vector<Statement *> Statements;
	vector<Block *> blocks;
	vector<BackEdge *> backEdges;
	vector<_code> *codes;
	vector<_data> *datas;
	map<string, string> conditionalInstructionMap;

	void initData();
	bool isEndOfProgram(Statement *statement);
	bool isEndOfFunction(Statement *statement);
	void addEdgeToBlock(Block *block_jumped_from, Block *block_jumped_to, Edge *edge, Function *function);
	bool tagStatementAsStart(uint64_t number_of_statements, Statement *prev, Statement *current, map<uint64_t, Statement *> *jump_offsets);
	bool traceBackTagStatementAsStart(vector<Statement *> stmt, uint64_t prev_stmt_number, uint64_t offset);
	void initBlocks(map<uint64_t, Statement *> &jump_offsets);

	Statement *ProcessStatements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets);
	Statement *Process_A_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number);
	Statement *Process_C_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets);
	Statement *Process_F_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number);
	Statement *Process_I_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number);
	Statement *Process_L_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number);
	Statement *Process_M_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number);
	Statement *Process_P_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number);
	Statement *Process_R_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number);
	Statement *Process_S_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number);
	Statement *Process_V_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number);
	Statement *Process_X_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number);

	int64_t getValue(uint64_t pc, _DecodedInst *disassembled, bool &memory);
	int64_t computeValue(_DecodedInst *disassembled, string addr, uint64_t ic);
	int64_t getRegisterValue(string reg, _DecodedInst *disassembled, uint64_t ic);

public:
	x86AsmToMAIL(vector<_code> *codes, vector<_data> *datas);
	~x86AsmToMAIL();
	uint64_t Translate(uint64_t entryPointAddress);
	vector<Function *> GetFunctions();
	vector<Statement *> GetStatements();
	vector<Block *> GetBlocks();
	vector<BackEdge *> GetBackEdges();
	void Print();
};

#endif // __x86ASMTOMAIL_H__
