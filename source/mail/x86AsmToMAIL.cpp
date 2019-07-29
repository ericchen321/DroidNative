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

#include "x86AsmToMAIL.h"

x86AsmToMAIL::x86AsmToMAIL(vector<_code> *codes, vector<_data> *datas)
{
	this->codes = codes;
	this->datas = datas;

	initData();
}

x86AsmToMAIL::~x86AsmToMAIL()
{
	for (int i = 0; i < (int)backEdges.size(); i++)
		delete (backEdges[i]);
	backEdges.erase(backEdges.begin(), backEdges.end());

#ifdef __SIGNATURE_MATCHING__
	for (int i = 0; i < (int)functions.size(); i++)
	{
		vector <Block *> blocks_local = functions[i]->blocks;
		for (int b = 0; b < (int)blocks_local.size(); b++)
		{
			for (int e = 0; e < (int)blocks_local[b]->edges.size(); e++)
			{
#ifdef __DEBUG__
				cerr << "ArmAsmToMAIL::~ArmAsmToMAIL: block number: " << blocks_local[b]->number << " Deleting edge: " << blocks_local[b]->edges[e]->tail->number << " --> " << blocks_local[b]->edges[e]->head->number << endl;
				cout << "ArmAsmToMAIL::~ArmAsmToMAIL: block number: " << blocks_local[b]->number << " Deleting edge: " << blocks_local[b]->edges[e]->tail->number << " --> " << blocks_local[b]->edges[e]->head->number << endl;
#endif
				delete (blocks_local[b]->edges[e]);
			}
			blocks_local[b]->edges.erase(blocks_local[b]->edges.begin(), blocks_local[b]->edges.end());
			blocks_local[b]->in_edges.erase(blocks_local[b]->in_edges.begin(), blocks_local[b]->in_edges.end());

			vector<Statement *> statements = blocks_local[b]->statements;
			for (int s = 0; s < (int)statements.size(); s++)
				delete (statements[s]);
			statements.erase(statements.begin(), statements.end());

#ifdef __DEBUG__
			cerr << "ArmAsmToMAIL::~ArmAsmToMAIL: Deleting block number: " << blocks_local[b]->number << endl;
			cout << "ArmAsmToMAIL::~ArmAsmToMAIL: Deleting block number: " << blocks_local[b]->number << endl;
#endif
			delete (blocks_local[b]);
		}
		blocks_local.erase(blocks_local.begin(), blocks_local.end());

		functions[i]->backEdges.erase(functions[i]->backEdges.begin(), functions[i]->backEdges.end());
		delete (functions[i]);
	}

	Statements.erase(Statements.begin(), Statements.end());
	blocks.erase(blocks.begin(), blocks.end());
	functions.erase(functions.begin(), functions.end());
#endif

	conditionalInstructionMap.erase(conditionalInstructionMap.begin(), conditionalInstructionMap.end());
}

void x86AsmToMAIL::initData()
{
	conditionalInstructionMap.insert(pair<string, string>("AE"  , "(CF == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("A"   , "(CF == 0 and ZF == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("BE"  , "(CF == 1 and ZF == 1)"));
	conditionalInstructionMap.insert(pair<string, string>("B"   , "(CF == 1)"));
	conditionalInstructionMap.insert(pair<string, string>("CXZ" , "(CX == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("C"   , "(CF == 1)"));
	conditionalInstructionMap.insert(pair<string, string>("ECXZ", "(ECX == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("RCXZ", "(RCX == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("E"   , "(ZF == 1)"));
	conditionalInstructionMap.insert(pair<string, string>("GE"  , "(SF == 1)"));
	conditionalInstructionMap.insert(pair<string, string>("G"   , "(ZF == 0 and SF == 1)"));
	conditionalInstructionMap.insert(pair<string, string>("LE"  , "(ZF == 1 and SF == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("L"   , "(SF == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("NAE" , "(CF == 1)"));
	conditionalInstructionMap.insert(pair<string, string>("NA"  , "(CF == 1 and ZF == 1)"));
	conditionalInstructionMap.insert(pair<string, string>("NBE" , "(CF == 0 and ZF == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("NB"  , "(CF == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("NC"  , "(CF == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("NE"  , "(ZF == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("NGE" , "(SF == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("NG"  , "(ZF == 1 and SF == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("NLE" , "(ZF == 0 and SF == 1)"));
	conditionalInstructionMap.insert(pair<string, string>("NL"  , "(SF == 1)"));
	conditionalInstructionMap.insert(pair<string, string>("NO"  , "(OF == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("NP"  , "(PF == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("NS"  , "(SF == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("NZ"  , "(ZF == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("O"   , "(OF == 1)"));
	conditionalInstructionMap.insert(pair<string, string>("P"   , "(PF == 1)"));
	conditionalInstructionMap.insert(pair<string, string>("PE"  , "(PF == 1)"));
	conditionalInstructionMap.insert(pair<string, string>("PO"  , "(PF == 0)"));
	conditionalInstructionMap.insert(pair<string, string>("S"   , "(SF == 1)"));
	conditionalInstructionMap.insert(pair<string, string>("Z"   , "(ZF == 1)"));
}

/*
 *
 * Check if the statement is the end of the program
 *
 */
bool x86AsmToMAIL::isEndOfProgram(Statement *statement)
{
	if (statement->value.find("halt") == 0)
		return true;
	return false;
}

/*
 *
 * Check if the statement is the end of the function
 *
 */
bool x86AsmToMAIL::isEndOfFunction(Statement *statement)
{
	if (statement->value.find("jmp [sp=sp") == 0)
		return true;
	return false;
}

/*
 *
 * Add an edge to the block
 *
 */
void x86AsmToMAIL::addEdgeToBlock(Block *block_jumped_from, Block *block_jumped_to, Edge *edge, Function *function)
{
	/*
	 * Do not add the edge if it has already been added
	 */
	bool alreadyAdded = false;
	for (int b = 0; b < block_jumped_from->edges.size(); b++)
	{
		if (block_jumped_from->edges[b]->tail == edge->tail && block_jumped_from->edges[b]->head == edge->head)
		{
			alreadyAdded = true;
			break;
		}
	}

	if (!alreadyAdded)
	{
		block_jumped_from->edges.push_back(edge);
		block_jumped_to->in_edges.push_back(edge);
		/*
		 * Keep record of the back edges to be used latter for finding loops.
		 */
		if (block_jumped_from->number > edge->head->number)
		{
			BackEdge *be = new BackEdge();
			be->tail = edge->head;
			be->head = block_jumped_from;
			backEdges.push_back(be);
			function->backEdges.push_back(be);
		}
#ifdef __DEBUG__
	cout << dec << block_jumped_from->number << " --> " << edge->head->number << endl;
#endif
	}
}

/*
 *
 * If the previous instruction is the end instruction then tag the instruction as start.
 * Also check if this instruction is jumped to by another instruction then tag this
 * instruction as start and the previous instruction of this instruction as the end
 * instruction.
 *
 * Returns true if this instruction is jumped to.
 *
 */
bool x86AsmToMAIL::tagStatementAsStart(uint64_t number_of_statements, Statement *prev, Statement *current, map<uint64_t, Statement *> *jump_offsets)
{
	if (number_of_statements == 0)
		current->start = true;
	else if (number_of_statements > 0 && prev->end)
	{
		current->start = true;
		return true;
	}
	else if (number_of_statements > 0)
	{
		/*
		 * If jumped to the current statement's offset
		 */
		map<uint64_t, Statement *>::iterator it_j_offsets = jump_offsets->find(current->offset);
		if (it_j_offsets != jump_offsets->end())
		{
			prev->end = true;
			current->start = true;
			return true;
		}
	}

	return false;
}

/*
 *
 * This function translates the x86 assembly program to MAIL program
 * It is passed the disassembled instructions (code):
 * e.g for PE format:
 * .text, .textbss
 * in that order
 *
 * Whenever there is a jump to an instruction address that address is added to the
 * jump_offsets vector to keep track of all the jumps/calls. These
 * addresses are then checked and tagged accordingly during the trnaslation process.
 *
 * entryPointAddress = Entry address currenlty not used
 * We start from the beginning of the .text section
 *
 */
uint64_t x86AsmToMAIL::Translate(uint64_t entryPointAddress)
{
	uint64_t register_number = 0;
	Statement *prev_statement = NULL;
	uint64_t number_of_statements = 0;
	vector<_code>::iterator it_n_code;

	/*
	 * Map of all the jumps to be used latter to add edges to blocks
	 * It stores the jump offset with the jump statement
	 */
	map<uint64_t, Statement *> jump_offsets;

#ifdef __DEBUG__
	printf ("|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
	printf ("|                                     Instructions                                   translated to                         Statements\n");
	printf ("| Count  Offset        Hex Dump                Opcode                Operands                       Count  Offset              Statement\n");
	printf ("|\n");
#endif

#ifdef __TRANSLATION_TIME__
	clock_t start = clock();
#endif

	for (it_n_code = codes->begin(); it_n_code != codes->end(); it_n_code++)
	{
		for (uint64_t i = 0; i < it_n_code->code_size; i++)
		{
			/*
			 * Normalization/Optimization:
			 *
			 * Throw away NOP instructions
			 * Throw away DB instructions
			 */
			string opcode = (char *)it_n_code->decoded[i].mnemonic.p;
			Util::removeWhiteSpaces(opcode);
			if (opcode.find("DB") == std::string::npos && opcode.find("NOP") == std::string::npos)// && it_n_code->decoded[i].offset >= entryPointAddress)
			{
#ifdef __DEBUG__
				printf("%5d %7x %26s %10s %36s", (int)i, (int)it_n_code->decoded[i].offset, it_n_code->decoded[i].instructionHex.p, it_n_code->decoded[i].mnemonic.p, it_n_code->decoded[i].operands.p);
#endif
				/*
				 * Normalization/Optimization:
				 *
				 * Throw away JUNK instructions
				 * i.e:
				 *   000000
				 */
				if (it_n_code->decoded[i].instructionHex.p[0] == '0' && it_n_code->decoded[i].instructionHex.p[1] == '0')
				{
					int zero = 1;
					i++;
					for ( ; i < it_n_code->code_size; i++)
					{
						if (it_n_code->decoded[i].instructionHex.p[0] == '0' && it_n_code->decoded[i].instructionHex.p[1] == '0')
							zero++;
						else
							break;
					}
					if (i >= it_n_code->code_size)
						break;
					i--;
					if (zero > 2)
					{
#ifdef __DEBUG__
						printf ("\n");
#endif
						continue;
					}
				}
				/*
				 * Normalization/Optimization:
				 *
				 * Throw away INT 3 instructions
				 * i.e:
				 *   00cc
				 *   cccc
				 */
				if ( (it_n_code->decoded[i].instructionHex.p[0] == '0' && it_n_code->decoded[i].instructionHex.p[1] == '0')
					||
					(it_n_code->decoded[i].instructionHex.p[0] == 'c' && it_n_code->decoded[i].instructionHex.p[1] == 'c')
					)
				{
					int int3 = 1;
					i++;
					for ( ; i < it_n_code->code_size; i++)
					{
						if (it_n_code->decoded[i].instructionHex.p[0] == 'c' && it_n_code->decoded[i].instructionHex.p[1] == 'c')
							int3++;
						else
							break;
					}
					i--;
					if (int3 > 1)
					{
#ifdef __DEBUG__
						printf ("\n");
#endif
						continue;
					}
				}
				/*
				 * Normalization/Optimization:
				 *
				 * Remove REP(NZ) prefixes
				 */
				if (opcode.find("REP") != string::npos)
				{
					int pos = opcode.find_first_of(" ");
					if (pos != std::string::npos)
						opcode = opcode.substr(pos+1, opcode.size()-pos+1);
					Util::removeWhiteSpaces(opcode);
				}

				/*-------------------------------------------------------
				 *
				 * New statements of the language MAIL are created.
				 *
				 ------------------------------------------------------*/
				Statement *statement = new Statement();       // Get a pointer to the new structure Statement
				statement->start = false;
				statement->end = false;
				statement->value = "";
				statement->type = PATTERN_NOTDEFINED;
				statement->branch_to_offset = BRANCH_TO_UNKNOWN;
				statement->offset = it_n_code->decoded[i].offset;

				/*
				 * Separate the operands to help in translation
				 * There are at most three operands in x86 assembly language
				 * separated by ','
				 */
				string operand[3];
				char *tokens = strtok((char *)it_n_code->decoded[i].operands.p, ",");
				if (tokens != NULL)
				{
					operand[0] = tokens;
					Util::removeWhiteSpaces(operand[0]);
					tokens = strtok(NULL, ",");
					if (tokens != NULL)
					{
						operand[1] = tokens;
						Util::removeWhiteSpaces(operand[1]);
						tokens = strtok(NULL, ",");
						if (tokens != NULL)
						{
							operand[2] = tokens;
							Util::removeWhiteSpaces(operand[2]);
						}
					}
					/*
					 * Normalization/Optimization:
					 *
					 * Remove (D/Q)WORD / BYTE prefixes
					 */
					int pos = operand[0].find("WORD");
					if (pos != std::string::npos)
					{
						string temp = operand[0];
						if ( (pos > 0) && (operand[0][pos-1] == 'D' || operand[0][pos-1] == 'Q') )
						{
							pos--;
							operand[0] = temp.substr(0, pos);
							operand[0] += temp.substr(pos+6);
						}
						else
						{
							operand[0] = temp.substr(0, pos);
							operand[0] += temp.substr(pos+5);
						}
					}
					else
					{
						pos = operand[0].find("BYTE");
						if (pos != std::string::npos)
						{
							string temp = operand[0];
							operand[0] = temp.substr(0, pos);
							operand[0] += temp.substr(pos+5);
						}
					}
				}
				statement = ProcessStatements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);

				if (statement != NULL)
				{
					//
					// The last statement is automaticaly tagged as the END_OF_FUNCTION
					//
					if (i == (it_n_code->code_size-1))
					{
						statement->end = true;
						statement->branch_to_offset = END_OF_FUNCTION;
					}
#ifdef __DEBUG__
					printf("    --->    %5d %7x   %s\n", (int)i, (int)statement->offset, statement->value.c_str());
#endif
					prev_statement = statement;
					Statements.push_back(statement);
					number_of_statements++;
				}
#ifdef __DEBUG__
				else
					printf ("\n");
#endif
			}
		}
		delete (it_n_code->decoded);
		it_n_code->decoded = NULL;
	}
	codes->erase(codes->begin(), codes->end());

#ifdef __DEBUG__
	printf ("\n\n");
#endif

#ifdef __DEBUG__
	printf ("\n\n");
	for (int s = 0; s < Statements.size(); s++)
	{
		printf ("%5d", s);
		printf ("%12x", (int)Statements[s]->offset);
		printf ("%50s", Statements[s]->value.c_str());
		if (Statements[s]->start)
			printf("%12s", "START");
		if (Statements[s]->end)
			printf("%12s", "END");
		if (Statements[s]->branch_to_offset >= 0)
			printf ("%12x", (int)Statements[s]->branch_to_offset);
		printf ("\n");
	}
#endif

	initBlocks(jump_offsets);

#ifdef __TRANSLATION_TIME__
	clock_t end = clock();
	cerr << "Translation time: " << ((float)(end - start))/CLOCKS_PER_SEC << " second(s)\n";
	cout << "Translation time: " << ((float)(end - start))/CLOCKS_PER_SEC << " second(s)\n";
#endif

	return (number_of_statements);
}

/*
 *
 * This function initialses the block structure which is used to build the CFG
 * Any jump outside the code region is ignored.
 *
 */
void x86AsmToMAIL::initBlocks(map<uint64_t, Statement *> &jump_offsets)
{
	bool newBlock = false;
	uint64_t fn = 0, bn = 0;
	char temp_str[MAX_TEXT_SIZE+1];
	map<uint64_t, Statement *>::iterator it_j_offsets;
	multimap<uint64_t, uint64_t> jump_offsets_to_block;

	/*-------------------------------------------------------
	 *
	 * Provide support for CFG construction. Statements are
	 * added to the block. These blocks are latter added to
	 * the CFG. Statements can also be used to build a tree
	 * for the language MAIL.
	 *
	 ------------------------------------------------------*/
	for (int s = 0; s < Statements.size(); s++)
	{
		/*
		 * Normalization/Optimization:
		 *
		 * Remove (D)WORD prefixes
		 * --- NOT IMPLEMENTED ---
		 */
/*		int pos = Statements[s]->value.find("WORD");
		if (pos != std::string::npos)
		{
			string temp = Statements[s]->value;
			if ( (pos > 0) && (Statements[s]->value[pos-1] == 'D' || Statements[s]->value[pos-1] == 'Q') )
			{
				pos--;
				Statements[s]->value = temp.substr(0, pos);
				Statements[s]->value += temp.substr(pos+6);
			}
			else
			{
				Statements[s]->value = temp.substr(0, pos);
				Statements[s]->value += temp.substr(pos+5);
			}
		}
		else
		{
			pos = Statements[s]->value.find("BYTE");
			if (pos != std::string::npos)
			{
				string temp = Statements[s]->value;
				Statements[s]->value = temp.substr(0, pos);
				Statements[s]->value += temp.substr(pos+5);
			}
		}*/
		/*
		 *
		 * <p>
		 *
		 * Mapping of jump offsets to block numbers (Statements are stored that contains the block number)
		 * to be used latter to add edges to the blocks. The jumps that are outside the code section will
		 * not be taken as an edge. We need a multimap here because a statement can be jumped from multiple
		 * statements.
		 * e.g:
		 * multimap<uint64_t, Statement *> jump_offsets_to_block;
		 *         <jump_offset, block_number>
		 * </p>
		 * <p>
		 * -----------------------------------------------------------------------------------------------------------------------------
		 * block        offset                hex dump                instruction                   start        branch    branch block
		 * number                                                                                   /end         offset       number
		 * -----------------------------------------------------------------------------------------------------------------------------
		 *   2      400853                        8b45fc         MOV           EAX, [RBP-0x4]       START
		 *   2      400856                          4898        CDQE
		 *   2      400858                      8b5485b0         MOV    EDX, [RBP+RAX*4-0x50]
		 *   2      40085c                    b86c094000         MOV            EAX, 0x40096c
		 *   2      400861                          89d6         MOV                 ESI, EDX
		 *   2      400863                        4889c7         MOV                 RDI, RAX
		 *   2      400866                    b800000000         MOV                 EAX, 0x0
		 *   2      40086b                    e820fcffff        CALL                 0x400490         END      400490          68
		 *   3      400870                      8345fc01         ADD     DWORD [RBP-0x4], 0x1       START         END
		 *   2      400853                        8b45fc         MOV           EAX, [RBP-0x4]       START
		 *   2      400856                          4898        CDQE
		 *   2      400858                      8b5485b0         MOV    EDX, [RBP+RAX*4-0x50]
		 *   2      40085c                    b86c094000         MOV            EAX, 0x40096c
		 *   2      400861                          89d6         MOV                 ESI, EDX
		 *   2      400863                        4889c7         MOV                 RDI, RAX
		 *   2      400866                    b800000000         MOV                 EAX, 0x0
		 *   2      40086b                    e820fcffff        CALL                 0x400490         END      400490          68
		 *   3      400870                      8345fc01         ADD     DWORD [RBP-0x4], 0x1       START         END
		 *   4      400874                      837dfc0f         CMP     DWORD [RBP-0x4], 0xf       START
		 *   4      400878                          7ed9         JLE                 0x400853         END      400853           2
		 *   ---
		 *   ---
		 *   ---
  		 *   20      4004fc                      4883ec08         SUB                 RSP, 0x8       START
  		 *   20      400500                488b05d90a2000         MOV      RAX, [RIP+0x200ad9]
  		 *   20      400507                        4885c0        TEST                 RAX, RAX
  		 *   20      40050a                          7402          JZ                 0x40050e         END      40050e          22
  		 *   21      40050c                          ffd0        CALL                      RAX       START         END
  		 *   22      40050e                      4883c408         ADD                 RSP, 0x8       START
  		 *   22      400512                            c3         RET
  		 *   22      400513                            90         NOP
  		 *   22      400514                            90         NOP
  		 *   22      400515                            90         NOP
  		 *   22      400516                            90         NOP
  		 *   22      400517                            90         NOP
  		 *   22      400518                            90         NOP
  		 *   22      400519                            90         NOP
  		 *   22      40051a                            90         NOP
  		 *   22      40051b                            90         NOP
  		 *   22      40051c                            90         NOP
  		 *   22      40051d                            90         NOP
  		 *   22      40051e                            90         NOP
  		 *   22      40051f                            90         NOP                                  END END_OF_FUNCTION
  		 *   23      400520                            55        PUSH                      RBP       START
  		 *   23      400521                        4889e5         MOV                 RBP, RSP
  		 *   23      400524                            53        PUSH                      RBX
  		 *   23      400525                      4883ec08         SUB                 RSP, 0x8
  		 *   23      400529                803d000b200000         CMP BYTE [RIP+0x200b00], 0x0
  		 *   23      400530                          754b         JNZ                 0x40057d         END      40057d          29
		 *   ---
		 *   ---
		 *   ---
		 * ---------------------------------------------------------------------------------------------------------------------------
		 *
		 * Initialize the blocks with the initial edges.
		 *
		 * We use multimap to store different elements (instructions) with the same key (block number)
		 *
		 * </p>
		 *
		 */
		if (Statements[s]->branch_to_offset >= 0)
			jump_offsets_to_block.insert(pair<uint64_t, uint64_t>((uint64_t)Statements[s]->branch_to_offset, Statements[s]->offset));

		/*
		 * For finding if any of the jumps are illegal
		 * i.e: if they jump in between the instructions
		 * or jump to a junk instruction.
		 * Sometimes the metamorphic malwares try to insert
		 * code in place of the junk code during runtime
		 * and these instructions can then jump to these
		 * inserted malicious code.
		 *
		 * We erase all the known (legal) jumps.
		 * --- NOT YET IMPLEMENTED ---
		 */
		/*it_j_offsets = jump_offsets.find(Statements[s]->offset);
		if (it_j_offsets != jump_offsets.end())
			jump_offsets.erase(it_j_offsets);*/
		/*
		 * In the following LOCK statement:
		 *
		 *    0x40fd7f     74 01                          JZ           0x40fd82
		 *    0x40fd81     f0 48 0f b1 35 f2 62 29 00     LOCK CMPXCHG [RIP+0x2962f2], RSI
		 *
		 * The jump is inside the instruction to avoid lock.
		 * The following code takes care of such weird LEGAL jump instructions.
		 */
		/*else if (Statements[s]->value.find("lock") == 0)
		{
			it_j_offsets = jump_offsets.find(Statements[s]->offset + 1);
			if (it_j_offsets != jump_offsets.end())
				jump_offsets.erase(it_j_offsets);
		}*/

		if (Statements[s]->start)
		{
			Block *block = new Block();
			blocks.push_back(block);

			blocks[bn]->visited = false;
			blocks[bn]->inLoop = false;
			blocks[bn]->type = BLOCK_NORMAL;
			blocks[bn]->number = bn;
			blocks[bn]->statements.push_back(Statements[s]);

			if (bn == 0)
			{
				blocks[bn]->type = BLOCK_START_OF_PROGRAM;
				blocks[bn]->type = BLOCK_START_OF_FUNCTION;
				sprintf (temp_str, " start_function_%d", (int)fn);
				blocks[bn]->statements[0]->value.append(temp_str);
				Function *function = new Function();
				functions.push_back(function);
				blocks[bn]->function_number = fn;
			}
			else if (blocks[bn-1]->type == BLOCK_END_OF_FUNCTION)
			{
				uint32_t last = blocks[bn-1]->statements.size() - 1;
				sprintf (temp_str, " end_function_%d", (int)fn);
				blocks[bn-1]->statements[last]->value.append(temp_str);
				blocks[bn-1]->function_number = fn;

				fn++;


				blocks[bn]->type = BLOCK_START_OF_FUNCTION;
				sprintf (temp_str, " start_function_%d", (int)fn);
				blocks[bn]->statements[0]->value.append(temp_str);

				Function *function = new Function();
				functions.push_back(function);
				blocks[bn]->function_number = fn;
			}
			functions[fn]->blocks.push_back(blocks[bn]);
			blocks[bn]->function_number = fn;

			if (isEndOfFunction(Statements[s]))
				blocks[bn]->type = BLOCK_END_OF_FUNCTION;
			else if (isEndOfProgram(Statements[s]))
				blocks[bn]->type = BLOCK_END_OF_PROGRAM;

			newBlock = true;
		}
		/*
		 * Start statement has been added
		 */
		if (Statements[s]->end && newBlock)
		{
			if (isEndOfFunction(Statements[s]))
				blocks[bn]->type = BLOCK_END_OF_FUNCTION;
			else if (isEndOfProgram(Statements[s]))
				blocks[bn]->type = BLOCK_END_OF_PROGRAM;

			if (!Statements[s]->start)
				blocks[bn]->statements.push_back(Statements[s]);

			newBlock = false;
			bn++;
		}
		/*
		 * Start statement has been added
		 */
		else if (!Statements[s]->start && newBlock)
			blocks[bn]->statements.push_back(Statements[s]);
		/*
		 * Start statement has not been added
		 */
		else if (!Statements[s]->start)
			cerr << "Error::x86AsmToMAIL::translate: No start statement found @: " << dec << (bn-1) << " instruction offset: " << hex << Statements[s]->offset << ":  " << Statements[s]->value << "\n";
	}
	if (blocks.size() > 0)
	{
		blocks[bn-1]->type = BLOCK_END_OF_PROGRAM;
		blocks[bn-1]->type = BLOCK_END_OF_FUNCTION;
		sprintf (temp_str, " end_function_%d", (int)fn);
		uint64_t last = blocks[bn-1]->statements.size() - 1;
		blocks[bn-1]->statements[last]->value.append(temp_str);
	}

	/*
	 * Tagging illegal jumps as defined above
	 * --- NOT YET IMPLEMENTED ---
	 */
	/*
#ifdef __DEBUG__
	cout << "|\n";
	cout << "|   Printing Illegal jumps\n";
	cout << "|\n";
#endif
	for (it_j_offsets = jump_offsets.begin(); it_j_offsets != jump_offsets.end(); it_j_offsets++)
	{
		Statement *stmt = it_j_offsets->second;
		int pos = stmt->value.find_last_of(";");
		stmt->value.insert(pos, " ILLEGAL");
#ifdef __DEBUG__
		cout << hex << it_j_offsets->first << ": " << it_j_offsets->second->value << endl;
#endif
	}*/

	/*
	 * Add block numbers according to the functions in the program
	 * Add edges to the blocks using the multimap build earlier
	 */
	for (int f = 0; f < functions.size(); f++)
	{
		vector <Block *> blocks_local = functions[f]->blocks;
		uint64_t offset_start = blocks_local[0]->statements[0]->offset;
		uint64_t offset_end = blocks_local[blocks_local.size()-1]->statements[0]->offset;
		for (unsigned int b = 0; b < blocks_local.size(); b++)
		{
			int size = blocks_local[b]->statements.size();
			blocks_local[b]->number = b;
			if (b > 0)
			{
				Edge *edge = new Edge();
				edge->visited = false;
				edge->tail = blocks_local[b-1];
				edge->head = blocks_local[b];
				addEdgeToBlock(blocks_local[b-1], blocks_local[b], edge, functions[blocks[b-1]->function_number]);
			}

			uint64_t off = blocks_local[b]->statements[0]->offset;
			multimap<uint64_t, uint64_t>::iterator it;
			if (jump_offsets_to_block.count(off))
			{
				for (it = jump_offsets_to_block.equal_range(off).first; it != jump_offsets_to_block.equal_range(off).second; it++)
				{
					uint64_t block_offset_jumped_from = it->second;
					if (block_offset_jumped_from >= offset_start && block_offset_jumped_from <= offset_end)
					{
						uint64_t block_number_jumped_from = 0;
						for (int b1 = blocks_local.size()-1; b1 > 0; b1--)
						{
							if (block_offset_jumped_from >= blocks_local[b1]->statements[0]->offset)
							{
								block_number_jumped_from = b1;
								break;
							}
						}
						if ((blocks_local[b]->number < block_number_jumped_from)
							||
							(blocks_local[b]->number - block_number_jumped_from) > 1)
						{
							Edge *edge = new Edge();
							edge->visited = false;
							edge->tail = blocks_local[block_number_jumped_from];
							edge->head = blocks_local[b];
							addEdgeToBlock(blocks_local[block_number_jumped_from], blocks_local[b], edge, functions[blocks_local[block_number_jumped_from]->function_number]);
						}
					}
				}
			}
		}
	}

#ifdef __DEBUG__
	for (int f = 0; f < functions.size(); f++)
	{
		vector <Block *> blocks_local = functions[f]->blocks;
		cout << "New Function Size: " << blocks_local.size() << endl;
		for (unsigned int b = 0; b < blocks_local.size(); b++)
		{
			vector <Edge *> edges = blocks_local[b]->edges;
			for (int e = 0; e < edges.size(); e++)
				cout << dec << edges[e]->tail->number << " --> " << edges[e]->head->number << endl;
		}
	}

	for (int s = 0; s < Statements.size(); s++)
	{
		printf ("%5d", s);
		printf ("%5d", (int)Statements[s]->offset);
		printf ("%12x", (int)Statements[s]->offset);
		printf ("%50s", Statements[s]->value.c_str());
		if (Statements[s]->start)
			printf("%12s", "START");
		if (Statements[s]->end)
			printf("%12s", "END");
		if (Statements[s]->branch_to_offset >= 0)
			printf ("%12x", (int)Statements[s]->branch_to_offset);
		printf ("\n");
	}

	printf ("|\n|\n");
	printf ("|   Printing blocks\n");
	printf ("|\n|\n");
	for (unsigned int b = 0; b < blocks.size(); b++)
	{
		printf ("Printing block number: %5d   ", b);
		if (blocks[b]->type == BLOCK_START_OF_PROGRAM)
			printf ("%20s", "START_OF_PROGRAM");
		else if (blocks[b]->type == BLOCK_START_OF_FUNCTION)
		{
			printf ("%20s", "[START_OF_FUNCTION");
			printf ("%5d]", blocks[b]->function_number);
		}
		else if (blocks[b]->type == BLOCK_END_OF_FUNCTION)
		{
			printf ("%20s", "[END_OF_FUNCTION");
			printf ("%5d]", blocks[b]->function_number);
		}
		else if (blocks[b]->type == BLOCK_END_OF_PROGRAM)
		{
			printf ("%20s", "[END_OF_PROGRAM");
			printf ("%5d]", blocks[b]->function_number);
		}
		else
			printf ("   [%5d]", blocks[b]->function_number);
		printf ("\n");
		printf ("Edges: %d: ", blocks[b]->edges.size());
		for (int n = 0; n < blocks[b]->edges.size(); n++)
			printf ("%5d -> %5d : ", (int)blocks[b]->edges[n]->tail->number, (int)blocks[b]->edges[n]->head->number);
		printf ("\n");
		if (blocks[b]->statements.size() > 0)
		{
			for (int i = 0; i < blocks[b]->statements.size(); i++)
			{
				Statement *stmt = blocks[b]->statements[i];
				printf("     %5d", (int)stmt->offset);
				printf ("%12x", (int)stmt->offset);
				printf ("%50s", stmt->value.c_str());
				if (stmt->start)
					printf("%12s", "START");
				if (stmt->end)
					printf("%12s", "END");
				if (stmt->branch_to_offset >= 0)
					printf ("%12x", (int)stmt->branch_to_offset);
				printf ("\n");
			}
		}
		else
			printf ("Error:initBlocks::Print: Block [%d:%d] without instructions\n", b, (int)blocks[b]->function_number);
	}

	for (int f = 0; f < functions.size(); f++)
	{
		cout << "Function number " << f << ": " << dec << functions[f]->blocks.size() << " " << functions[f]->backEdges.size() << endl;
	}
#endif
}

/*
 * Returns a vector of all the functions
 */
vector<Function *> x86AsmToMAIL::GetFunctions()
{
	return (functions);
}

/*
 * Returns a vector of all the statements
 */
vector<Statement *> x86AsmToMAIL::GetStatements()
{
	return (Statements);
}

/*
 * Returns a vector of all the blocks
 */
vector<Block *> x86AsmToMAIL::GetBlocks()
{
	return (blocks);
}

/*
 * Returns a vector of all the back edges
 */
vector<BackEdge *> x86AsmToMAIL::GetBackEdges()
{
	return (backEdges);
}

/*
 *
 */
Statement *x86AsmToMAIL::ProcessStatements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	if (opcode[0] == 'A')
	{
		statement = Process_A_Statements(statement, opcode, operand, register_number, it_n_code, i);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'B')
	{
		// BLENDPD, BLENDPS, BLENDVPD and BLENDVPS
		if (opcode[1] == 'L')
		{
			statement->value = operand[0] + " = " + operand[1] + ";";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// BOUND - check array bounds
		else if (opcode[1] == 'O') { delete (statement); statement = NULL; }
		else if (opcode[1] == 'S')
		{
			// BSF - bit scan forward
			if (opcode[2] == 'F')
			{
				statement->value = "scanf(" + operand[0] + ", " + operand[1] + ");";
			}
			// BSR - bit scan reverse
			else if (opcode[2] == 'R')
			{
				statement->value = "scanr(" + operand[0] + ", " + operand[1] + ");";
			}
			// BSWAP - byte swap
			else if (opcode[2] == 'W')
			{
				statement->value = "swap(" + operand[0] + ");";
			}
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		else if (opcode[1] == 'T')
		{
			// BT - Store selected bit in CF flag
			// operand[0] is the bit base and operand[1] is the offset
			statement->value = "CF = bit(" + operand[0] + ", " + operand[1] + ");";
			if (opcode.size() > 2)
			{
				// BTC - complement it
				if (opcode[2] == 'C')
				{
					statement->value = "complement(" + operand[0] + ", " + operand[1] + ");";
				}
				// BTR - reset/clear it
				else if (opcode[2] == 'R')
				{
					statement->value = "clear(" + operand[0] + ", " + operand[1] + ", 0);";
				}
				// BTS - set it
				else if (opcode[2] == 'S')
				{
					statement->value = "set(" + operand[0] + ", " + operand[1] + ", 0);";
				}
			}
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		// UNKNOWN
		else
		{
			statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
			statement->type = PATTERN_UNKNOWN;
		}

		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'C')
	{
		statement = Process_C_Statements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'D')
	{
		// DAA, DAS
		if (opcode[1] == 'A') { delete (statement); statement = NULL; }
		// DEC
		else if (opcode[1] == 'E')
		{
			statement->value = operand[0] + " = " + operand[0] + " - 1;";
			statement->type = PATTERN_ASSIGN;
		}
		else if (opcode[1] == 'I')
		{
			// DIVPD, DIVPS, DIVSD and DIVSS
			if (opcode.size() > 3)
			{
				statement->value = operand[0] + " = " + operand[0] + " / " + operand[1] + ";";
				if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			// DIV
			else
			{
/*				string operands = operand[0];
				char *tokens = strtok((char *)operands.c_str(), " ");
				if (tokens != NULL)
				{
					operand[0] = tokens;
					tokens = strtok(NULL, " ");
					if (tokens != NULL)
						operand[1] = tokens;
				}
				if (operand[0].find("QWORD") == 0)
				{
					statement->value = "RAX = RDX:RAX / " + operand[1] + ";";
					statement->value += "RDX = RDX:RAX % " + operand[1] + ";";
				}
				else if (operand[0].find("DWORD") == 0)
				{
					statement->value = "EAX = EDX:EAX / " + operand[1] + ";";
					statement->value += "EDX = EDX:EAX % " + operand[1] + ";";
				}
				else if (operand[0].find("WORD") == 0)
				{
					statement->value = "AX = DX:AX / " + operand[1] + ";";
					statement->value += "DX = DX:AX % " + operand[1] + ";";
				}
				else
				{
					statement->value = "AL = AX / " + operand[1] + ";";
					statement->value += "AH = AX % " + operand[1] + ";";
				}*/
				statement->value = "EAX = EDX:EAX / " + operand[0] + ";";
				statement->value += "EDX = EDX:EAX % " + operand[0] + ";";
				if (operand[1].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
		// DPPD and DPPS - Dot product
		else if (opcode[1] == 'P')
		{
			statement->value = operand[0] + " = " + operand[0] + " . " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// UNKNOWN
		else
		{
			statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
			statement->type = PATTERN_UNKNOWN;
		}

		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'E')
	{
		// EMMS, ENTER
		if (opcode[1] == 'M' || opcode[1] == 'N') { delete (statement); statement = NULL; }
		// EXTRACTPS
		else if (opcode[1] == 'X')
		{
			stringstream ss;
			ss << dec << register_number++;
			string gr = "gr_" + ss.str();
			statement->value = gr + " = 32 * " + operand[2] + ";";
			statement->value += gr + " = " + gr + " and 0x0FFFFFFFF;";
			statement->value += operand[0] + " = " + operand[1] + " >> " + gr + ";";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// UNKNOWN
		else
		{
			statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
			statement->type = PATTERN_UNKNOWN;
		}

		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'F')
	{
		statement = Process_F_Statements(statement, opcode, operand, register_number, it_n_code, i);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'G')
	{
		// GETSEC
		if (opcode[1] == 'E') { delete (statement); statement = NULL; }
		// UNKNOWN
		else
		{
			statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
			statement->type = PATTERN_UNKNOWN;
		}

		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'H')
	{
		// HADDPD and HADDPS
		if (opcode[1] == 'A')
		{
			statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// HLT
		else if (opcode[1] == 'L')
		{
			statement->value = "halt;";
			statement->type = PATTERN_HALT;
		}
		// HSUBPD and HSUBPS
		else if (opcode[1] == 'S')
		{
			statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// UNKNOWN
		else
		{
			statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
			statement->type = PATTERN_UNKNOWN;
		}

		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'I')
	{
		statement = Process_I_Statements(statement, opcode, operand, register_number, it_n_code, i);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'J')
	{
		char temp_str[MAX_TEXT_SIZE+1];
		bool memory = false;
		statement->end = true;
		statement->branch_to_offset = getValue(i, it_n_code->decoded, memory);

		if (number_of_statements > 0)
		{
			/*
			 * Adding the jump offset and the jump statement to
			 * be used latter for determining the start of the block
			 * when tracing back or forward.
			 */
			if (statement->branch_to_offset >= 0)
				jump_offsets.insert(pair<uint64_t, Statement *>(statement->branch_to_offset, statement));

			if (!tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets))
			{
				/*
				 * traceBackTagStatementAsStart()
				 * Tracing back and tagging instruction as start
				 */
				uint64_t prev_stmt_number = number_of_statements - 1;
				for (unsigned int s = prev_stmt_number; s > 0; s--)
				{
					// There is no need to search back to another function
					// So we keep our search within a function
					if (isEndOfFunction(Statements[s]))
						break;
					else if (Statements[s]->offset == statement->branch_to_offset)
					{
						Statements[s]->start = true;
						Statements[s-1]->end = true;
						break;
					}
				}
			}
		}
		else if (number_of_statements == 0)
			statement->start = true;

		if (statement->branch_to_offset > 0)
		{
			if  (memory == false)
				sprintf (temp_str, "0x%x", (int)statement->branch_to_offset);
			else
				sprintf (temp_str, "[0x%x]", (int)statement->branch_to_offset);
		}
		else
		{
			sprintf (temp_str, "%s UNKNOWN", it_n_code->decoded[i].operands.p);
		}
		string address = temp_str;

		// JMP
		if (opcode[1] == 'M')
		{
			statement->value = "jmp " + address + ";";
			if (address.find("0x") == 0 || address.find("0x") == 1)
				statement->type = PATTERN_JUMP_C;
			else
				statement->type = PATTERN_JUMP;
		}
		// JNZ, JZ . . . . . . etc
		else
		{
			string condition = opcode.substr(1, opcode.size()-1);
			map<string, string>::iterator it_c_table = conditionalInstructionMap.find(condition);
			if (it_c_table != conditionalInstructionMap.end())
			{
				statement->value = "if " + it_c_table->second + " jmp " + address + ";";
				if (address.find("0x") == 0 || address.find("0x") == 1)
					statement->type = PATTERN_CONTROL_C;
				else
					statement->type = PATTERN_CONTROL;
			}
			// UNKNOWN
			else
			{
				statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
				statement->type = PATTERN_UNKNOWN;
			}
		}
	}
	// There are no instruction that starts with 'K'
	else if (opcode[0] == 'K') { delete (statement); statement = NULL; }
	else if (opcode[0] == 'L')
	{
		statement = Process_L_Statements(statement, opcode, operand, register_number, it_n_code, i);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'M')
	{
		statement = Process_M_Statements(statement, opcode, operand, register_number, it_n_code, i);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'N')
	{
		// NEG - set the CF flag
		if (opcode[1] == 'E')
		{
			statement->value = operand[0] + " = - " + operand[0];
			if (operand[0].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// NOT
		else if (opcode[1] == 'O')
		{
			statement->value = operand[0] + " = ! " + operand[0];
			if (operand[0].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// UNKNOWN
		else
		{
			statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
			statement->type = PATTERN_UNKNOWN;
		}

		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'O')
	{
		// OR, ORPD, ORPS
		if (opcode[1] == 'R')
		{
			statement->value = operand[0] + " = " + operand[0] + " or " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		else if (opcode[1] == 'U')
		{
			// OUTS - output string at [DS:ESI] to port specified in DX
			if (opcode.size() > 3)
			{
				if (operand[0].size() > 0 && operand[1].size() > 0)
					statement->value = operand[0] + " = " + operand[1] + ";";
				else if (operand[0].size() > 0)
					statement->value = operand[0] + " = [DS:ESI];";
				else
					statement->value = "DX = [DS:ESI];";
			}
			// OUT
			else
			{
/*				string operands = operand[0];
				char *tokens = strtok((char *)operands.c_str(), " ");
				if (tokens != NULL)
				{
					operand[0] = tokens;
					tokens = strtok(NULL, " ");
					if (tokens != NULL)
						operand[1] = tokens;
				}
				if (operand[0].find("DWORD") == 0)
				{
					statement->value = operand[1] + " = EAX;";
				}
				else if (operand[0].find("WORD") == 0)
				{
					statement->value = operand[1] + " = AX;";
				}
				else
				{
					statement->value = operand[1] + " = AL;";
				}*/
				statement->value = operand[1] + " = EAX;";
			}
			statement->type = PATTERN_ASSIGN;
		}
		// UNKNOWN
		else
		{
			statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
			statement->type = PATTERN_UNKNOWN;
		}

		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'P')
	{
		statement = Process_P_Statements(statement, opcode, operand, register_number, it_n_code, i);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	// There are no instruction that starts with 'Q'
	else if (opcode[0] == 'Q') { delete (statement); statement = NULL; }
	else if (opcode[0] == 'R')
	{
		statement = Process_R_Statements(statement, opcode, operand, register_number, it_n_code, i);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'S')
	{
		statement = Process_S_Statements(statement, opcode, operand, register_number, it_n_code, i);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'T')
	{
		// TEST
		// The OF and CF flags are set to 0. The SF, ZF,
		// and PF flags are set according to the result.
		// The state of the AF flag is undefined.
		if (opcode[1] == 'E')
		{
			statement->value = operand[1] + " and " + operand[0] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_TEST_C;
			else
				statement->type = PATTERN_TEST;
		}

		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'U')
	{
		// UCOMISD, UCOMISS
		if (opcode[1] == 'C')
		{
			statement->value = "compare(" + operand[0] + ", " + operand[1] + ");";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		// UD2
		else if (opcode[1] == 'D')
		{
			statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
			statement->type = PATTERN_UNKNOWN;
		}
		else if (opcode[1] == 'N' && opcode.size() > 5)
		{
			// UNDEFINED
			if (opcode[2] == 'D')
			{
				statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
				statement->type = PATTERN_UNKNOWN;
			}
			// UNPCKHPD, UNPCKHPS
			else if (opcode[5] == 'H')
			{
				stringstream ss1, ss2;
				ss1 << dec << register_number++;
				string gr1 = "gr_" + ss1.str();
				ss2 << dec << register_number++;
				string gr2 = "gr_" + ss2.str();
				statement->value = gr1 + " = substr(" + operand[0] + ", 64, 64);";
				statement->value += gr2 + " = substr(" + operand[1] + ", 64, 64);";
				statement->value += operand[0] + " = " + gr2 + ":" + gr1 + ";";
				if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
			// UNPCKLPD, UNPCKLPS
			else if (opcode[5] == 'L')
			{
				stringstream ss1, ss2;
				ss1 << dec << register_number++;
				string gr1 = "gr_" + ss1.str();
				ss2 << dec << register_number++;
				string gr2 = "gr_" + ss2.str();
				statement->value = gr1 + " = substr(" + operand[0] + ", 0, 64);";
				statement->value += gr2 + " = substr(" + operand[1] + ", 0, 64);";
				statement->value += operand[0] + " = " + gr2 + ":" + gr1 + ";";
				if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
		}
		// UNKNOWN
		else
		{
			statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
			statement->type = PATTERN_UNKNOWN;
		}

		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'V')
	{
		statement = Process_V_Statements(statement, opcode, operand, register_number, it_n_code, i);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'W')
	{
		// WAIT
		if (opcode[1] == 'A') { delete (statement); statement = NULL; }
		// WBINVD - Write back and flush Internal caches; initiate.
		// writing-back and flushing of external caches.
		else if (opcode[1] == 'B') { delete (statement); statement = NULL; }
		// WRFSBASE, WRGSBASE. WRMSR
		else if (opcode[1] == 'R')
		{
			// WRFSBASE
			if (opcode[2] == 'F')
			{
				statement->value = "FS = EDX:EAX;";
			}
			// WRGSBASE
			else if (opcode[2] == 'G')
			{
				statement->value = "FS = EDX:EAX;";
			}
			// WRMSR
			else if (opcode[2] == 'M')
			{
				statement->value = "MSR = EDX:EAX;";
			}
			statement->type = PATTERN_ASSIGN;
		}
		// UNKNOWN
		else
		{
			statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
			statement->type = PATTERN_UNKNOWN;
		}
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'X')
	{
		statement = Process_X_Statements(statement, opcode, operand, register_number, it_n_code, i);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	// 3DNOW
	else if (opcode[0] == '3') { delete (statement); statement = NULL; }
	else
	{
		tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);

statement->value = (char *)it_n_code->decoded[i].instructionHex.p;
statement->value += (char *)it_n_code->decoded[i].mnemonic.p;
statement->value += (char *)it_n_code->decoded[i].operands.p;
//delete (statement); statement = NULL;
		cerr << "Error::CFG::Build: Instruction type UNDEFINED\r\n";
		cerr << "   Instruction " << dec << i << " @ " << hex << it_n_code->decoded[i].offset << ":  " << it_n_code->decoded[i].instructionHex.p << "   " << it_n_code->decoded[i].mnemonic.p << "   " << it_n_code->decoded[i].operands.p << "\n";
	}

	current_instruction_number = i;
	return (statement);
}

/*
 *
 */
Statement *x86AsmToMAIL::Process_A_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number)
{
	uint64_t i = current_instruction_number;

	// AAA, AAD, AAM, AAS - ASCII adjust
	if (opcode[1] == 'A') { delete (statement); statement = NULL; }
	else if (opcode[1] == 'D')
	{
		// ADC
		if (opcode[2] == 'C')
		{
			statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
			statement->value += operand[0] + " = " + operand[0] + " + CF;";
			statement->type = PATTERN_ASSIGN;
		}
		// ADDSUBPD, ADDSUBPS
		else if (opcode.size() > 7 && opcode[7] == 'D')
		{
			stringstream ss1, ss2;
			ss1 << dec << register_number++;
			string gr1 = "gr_" + ss1.str();
			ss2 << dec << register_number++;
			string gr2 = "gr_" + ss2.str();
			statement->value = gr1 + " = " + operand[1] + " + " + operand[2] + ";";
			statement->value += gr2 + " = " + operand[1] + " - " + operand[2] + ";";
			statement->value += operand[0] + " = " + gr2 + ":" + gr1 + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// ADD, ADDPD, ADDPS, ADDSD, ADDSS
		else if (opcode[2] == 'D')
		{
			statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	// AESDEC, AESDECLAST, AESENC, AESENCLAST, AESIMC, AESKEYGENASSIST
	else if (opcode[1] = 'E')
	{
		/*
		statement->value = operand[0] + " = aes(" + operand[1] + ");";
		*/
		delete (statement);
		statement = NULL;
	}
	// ANDNPD, ANDNPS
	else if (opcode[1] == 'N' && opcode.size() > 5)
	{
		if (opcode[3] == 'N')
		{
			statement->value = operand[0] + " = !" + operand[0] + ";";
			statement->value += operand[0] + " = " + operand[0] + " and " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	// AND, ANDPD, ANDPS
	else if (opcode[1] == 'N')
	{
		statement->value = operand[0] + " = " + operand[0] + " and " + operand[1] + ";";
		if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	// ARPL - adjust RPL field of the segment selector
	else if (opcode[1] == 'R') { delete (statement); statement = NULL; }
	// UNKNOWN
	else
	{
		statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
		statement->type = PATTERN_UNKNOWN;
	}

	current_instruction_number = i;
	return (statement);
}

/*
 *
 */
Statement *x86AsmToMAIL::Process_C_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	// CALL
	if (opcode[1] == 'A')   // INSTRUCTION_TYPE_CONTROL_BRANCH
	{
		char temp_str[MAX_TEXT_SIZE+1];
		statement->value = "[sp=sp+1]";
		statement->value += " = ";
		sprintf (temp_str, "0x%x; ", (int)(it_n_code->decoded[i].offset + it_n_code->decoded[i].size));
		statement->value += temp_str;
		bool memory = false;
		statement->end = true;
		statement->branch_to_offset = getValue(i, it_n_code->decoded, memory);

		if (number_of_statements > 0)
		{
			/*
			 * Adding the jump offset and the jump statement to
			 * be used latter for determining the start of the block
			 * when tracing back or forward.
			 */
			if (statement->branch_to_offset >= 0)
				jump_offsets.insert(pair<uint64_t, Statement *>(statement->branch_to_offset, statement));
			if (!tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets))
			{
				/*
				 * traceBackTagStatementAsStart()
				 * Tracing back and tagging instruction as start
				 */
				uint64_t prev_stmt_number = number_of_statements - 1;
				for (unsigned int s = prev_stmt_number; s > 0; s--)
				{
					// There is no need to search back to another function
					// So we keep our search within a function
					if (isEndOfFunction(Statements[s]))
						break;
					if (Statements[s]->offset == statement->branch_to_offset)
					{
						Statements[s]->start = true;
						Statements[s-1]->end = true;
						break;
					}
				}
			}
		}
		else if (number_of_statements == 0)
			statement->start = true;

		if (statement->branch_to_offset > 0)
		{
			if  (memory == false)
				sprintf (temp_str, "0x%x", (int)statement->branch_to_offset);
			else
				sprintf (temp_str, "[0x%x]", (int)statement->branch_to_offset);
		}
		else
		{
			sprintf (temp_str, "%s UNKNOWN", it_n_code->decoded[i].operands.p);
		}
		string address = temp_str;
		statement->value += "call (" + address;

		/*
		 * In this version there are no arguments passed to the call function
		 * --- TODO ---
		 * Will be changed latter to include the arguments
		 */
		/*vector<string> args;
		for (int a = 0; a < args.size(); a++)
		{
			sprintf (temp_str, ", %s", args[a]);
			statement->value += temp_str;
		}*/
		statement->value += ");";
		if (address.find("0x") == 0 || address.find("0x") == 1)
			statement->type = PATTERN_CALL_C;
		else
			statement->type = PATTERN_CALL;
	}
	// CBW
	else if (opcode[1] == 'B')
	{
		statement->value = "DX:AX = AX;";
		statement->type = PATTERN_ASSIGN;
	}
	// CDQ, CDQE
	else if (opcode[1] == 'D')
	{
		statement->value = "RDX:RAX = RAX;";
		statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'L')
	{
		// CLFLUSH, CLTS - flush caches, clear TLB
		if (opcode[2] == 'F' || opcode[2] == 'T') { delete (statement); statement = NULL; }
		// CLC
		else if (opcode[2] == 'C')
		{
			statement->value = "CF = 1;";   // carry flag
			statement->type = PATTERN_FLAG;
		}
		// CLD
		else if (opcode[2] = 'D')
		{
			statement->value = "DF = 1;";   // direction flag
			statement->type = PATTERN_FLAG;
		}
		// CLI
		else if (opcode[2] == 'I')
		{
			statement->value = "IF = 1;";   // interrupt flag
			statement->type = PATTERN_FLAG;
		}
		// CLGI
		else if (opcode[2] == 'G')
		{
			statement->value = "GIF = 1;";   // global interrupt flag
			statement->type = PATTERN_FLAG;
		}
	}
	else if (opcode[1] == 'M')
	{
		// CMC
		if (opcode[2] == 'C') { delete (statement); statement = NULL; }
		// CMOVcc
		else if (opcode[2] == 'O')
		{
			string condition = opcode.substr(4, opcode.size()-4);
			map<string, string>::iterator it_c_table = conditionalInstructionMap.find(condition);
			if (it_c_table != conditionalInstructionMap.end())
			{
				statement->value = "if " + it_c_table->second + " ";
				statement->value += operand[0] + " = " + operand[1] + ";";
				if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
					statement->type = PATTERN_CONTROL_C;
				else
					statement->type = PATTERN_CONTROL;
			}
			// UNKNOWN
			else
			{
				statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
				statement->type = PATTERN_UNKNOWN;
			}
		}
		// CMP, CMPS, CMPSB, CMPSW, CMPSD, CMPSQ
		// COMISD and COMISS
		// CMPPD, CMPPS, CMPSD, CMPSS
		else if (opcode[2] == 'P')
		{
			// CMPEQPD, CMPEQPS, CMPEQSD, CMPEQSS
			if (opcode[3] == 'E')
			{
				statement->value = operand[0] + " = " + operand[0] + " == " + operand[1] + ";";
			}
			else if (opcode[3] == 'L')
			{
				// CMPLT
				if (opcode[4] == 'T')
				{
					statement->value = operand[0] + " = " + operand[0] + " < " + operand[1] + ";";
				}
				// CMPLE
				else if (opcode[4] == 'E')
				{
					statement->value = operand[0] + " = " + operand[0] + " <= " + operand[1] + ";";
				}
			}
			else if (opcode[3] == 'N')
			{
				// CMPNEQ
				if (opcode[4] == 'E')
				{
					statement->value = operand[0] + " = " + operand[0] + " != " + operand[1] + ";";
				}
				// CMPNLT
				else if (opcode[5] == 'T')
				{
					statement->value = operand[0] + " = " + operand[0] + " >= " + operand[1] + ";";
				}
				// CMPNLE
				else if (opcode[5] == 'E')
				{
					statement->value = operand[0] + " = " + operand[0] + " > " + operand[1] + ";";
				}
			}
			// CMPORD
			else if (opcode[3] == 'O')
			{
				statement->value = operand[0] + " = " + operand[0] + " = " + operand[1] + ";";
			}
			// CMPUORD
			else if (opcode[3] == 'U')
			{
				statement->value = operand[0] + " = " + operand[0] + " != " + operand[1] + ";";
			}
			// CMPS, CMPSB, CMPSW, CMPSD, CMPSQ
			else if (opcode[3] == 'S')
			{
				statement->value = "compare([DS:ESI], [ES:EDI]);";
			}
			else if (opcode.size() > 3 && opcode[3] == 'X')
			{
				if (opcode.size() > 7)
				{
					// CMPXCHG8B
					if (opcode[7] == '8')
					{
						statement->value = "if EDX:EAX == " + operand[0] + ";";
						statement->value += operand[1] + " = " + operand[0] + ";";
					}
					// CMPXCHG16B
					else if (opcode[7] == '1')
					{
						statement->value = "if RDX:RAX == " + operand[0] + ";";
						statement->value += operand[1] + " = " + operand[0] + ";";
					}
				}
				// CMPXCHG
				else
				{
					statement->value = "if EAX == " + operand[0] + ";";
					statement->value += operand[1] + " = " + operand[0] + ";";
				}
			}
			// CMP
			else
			{
				statement->value = "compare(" + operand[0] + ", " + operand[1] + ");";
			}
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
	}
	// COMISD and COMISS
	else if (opcode[1] == 'O')
	{
		statement->value = "compare(" + operand[0] + ", " + operand[1] + ");";
		if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
			statement->type = PATTERN_LIBCALL_C;
		else
			statement->type = PATTERN_LIBCALL;
	}
	// CPUID, CRC32
	else if (opcode[1] == 'P' || opcode[1] == 'R') { delete (statement); statement = NULL; }
	// CQO - quadword to octaword
	else if (opcode[1] == 'Q')
	{
		statement->value = "RDX:RAX = RAX;";
		statement->type = PATTERN_ASSIGN;
	}
	// CVTDQ2PD, CVTDQ2PS, CVTPD2DQ, CVTPD2PI, CVTPD2PS, CVTPH2PS, CVTPI2PD, CVTPI2PS,
	// CVTPS2DQ, CVTPS2PD, CVTPS2PH, CVTPS2PI, CVTSD2SI, CVTSD2SS, CVTSI2SD, CVTSI2SS,
	// CVTSS2SD, CVTSS2SI, CVTTPD2DQ, CVTTPD2PI, CVTTPS2DQ, CVTTPS2PI, CVTTSD2SI, CVTTSS2SI
	else if (opcode[1] == 'V')
	{
		statement->value = operand[1] + " = " + operand[0] + ";";
		if (operand[0].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	// CWD, CWDE - word to double word
	else if (opcode[1] == 'W')
	{
		statement->value = "EDX:EAX = EAX;";
		statement->type = PATTERN_ASSIGN;
	}
	// UNKNOWN
	else
	{
		statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
		statement->type = PATTERN_UNKNOWN;
	}

	current_instruction_number = i;
	return (statement);
}

/*
 *
 */
Statement *x86AsmToMAIL::Process_F_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number)
{
	uint64_t i = current_instruction_number;

	// F2XMI
	if (opcode[1] == '2')
	{
		statement->value = "fr_0 = pow(2, fr_0)";
		statement->type = PATTERN_LIBCALL;
	}
	else if (opcode[1] == 'A')
	{
		// FABS
		if (opcode[2] == 'B')
		{
			statement->value = "fr_0 = abs(fr_0)";
			statement->type = PATTERN_LIBCALL;
		}
		// FADD, FADDP
		else if (opcode[2] == 'D')
		{
			statement->value = "fr_1 = fr_1 + fr_0";
			statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'B')
	{
		// FBLD
		if (opcode[2] == 'L')
		{
			statement->value = "fr_0 = " + operand[0] + ";";
			if (operand[0].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// FBSTP
		else if (opcode[2] == 'S')
		{
			statement->value = operand[0] + " = fr_0;";
			statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'C')
	{
		// FCHS
		if (opcode[2] == 'H')
		{
			statement->value = "fr_0 = -fr_0";
			statement->type = PATTERN_ASSIGN;
		}
		// FCLEX
		else if (opcode[2] == 'L') { delete (statement); statement = NULL; }
		// FCMOVB, FCMOVBE, FCMOVE, FCMOVNB, FCMOVNBE, FCMOVNE, FCMOVNU, FCMOVU
		else if (opcode[2] == 'M')
		{
			string operands = operand[1];
			int pos = operands.find_first_of('(');
			if (pos != std::string::npos)
				operands = "fr_" + operands[pos];
			else
				operands = "fr_1";

			string condition = opcode.substr(5, opcode.size()-5);
			map<string, string>::iterator it_c_table = conditionalInstructionMap.find(condition);
			if (it_c_table != conditionalInstructionMap.end())
			{
				statement->value = "if fr_0 " +  it_c_table->second + operands + ";";
				statement->value += "fr_0 = " + operands + ";";
				statement->type = PATTERN_CONTROL;
			}
			// UNKNOWN
			else
			{
				statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
				statement->type = PATTERN_UNKNOWN;
			}
		}
		else if (opcode[2] == 'O')
		{
			// FCOM, FCOMI, FCOMIP, FCOMP, FCOMPP
			if (opcode[3] == 'M')
			{
				string operands;
				if (operand[0].size() > 0)
					operands = operand[0];
				else
				{
					operands = (char *)it_n_code->decoded[i].operands.p;
					int pos = operands.find_first_of('(');
					if (pos != std::string::npos)
						operands = "fr_" + operands[pos];
					else
						operands = "fr_1";
				}
				statement->value = "compare(fr_0, " + operands + ");";
			}
			// FCOS
			else if (opcode[3] == 'S')
			{
				statement->value = "fr_0 = cos(fr_0)";
			}
			statement->type = PATTERN_LIBCALL;
		}
	}
	else if (opcode[1] == 'D')
	{
		// FDECSTP
		if (opcode[2] == 'E') { delete (statement); statement = NULL; }
		else if (opcode[2] == 'I')
		{
			// FDIVR, FDIVRP
			if (opcode.size() > 4 && opcode[4] == 'R')
			{
				statement->value = "fr_0 = fr_0 / fr_1";
			}
			// FDIV, FDIVP
			else
			{
				statement->value = "fr_1 = fr_1 / fr_0";
			}
			statement->type = PATTERN_ASSIGN;
		}
	}
	// FEDISI, FEMMS, FENI
	// Not able to find any information about these instructions
	else if (opcode[1] == 'E') { delete (statement); statement = NULL; }
	// FFREE
	else if (opcode[1] == 'F') { delete (statement); statement = NULL; }
	else if (opcode[1] == 'I')
	{
		// FIADD
		if (opcode[2] == 'A')
		{
			statement->value = "fr_1 = fr_1 + fr_0";
			statement->type = PATTERN_ASSIGN;
		}
		// FICOM, FICOMP
		else if (opcode[2] == 'C')
		{
			statement->value = "compare(fr_0, " + operand[0] + ");";
			if (operand[0].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		else if (opcode[2] = 'D')
		{
			// FIDIVR
			if (opcode.size() > 5 && opcode[5] == 'R')
			{
				statement->value = "fr_0 = fr_0 / fr_1";
			}
			// FIDIV
			else
			{
				statement->value = "fr_1 = fr_1 / fr_0";
			}
			statement->type = PATTERN_ASSIGN;
		}
		// FILD
		else if (opcode[2] == 'L')
		{
			statement->value = "fr_0 = " + operand[0] + ";";
			if (operand[0].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// FIMUL
		else if (opcode[2] == 'M')
		{
			statement->value = "fr_1 = fr_1 * fr_0";
			statement->type = PATTERN_ASSIGN;
		}
		// FINCSTP, FINIT
		else if (opcode[2] == 'N') { delete (statement); statement = NULL; }
		else if (opcode[2] == 'S')
		{
			// FIST, FISTP, FISTTP
			if (opcode[3] == 'T')
			{
				statement->value = (char *)it_n_code->decoded[i].operands.p;
				statement->value += " = fr_0;";
			}
			else if (opcode[3] == 'U')
			{
				// FISUBR
				if (opcode.size() > 5 && opcode[5] == 'R')
				{
					statement->value = "fr_0 = fr_0 - fr_1";
				}
				// FISUB
				else
				{
					statement->value = "fr_1 = fr_1 - fr_0";
				}
			}
			statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'L')
	{
		// FLDCW, FLDENV 
		if (opcode[3] == 'C' || opcode[3] == 'E') { delete (statement); statement = NULL; }
		// FLD, FLD1, FLDL2E, FLDL2T, FLDLG2, FLDLN2, FLDPI, FLDZ
		else
		{
			statement->value = "fr_0 = ";
			string operands = operand[0];
			int pos = operands.find_first_of('(');
			if (pos != std::string::npos)
				operands = "fr_" + operands[pos];
			else if (opcode.find("FLD1")) operands = "1";
			else if (opcode.find("FLDL2T")) operands = "3.32193";
			else if (opcode.find("FLDL2E")) operands = "1.44269";
			else if (opcode.find("FLDPI")) operands = "3.14159";
			else if (opcode.find("FLDLG2")) operands = "0.30103";
			else if (opcode.find("FLDLN2")) operands = "0.69315";
			else if (opcode.find("FLDZ")) operands = "0";
			statement->value += operands;
			statement->type = PATTERN_ASSIGN_C;
		}
	}
	// FMUL, FMULP
	else if (opcode[1] == 'M')
	{
		statement->value = "fr_1 = fr_1 * fr_0";
		statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'N')
	{
		// FNCLEX, FNINIT
		if (opcode[2] == 'C' || opcode[2] == 'I') { delete (statement); statement = NULL; }
		// FNSAVE, FNSTCW, FNSTENV, FNSTSW
		else if (opcode[2] == 'S') { delete (statement); statement = NULL; }
	}
	else if (opcode[1] == 'P')
	{
		// FPATAN
		if (opcode[2] == 'A')
		{
			statement->value = "fr_1 = fr_1 / fr_0;";
			statement->value += "fr_1 = atan(fr_1);";
			statement->type = PATTERN_LIBCALL;
		}
		// FPREM, FPREM1
		else if (opcode[2] == 'R')
		{
			statement->value = "fr_0 = fr_1 % fr_0);";
			statement->type = PATTERN_ASSIGN;
		}
		// FPTAN
		else if (opcode[2] == 'T')
		{
			statement->value = "fr_0 = tan(fr_0);";
			statement->type = PATTERN_LIBCALL;
		}
	}
	else if (opcode[1] == 'R')
	{
		// FRNDINT
		if (opcode[2] == 'N')
		{
			statement->value = "fr_0 = round(fr_0);";
			statement->type = PATTERN_LIBCALL;
		}
		// FRSTOR
		else { delete (statement); statement = NULL; }
	}
	else if (opcode[1] == 'S')
	{
		// FSAVE
		if (opcode[2] == 'A') { delete (statement); statement = NULL; }
		// FSCALE
		else if (opcode[2] == 'C')
		{
			statement->value = "fr_1 = round(fr_1)";
			statement->value += "fr_0 = fr_0 * fr_1;";
			statement->type = PATTERN_LIBCALL;
		}
		// FSETPM
		else if (opcode[2] == 'E') { delete (statement); statement = NULL; }
		// FSIN, FSINCOS
		else if (opcode[2] == 'I')
		{
			if (opcode.size() > 4 && opcode[4] == 'C')
			{
				statement->value = "fr_0 = cos(fr_0);";
			}
			statement->value += "fr_0 = sin(fr_0)";
			statement->type = PATTERN_LIBCALL;
		}
		// FSQRT
		else if (opcode[2] == 'Q')
		{
			statement->value = "fr_0 = sqrt(fr_0)";
			statement->type = PATTERN_LIBCALL;
		}
		else if (opcode[2] == 'T')
		{
			// FST, FSTP
			if (opcode.size() == 3 || opcode[3] == 'P')
			{
				statement->value = "fr_0 = ";
				string operands = operand[0];
				int pos = operands.find_first_of('(');
				if (pos != std::string::npos)
					operands = "fr_" + operands[pos];
				statement->value += operands + ";";
				statement->type = PATTERN_ASSIGN;
			}
			// FSTCW, FSTENV, FSTSW
			else { delete (statement); statement = NULL; }
		}
		else if (opcode[2] == 'U')
		{
			// FSUBR, FSUBRP
			if (opcode.size() > 4 && opcode[4] == 'R')
			{
				statement->value = "fr_0 = fr_0 - fr_1";
			}
			// FSUB, FSUBP
			else
			{
				statement->value = "fr_1 = fr_1 - fr_0";
			}
			statement->type = PATTERN_ASSIGN;
		}
	}
	// FTST
	else if (opcode[1] == 'T')
	{
		statement->value = "compare(fr_0, 0);";
		statement->type = PATTERN_LIBCALL_C;
	}
	// FUCOM, FUCOMI, FUCOMIP, FUCOMP, FUCOMPP
	else if (opcode[1] == 'U')
	{
		string operands = operand[0];
		if (operands.size() > 0)
		{
			int pos = operands.find_first_of('(');
			if (pos != std::string::npos)
				operands = "fr_" + operands[pos];
		}
		else
			operands = "fr_1";
		statement->value = "compare(fr_0, " + operands + ");";
		statement->type = PATTERN_LIBCALL;
	}
	else if (opcode[1] == 'X')
	{
		// FXAM
		if (opcode[2] == 'A')
		{
			statement->value = "compare(fr_0, 0);";
			statement->type = PATTERN_LIBCALL_C;
		}
		// FXCH
		if (opcode[2] == 'C')
		{
			string operands = operand[0];
			int pos = operands.find_first_of('(');
			if (pos != std::string::npos)
				operands = operands[pos];
			else
				operands = "1";

			stringstream ss;
			ss << dec << register_number++;
			string gr = "gr_" + ss.str();
			statement->value = gr + " = fr_0;";
			statement->value += "fr_0 = fr_" + operands + ";";
			statement->value += "fr_" + operands + " = " + gr + ";";
			statement->type = PATTERN_LIBCALL;
		}
		// FXRSTOR, FXRSTOR64, FXSAVE, FXSAVE64, FXTRACT
		else if (opcode[2] == 'R' || opcode[2] == 'S' || opcode[2] == 'T') { delete (statement); statement = NULL; }
	}
	else if (opcode[1] == 'Y')
	{
		// FYL2XP1
		if (opcode.size() > 5 && opcode[5] == 'P')
		{
			statement->value = "fr_0 = fr_0 + 1;";
			statement->value += "fr_0 = log(2, fr_0);";
			statement->value += "fr_1 = fr_1 * fr_0;";
		}
		// FYL2X
		else
		{
			statement->value = "fr_0 = log(2, fr_0);";
			statement->value += "fr_1 = fr_1 * fr_0;";
		}
		statement->type = PATTERN_ASSIGN;
	}
	// UNKNOWN
	else
	{
		statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
		statement->type = PATTERN_UNKNOWN;
	}

	current_instruction_number = i;
	return (statement);
}

/*
 *
 */
Statement *x86AsmToMAIL::Process_I_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number)
{
	uint64_t i = current_instruction_number;

	// IDIV
	if (opcode[1] == 'D')
	{
/*		string operands = operand[0];
		char *tokens = strtok((char *)operands.c_str(), " ");
		if (tokens != NULL)
		{
			operand[0] = tokens;
			tokens = strtok(NULL, " ");
			if (tokens != NULL)
				operand[1] = tokens;
		}
		if (operand[0].find("QWORD") == 0)
		{
			statement->value = "RAX = RDX:RAX / " + operand[1] + ";";
			statement->value += "RDX = RDX:RAX % " + operand[1] + ";";
		}
		else if (operand[0].find("DWORD") == 0)
		{
			statement->value = "EAX = EDX:EAX / " + operand[1] + ";";
			statement->value += "EDX = EDX:EAX % " + operand[1] + ";";
		}
		else if (operand[0].find("WORD") == 0)
		{
			statement->value = "AX = DX:AX / " + operand[1] + ";";
			statement->value += "DX = DX:AX % " + operand[1] + ";";
		}
		else
		{
			statement->value = "AL = AX / " + operand[1] + ";";
			statement->value += "AH = AX % " + operand[1] + ";";
		}*/
		statement->value = "EAX = EDX:EAX / " + operand[1] + ";";
		statement->value += "EDX = EDX:EAX % " + operand[1] + ";";
		if (operand[1].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	// IMUL
	if (opcode[1] == 'M')
	{
		// Three operand
		if (operand[2].size() > 0)
		{
			statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + ";";
			if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// Two operand
		else if (operand[2].size() <= 0)
		{
			statement->value = operand[0] + " = " + operand[0] + " * " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// One operand
		else
		{
/*			string operands = operand[0];
			char *tokens = strtok((char *)operands.c_str(), " ");
			if (tokens != NULL)
			{
				operand[0] = tokens;
				tokens = strtok(NULL, " ");
				if (tokens != NULL)
					operand[1] = tokens;
			}
			if (operand[0].find("QWORD") == 0)
			{
				statement->value = "RAX = RDX:RAX * " + operand[1] + ";";
				statement->value += "RDX = RDX:RAX % " + operand[1] + ";";
			}
			else if (operand[0].find("DWORD") == 0)
			{
				statement->value = "EAX = EDX:EAX * " + operand[1] + ";";
				statement->value += "EDX = EDX:EAX % " + operand[1] + ";";
			}
			else if (operand[0].find("WORD") == 0)
			{
				statement->value = "AX = DX:AX * " + operand[1] + ";";
				statement->value += "DX = DX:AX % " + operand[1] + ";";
			}
			else
			{
				statement->value = "AL = AX * " + operand[1] + ";";
				statement->value += "AH = AX % " + operand[1] + ";";
			}*/
			statement->value = "EAX = EDX:EAX * " + operand[1] + ";";
			statement->value += "EDX = EDX:EAX % " + operand[1] + ";";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'N')
	{
		// IN - input from port in operand[1]
		if (opcode.size() == 2)
		{
			statement->value = operand[0] + " = " + operand[1] + ";";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// INC
		else if (opcode[2] == 'C')
		{
			statement->value = operand[0] + " = " + operand[0] + " + 1;";
			statement->type = PATTERN_ASSIGN;
		}
		// INS, INSB, INSW and INSD - input from port in DX to ES:EDI
		else if (opcode[2] == 'S')
		{
			// INSERTPS
			if (opcode.find("INSERT") == 0)
			{
				statement->value = operand[0] + " = " + operand[1] + ";";
				if (operand[1].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			else
			{
				statement->value = "[ES:EDI] = DX;";
				statement->type = PATTERN_ASSIGN;
			}
		}
		// INT 3, INT number and INTO
		else if (opcode[2] == 'T')
		{
			/*
			 * Normalization/Optimization:
			 *
			 * If there are more than one INT 3 instructions (INT 3 is only used in debugging)
			 * then throw away those instructions.
			 */
			if (opcode.size() > 4 && opcode[4] == '3')
			{
				int i3 = 1;
				for ( ; i < it_n_code->code_size; i++)
				{
					opcode = (char *)it_n_code->decoded[i].mnemonic.p;
					Util::removeWhiteSpaces(opcode);
					if (opcode.find("INT 3") == 0)
						i3++;
					else
						break;
				}

				if (i3 == 1)
				{
					/*
					// push EIP, CS and EFLAGS registers
					statement->value = "[sp=sp+0x1] = eflags;";
					statement->value += "[sp=sp+0x1] = cs;";
					statement->value += "[sp=sp+0x1] = eip;";
					statement->value += "interrupt(3);";
					*/
					delete (statement);
					statement = NULL;
				}
				else
				{
					delete (statement);
					statement = NULL;
					i--;
				}
			}
			else
			{
				/*
				// push EIP, CS and EFLAGS registers
				statement->value = "[sp=sp+0x1] = eflags;";
				statement->value += "[sp=sp+0x1] = cs;";
				statement->value += "[sp=sp+0x1] = eip;";
				statement->value += "interrupt(" + operand[0] + ");";
				*/
				delete (statement);
				statement = NULL;
			}
		}
		// INVD, INVEPT, INVLPG, INVLPGA, INVPCID, INVVPID
		// Invalidate caches, TLB, process context identifier and others
		else if (opcode[2] == 'V') { delete (statement); statement = NULL; }
	}
	// IRET
	else if (opcode[1] == 'R')
	{
		statement->end = true;
		statement->branch_to_offset = END_OF_FUNCTION;
		// pop EIP, CS and EFLAGS registers
		statement->value = "eip = [sp=sp-0x1];";
		statement->value += "cs = [sp=sp-0x1];";
		statement->value += "eflags = [sp=sp-0x1];";
		statement->value += "jmp eip;";
		statement->type = PATTERN_JUMP_S;
	}
	else
	{
		statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
		statement->type = PATTERN_UNKNOWN;
	}

	current_instruction_number = i;
	return (statement);
}

/*
 *
 */
Statement *x86AsmToMAIL::Process_L_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number)
{
	uint64_t i = current_instruction_number;

	if (opcode[1] == 'A')
	{
		// LAHF
		if (opcode[2] == 'H')
		{
			statement->value = "AH = EFLAGS;";
			statement->type = PATTERN_FLAG;
		}
		// LAR - loads access rights byte
		else if (opcode[2] == 'R')
		{
			statement->value = operand[0] + " = [" + operand[1] + "];";
			statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'D')
	{
		// LDDQU
		if (opcode[2] == 'D')
		{
			statement->value = operand[0] + " = [" + operand[1] + "];";
			statement->type = PATTERN_ASSIGN;
		}
		// LDMXCSR
		else if (opcode[2] == 'M')
		{
			statement->value = " MXCSR = " + operand[0] + ";";
			if (operand[0].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// LDS
		else if (opcode[2] == 'S')
		{
			statement->value = " DS: " + operand[0] + " = " + operand[1] + ";";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'E')
	{
		if (opcode[2] = 'A')
		{
			// LEAVE
			if (opcode.size() > 3) { delete (statement); statement = NULL; }
			// LEA
			else
			{
				statement->value = operand[0] + " = " + operand[1] + ";";
				if (operand[1].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
		// LES
		else if (opcode[2] = 'S')
		{
			statement->value = " ES: " + operand[0] + " = " + operand[1] + ";";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'F')
	{
		// LFS
		if (opcode[2] == 'S')
		{
			statement->value = " FS: " + operand[0] + " = " + operand[1] + ";";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// LFENCE - Serialzes load operations
		else { delete (statement); statement = NULL; }
	}
	// LGS
	else if (opcode[1] == 'G')
	{
		// LGS
		if (opcode[2] == 'S')
		{
			statement->value = " GS: " + operand[0] + " = " + operand[1] + ";";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// LGDT
		else
		{
			statement->value = " GDTR = " + operand[0] + ";";
			if (operand[0].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	// LIDT
	else if (opcode[1] == 'I')
	{
		statement->value = " IDTR = " + operand[0] + ";";
		if (operand[0].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	// LLDT
	else if (opcode[1] == 'L')
	{
		statement->value = " LDTR = " + operand[0] + ";";
		if (operand[0].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	// LMSW
	else if (opcode[1] == 'M')
	{
		statement->value = " CR0 = " + operand[0] + ";";
		if (operand[0].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'O')
	{
		// LOCK - turns the next statement into atomic statement
		if (opcode[2] == 'C')
		{
			statement->value = "lock;";
			statement->type = PATTERN_LOCK;
		}
		// LODS
		else if (opcode[2] == 'D')
		{
/*			string operands = operand[0];
			char *tokens = strtok((char *)operands.c_str(), " ");
			if (tokens != NULL)
			{
				operand[0] = tokens;
				tokens = strtok(NULL, " ");
				if (tokens != NULL)
					operand[1] = tokens;
			}

			if (operand[0].find("QWORD") == 0)
			{
				statement->value = "RAX = [RSI];";
			}
			else if (operand[0].find("DWORD") == 0)
			{
				statement->value = "EAX = [DS:ESI];";
			}
			else if (operand[0].find("WORD") == 0)
			{
				statement->value = "AX = [DS:ESI];";
			}
			else
			{
				statement->value = "AL = [DS:ESI];";
			}*/
			statement->value = "EAX = [DS:ESI];";
			statement->type = PATTERN_ASSIGN;
		}
		// LOOP
		else if (opcode[2] == 'O')
		{
			statement->value = "ECX = ECX - 1;";
			if (opcode.size() > 3)
			{
				// LOOPZ
				if (opcode[4] == 'Z')
				{
					statement->value += "if (ZF == 1 and ECX != 0) jmp " + operand[0] + ";";
				}
				// LOOPNZ
				else if (opcode[4] == 'N')
				{
					statement->value += "if (ZF == 0 and ECX != 0) jmp " + operand[0] + ";";
				}
			}
			// LOOP
			else
			{
				statement->value += "if (ECX != 0) jmp " + operand[0] + ";";
			}
			if (operand[0].find("0x") == 0)
				statement->type = PATTERN_JUMP_C;
			else
				statement->type = PATTERN_JUMP;
		}
	}
	else if (opcode[1] == 'S')
	{
		// LSL
		if (opcode[2] == 'L')
		{
			statement->value = operand[0] + " = " + operand[1] + ";";
		}
		// LSS
		else
		{
			statement->value = " SS: " + operand[0] + " = " + operand[1] + ";";
		}
		if (operand[1].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	// LTR
	else if (opcode[1] == 'T')
	{
		statement->value = " TR = " + operand[0] + ";";
		if (operand[0].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	// LZCNT
	else if (opcode[1] == 'Z') { delete (statement); statement = NULL; }
	// UNKNOWN
	else
	{
		statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
		statement->type = PATTERN_UNKNOWN;
	}

	current_instruction_number = i;
	return (statement);
}

/*
 *
 */
Statement *x86AsmToMAIL::Process_M_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number)
{
	uint64_t i = current_instruction_number;

	if (opcode[1] == 'A')
	{
		// MASKMOVDQU and MASKMOVQ
		if (opcode[2] == 'S')
		{
			statement->value = " [DS:EDI] = " + operand[0] + ";";
			if (operand[0].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		else if (opcode[2] == 'X')
		{
			statement->value = operand[0] + " = max(" + operand[0] + ", " + operand[1] + ");";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
	}
	// MFENCE
	else if (opcode[1] == 'F') { delete (statement); statement = NULL; }
	// MIN
	else if (opcode[1] == 'I')
	{
		statement->value = operand[0] + " = min(" + operand[1] + ", " + operand[2] + ");";
		if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
			statement->type = PATTERN_LIBCALL_C;
		else
			statement->type = PATTERN_LIBCALL;
	}
	else if (opcode[1] == 'O')
	{
		// MONITOR
		if (opcode[2] == 'N') { delete (statement); statement = NULL; }
		else if (opcode[2] == 'V')
		{
			// MOVS
			if (opcode.size() > 3 && opcode[3] == 'S')
			{
				if (opcode.size() > 4)
				{
					// MOVSB, MOVSD, MOVSW, MOVSQ - move string to string
					if (opcode[4] == 'B' || opcode[4] == 'D' || opcode[4] == 'W')
					{
						statement->value = "[ES:EDI] = [DS:ESI];";
						statement->type = PATTERN_ASSIGN;
					}
					else if (opcode[4] == 'Q')
					{
						statement->value = "[EDI] = [ESI];";
						statement->type = PATTERN_ASSIGN;
					}
					// MOVSHDUP, MOVSLDUP, MOVSS, MOVSX, MOVSXD
					else
					{
						statement->value = operand[0] + " = " + operand[1] + ";";
						if (operand[1].find("0x") == 0)
							statement->type = PATTERN_ASSIGN_C;
						else
							statement->type = PATTERN_ASSIGN;
					}
				}
				// MOVS - move string to string
				else
				{
/*					string operands = operand[0];
					char *tokens = strtok((char *)operands.c_str(), " ");
					if (tokens != NULL)
					{
						operand[0] = tokens;
						tokens = strtok(NULL, " ");
						if (tokens != NULL)
							operand[1] = tokens;
					}
					if (operand[0].find("QWORD") == 0)
					{
						statement->value = "[EDI] = [ESI];";
					}
					else
					{
						statement->value = "[ES:EDI] = [DS:ESI];";
					}*/
					statement->value = "[ES:EDI] = [DS:ESI];";
					statement->type = PATTERN_ASSIGN;
				}
			}
			// MOV
			else
			{
				statement->value = operand[0] + " = " + operand[1] + ";";
				if (operand[1].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
	}
	// MPSADBW
	else if (opcode[1] == 'P') { delete (statement); statement = NULL; }
	// MUL
	else if (opcode[1] == 'U')
	{
		// MULPD, MULPS, MULSD and MULSS
		if (opcode.size() > 3)
		{
			statement->value = operand[0] + " = " + operand[0] + " * " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// MUL
		else
		{
/*			string operands = operand[0];
			char *tokens = strtok((char *)operands.c_str(), " ");
			if (tokens != NULL)
			{
				operand[0] = tokens;
				tokens = strtok(NULL, " ");
				if (tokens != NULL)
					operand[1] = tokens;
			}
			if (operand[0].find("QWORD") == 0)
			{
				statement->value = "RAX = RDX:RAX * " + operand[1] + ";";
				statement->value += "RDX = RDX:RAX % " + operand[1] + ";";
			}
			else if (operand[0].find("DWORD") == 0)
			{
				statement->value = "EAX = EDX:EAX * " + operand[1] + ";";
				statement->value += "EDX = EDX:EAX % " + operand[1] + ";";
			}
			else if (operand[0].find("WORD") == 0)
			{
				statement->value = "AX = DX:AX * " + operand[1] + ";";
				statement->value += "DX = DX:AX % " + operand[1] + ";";
			}
			else
			{
				statement->value = "AL = AX * " + operand[1] + ";";
				statement->value += "AH = AX % " + operand[1] + ";";
			}*/
			statement->value = "EAX = EDX:EAX * " + operand[1] + ";";
			statement->value += "EDX = EDX:EAX % " + operand[1] + ";";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	// MWAIT
	else if (opcode[1] == 'W') { delete (statement); statement = NULL; }
	// UNKNOWN
	else
	{
		statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
		statement->type = PATTERN_UNKNOWN;
	}

	current_instruction_number = i;
	return (statement);
}

/*
 *
 */
Statement *x86AsmToMAIL::Process_P_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number)
{
	uint64_t i = current_instruction_number;

	if (opcode[1] == 'A')
	{
		// PABSB
		if (opcode[2] == 'B')
		{
			statement->value = operand[0] + " = abs(" + operand[1] + ");";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		// PACK
		else if (opcode[2] == 'C')
		{
			statement->value = operand[0] + " = " + operand[1] + ":" + operand[0] + ";";
			statement->type = PATTERN_ASSIGN;
		}
		// PADD
		else if (opcode[2] == 'D')
		{
			statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// PALIGNR
		else if (opcode[2] == 'L')
		{
			statement->value = operand[0] + " = " + operand[1] + ":" + operand[0] + ";";
			statement->type = PATTERN_ASSIGN;
		}
		// PANDN
		else if (opcode.find("PANDN") == 0)
		{
			statement->value = operand[0] + " = " + operand[0] + " and " + operand[1] + ";";
			statement->value += operand[0] + " = -" + operand[0] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// PAND
		else if (opcode[2] == 'N')
		{
			statement->value = operand[0] + " = " + operand[0] + " and " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// PAUSE
		else if (opcode[2] == 'U') { delete (statement); statement = NULL; }
		// PAVG
		else if (opcode[2] == 'V')
		{
			statement->value = operand[0] + " = avg(" + operand[0] + ", " + operand[1] + ");";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
	}
	// PBLEND
	else if (opcode[1] == 'B')
	{
		statement->value = operand[0] + " = " + operand[1] + ":" + operand[0] + ";";
		statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'C')
	{
		// PCLMUL
		if (opcode[2] == 'L')
		{
			statement->value = operand[0] + " = " + operand[0] + " * " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		else if (opcode[2] == 'M' == 0 && opcode.size() > 6)
		{
			if (opcode[4] == 'E')
			{
				// PCMPEQB
				if (opcode[6] == 'B')
				{
					statement->value = "if " + operand[0] + " == " + operand[1] + ";";
					statement->value += operand[0] + " = 0XFF;";
					statement->value += " else ";
					statement->value += operand[0] + " = 0X00;";
				}
				// PCMPEQW
				else if (opcode[6] == 'W')
				{
					statement->value = "if " + operand[0] + " == " + operand[1] + ";";
					statement->value += operand[0] + " = 0XFFFF;";
					statement->value += " else ";
					statement->value += operand[0] + " = 0X0000;";
				}
				// PCMPEQD
				else if (opcode[6] == 'D')
				{
					statement->value = "if " + operand[0] + " == " + operand[1] + ";";
					statement->value += operand[0] + " = 0XFFFFFFFF;";
					statement->value += " else ";
					statement->value += operand[0] + " = 0X00000000;";
				}
				// PCMPEQQ
				else if (opcode[6] == 'Q')
				{
					statement->value = "if " + operand[0] + " == " + operand[1] + ";";
					statement->value += operand[0] + " = 0XFFFFFFFFFFFFFFFF;";
					statement->value += " else ";
					statement->value += operand[0] + " = 0X0000000000000000;";
				}
				if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
					statement->type = PATTERN_CONTROL_C;
				else
					statement->type = PATTERN_CONTROL;
			}
			else if (opcode[4] == 'G')
			{
				// PCMPGTB
				if (opcode[6] == 'B')
				{
					statement->value = "if " + operand[0] + " > " + operand[1] + ";";
					statement->value += operand[0] + " = 0XFF;";
					statement->value += " else ";
					statement->value += operand[0] + " = 0X00;";
				}
				// PCMPGTW
				else if (opcode[6] == 'W')
				{
					statement->value = "if " + operand[0] + " > " + operand[1] + ";";
					statement->value += operand[0] + " = 0XFFFF;";
					statement->value += " else ";
					statement->value += operand[0] + " = 0X0000;";
				}
				// PCMPGTD
				else if (opcode[6] == 'D')
				{
					statement->value = "if " + operand[0] + " > " + operand[1] + ";";
					statement->value += operand[0] + " = 0XFFFFFFFF;";
					statement->value += " else ";
					statement->value += operand[0] + " = 0X00000000;";
				}
				// PCMPGTQ
				else if (opcode[6] == 'Q')
				{
					statement->value = "if " + operand[0] + " > " + operand[1] + ";";
					statement->value += operand[0] + " = 0XFFFFFFFFFFFFFFFF;";
					statement->value += " else ";
					statement->value += operand[0] + " = 0X0000000000000000;";
				}
				if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
					statement->type = PATTERN_CONTROL_C;
				else
					statement->type = PATTERN_CONTROL;
			}
			// PCMPESTRI and PCMPISTRI
			else if (opcode[opcode.size()-1] == 'I')
			{
				statement->value = "ECX = compare(" + operand[0] + ", " + operand[1] + ");";
				if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
			// PCMPESTRM and PCMPISTRM
			else if (opcode[opcode.size()-1] == 'M')
			{
				statement->value = "XMM0 = compare(" + operand[0] + ", " + operand[1] + ");";
				if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
		}
	}
	else if (opcode[1] == 'E')
	{
		// PEXTRB
		if (opcode[5] == 'B')
		{
			statement->value = operand[0] + " = substr(" + operand[1] + ", " + operand[2] + ", 8);";
		}
		// PEXTRW
		else if (opcode[5] == 'W')
		{
			statement->value = operand[0] + " = substr(" + operand[1] + ", " + operand[2] + ", 16);";
		}
		// PEXTRD
		else if (opcode[5] == 'D')
		{
			statement->value = operand[0] + " = substr(" + operand[1] + ", " + operand[2] + ", 32);";
		}
		// PEXTRQ
		else if (opcode[5] == 'Q')
		{
			statement->value = operand[0] + " = substr(" + operand[1] + ", " + operand[2] + ", 64);";
		}
		if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
			statement->type = PATTERN_LIBCALL_C;
		else
			statement->type = PATTERN_LIBCALL;
	}
	// AMD additions
	else if (opcode[1] == 'F')
	{
		// PF2ID and PF2IW
		if (opcode[2] == '2')
		{
			statement->value = operand[0] + " = " + operand[1];
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// PFACC, PFNACC and PFPNACC - accumulate
		else if (opcode[opcode.size()-3] == 'A' && opcode[opcode.size()-2] == 'C')
		{
			statement->value = operand[0] + " = " + operand[1] + ":" + operand[0] + ";";
			statement->type = PATTERN_ASSIGN;
		}
		// PFADD
		else if (opcode[2] == 'A' && opcode[3] == 'D')
		{
			statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// PFCMPEQ, PFCMPGE and PFCMPGT
		else if (opcode[2] == 'C')
		{
			if (opcode[6] == 'Q')
			{
				statement->value = "if " + operand[0] + " == " + operand[1] + ";";
				statement->value += operand[0] + " = 0XFFFFFFFFFFFFFFFF;";
				statement->value += " else ";
				statement->value += operand[0] + " = 0X0000000000000000;";
			}
			else if (opcode[6] == 'E')
			{
				statement->value = "if " + operand[0] + " >= " + operand[1] + ";";
				statement->value += operand[0] + " = 0XFFFFFFFFFFFFFFFF;";
				statement->value += " else ";
				statement->value += operand[0] + " = 0X0000000000000000;";
			}
			else if (opcode[6] == 'T')
			{
				statement->value = "if " + operand[0] + " > " + operand[1] + ";";
				statement->value += operand[0] + " = 0XFFFFFFFFFFFFFFFF;";
				statement->value += " else ";
				statement->value += operand[0] + " = 0X0000000000000000;";
			}
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_CONTROL_C;
			else
				statement->type = PATTERN_CONTROL;
		}
		// PFMAX, PFMIN and PFMUL
		else if (opcode[2] == 'M')
		{
			if (opcode[3] == 'A')
			{
				statement->value = operand[0] + " = max(" + operand[0] + ", " + operand[1] + ");";
				if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
			else if (opcode[3] == 'I')
			{
				statement->value = operand[0] + " = min(" + operand[0] + ", " + operand[1] + ");";
				if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
			else if (opcode[3] == 'U')
			{
				statement->value = operand[0] + " = " + operand[0] + " * " + operand[1] + ";";
				if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
		// PFRCP, PFRCPIT1 and PFRCPIT2 - reciprocal
		else if (opcode[2] == 'R')
		{
			if (opcode[3] == 'C')
			{
				statement->value = operand[0] + " = " + " 1 / " + operand[1] + ";";
				if (operand[1].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			// PFRSQRT and PFRSQRT1 - reciprocal square root
			else if (opcode[3] == 'S')
			{
				stringstream ss;
				ss << dec << register_number++;
				string gr = "gr_" + ss.str();
				statement->value = gr + " = sqrt(" + operand[1] + ");";
				statement->value += operand[0] + " = " + " 1 / " + gr + ";";
				if (operand[1].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
		}
		else if (opcode[2] == 'S')
		{
			// PFSUBR - reverse subtraction
			if (opcode[opcode.size()-1] == 'R')
			{
				statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
			}
			// PFSUB
			else
			{
				statement->value = operand[0] + " = " + operand[1] + " - " + operand[0] + ";";
			}
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'H')
	{
		// PHADD
		if (opcode[2] == 'A')
		{
			statement->value = operand[0] + " = " + operand[1] + " + " + operand[0] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// PHSUB
		else if (opcode[2] == 'S')
		{
			statement->value = operand[0] + " = " + operand[1] + " - " + operand[0] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// PHMIN
		else if (opcode[2] == 'M')
		{
			statement->value = operand[0] + " = " + operand[1] + ";";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'I')
	{
		// AMD additions
		// PI2FD and PI2FW
		if (opcode[2] == '2')
		{
			statement->value = operand[0] + " = " + operand[1];
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		else if (opcode[2] == 'N')
		{
			// PINSRB
			if (opcode[5] == 'B')
			{
				statement->value = operand[0] + " = substr(" + operand[1] + ", " + operand[2] + ", 8);";
				if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
			// PINSRW
			else if (opcode[5] == 'W')
			{
				statement->value = operand[0] + " = substr(" + operand[1] + ", " + operand[2] + ", 16);";
				if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
		}
	}
	else if (opcode[1] == 'M')
	{
		// PMUL
		if (opcode[2] == 'U')
		{
			statement->value = operand[0] + " = " + operand[0] + " * " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// PMADD
		else if (opcode[3] == 'D')
		{
			statement->value = operand[0] + " = " + operand[0] + " * " + operand[1] + ";";
			statement->value += operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// PMAX
		else if (opcode[3] == 'X')
		{
			statement->value = operand[0] + " = max(" + operand[0] + "," + operand[1] + ");";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		// PMIN
		else if (opcode[3] == 'N')
		{
			statement->value = operand[0] + " = min(" + operand[0] + "," + operand[1] + ");";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		// PMOV
		else if (opcode[3] == 'V')
		{
			statement->value = operand[0] + " = " + operand[1] + ";";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'O')
	{
		// POPA and POPAD
		if (opcode[3] == 'A')
		{
			statement->value = "edi = [sp=sp-0x1];";
			statement->value += "esi = [sp=sp-0x1];";
			statement->value += "ebp = [sp=sp-0x1];";
			statement->value += "esp = [sp=sp-0x1];";
			statement->value += "ebx = [sp=sp-0x1];";
			statement->value += "edx = [sp=sp-0x1];";
			statement->value += "ecx = [sp=sp-0x1];";
			statement->value += "eax = [sp=sp-0x1];";
			statement->type = PATTERN_STACK;
		}
		// POPCNT -- clear all flags and set ZF flag depending on the source operand
		else if (opcode[3] == 'C')
		{
			statement->value = operand[0] + " = count(" + operand[1] + ");";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		// POPF
		else if (opcode[3] == 'F')
		{
			statement->value = "eflags = [sp=sp-0x1];";
			statement->type = PATTERN_FLAG_S;
		}
		// POP
		else if (opcode[2] == 'P')
		{
			statement->value = operand[0] + " = [sp=sp-0x1];";
			statement->type = PATTERN_STACK;
		}
		// POR
		else if (opcode[2] == 'R')
		{
			statement->value = operand[0] + " = " + operand[0] + " or " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	// PREFETCH
	else if (opcode[1] == 'R') { delete (statement); statement = NULL; }
	else if (opcode[1] == 'S')
	{
		// PSAD PSHUF and PSIGN
		if (opcode[2] == 'A' || opcode[2] == 'H' || opcode[2] == 'I') { delete (statement); statement = NULL; }
		// PSL
		else if (opcode[2] == 'L')
		{
			statement->value = operand[0] + " = " + operand[0] + " << " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// PSR
		else if (opcode[2] == 'R')
		{
			statement->value = operand[0] + " = " + operand[0] + " >> " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// PSUB
		else if (opcode[2] == 'U')
		{
			statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// PSWAP
		else if (opcode[2] == 'W')
		{
			statement->value = operand[0] + " = swap(" + operand[0] + ", " + operand[1] + ");";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
	}
	// PTEST
	else if (opcode[1] == 'T')
	{
		statement->value = operand[1] + " and " + operand[0] + ";";
		if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
			statement->type = PATTERN_TEST_C;
		else
			statement->type = PATTERN_TEST;
	}
	else if (opcode[1] == 'U')
	{
		if (opcode[2] == 'S')
		{
			if (opcode.size() > 4)
			{
				// PUSHA
				if (opcode[4] == 'A')
				{
					statement->value = "[sp=sp+0x1] = edi;";
					statement->value += "[sp=sp+0x1] = esi;";
					statement->value += "[sp=sp+0x1] = ebp;";
					statement->value += "[sp=sp+0x1] = esp;";
					statement->value += "[sp=sp+0x1] = ebx;";
					statement->value += "[sp=sp+0x1] = edx;";
					statement->value += "[sp=sp+0x1] = ecx;";
					statement->value += "[sp=sp+0x1] = eax;";
					statement->type = PATTERN_STACK;
				}
				// PUSHF
				else
				{
					statement->value = "[sp=sp+0x1] = eflags;";
					statement->type = PATTERN_FLAG_S;
				}
			}
			// PUSH
			else
			{
				statement->value = "[sp=sp+0x1] = " + operand[0] + ";";
				if (operand[0].find("0x") == 0)
					statement->type = PATTERN_STACK_C;
				else
					statement->type = PATTERN_STACK;
			}
		}
		// PUNPCKHBW
		else if (opcode[6] == 'H')
		{
			if (opcode[8] == 'W')
			{
				stringstream ss1, ss2;
				ss1 << dec << register_number++;
				string gr1 = "gr_" + ss1.str();
				ss2 << dec << register_number++;
				string gr2 = "gr_" + ss2.str();
				statement->value = gr1 + " = substr(" + operand[0] + ", 8, 8);";
				statement->value += gr2 + " = substr(" + operand[1] + ", 8, 8);";
				statement->value += operand[0] + " = " + gr2 + ":" + gr1 + ";";
			}
			// PUNPCKHWD
			else if (opcode[7] == 'W')
			{
				stringstream ss1, ss2;
				ss1 << dec << register_number++;
				string gr1 = "gr_" + ss1.str();
				ss2 << dec << register_number++;
				string gr2 = "gr_" + ss2.str();
				statement->value = gr1 + " = substr(" + operand[0] + ", 16, 16);";
				statement->value += gr2 + " = substr(" + operand[1] + ", 16, 16);";
				statement->value += operand[0] + " = " + gr2 + ":" + gr1 + ";";
			}
			// PUNPCKHDQ
			else if (opcode[8] == 'Q')
			{
				stringstream ss1, ss2;
				ss1 << dec << register_number++;
				string gr1 = "gr_" + ss1.str();
				ss2 << dec << register_number++;
				string gr2 = "gr_" + ss2.str();
				statement->value = gr1 + " = substr(" + operand[0] + ", 32, 32);";
				statement->value += gr2 + " = substr(" + operand[1] + ", 32, 32);";
				statement->value += operand[0] + " = " + gr2 + ":" + gr1 + ";";
			}
			// PUNPCKHQDQ
			else if (opcode[8] == 'D')
			{
				stringstream ss1, ss2;
				ss1 << dec << register_number++;
				string gr1 = "gr_" + ss1.str();
				ss2 << dec << register_number++;
				string gr2 = "gr_" + ss2.str();
				statement->value = gr1 + " = substr(" + operand[0] + ", 64, 64);";
				statement->value += gr2 + " = substr(" + operand[1] + ", 64, 64);";
				statement->value += operand[0] + " = " + gr2 + ":" + gr1 + ";";
			}
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		else if (opcode[6] == 'L')
		{
			// PUNPCKLBW
			if (opcode[8] == 'W')
			{
				stringstream ss1, ss2;
				ss1 << dec << register_number++;
				string gr1 = "gr_" + ss1.str();
				ss2 << dec << register_number++;
				string gr2 = "gr_" + ss2.str();
				statement->value = gr1 + " = substr(" + operand[0] + ", 0, 8);";
				statement->value += gr2 + " = substr(" + operand[1] + ", 0, 8);";
				statement->value += operand[0] + " = " + gr2 + ":" + gr1 + ";";
			}
			// PUNPCKLWD
			else if (opcode[7] == 'W')
			{
				stringstream ss1, ss2;
				ss1 << dec << register_number++;
				string gr1 = "gr_" + ss1.str();
				ss2 << dec << register_number++;
				string gr2 = "gr_" + ss2.str();
				statement->value = gr1 + " = substr(" + operand[0] + ", 0, 16);";
				statement->value += gr2 + " = substr(" + operand[1] + ", 0, 16);";
				statement->value += operand[0] + " = " + gr2 + ":" + gr1 + ";";
			}
			// PUNPCKLDQ
			else if (opcode[8] == 'Q')
			{
				stringstream ss1, ss2;
				ss1 << dec << register_number++;
				string gr1 = "gr_" + ss1.str();
				ss2 << dec << register_number++;
				string gr2 = "gr_" + ss2.str();
				statement->value = gr1 + " = substr(" + operand[0] + ", 0, 32);";
				statement->value += gr2 + " = substr(" + operand[1] + ", 0, 32);";
				statement->value += operand[0] + " = " + gr2 + ":" + gr1 + ";";
			}
			// PUNPCKLQDQ
			else if (opcode[8] == 'D')
			{
				stringstream ss1, ss2;
				ss1 << dec << register_number++;
				string gr1 = "gr_" + ss1.str();
				ss2 << dec << register_number++;
				string gr2 = "gr_" + ss2.str();
				statement->value = gr1 + " = substr(" + operand[0] + ", 0, 64);";
				statement->value += gr2 + " = substr(" + operand[1] + ", 0, 64);";
				statement->value += operand[0] + " = " + gr2 + ":" + gr1 + ";";
			}
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
	}
	// PXOR
	else if (opcode[1] == 'X')
	{
		statement->value = operand[0] + " = " + operand[0] + " xor " + operand[1] + ";";
		if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	// UNKNOWN
	else
	{
		statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
		statement->type = PATTERN_UNKNOWN;
	}

	current_instruction_number = i;
	return (statement);
}

/*
 *
 */
Statement *x86AsmToMAIL::Process_R_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number)
{
	uint64_t i = current_instruction_number;

	if (opcode[1] == 'C')
	{
		// RCPPS and RCPSS
		if (opcode[3] == 'P' || opcode[3] == 'S')
		{
			statement->value = operand[0] + " = 1 / " + operand[1] + ";";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// RCL, RCR
		else if (opcode[2] == 'L' || opcode[2] == 'R')
		{
			delete (statement);
			statement = NULL;
			/*
			string operands = operand[0];
			char *tokens = strtok((char *)operands.c_str(), " ");
			if (tokens != NULL)
			{
				operand[0] = tokens;
				tokens = strtok(NULL, " ");
				if (tokens != NULL)
					operand[1] = tokens;
			}
			if (operand[0].find("QWORD") == 0)
			{
				statement->value = operand[0] + " = rotate(" + operand[0] + ", " + operand[1] + ", 64);";
			}
			else if (operand[0].find("DWORD") == 0)
			{
				statement->value = operand[0] + " = rotate(" + operand[0] + ", " + operand[1] + ", 32);";
			}
			else if (operand[0].find("WORD") == 0)
			{
				statement->value = operand[0] + " = rotate(" + operand[0] + ", " + operand[1] + ", 16);";
			}
			else
			{
				statement->value = operand[0] + " = rotate(" + operand[0] + ", " + operand[1] + ", 8);";
			}
			*/
		}
	}
	else if (opcode[1] == 'D')
	{
		// RDMSR
		if (opcode[2] == 'M')
		{
			statement->value = "EDX:EAX = MSR;";
			statement->type = PATTERN_ASSIGN;
		}
		// RDPMC
		if (opcode[2] == 'P')
		{
			statement->value = "EDX:EAX = PMC;";
			statement->type = PATTERN_ASSIGN;
		}
		// RDRAND - read hardware generated random number
		else if (opcode[2] == 'R')
		{
			/*
			statement->value = operand[0] + " = random();";
			*/
			delete (statement);
			statement = NULL;
		}
		// RDTSC, RDTSCP
		else if (opcode[2] == 'T')
		{
			/*
			statement->value = "EDX:EAX = time();";
			*/
			delete (statement);
			statement = NULL;
		}
		// RDFSBASE
		else if (opcode[2] == 'F')
		{
			statement->value = operand[0] + " = FS;";
			statement->type = PATTERN_ASSIGN;
		}
		// RDGSBASE
		else if (opcode[2] == 'G')
		{
			statement->value = operand[0] + " = GS;";
			statement->type = PATTERN_ASSIGN;
		}
	}
	// RET, RETF
	else if (opcode[1] == 'E')
	{
		statement->end = true;
		statement->branch_to_offset = END_OF_FUNCTION;
		uint16_t sub = 1;
		if (Util::isHexString(opcode))
		{
			stringstream ss;
			ss << hex << opcode;
			ss >> sub;
		}
		char temp_str[MAX_TEXT_SIZE+1];
		sprintf (temp_str, "jmp [sp=sp-0x%x];", sub);
		statement->value = temp_str;
		statement->type = PATTERN_JUMP_S;
	}
	else if (opcode[1] == 'O')
	{
		delete (statement);
		statement = NULL;
		/*
		// ROL and ROR
		if (opcode[2] == 'L' || opcode[2] == 'R')
		{
			string operands = operand[0];
			char *tokens = strtok((char *)operands.c_str(), " ");
			if (tokens != NULL)
			{
				operand[0] = tokens;
				tokens = strtok(NULL, " ");
				if (tokens != NULL)
					operand[1] = tokens;
			}
			if (operand[0].find("QWORD") == 0)
			{
				statement->value = operand[0] + " = rotate(" + operand[0] + ", " + operand[1] + ", 64);";
			}
			else if (operand[0].find("DWORD") == 0)
			{
				statement->value = operand[0] + " = rotate(" + operand[0] + ", " + operand[1] + ", 32);";
			}
			else if (operand[0].find("WORD") == 0)
			{
				statement->value = operand[0] + " = rotate(" + operand[0] + ", " + operand[1] + ", 16);";
			}
			else
			{
				statement->value = operand[0] + " = rotate(" + operand[0] + ", " + operand[1] + ", 8);";
			}
		}
		*/
		// ROUNDPD, ROUNDPS, ROUNDSD and ROUNDSS
		if (opcode[2] == 'U')
		{
			statement->value = operand[0] + " = round(" + operand[1] + ");";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
	}
	else if (opcode[1] == 'S')
	{
		// RSM - restore machine status word
		if (opcode[2] == 'M') { delete (statement); statement = NULL; }
		// RSQRTPS and RSQRTSS
		else if (opcode[2] == 'Q')
		{
			stringstream ss;
			ss << dec << register_number++;
			string gr = "gr_" + ss.str();
			statement->value = gr + " = sqrt(" + operand[1] + ");";
			statement->value += opcode[0] + " = 1 / " + gr + ";";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
	}
	// UNKNOWN
	else
	{
		statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
		statement->type = PATTERN_UNKNOWN;
	}

	current_instruction_number = i;
	return (statement);
}

/*
 *
 */
Statement *x86AsmToMAIL::Process_S_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number)
{
	uint64_t i = current_instruction_number;

	if (opcode[1] == 'A')
	{
		// SAHF - Loads SF, ZF, AF, PF, and CF from AH into EFLAGS register
		if (opcode[2] == 'H')
		{
			statement->value = "EFALGS = AH;";
			statement->type = PATTERN_FLAG;
		}
		// SALC - set AL on carry
		else if (opcode[opcode.size()-1] == 'C')
		{
			statement->value = "if (CF == 0) AL = 0x00 else AL = 0xFF;";
			statement->type = PATTERN_CONTROL_C;
		}
		// SAL - shift left
		else if (opcode[2] == 'L')
		{
			statement->value = operand[0] + " = " + operand[0] + " << " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// SAR
		else if (opcode[2] == 'R')
		{
			statement->value = operand[0] + " = " + operand[0] + " >> " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	// SBB - subtract with borrow
	// The OF, SF, ZF, AF, PF, and CF flags are set according to the result
	else if (opcode[1] == 'B')
	{
		statement->value = operand[1] + " = " + operand[1] + " + CF;";
		statement->value += operand[0] + " = " + operand[1] + " - " + operand[0] + ";";
		if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	// SCAS - compare
	// The OF, SF, ZF, AF, PF, and CF flags are set according to the result
	else if (opcode[1] == 'C')
	{
/*		string operands = operand[0];
		char *tokens = strtok((char *)operands.c_str(), " ");
		if (tokens != NULL)
		{
			operand[0] = tokens;
			tokens = strtok(NULL, " ");
			if (tokens != NULL)
				operand[1] = tokens;
		}
		if (operand[0].find("QWORD") == 0)
		{
			statement->value = operand[0] + " = compare(RAX, [EDI]);";
		}
		else if (operand[0].find("DWORD") == 0)
		{
			statement->value = operand[0] + " = compare(EAX, [ES:EDI]);";
		}
		else if (operand[0].find("WORD") == 0)
		{
			statement->value = operand[0] + " = compare(AX, [ES:EDI]);";
		}
		else
		{
			statement->value = operand[0] + " = compare(AL, [ES:EDI]);";
		}*/
		statement->value = operand[0] + " = compare(EAX, [ES:EDI]);";
		statement->type = PATTERN_LIBCALL;
	}
	// SETA, SETAE, SETB, SETBE, SETG, SETGE, SETL, SETLE,
	// SETNO, SETNP, SETNS, SETNZ, SETO, SETP, SETS, SETZ
	else if (opcode[1] == 'E')
	{
		string condition = opcode.substr(3, opcode.size()-3);
		map<string, string>::iterator it_c_table = conditionalInstructionMap.find(condition);
		if (it_c_table != conditionalInstructionMap.end())
		{
			statement->value = "if " + it_c_table->second + " ";
			statement->value += operand[0] + " = 1;";
			statement->value += "else " + operand[0] + " = 0;";
			statement->type = PATTERN_CONTROL_C;
		}
		// UNKNOWN
		else
		{
			statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
			statement->type = PATTERN_UNKNOWN;
		}
	}
	// SFENCE
	else if (opcode[1] == 'F') { delete (statement); statement = NULL; }
	else if (opcode[1] == 'G')
	{
		statement->value = operand[0] + " = GDTR;";
		statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'H')
	{
		// SHLD and SHRD
		if (opcode.size() > 3 && opcode[3] == 'D')
		{
			if (opcode[2] == 'L')
			{
				statement->value = operand[0] + " = " + operand[0] + " << " + operand[2] + ";";
				statement->value += operand[0] + " = bit(" + operand[1] + ", 0, " + operand[2] + ");";
			}
			// SHR
			else if (opcode[2] == 'R')
			{
				statement->value = operand[0] + " = " + operand[0] + " >> " + operand[2] + ";";
				statement->value += operand[0] + " = bit(" + operand[1] + ", 0, " + operand[2] + ");";
			}
			if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		// SHL
		else if (opcode[2] == 'L')
		{
			statement->value = operand[0] + " = " + operand[0] + " << " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// SHR
		else if (opcode[2] == 'R')
		{
			statement->value = operand[0] + " = " + operand[0] + " >> " + operand[1] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// SHUFPD, SHUFPS
		else if (opcode[2] == 'U') { delete (statement); statement = NULL; }
	}
	// SIDT
	else if (opcode[1] == 'I')
	{
		statement->value = operand[0] + " = IDTR;";
		statement->type = PATTERN_ASSIGN;
	}
	// SKINIT - Secure Init and Jump With Attestation
	// Verifiable startup of trusted software based on secure hash comparison
	else if (opcode[1] == 'K') { delete (statement); statement = NULL; }
	// SLDT
	else if (opcode[1] == 'L')
	{
		statement->value = operand[0] + " = LDTR;";
		statement->type = PATTERN_ASSIGN;
	}
	// SMSW - restore machine status word
	else if (opcode[1] == 'M') { delete (statement); statement = NULL; }
	// SQRTPD, SQRTPS, SQRTSD and SQRTSS
	else if (opcode[1] == 'Q')
	{
		statement->value = operand[0] + " = sqrt(" + operand[1] + ");";
		if (operand[1].find("0x") == 0)
			statement->type = PATTERN_LIBCALL_C;
		else
			statement->type = PATTERN_LIBCALL;
	}
	else if (opcode[1] == 'T')
	{
		// STC
		if (opcode[2] == 'C')
		{
			statement->value = "CF = 1;";
			statement->type = PATTERN_FLAG;
		}
		// STD
		else if (opcode[2] == 'D')
		{
			statement->value = "DF = 1;";
			statement->type = PATTERN_FLAG;
		}
		// STGI
		else if (opcode[2] == 'G')
		{
			statement->value = "GIF = 1;";
			statement->type = PATTERN_FLAG;
		}
		// STI
		else if (opcode[2] == 'I')
		{
			statement->value = "IF = 1;";
			statement->type = PATTERN_FLAG;
		}
		// STMXCSR
		else if (opcode[2] == 'M')
		{
			statement->value = "MXCSR = " + operand[0] + ";";
			if (operand[0].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// STOS
		else if (opcode[2] == 'O')
		{
/*			string operands = operand[0];
			char *tokens = strtok((char *)operands.c_str(), " ");
			if (tokens != NULL)
			{
				operand[0] = tokens;
				tokens = strtok(NULL, " ");
				if (tokens != NULL)
					operand[1] = tokens;
			}
			if (operand[0].find("QWORD") == 0)
			{
				statement->value = "EDI = RAX;";
			}
			else if (operand[0].find("DWORD") == 0)
			{
				statement->value = "ES:EDI = EAX;";
			}
			else if (operand[0].find("WORD") == 0)
			{
				statement->value = "ES:EDI = AX;";
			}
			else
			{
				statement->value = "ES:EDI = AL;";
			}*/
			statement->value = "ES:EDI = EAX;";
			statement->type = PATTERN_ASSIGN;
		}
		// STR
		if (opcode[2] == 'R')
		{
			statement->value = operand[0] + " = TR;";
			statement->type = PATTERN_ASSIGN;
		}
	}
	// SUB, SUBPD, SUBPS, SUBSD and SUBSS
	// The OF, SF, ZF, AF, PF, and CF flags are set according to the result
	else if (opcode[1] == 'U')
	{
		statement->value = operand[0] + " = " + operand[1] + " - " + operand[0] + ";";
		if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	// SWAPGS
	else if (opcode[1] == 'W')
	{
		statement->value = "GD = MSR;";
		statement->type = PATTERN_ASSIGN;
	}
	// SYSCALL, SYSENTER, SYSEXIT, SYSRET
	else if (opcode[1] == 'Y') { delete (statement); statement = NULL; }
	else
	{
		statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
		statement->type = PATTERN_UNKNOWN;
	}

	current_instruction_number = i;
	return (statement);
}

/*
 *
 */
Statement *x86AsmToMAIL::Process_V_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number)
{
	uint64_t i = current_instruction_number;

	if (opcode[1] == 'A')
	{
		if (opcode[2] == 'D')
		{
			// VADDSUBPD, VADDSUBPS
			if (opcode.size() > 7 && opcode[7] == 'D')
			{
				stringstream ss1, ss2;
				ss1 << dec << register_number++;
				string gr1 = "gr_" + ss1.str();
				ss2 << dec << register_number++;
				string gr2 = "gr_" + ss2.str();
				statement->value = gr1 + " = " + operand[1] + " + " + operand[2] + ";";
				statement->value += gr2 + " = " + operand[1] + " - " + operand[2] + ";";
				statement->value += operand[0] + " = " + gr2 + ":" + gr1 + ";";
			}
			// VADDPD, VADDPS, VADDSD, VADDSS
			else
			{
				statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + ";";
			}
			if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// VAESDEC, VAESDECLAST, VAESENC, VAESENCLAST, VAESIMC, VAESKEYGENASSIST
		else if (opcode[2] = 'E')
		{
			/*
			statement->value = operand[0] + " = aes(" + operand[1] + ");";
			*/
			delete (statement);
			statement = NULL;
		}
		// VANDNPD, VANDNPS
		else if (opcode[2] == 'N' && opcode.size() > 5)
		{
			statement->value = operand[1] + " = !" + operand[1] + ";";
			statement->value += operand[0] + " = " + operand[1] + " and " + operand[2] + ";";
			if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// VANDPD, VANDPS
		else if (opcode[2] == 'N')
		{
			statement->value = operand[0] + " = " + operand[1] + " and " + operand[2] + ";";
			if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	// VBLENDPD, VBLENDPS, VBLENDVPD, VBLENDVPS
	else if (opcode[1] == 'B')
	{
		if (opcode[2] == 'L')
		{
			statement->value = operand[0] + " = " + operand[1] + " or " + operand[2] + ";";
			if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// VBROADCASTF128, VBROADCASTSD, VBROADCASTSS
		else if (opcode[2] == 'R')
		{
			statement->value = operand[0] + " = " + operand[1] + ";";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'C')
	{
		if (opcode[2] == 'M')
		{
			// VCMPEQPD, VCMPEQPS, VCMPEQSD, VCMPEQSS
			if (opcode[4] == 'E')
			{
				statement->value = operand[0] + " = " + operand[2] + " == " + operand[1] + ";";
			}
			// VCMPLEPD, VCMPLEPS, VCMPLESD, VCMPLESS
			else if (opcode[5] == 'E')
			{
				statement->value = operand[0] + " = " + operand[2] + " <= " + operand[1] + ";";
			}
			// VCMPLTPD, VCMPLTPS, VCMPLTSD, VCMPLTSS
			else if (opcode[5] == 'T')
			{
				statement->value = operand[0] + " = " + operand[2] + " < " + operand[1] + ";";
			}
			else if (opcode[4] == 'N')
			{
				// VCMPNEQPD, VCMPNEQPS, VCMPNEQSD, VCMPNEQSS
				if (opcode[5] == 'E')
				{
					statement->value = operand[0] + " = " + operand[2] + " != " + operand[1] + ";";
				}
				// VCMPNLEPD, VCMPNLEPS, VCMPNLESD, VCMPNLESS
				else if (opcode[6] == 'E')
				{
					statement->value = operand[0] + " = " + operand[2] + " >= " + operand[1] + ";";
				}
				// VCMPNLTPD, VCMPNLTPS, VCMPNLTSD, VCMPNLTSS
				else if (opcode[6] == 'T')
				{
					statement->value = operand[0] + " = " + operand[2] + " > " + operand[1] + ";";
				}
			}
			// VCMPORDPD, VCMPORDPS, VCMPORDSD, VCMPORDSS
			else if (opcode[4] == 'O')
			{
				statement->value = operand[0] + " = " + operand[2] + " = " + operand[1] + ";";
			}
			// VCMPUNORDPD, VCMPUNORDPS, VCMPUNORDSD, VCMPUNORDSS
			else if (opcode[4] = 'U')
			{
				statement->value = operand[0] + " = " + operand[2] + " != " + operand[1] + ";";
			}
			if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// VCOMISD and VCOMISS
		else if (opcode[2] == 'O')
		{
			statement->value = "compare(" + operand[0] + ", " + operand[1] + ");";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		// VCMPESTRI, VCVTDQ2PD, VCVTDQ2PS, VCVTPD2DQ, VCVTPD2PS, VCVTPS2DQ,
		// VCVTPS2PD, VCVTSD2SI, VCVTSD2SS, VCVTSI2SD, VCVTSI2SS, VCVTSS2SD,
		// VCVTSS2SI, VCVTTPD2DQ, VCVTTPS2DQ, VCVTTSD2SI, VCVTTSS2SI
		else if (opcode[2] == 'V')
		{
			statement->value = operand[1] + " = " + operand[0] + ";";
			if (operand[0].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'D')
	{
		// VDIVPD, VDIVPS, VDIVSD and VDIVSS
		if (opcode[2] == 'I')
		{
			statement->value = operand[0] + " = " + operand[1] + " / " + operand[2] + ";";
		}
		// VDPPD and VDPPS
		else if (opcode[2] == 'P')
		{
			statement->value = operand[0] + " = " + operand[1] + " . " + operand[2] + ";";
		}
		if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'E')
	{
		// VERR, VERW -- verify if a segment can be read or written
		if (opcode[2] == 'R') { delete (statement); statement = NULL; }
		// VEXTRACTF128, VEXTRACTPS
		else if (opcode[2] == 'X')
		{
			stringstream ss;
			ss << dec << register_number++;
			string gr = "gr_" + ss.str();
			statement->value = gr + " = 32 * " + operand[2] + ";";
			statement->value += gr + " = " + gr + " and 0x0FFFFFFFF;";
			statement->value += operand[0] + " = " + operand[1] + " >> " + gr + ";";
			if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'F' && opcode.size() > 6)
	{
		if (opcode[3] == 'A')
		{
			// VFMADDSUB132PD, VFMADDSUB132PS, VFMADDSUB213PD
			// VFMADDSUB213PS, VFMADDSUB231PD, VFMADDSUB231PS
			if (opcode[6] == 'S')
			{
				stringstream ss1, ss2;
				ss1 << dec << register_number++;
				string gr1 = "gr_" + ss1.str();
				ss2 << dec << register_number++;
				string gr2 = "gr_" + ss2.str();
				statement->value = operand[1] + " = " + operand[1] + " * " + operand[2] + ";";
				statement->value += gr1 + " = " + operand[0] + " + " + operand[1] + ";";
				statement->value += gr2 + " = " + operand[0] + " - " + operand[1] + ";";
				statement->value += operand[0] + " = " + gr2 + ":" + gr1 + ";";
			}
			// VFMADD132PD, VFMADD132PS, VFMADD132SD, VFMADD132SS
			// VFMADD213PD, VFMADD213PS, VFMADD213SD, VFMADD213SS
			// VFMADD231PD, VFMADD231PS, VFMADD231SD, VFMADD231SS
			else
			{
				stringstream ss;
				ss << dec << register_number++;
				string gr = "gr_" + ss.str();
				statement->value = gr + " = " + operand[1] + " * " + operand[2] + ";";
				statement->value += operand[0] + " = " + gr + " + " + operand[2] + ";";
			}
		}
		else if (opcode[3] == 'S')
		{
			// VFMSUBADD132PD, VFMSUBADD231PD, VFMSUBADD213PD
			// VFMSUBADD213PS, VFMSUBADD132PS, VFMSUBADD231PS
			if (opcode[6] == 'A')
			{
				stringstream ss1, ss2;
				ss1 << dec << register_number++;
				string gr1 = "gr_" + ss1.str();
				ss2 << dec << register_number++;
				string gr2 = "gr_" + ss2.str();
				statement->value = operand[1] + " = " + operand[1] + " * " + operand[2] + ";";
				statement->value += gr1 + " = " + operand[0] + " - " + operand[1] + ";";
				statement->value += gr2 + " = " + operand[0] + " + " + operand[1] + ";";
				statement->value += operand[0] + " = " + gr2 + ":" + gr1 + ";";
			}
			// VFMSUB132PD, VFMSUB132PS, VFMSUB132SD, VFMSUB132SS
			// VFMSUB213PD, VFMSUB213PS, VFMSUB213SD, VFMSUB213SS
			// VFMSUB231PD, VFMSUB231PS, VFMSUB231SD, VFMSUB231SS
			else
			{
				stringstream ss;
				ss << dec << register_number++;
				string gr = "gr_" + ss.str();
				statement->value = gr + " = " + operand[1] + " * " + operand[2] + ";";
				statement->value += operand[0] + " = " + gr + " - " + operand[2] + ";";
			}
		}
		else if (opcode[2] == 'N')
		{
			// VFNMADD132PD, VFNMADD132PS, VFNMADD132SD, VFNMADD132SS
			// VFNMADD213PD, VFNMADD213PS, VFNMADD213SD, VFNMADD213SS
			// VFNMADD231PD, VFNMADD231PS, VFNMADD231SD, VFNMADD231SS
			if (opcode[4] == 'A')
			{
				stringstream ss;
				ss << dec << register_number++;
				string gr = "gr_" + ss.str();
				statement->value = gr + " = " + operand[1] + " * " + operand[2] + ";";
				statement->value += gr + " = -" + gr + ";";
				statement->value += operand[0] + " = " + gr + " + " + operand[2] + ";";
			}
			// VFNMSUB132PD = 8548, I_VFNMSUB132PS = 8534, I_VFNMSUB132SD = 8576, I_VFNMSUB132SS = 8562,
			// VFNMSUB213PD = 8828, I_VFNMSUB213PS = 8814, I_VFNMSUB213SD = 8856, I_VFNMSUB213SS = 8842,
			// VFNMSUB231PD = 9108, I_VFNMSUB231PS = 9094, I_VFNMSUB231SD = 9136, I_VFNMSUB231SS = 9122,
			else
			{
				stringstream ss;
				ss << dec << register_number++;
				string gr = "gr_" + ss.str();
				statement->value = gr + " = " + operand[1] + " * " + operand[2] + ";";
				statement->value += gr + " = -" + gr + ";";
				statement->value += operand[0] + " = " + gr + " - " + operand[2] + ";";
			}
		}
		if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'H')
	{
		// VHADDPD and VHADDPS
		if (opcode[2] == 'A')
		{
			statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
		}
		// VHSUBPD and VHSUBPS
		else if (opcode[2] == 'S')
		{
			statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
		}
		if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	// VINSERTF128, VINSERTPS
	else if (opcode[1] == 'I')
	{
		statement->value = operand[0] + " = " + operand[2] + ";";
		if (operand[2].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	// VLDDQU, VLDMXCSR
	else if (opcode[1] == 'L')
	{
		if (opcode[3] == 'D')
		{
			statement->value = operand[0] + " = [" + operand[1] + "];";
			statement->type = PATTERN_ASSIGN;
		}
		else if (opcode[3] == 'M')
		{
			statement->value = " MXCSR = " + operand[0] + ";";
			if (operand[0].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'M')
	{
		// VMASKMOVDQU, VMASKMOVPD, VMASKMOVPS
		if (opcode.size() > 8 && opcode[2] == 'A')
		{
			if (opcode[8] == 'D')
			{
				statement->value = " [DS:EDI] = " + operand[0] + ";";
				if (operand[0].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			else
			{
				statement->value = operand[0] + " = " + operand[2] + ";";
				if (operand[2].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
		// VMAXPD, VMAXPS, VMAXSD, VMAXSS
		else if (opcode[3] == 'X')
		{
			statement->value = operand[0] + " = max(" + operand[1] + ", " + operand[2] + ");";
			if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		// VMCALL, VMCLEAR, VMFUNC, VMLAUNCH, VMLOAD, VMMCALL
		// We generate a fake VM call for information
		else if (opcode[2] == 'C' || opcode[2] == 'F'|| opcode[2] == 'L'|| opcode[2] == 'M')
		{
			/*
			statement->value = "vm();";
			*/
			delete (statement);
			statement = NULL;
		}
		// VMINPD, VMINPS, VMINSD, VMINSS
		else if (opcode[3] == 'I')
		{
			statement->value = operand[0] + " = min(" + operand[1] + ", " + operand[2] + ");";
			if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		else if (opcode[3] == 'O')
		{
			// VMOVAPD, VMOVAPS, VMOVD, VMOVDDUP, VMOVDQA, VMOVDQU, VMOVMSKPD, VMOVMSKPS,
			// VMOVNTDQ, VMOVNTDQA, VMOVNTPD, VMOVNTPS, VMOVQ, VMOVUPD, VMOVUPS
			if (opcode[4] == 'A' || opcode[4] == 'D' || opcode[4] == 'M' 
				|| opcode[4] == 'N' || opcode[4] == 'Q' || opcode[4] == 'U')
			{
				statement->value = operand[0] + " = " + operand[1] + ";";
				if (operand[1].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			// VMOVHLPS, VMOVHPD, VMOVHPS, VMOVLHPS, VMOVLPD, VMOVLPS,
			// VMOVSHDUP, VMOVSLDUP, VMOVSD, VMOVSS
			else if (opcode[4] == 'H' || opcode[4] == 'L' || opcode[4] == 'S')
			{
				statement->value = operand[0] + " = " + operand[2] + ";";
				if (operand[2].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
		else if (opcode[2] == 'P')
		{
			// VMPSADBW
			if (opcode[3] == 'S') { delete (statement); statement = NULL; }
			// VMPTRLD, VMPTRST - load or store pointer to VM control structure
			if (opcode[3] == 'T')
			{
				/*
				statement->value = "vm();";
				*/
				delete (statement);
				statement = NULL;
			}

		}
		// VMREAD, VMRESUME, VMRUN, VMSAVE
		// read field from VM control structure, resume VM, run VM and save VM state
		else if (opcode[2] == 'R' || opcode[2] == 'S')
		{
			/*
			statement->value = "vm();";
			*/
			delete (statement);
			statement = NULL;
		}
		// VMULPD, VMULPS, VMULSD, VMULSS
		else if (opcode[2] == 'U')
		{
			statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + ";";
			if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// VMWRITE, VMXOFF, I_VMXON = 10006, 
		// write to field in VM control structure, turn off VM and turn on VM
		else if (opcode[2] == 'W' || opcode[2] == 'X')
		{
			/*
			statement->value = "vm();";
			*/
			delete (statement);
			statement = NULL;
		}
	}
	// VORPD, VORPS
	else if (opcode[1] == 'O')
	{
		statement->value = operand[0] + " = " + operand[1] + " or " + operand[2];
		if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'P')
	{
		if (opcode[2] == 'A')
		{
			// VPABSB, VPABSD, VPABSW
			if (opcode[3] == 'B')
			{
				statement->value = operand[0] + " = abs(" + operand[1] + ");";
				if (operand[1].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
			// I_VPACKSSDW, VPACKSSWB, VPACKUSDW, VPACKUSWB
			else if (opcode[3] == 'C')
			{
				statement->value = operand[0] + " = " + operand[2] + ":" + operand[1] + ";";
				statement->type = PATTERN_ASSIGN;
			}
			// VPADDB, VPADDD, VPADDQ, VPADDSB, VPADDSW, VPADDUSW, VPADDW
			else if (opcode[3] == 'D')
			{
				statement->value = operand[0] + " = " + operand[1] + " + " + operand[2];
				if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			// VPALIGNR
			else if (opcode[3] == 'L')
			{
				statement->value = operand[0] + " = " + operand[2] + ":" + operand[1];
				statement->type = PATTERN_ASSIGN;
			}
			// VPANDN
			else if (opcode.size() > 5 && opcode[5] == 'N')
			{
				statement->value = operand[0] + " = " + operand[1] + " and " + operand[2] + ";";
				statement->value += operand[0] + " = -" + operand[0] + ";";
				if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			// VPAND
			else if (opcode[3] == 'N')
			{
				statement->value = operand[0] + " = " + operand[1] + " and " + operand[2] + ";";
				if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			// VPAVGW
			else if (opcode[3] == 'V')
			{
				statement->value = operand[0] + " = avg(" + operand[1] + ", " + operand[2] + ");";
				if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
		}
		// VPBLENDVB, VPBLENDW
		else if (opcode[2] == 'B')
		{
			statement->value = operand[0] + " = " + operand[1] + ":" + operand[2] + ";";
			statement->type = PATTERN_ASSIGN;
		}
		else if (opcode[2] == 'C')
		{
			// VPCLMULQDQ
			if (opcode[3] == 'L')
			{
				statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + ";";
				if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			else if (opcode[3] == 'M' && opcode.size() > 7)
			{
				if (opcode[6] == 'Q')
				{
					// VPCMPEQB
					if (opcode[7] == 'B')
					{
						statement->value = "if " + operand[1] + " == " + operand[2] + ";";
						statement->value += operand[0] + " = 0XFF;";
						statement->value += " else ";
						statement->value += operand[0] + " = 0X00;";
					}
					// VPCMPEQW
					else if (opcode[7] == 'W')
					{
						statement->value = "if " + operand[1] + " == " + operand[2] + ";";
						statement->value += operand[0] + " = 0XFFFF;";
						statement->value += " else ";
						statement->value += operand[0] + " = 0X0000;";
					}
					// VPCMPEQD
					else if (opcode[7] == 'D')
					{
						statement->value = "if " + operand[1] + " == " + operand[2] + ";";
						statement->value += operand[0] + " = 0XFFFFFFFF;";
						statement->value += " else ";
						statement->value += operand[0] + " = 0X00000000;";
					}
					// VPCMPEQQ
					else if (opcode[7] == 'Q')
					{
						statement->value = "if " + operand[1] + " == " + operand[2] + ";";
						statement->value += operand[0] + " = 0XFFFFFFFFFFFFFFFF;";
						statement->value += " else ";
						statement->value += operand[0] + " = 0X0000000000000000;";
					}
					statement->type = PATTERN_CONTROL_C;
				}
				else if (opcode.size() > 9 && (opcode[5] == 'E' || opcode[5] == 'I'))
				{
					// VPCMPESTRI, VPCMPISTRI
					if (opcode[9] == 'I')
					{
						statement->value = "ECX = compare(" + operand[0] + ", " + operand[1] + ");";
					}
					// VPCMPESTRM, VPCMPISTRM
					else
					{
						statement->value = "XMM0 = compare(" + operand[0] + ", " + operand[1] + ");";
					}
					if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
						statement->type = PATTERN_LIBCALL_C;
					else
						statement->type = PATTERN_LIBCALL;
				}
				else if (opcode[6] == 'T')
				{
					// VPCMPGTB
					if (opcode[7] == 'B')
					{
						statement->value = "if " + operand[1] + " > " + operand[2] + ";";
						statement->value += operand[0] + " = 0XFF;";
						statement->value += " else ";
						statement->value += operand[0] + " = 0X00;";
					}
					// VPCMPGTD
					else if (opcode[7] == 'W')
					{
						statement->value = "if " + operand[1] + " > " + operand[2] + ";";
						statement->value += operand[0] + " = 0XFFFF;";
						statement->value += " else ";
						statement->value += operand[0] + " = 0X0000;";
					}
					// VPCMPGTQ
					else if (opcode[7] == 'D')
					{
						statement->value = "if " + operand[1] + " > " + operand[2] + ";";
						statement->value += operand[0] + " = 0XFFFFFFFF;";
						statement->value += " else ";
						statement->value += operand[0] + " = 0X00000000;";
					}
					// VPCMPGTW
					else if (opcode[7] == 'Q')
					{
						statement->value = "if " + operand[1] + " > " + operand[2] + ";";
						statement->value += operand[0] + " = 0XFFFFFFFFFFFFFFFF;";
						statement->value += " else ";
						statement->value += operand[0] + " = 0X0000000000000000;";
					}
					statement->type = PATTERN_CONTROL_C;
				}
			}
		}
		else if (opcode[2] == 'E')
		{
			// VPERM2F128, VPERMILPD, VPERMILPS
			if (opcode[3] == 'R')
			{
				statement->value = operand[0] + " = " + operand[1] + ";";
				if (operand[1].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			else if (opcode[3] == 'X' && opcode.size() > 6)
			{
				// VPEXTRB
				if (opcode[6] == 'B')
				{
					statement->value = operand[0] + " = substr(" + operand[1] + ", " + operand[2] + ", 8);";
				}
				// VPEXTRD
				else if (opcode[6] == 'W')
				{
					statement->value = operand[0] + " = substr(" + operand[1] + ", " + operand[2] + ", 16);";
				}
				// VPEXTRQ
				else if (opcode[6] == 'D')
				{
					statement->value = operand[0] + " = substr(" + operand[1] + ", " + operand[2] + ", 32);";
				}
				// VPEXTRW
				else if (opcode[6] == 'Q')
				{
					statement->value = operand[0] + " = substr(" + operand[1] + ", " + operand[2] + ", 64);";
				}
				if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
		}
		else if (opcode[2] == 'H')
		{
			// VPHADDD, VPHADDSW, VPHADDW
			if (opcode[3] == 'A')
			{
				statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + ";";
				if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			// VPHMINPOSUW
			else if (opcode[3] == 'M')
			{
				statement->value = operand[0] + " = min(" + operand[1] + ", " + operand[2] + ", 64);";
				if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
			// VPHSUBD, VPHSUBSW, VPHSUBW
			if (opcode[3] == 'S')
			{
				statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + ";";
				if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
		else if (opcode[2] == 'I' && opcode.size() > 6)
		{
			// VPINSRB
			if (opcode[6] == 'B')
			{
				statement->value = operand[0] + " = substr(" + operand[1] + ", " + operand[2] + ", 8);";
			}
			// VPINSRD
			else if (opcode[6] == 'W')
			{
				statement->value = operand[0] + " = substr(" + operand[1] + ", " + operand[2] + ", 16);";
			}
			// VPINSRQ
			else if (opcode[6] == 'D')
			{
				statement->value = operand[0] + " = substr(" + operand[1] + ", " + operand[2] + ", 32);";
			}
			// I_VPINSRW
			else if (opcode[6] == 'Q')
			{
				statement->value = operand[0] + " = substr(" + operand[1] + ", " + operand[2] + ", 64);";
			}
			if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		else if (opcode[2] == 'M')
		{
			if (opcode[3] == 'A')
			{
				// VPMADDUBSW, VPMADDWD
				if (opcode[4] == 'D')
				{
					stringstream ss;
					ss << dec << register_number++;
					string gr = "gr_" + ss.str();
					statement->value = gr + " = " + operand[1] + " * " + operand[2] + ";";
					statement->value += operand[0] + " = " + gr + " + " + operand[2] + ";";
					if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
						statement->type = PATTERN_ASSIGN_C;
					else
						statement->type = PATTERN_ASSIGN;
				}
				else if (opcode[4] == 'X')
				{
					statement->value = operand[0] + " = max(" + operand[1] + ", " + operand[2] + ");";
					if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
						statement->type = PATTERN_LIBCALL_C;
					else
						statement->type = PATTERN_LIBCALL;
				}
			}
			// VPMINSB, VPMINSD, VPMINSW, VPMINUB, VPMINUD, VPMINUW
			else if (opcode[3] == 'I')
			{
				statement->value = operand[0] + " = min(" + operand[1] + ", " + operand[2] + ");";
				if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
			// VPMOVMSKB, VPMOVSXBD, VPMOVSXBQ, VPMOVSXBW, VPMOVSXDQ,
			// VPMOVSXWD, VPMOVSXWQ, VPMOVZXBD, VPMOVZXBQ,
			// VPMOVZXBW, VPMOVZXDQ, VPMOVZXWD, VPMOVZXWQ
			else if (opcode[3] == 'O')
			{
				statement->value = operand[0] + " = " + operand[1] + ";";
				if (operand[1].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			// VPMULDQ, VPMULHRSW, VPMULHUW, VPMULHW, VPMULLD, VPMULLW, VPMULUDQ
			else if (opcode[3] == 'U')
			{
				statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + ";";
				if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
		// VPOR
		else if (opcode[2] == 'O')
		{
			statement->value = operand[0] + " = " + operand[1] + " or " + operand[2] + ";";
			if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		else if (opcode[2] == 'S')
		{
			// VPSADBW, VPSHUFB, VPSHUFD, VPSHUFHW, VPSHUFLW, VPSIGNB, VPSIGND, VPSIGNW
			if (opcode[3] == 'A' || opcode[3] == 'H') { delete (statement); statement = NULL; }
			// VPSLLD, VPSLLDQ, VPSLLQ, VPSLLW
			else if (opcode[3] == 'L') 
			{
				statement->value = operand[0] + " = " + operand[1] + " << " + operand[2] + ";";
				if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			// VPSRAD, VPSRAW, VPSRLD, VPSRLDQ, VPSRLQ, VPSRLW
			else if (opcode[3] == 'R') 
			{
				statement->value = operand[0] + " = " + operand[1] + " >> " + operand[2] + ";";
				if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			// VPSUBB, VPSUBD, VPSUBQ, VPSUBSB, VPSUBSW, VPSUBUSB, VPSUBUSW, VPSUBW
			else if (opcode[3] == 'U') 
			{
				statement->value = operand[0] + " = " + operand[2] + " - " + operand[1] + ";";
				if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
		// VPTEST
		else if (opcode[2] == 'T')
		{
			statement->value = operand[1] + " and " + operand[0] + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_TEST_C;
			else
				statement->type = PATTERN_TEST;
		}
		else if (opcode[2] == 'U' && opcode.size() > 9)
		{
			if (opcode.size() > 10)
			{
				// VPUNPCKHQDQ
				if (opcode[7] == 'H')
				{
					stringstream ss1, ss2;
					ss1 << dec << register_number++;
					string gr1 = "gr_" + ss1.str();
					ss2 << dec << register_number++;
					string gr2 = "gr_" + ss2.str();
					statement->value = gr1 + " = substr(" + operand[1] + ", 64, 64);";
					statement->value += gr2 + " = substr(" + operand[2] + ", 64, 64);";
					statement->value += operand[0] + gr2 + ":" + gr1 + ";";
				}
				// VPUNPCKLQDQ
				else
				{
					stringstream ss1, ss2;
					ss1 << dec << register_number++;
					string gr1 = "gr_" + ss1.str();
					ss2 << dec << register_number++;
					string gr2 = "gr_" + ss2.str();
					statement->value = gr1 + " = substr(" + operand[1] + ", 0, 64);";
					statement->value += gr2 + " = substr(" + operand[2] + ", 0, 64);";
					statement->value += operand[0] + gr2 + ":" + gr1 + ";";
				}
			}
			else if (opcode[9] == 'W')
			{
				// VPUNPCKHBW
				if (opcode[7] == 'H')
				{
					stringstream ss1, ss2;
					ss1 << dec << register_number++;
					string gr1 = "gr_" + ss1.str();
					ss2 << dec << register_number++;
					string gr2 = "gr_" + ss2.str();
					statement->value = gr1 + " = substr(" + operand[1] + ", 8, 8);";
					statement->value += gr2 + " = substr(" + operand[2] + ", 8, 8);";
					statement->value += operand[0] + gr2 + ":" + gr1 + ";";
				}
				// VPUNPCKLBW,
				else
				{
					stringstream ss1, ss2;
					ss1 << dec << register_number++;
					string gr1 = "gr_" + ss1.str();
					ss2 << dec << register_number++;
					string gr2 = "gr_" + ss2.str();
					statement->value = gr1 + " = substr(" + operand[1] + ", 0, 8);";
					statement->value += gr2 + " = substr(" + operand[2] + ", 0, 8);";
					statement->value += operand[0] + gr2 + ":" + gr1 + ";";
				}
			}
			else if (opcode[9] == 'D')
			{
				// VPUNPCKHWD
				if (opcode[7] == 'H')
				{
					stringstream ss1, ss2;
					ss1 << dec << register_number++;
					string gr1 = "gr_" + ss1.str();
					ss2 << dec << register_number++;
					string gr2 = "gr_" + ss2.str();
					statement->value = gr1 + " = substr(" + operand[1] + ", 16, 16);";
					statement->value += gr2 + " = substr(" + operand[2] + ", 16, 16);";
					statement->value += operand[0] + gr2 + ":" + gr1 + ";";
				}
				// VPUNPCKLWD,
				else
				{
					stringstream ss1, ss2;
					ss1 << dec << register_number++;
					string gr1 = "gr_" + ss1.str();
					ss2 << dec << register_number++;
					string gr2 = "gr_" + ss2.str();
					statement->value = gr1 + " = substr(" + operand[1] + ", 0, 16);";
					statement->value += gr2 + " = substr(" + operand[2] + ", 0, 16);";
					statement->value += operand[0] + gr2 + ":" + gr1 + ";";
				}
			}
			else if (opcode[9] == 'Q')
			{
				// VPUNPCKHDQ
				if (opcode[7] == 'H')
				{
					stringstream ss1, ss2;
					ss1 << dec << register_number++;
					string gr1 = "gr_" + ss1.str();
					ss2 << dec << register_number++;
					string gr2 = "gr_" + ss2.str();
					statement->value += gr1 + " = substr(" + operand[1] + ", 32, 32);";
					statement->value += gr2 + " = substr(" + operand[2] + ", 32, 32);";
					statement->value += operand[0] + gr2 + ":" + gr1 + ";";
				}
				// VPUNPCKLDQ
				else
				{
					stringstream ss1, ss2;
					ss1 << dec << register_number++;
					string gr1 = "gr_" + ss1.str();
					ss2 << dec << register_number++;
					string gr2 = "gr_" + ss2.str();
					statement->value = gr1 + " = substr(" + operand[1] + ", 0, 32);";
					statement->value += gr2 + " = substr(" + operand[2] + ", 0, 32);";
					statement->value += operand[0] + gr2 + ":" + gr1 + ";";
				}
			}
			if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		// VPXOR
		else if (opcode[2] == 'X')
		{
			statement->value = operand[0] + " = " + operand[1] + " xor " + operand[2] + ";";
			if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	// VRCPPS, VRCPSS
	else if (opcode[1] == 'R')
	{
		if (opcode[2] == 'C')
		{
			if (operand[2].size() > 0)
			{
				statement->value = operand[0] + " = 1 / " + operand[2] + ";";
				if (operand[2].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			else
			{
				statement->value = operand[0] + " = 1 / " + operand[1] + ";";
				if (operand[1].find("0x") == 0)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
		// VROUNDPD, VROUNDPS, VROUNDSD and VROUNDSS
		else if (opcode[2] == 'O')
		{
			statement->value = operand[0] + " = round(" + operand[1] + ");";
			if (operand[1].find("0x") == 0)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		else if(opcode[2] == 'S' && opcode.size() > 6)
		{
			// VRSQRTPS
			if (opcode[6] == 'P')
			{
				statement->value = operand[0] + " = sqrt(" + operand[1] + ");";
				if (operand[1].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
			// VRSQRTSS
			else
			{
				statement->value = operand[0] + " = sqrt(" + operand[2] + ");";
				if (operand[2].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
		}
	}
	else if (opcode[1] == 'S')
	{
		// VSHUFPD, VSHUFPS
		if (opcode[2] == 'H') {	delete (statement); statement = NULL; }
		else if (opcode[2] == 'Q')
		{
			// VSQRTPD, VSQRTPD
			if (opcode[5] == 'P')
			{
				statement->value = operand[0] + " = sqrt(" + operand[1] + ");";
				if (operand[1].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
			// VSQRTSD, VSQRTSS
			else
			{
				statement->value = operand[0] + " = sqrt(" + operand[2] + ");";
				if (operand[2].find("0x") == 0)
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
		}
		// VSTMXCSR
		else if (opcode[2] == 'T')
		{
			statement->value = "MXCSR = " + operand[0] + ";";
			if (operand[0].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// VSUBPD, VSUBPS, VSUBSD and VSUBSS
		// The OF, SF, ZF, AF, PF, and CF flags are set according to the result
		else if (opcode[2] == 'U')
		{
			statement->value = operand[0] + " = " + operand[2] + " - " + operand[1] + ";";
			if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	// VTESTPD, VTESTPS
	// The 0F, AF, PF, SF flags are cleared and the ZF, CF flags are set according to the operation.
	else if (opcode[1] == 'T')
	{
		statement->value = operand[1] + " and " + operand[0] + ";";
		if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
			statement->type = PATTERN_TEST_C;
		else
			statement->type = PATTERN_TEST;
	}
	// VUCOMISD, VUCOMISS
	// compare and set the eflags accordingly
	else if (opcode[1] == 'U' && opcode.size() > 5)
	{
		// VUNPCKHPD, VUNPCKHPS
		if (opcode[6] == 'H')
		{
			stringstream ss1, ss2;
			ss1 << dec << register_number++;
			string gr1 = "gr_" + ss1.str();
			ss2 << dec << register_number++;
			string gr2 = "gr_" + ss2.str();
			statement->value = gr1 + " = substr(" + operand[1] + ", 64, 64);";
			statement->value += gr2 + " = substr(" + operand[2] + ", 64, 64);";
			statement->value += operand[0] + " = " + gr2 + ":" + gr1 + ";";
		}
		// VUNPCKLPD, VUNPCKLPS
		else if (opcode[6] == 'L')
		{
			stringstream ss1, ss2;
			ss1 << dec << register_number++;
			string gr1 = "gr_" + ss1.str();
			ss2 << dec << register_number++;
			string gr2 = "gr_" + ss2.str();
			statement->value = gr1 + " = substr(" + operand[1] + ", 0, 64);";
			statement->value += gr2 + " = substr(" + operand[2] + ", 0, 64);";
			statement->value += operand[0] + " = " + gr2 + ":" + gr1 + ";";
		}
		if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
			statement->type = PATTERN_LIBCALL_C;
		else
			statement->type = PATTERN_LIBCALL;
	}
	// VXORPD and VXORPS
	else if (opcode[1] == 'X')
	{
		statement->value = operand[0] + " = " + operand[2] + " xor " + operand[1] + ";";
		if (operand[1].find("0x") == 0 || operand[2].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	// VZEROALL, VZEROUPPER
	else if (opcode[1] == 'Z') { delete (statement); statement = NULL; }
	// UNKNOWN
	else
	{
		statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
		statement->type = PATTERN_UNKNOWN;
	}

	current_instruction_number = i;
	return (statement);
}

/*
 *
 */
Statement *x86AsmToMAIL::Process_X_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number)
{
	uint64_t i = current_instruction_number;

	if (opcode[1] == 'A')
	{
		// XADD - exchange and add
		// The CF, PF, AF, SF, ZF, and OF flags are set according to the result
		// of the addition, which is stored in the destination operand.
		if (opcode[2] == 'D')
		{
			stringstream ss;
			ss << dec << register_number++;
			string gr = "gr_" + ss.str();
			statement->value = gr + " = " + operand[1] + " + " + operand[0] + ";";
			statement->value += operand[1] + " = " + operand[0] + ";";
			statement->value += operand[0] + " = " + gr + ";";
			if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	// XCHG
	else if (opcode[1] == 'C')
	{
		stringstream ss;
		ss << dec << register_number++;
		string gr = "gr_" + ss.str();
		statement->value = gr + " = " + operand[0] + ";";
		statement->value += operand[0] + " = " + operand[1] + ";";
		statement->value += operand[1] + " = " + gr + ";";
		statement->type = PATTERN_ASSIGN;
	}
	// XGETBV - get processor extended control register
	else if (opcode[1] == 'G')
	{
		statement->value = "EDX:EAX = XCR;";
		statement->type = PATTERN_ASSIGN;
	}
	// XLAT
	else if (opcode[1] == 'L')
	{
/*		string operands = operand[0];
		char *tokens = strtok((char *)operands.c_str(), " ");
		if (tokens != NULL)
		{
			operand[0] = tokens;
			tokens = strtok(NULL, " ");
			if (tokens != NULL)
				operand[1] = tokens;
		}
		if (operand[0].find("QWORD") == 0)
		{
			statement->value = "AL = [RBX+AL];";
		}
		else if (operand[0].find("DWORD") == 0)
		{
			statement->value = "AL = [DS:EBX+AL];";
		}
		else if (operand[0].find("WORD") == 0)
		{
			statement->value = "AL = [DS:BX+AL];";
		}*/
		statement->value = "AL = [DS:EBX+AL];";
		statement->type = PATTERN_ASSIGN;
	}
	// XOR, XORPD and XORPS
	else if (opcode[1] == 'O')
	{
		statement->value = operand[0] + " = " + operand[1] + " xor " + operand[0] + ";";
		if (operand[0].find("0x") == 0 || operand[1].find("0x") == 0)
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	// XRSTOR - Restore processor extended states from memory. The states are specified by EDX:EAX
	else if (opcode[1] == 'R') { delete (statement); statement = NULL; }
	else if (opcode[1] == 'S')
	{
		// XSAVE, XSAVEOPT - Save processor extended states from memory. The states are specified by EDX:EAX
		if (opcode[2] == 'A') { delete (statement); statement = NULL; }
		// XSETBV - set processor extended control register
		else if (opcode[2] == 'E')
		{
			statement->value = "XCR = EDX:EAX;";
			statement->type = PATTERN_ASSIGN;
		}
	}
	// UNKNOWN
	else
	{
		statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
		statement->type = PATTERN_UNKNOWN;
	}

	current_instruction_number = i;
	return (statement);
}

/*
 *
 * <p>
 * Gets the value in the instruction.
 * (1)
 *    It can be the address of a branch:
 *    The address where the branch is branching (jumping) to
 *    e.g:
 *    In case of the following jump instruction:
 *       jmp 0x30000                 = 0x30000
 *       jmp qword [RIP+0x200b6c]    = RIP+0x200b6c
 * (2)
 *    Can be any other value:
 *    e.g:
 *    0x4007c1+0x200
 * </p>
 *
 */
int64_t x86AsmToMAIL::getValue(uint64_t ic, _DecodedInst *disassembled, bool &memory)
{
	int64_t value = VALUE_UNKNOWN;
	string instr = (char *)disassembled[ic].operands.p;
	// Remove FAR from the instruction before finding the value
	if (instr.find("FAR") == 0)
		instr = instr.substr(3);
	instr = Util::removeWhiteSpaces(instr);
	int c = 0;

#ifdef __DEBUG__
	cout << "x86AsmToMAIL::getValue: " << instr << " @ offset: " << hex << disassembled[ic].offset << endl;
#endif

	memory = false;
	switch (instr[c])
	{
	/*
	 * e.g:
	 * QWORD [RAX*8+0x600e28]
	 * DWORD [RAX*8+0x600e28]
	 * WORD [RAX*8+0x600e28]
	 * [0x600e28]
	 */
	case 'Q':
	case 'D':
	case 'W':
	case '[':
		memory = true;
		c = instr.find_first_of('[');
		if (c >= 0)
		{
			int temp = instr.find_last_of(']');
			if (temp > 1)
			{
				instr = instr.substr(c+1, temp-c-1);
				value = computeValue(disassembled, instr, ic);
			}
			else
				cerr << "x86AsmToMAIL::getValue:Wrong value: " << instr << endl;
		}
		else
		{
			c = instr.find_first_of(' ');
			if (c < instr.size())
			{
				instr = instr.substr(c+1, instr.size()-c);
				value = computeValue(disassembled, instr, ic);
			}
			else
				cerr << "x86AsmToMAIL::getValue:Wrong value: " << instr << endl;
		}
		break;
	/*
	 *
	 * An immediate address (value)
	 * e.g:
	 *    0x4007c1
	 *    OR
	 *    0x4007c1+0x200
	 *
	 * RAX*8+0x600e28
	 * EAX*8+0x603e62
	 * 400+ECX
	 *
	 */
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	case 'R':
	case 'E':
		value = computeValue(disassembled, instr, ic);
		break;
	default:
		break;
	}

#ifdef __DEBUG__
	cout << "x86AsmToMAIL::getValue: Found: " << hex << value << endl;
#endif

	return value;
}

/*
 * Compute the address stored at instructions[ic]
 *
 * e.g:
 * RAX*8+0x600e28
 * RBX*8+RCX-0x600e28
 *
 * Computes the expression
 *
 */
int64_t x86AsmToMAIL::computeValue(_DecodedInst *disassembled, string addr, uint64_t ic)
{
	int64_t value = 0;

	Expression *ex = new Expression();
	vector<string> expr = ex->ArithmeticExpression(addr);
#ifdef __DEBUG__
	printf("Printing Expression %s\n", addr.c_str());
	printf("Printing Parsed Expression: ");
	for (int i = 0; i < expr.size(); i++)
		printf("%s ", expr[i].c_str());
	printf("\n");
#endif

	if (expr.size() > 0)
	{
		if (Util::isHexString(expr[0]))
		{
			stringstream ss;
			ss << hex << expr[0];
			ss >> value;
		}
		else if(Util::isNumeric(expr[0]))
		{
			stringstream ss;
			ss << dec << expr[0];
			ss >> value;
		}
		else
			value = getRegisterValue(expr[0], disassembled, ic);
	}

	if (value <= 0)
		return VALUE_UNKNOWN;

	for (int e = 1; e < expr.size(); e++)
	{
		Operator op_c;
		int16_t op;
		if (( op = op_c.IsArithmetic(expr[e]) ) <= 0 )
		{
			cout << "Error:x86AsmToMAIL::computeValue: Operation [ " << expr[e] << " ] not supported\n";
			break;
		}

		int64_t temp_value = 0;
		e++;
		if (Util::isHexString(expr[e]))
		{
			stringstream ss;
			ss << hex << expr[e];
			ss >> temp_value;
		}
		else if(Util::isNumeric(expr[e]))
		{
			stringstream ss;
			ss << dec << expr[e];
			ss >> temp_value;
		}
		else
			temp_value = getRegisterValue(expr[e], disassembled, ic);

		if (temp_value <= 0)
			return VALUE_UNKNOWN;

		if (expr.size() > 0)
		{
			if (op == PLUS) value +=  temp_value;
			else if (op == MINUS) value -=  temp_value;
			else if (op == MULTIPLICATION) value *=  temp_value;
			else if (op == DIVISION) value /=  temp_value;
			else if (op == LEFT_SHIFT) value <<=  temp_value;
			else if (op == RIGHT_SHIFT) value >>=  temp_value;
			else cout << "Warning:x86AsmToMAIL::computeValue: Operation not supported\n";
		}
	}

	if (value <= 0)
	{
		value = VALUE_UNKNOWN;
		cout << "Warning:x86AsmToMAIL::computeValue:Value not available/computed:Instruction: " << hex << disassembled[ic].offset << " " << disassembled[ic].instructionHex.p << " " << disassembled[ic].mnemonic.p << " " << disassembled[ic].operands.p << endl;
	}
#ifdef __DEBUG__
	printf("Value computed: %x\n", (int)value);
#endif

	delete (ex);
	return value;
}

/*
 * Gets the value of the register
 * For now we only compute and return the value of
 * the RIP i.e: the address of the next instruction.
 */
int64_t x86AsmToMAIL::getRegisterValue(string reg, _DecodedInst *disassembled, uint64_t ic)
{
	int64_t value = 0;

	if (reg.compare("RIP") == 0)
	{
		value = disassembled[ic].offset + disassembled[ic].size;
	}
	/*
	 *
	 * --- TO BE COMPLETED ---
	 *
	 * <p>
	 * Compute the value of a register at instruction ic.
	 * Trace back and compute the value assigned to this register.
	 *
	 * e.g:
	 *
	 *  400520                     55     PUSH                      RBP       START
	 *  400521                 4889e5      MOV                 RBP, RSP
	 *  400524                     53     PUSH                      RBX
	 *  400525               4883ec08      SUB                 RSP, 0x8
	 *  400529         803d000b200000      CMP BYTE [RIP+0x200b00], 0x0
	 *  400530                   754b      JNZ                 0x40057d         END
	 *  400532             bb300e6000      MOV            EBX, 0x600e30       START
	 *
	 *  // This is where RAX is assigned the value
	 *  400537         488b05fa0a2000      MOV      RAX, [RIP+0x200afa]
	 *  40053e         4881eb280e6000      SUB            RBX, 0x600e28
	 *  400545               48c1fb03      SAR                 RBX, 0x3
	 *  400549               4883eb01      SUB                 RBX, 0x1
	 *  40054d                 4839d8      CMP                 RAX, RBX
	 *  400550                   7324      JAE                 0x400576         END
	 *  400552           660f1f440000      NOP       WORD [RAX+RAX+0x0]       START   END
	 *
	 *  // This function is passed (the first instruction which has the potential
	 *  // to change the value of RAX) these two values (str_0=RAX, str_1=0x1)
	 *  400558               4883c001      ADD                 RAX, 0x1       START
	 *  40055c         488905d50a2000      MOV      [RIP+0x200ad5], RAX
	 *
	 *  // Find the value of RAX to compute the address of the jump/call
	 *  400563         ff14c5280e6000     CALL   QWORD [RAX*8+0x600e28]         END
	 *  </p>
	 *
	 */
	else
	{
		// TO DO
	}

	return value;
}

void x86AsmToMAIL::Print()
{
   printf ("\n Number    Offset                                                                                                      MAIL Statement                                                                           Pattern    Block/Function   Jump To\n\n");
   for (int s = 0; s < (int)Statements.size(); s++)
   {
      printf ("%5d", s);
      printf ("%12x", (int)Statements[s]->offset);
      printf ("%200s [%12s]", Statements[s]->value.c_str(), PatternsNames[Statements[s]->type]);
      if (Statements[s]->start)
         printf("%12s", "START");
      if (Statements[s]->end)
         printf("%12s", "END");
      if (Statements[s]->branch_to_offset == END_OF_FUNCTION)
         printf ("%16s", "END_OF_FUNCTION");
      if (Statements[s]->branch_to_offset != BRANCH_TO_UNKNOWN && Statements[s]->branch_to_offset != END_OF_FUNCTION)
         printf ("%16x", (int)Statements[s]->branch_to_offset);
      printf ("\n");
   }
}
