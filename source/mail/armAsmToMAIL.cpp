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

#include "armAsmToMAIL.h"

ArmAsmToMAIL::ArmAsmToMAIL(vector<_code> *codes, vector<_data> *datas)
{
	this->codes = codes;
	this->datas = datas;
}

ArmAsmToMAIL::~ArmAsmToMAIL()
{
	for (int i = 0; i < (int)backEdges.size(); i++)
		delete (backEdges[i]);
	backEdges.erase(backEdges.begin(), backEdges.end());
	backEdges.clear();

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
			blocks_local[b]->edges.clear();
			blocks_local[b]->in_edges.erase(blocks_local[b]->in_edges.begin(), blocks_local[b]->in_edges.end());
			blocks_local[b]->in_edges.clear();

			vector<Statement *> statements = blocks_local[b]->statements;
			for (int s = 0; s < (int)statements.size(); s++)
				delete (statements[s]);
			statements.erase(statements.begin(), statements.end());
			statements.clear();

#ifdef __DEBUG__
			cerr << "ArmAsmToMAIL::~ArmAsmToMAIL: Deleting block number: " << blocks_local[b]->number << endl;
			cout << "ArmAsmToMAIL::~ArmAsmToMAIL: Deleting block number: " << blocks_local[b]->number << endl;
#endif
			delete (blocks_local[b]);
		}
		blocks_local.erase(blocks_local.begin(), blocks_local.end());
		blocks_local.clear();

		functions[i]->backEdges.erase(functions[i]->backEdges.begin(), functions[i]->backEdges.end());
		functions[i]->backEdges.clear();
		delete (functions[i]);
	}

	Statements.erase(Statements.begin(), Statements.end());
	Statements.clear();
	blocks.erase(blocks.begin(), blocks.end());
	blocks.clear();
	functions.erase(functions.begin(), functions.end());
	functions.clear();
#endif
}

/*
 *
 * Check if the statement is the end of the program
 *
 */
bool ArmAsmToMAIL::isEndOfProgram(Statement *statement)
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
bool ArmAsmToMAIL::isEndOfFunction(Statement *statement)
{
	if (statement->branch_to_offset == END_OF_FUNCTION)
		return true;
	return false;
}

/*
 *
 * Add an edge to the block
 *
 */
void ArmAsmToMAIL::addEdgeToBlock(Block *block_jumped_from, Block *block_jumped_to, Edge *edge, Function *function)
{
	/*
	 * Do not add the edge if it has already been added
	 */
	bool alreadyAdded = false;
	for (int b = 0; b < (int)block_jumped_from->edges.size(); b++)
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
bool ArmAsmToMAIL::tagStatementAsStart(uint64_t number_of_statements, Statement *prev, Statement *current, map<uint64_t, Statement *> *jump_offsets)
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
 * This function translates the ARM assembly program to MAIL program
 * It is passed the disassembled instructions (code):
 * e.g for ELF format:
 * .text, .textbss
 * in that order
 *
 * Whenever there is a jump to an instruction address that address is added to the
 * jump_offsets vector to keep track of all the jumps/calls. These
 * addresses are then checked and tagged accordingly during the trnaslation process.
 *
 * entryPointAddress = Entry address currenlty not used
 *
 */
uint64_t ArmAsmToMAIL::Translate(uint64_t entryPointAddress)
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
			string opcode = (char *)it_n_code->instructions[i].mnemonic;
			Util::removeWhiteSpaces(opcode);
			if (opcode.find("nop") == std::string::npos)// && it_n_code->instructions[i].address >= entryPointAddress)
			{
				/*
				 * Normalization/Optimization:
				 *
				 * Throw away JUNK instructions
				 * i.e:
				 *   00
				 */
				if (it_n_code->instructions[i].bytes[0] == 0 && it_n_code->instructions[i].bytes[1] == 0)
				{
					i++;
					continue;
				}
#ifdef __DEBUG__
				printf("%5d %7x ", (int)i, (int)it_n_code->instructions[i].address);
				printf(" ");
				int s = 16 - (2 * it_n_code->instructions[i].size);
				for (int c = 1; c <= s; c++)
					printf(" ");
				for (int c = 0; c < it_n_code->instructions[i].size; c+=2)
				{
					// Print the byte
					printf("%02x", it_n_code->instructions[i].bytes[c+1]);
					printf("%02x", it_n_code->instructions[i].bytes[c]);
				}
				printf(" ");
				printf(" %10s %36s", it_n_code->instructions[i].mnemonic, it_n_code->instructions[i].op_str);
#endif
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
				statement->offset = it_n_code->instructions[i].address;

				/*
				 * Separate the operands to help in translation
				 * There are at most four operands in ARM assembly language
				 * separated by ','
				 */
				string operand[4];
				const char *str = it_n_code->instructions[i].op_str;
				Util::removeWhiteSpaces(str);
				int size_str = strlen(str);
				if (str[0] == '{')
				{
					operand[0].assign(str);
				}
				else
				{
					string temp;
					for (int i = 0; i < size_str; i++)
					{
						if (str[i] == ',')
						{
							i++;
							for ( ; i < size_str; i++)
							{
								if (str[i] == '{')
								{
									for ( ; i < size_str; i++)
									{
										operand[1] += str[i];
										if (str[i] == '}')
											break;
									}
								}
								else if (str[i] == '[')
								{
									for ( ; i < size_str; i++)
									{
										operand[1] += str[i];
										if (str[i] == ']')
											break;
									}
								}
								else if (str[i] == ',')
								{
									i++;
									for ( ; i < size_str; i++)
									{
										if (str[i] == '{')
										{
											for ( ; i < size_str; i++)
											{
												operand[2] += str[i];
												if (str[i] == '}')
													break;
											}
										}
										else if (str[i] == '[')
										{
											for ( ; i < size_str; i++)
											{
												operand[2] += str[i];
												if (str[i] == ']')
													break;
											}
										}
										else if (str[i] == ',')
										{
											i++;
											for ( ; i < size_str; i++)
											{
												operand[3] += str[i];
											}
										}
										else
										{
											operand[2] += str[i];
										}
									}
								}
								else
								{
									operand[1] += str[i];
								}
							}
						}
						else
							operand[0] += str[i];
					}
				}
				operand[0] = Util::removeWhiteSpaces(operand[0]);
				operand[1] = Util::removeWhiteSpaces(operand[1]);
				operand[2] = Util::removeWhiteSpaces(operand[2]);
				operand[3] = Util::removeWhiteSpaces(operand[3]);
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
					printf("    --->    %5d %7x   %s", (int)i, (int)statement->offset, statement->value.c_str());
					if (statement->start)
						printf("%12s", "START");
					if (statement->end)
						printf("%12s", "END");
					if (statement->branch_to_offset == END_OF_FUNCTION)
						printf ("%18s", "END_OF_FUNCTION");
					if (statement->branch_to_offset != BRANCH_TO_UNKNOWN && statement->branch_to_offset != END_OF_FUNCTION)
						printf ("%12x", (int)statement->branch_to_offset);
					printf ("\n");
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
		cs_free(it_n_code->instructions, it_n_code->code_size);
		it_n_code->instructions = NULL;
	}
	codes->erase(codes->begin(), codes->end());

#ifdef __DEBUG__
	printf ("\n\n");
#endif

#ifdef __DEBUG__
	printf ("\n\n");
	for (int s = 0; s < (int)Statements.size(); s++)
	{
		printf ("%5d", s);
		printf ("%12x", (int)Statements[s]->offset);
		printf ("%50s", Statements[s]->value.c_str());
		if (Statements[s]->start)
			printf("%12s", "START");
		if (Statements[s]->end)
			printf("%12s", "END");
		if (Statements[s]->branch_to_offset == END_OF_FUNCTION)
			printf ("%12s", "END_OF_FUNCTION");
		if (Statements[s]->branch_to_offset != BRANCH_TO_UNKNOWN && Statements[s]->branch_to_offset != END_OF_FUNCTION)
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
void ArmAsmToMAIL::initBlocks(map<uint64_t, Statement *> &jump_offsets)
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
	for (int s = 0; s < (int)Statements.size(); s++)
	{
		/*
		 *
		 * <p>
		 * Example is shown using Intel x86 format but is applied to ARM assembly
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
		 * Sometimes the malware programa try to insert
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
				sprintf (temp_str, " end_function_%d",(int) fn);
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

			if (isEndOfFunction(Statements[s]))
				blocks[bn]->type = BLOCK_END_OF_FUNCTION;
			else if (isEndOfProgram(Statements[s]))
				blocks[bn]->type = BLOCK_END_OF_PROGRAM;

			functions[fn]->blocks.push_back(blocks[bn]);
			blocks[bn]->function_number = fn;

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
			cerr << "Error::ArmAsmToMAIL::translate: No start statement found @: " << dec << (bn-1) << " instruction offset: " << hex << Statements[s]->offset << ":  " << Statements[s]->value << "\n";
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
	for (int f = 0; f < (int)functions.size(); f++)
	{
		vector <Block *> blocks_local = functions[f]->blocks;
		uint64_t offset_start = blocks_local[0]->statements[0]->offset;
		uint64_t offset_end = blocks_local[blocks_local.size()-1]->statements[0]->offset;
		for (unsigned int b = 0; b < blocks_local.size(); b++)
		{
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
	for (int f = 0; f < (int)functions.size(); f++)
	{
		vector <Block *> blocks_local = functions[f]->blocks;
		cout << "New Function Size: " << blocks_local.size() << endl;
		for (unsigned int b = 0; b < blocks_local.size(); b++)
		{
			vector <Edge *> edges = blocks_local[b]->edges;
			for (int e = 0; e < (int)edges.size(); e++)
				cout << dec << edges[e]->tail->number << " --> " << edges[e]->head->number << endl;
		}
	}

	for (int s = 0; s < (int)Statements.size(); s++)
	{
		printf ("%5d", s);
//		printf ("%5d", (int)Statements[s]->block_number);
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

	printf ("|\n");
	printf ("|\n");
	printf ("|   Printing blocks\n");
	printf ("|\n");
	printf ("|\n");
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
		printf ("Edges: %d: ", (int)blocks[b]->edges.size());
		for (int n = 0; n < (int)blocks[b]->edges.size(); n++)
			printf ("%5d -> %5d : ", (int)blocks[b]->edges[n]->tail->number, (int)blocks[b]->edges[n]->head->number);
		printf ("\n");
		if (blocks[b]->statements.size() > 0)
		{
			for (int i = 0; i < (int)blocks[b]->statements.size(); i++)
			{
				Statement *stmt = blocks[b]->statements[i];
//				printf("     %5d", (int)stmt->block_number);
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

	for (int f = 0; f < (int)functions.size(); f++)
	{
		cout << "Function number " << f << ": " << dec << functions[f]->blocks.size() << " " << functions[f]->backEdges.size() << endl;
	}
#endif
}

/*
 * Returns a vector of all the functions
 */
vector<Function *> ArmAsmToMAIL::GetFunctions()
{
	return (functions);
}

/*
 * Returns a vector of all the statements
 */
vector<Statement *> ArmAsmToMAIL::GetStatements()
{
	return (Statements);
}

/*
 * Returns a vector of all the blocks
 */
vector<Block *> ArmAsmToMAIL::GetBlocks()
{
	return (blocks);
}

/*
 * Returns a vector of all the back edges
 */
vector<BackEdge *> ArmAsmToMAIL::GetBackEdges()
{
	return (backEdges);
}

/*
 *
 */
Statement *ArmAsmToMAIL::ProcessStatements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	if (opcode[0] == 'a')
	{
		statement = Process_A_Statements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'b')
	{
		statement = Process_B_Statements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'c')
	{
		statement = Process_C_Statements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'd')
	{
		// DBG
		// Provides a hint to debug and related systems.
		//
		// DCPS1, DCPS2, DCPS3
		// Debug Change PE State allows the debugger to move the PE into a higher
		// Exception Level or to a specific mode at the current Exception Level.
		// These instructions are always UNDEFINED in Non-debug state.
		//
		// DMB
		// Data Memory Barrier is a memory barrier that ensures the ordering of
		// observations of memory accesses.
		//
		// DSB
		// Data Synchronization Barrier is a memory barrier that ensures the
		// completion of memory accesses.
		//
		// We ignore these instructions
		delete (statement);
		statement = NULL;
	}
	else if (opcode[0] == 'e')
	{
		statement = Process_E_Statements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'f')
	{
		statement = Process_F_Statements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'g')
	{
		// UNKNOWN
		statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
		statement->type = PATTERN_UNKNOWN;
	}
	else if (opcode[0] == 'h')
	{
		// HLT
		if (opcode[1] == 'l')
		{
			statement->value = "halt;";
			statement->type = PATTERN_HALT;
		}
		// HVC
		// Hypervisor Call causes a Hypervisor Call exception.
		// This instruction is ignored
		else if (opcode[1] == 'v')
		{
			delete (statement);
			statement = NULL;
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
	else if (opcode[0] == 'i')
	{
		statement = Process_I_Statements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'l')
	{
		statement = Process_L_Statements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'm')
	{
		statement = Process_M_Statements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'o')
	{
		statement = Process_O_Statements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'p')
	{
		statement = Process_P_Statements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'q')
	{
		statement = Process_Q_Statements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'r')
	{
		statement = Process_R_Statements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 's')
	{
		statement = Process_S_Statements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'u')
	{
		statement = Process_U_Statements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'v')
	{
		statement = Process_V_Statements(statement, opcode, operand, register_number, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		if (statement != NULL)
			tagStatementAsStart(number_of_statements, prev_statement, statement, &jump_offsets);
	}
	else if (opcode[0] == 'w')
	{
		// WFE, WFI
		if (opcode[1] == 'f')
		{
			// WFE
			// Wait For Event is a hint instruction that permits the PE to enter a low-power
			// state until one of a number of events occurs, including events signaled by
			// executing the SEV instruction on any PE in the multiprocessor system.
			//
			// WFI
			// Wait For Interrupt is a hint instruction that permits the PE to enter a
			// low-power state until one of a number of asynchronous events occurs.
			//
			// These instructions are ignored
			if (opcode[2] == 'e' || opcode[2] == 'i')
			{
				delete (statement);
				statement = NULL;
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
	// YIELD
	// YIELD is a hint instruction. Software with a multithreading capability can use a
	// YIELD instruction to indicate to the PE that it is performing a task, for example
	// a spin-lock, that could be swapped out to improve overall system performance.
	// The PE can use this hint to suspend and resume multiple software threads if it
	// supports the capability.
	// This instruction is ignored
	else if (opcode[0] == 'y')
	{
		delete (statement);
		statement = NULL;
	}
	else
	{
		delete (statement);
		statement = NULL;
#ifdef __DEBUG__
cout << "Error::CFG::Build: Instruction type UNDEFINED\r\n";
		printf("%5d %7x ", (int)i, (int)it_n_code->instructions[i].address);
		printf(" ");
		int s = 16 - (2 * it_n_code->instructions[i].size);
		for (int c = 1; c <= s; c++)
			printf(" ");
		for (int c = 0; c < it_n_code->instructions[i].size; c+=2)
		{
			// Print the byte
			printf("%02x", it_n_code->instructions[i].bytes[c+1]);
			printf("%02x", it_n_code->instructions[i].bytes[c]);
		}
		printf(" ");
		printf(" %10s %36s", it_n_code->instructions[i].mnemonic, it_n_code->instructions[i].op_str);
#endif
	}

	current_instruction_number = i;
	return (statement);
}

/*
 *
 */
Statement *ArmAsmToMAIL::ProcessJumpStatement(Statement *statement, vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	statement->end = true;

	if (number_of_statements > 0)
	{
		/*
		 * Adding the jump offset and the jump statement to
		 * be used latter for determining the start of the block
		 * when tracing back or forward.
		 */
		if (statement->branch_to_offset != BRANCH_TO_UNKNOWN || statement->branch_to_offset != END_OF_FUNCTION)
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
				else if ((int)Statements[s]->offset == statement->branch_to_offset)
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

	return (statement);
}

/*
 *
 */
Statement *ArmAsmToMAIL::Process_A_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	if (opcode[1] == 'd')
	{
		// ADC, ADCS
		// Ignore shift register instructions because they will not effect our malware analysis
		if (opcode[2] == 'c')
		{
		    // adc   r3, r3, #1
		    // adc   r3, r3, r4
			if (operand[2] == "")
			{
				statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + " + CF;";
				// Immediate value
				if (operand[1][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				// Register
				else
					statement->type = PATTERN_ASSIGN;
			}
		    // adc   r3, r2, #1
		    // adc   r3, r2, r4
			else
			{
				statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + " + CF;";
				// Immediate value
				if (operand[2][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				// Register
				else
					statement->type = PATTERN_ASSIGN;
			}

			/*
			 *
			 * If the destination register is a PC then the instruction is a branch to the
			 * address calculated by the operation. This address can only be known at runtime
			 * (an immediate value or a register value added to the PC) and hence PATTERN_JUMP
			 * is assigned as the MAIL Pattern.
			 *
			 */
			if (operand[0] == "pc")
			{
				int value = getHexValue(operand[1]);
				if (value != VALUE_UNKNOWN)
				{
					int pc = it_n_code->instructions[i].address + it_n_code->instructions[i].size;
					value += pc;
					char statementStr[24];
					sprintf(statementStr, "jmp 0x%x", value);
					statement->value.assign(statementStr);
					statement->type = PATTERN_JUMP_C;
					statement->branch_to_offset = value;
				}
				else
				{
					statement->value = "jmp UNKNOWN;";
					statement->type = PATTERN_JUMP;
				}
				statement = ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
			}
		}
		// ADD, ADDS
		// Ignore shift register instructions because they will not effect our malware analysis
		// Ignore the SP addition because it doesn't effect our malware analysis
		// it's only reading value from the SP and not writing any value to SP
		else if (opcode[2] == 'd')
		{
		    // add   r3, r3, #1
		    // add   r3, r3, r4
		    // add   r3, sp, #1
			if (operand[2] == "")
			{
				statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
				// Immediate value
				if (operand[1][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				// Register
				else
					statement->type = PATTERN_ASSIGN;
			}
		    // add   r3, r2, #1
		    // add   r3, r2, r4
		    // add   r3, sp, r4
			else
			{
				statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + ";";
				// Immediate value
				if (operand[2][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				// Register
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
		// ADR
		else if (opcode[2] == 'r')
		{
			statement->value = operand[0] + " = PC + " + operand[1] + ";";
			statement->type = PATTERN_ASSIGN_C;
		}

		/*
		 *
		 * If the destination register is a PC then the instruction is a branch to the
		 * address calculated by the operation. This address can only be known at runtime
		 * (an immediate value or a register value added to the PC) and hence PATTERN_JUMP
		 * is assigned as the MAIL Pattern.
		 *
		 */
		if (operand[0] == "pc")
		{
			int value = getHexValue(operand[1]);
			if (value != VALUE_UNKNOWN)
			{
				int pc = it_n_code->instructions[i].address + it_n_code->instructions[i].size;
				value += pc;
				char statementStr[24];
				sprintf(statementStr, "jmp 0x%x", value);
				statement->value.assign(statementStr);
				statement->type = PATTERN_JUMP_C;
				statement->branch_to_offset = value;
			}
			else
			{
				statement->value = "jmp UNKNOWN;";
				statement->type = PATTERN_JUMP;
			}
			statement = ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		}
	}
	// ----------------------------------------------------------
	//
	// Advance SIMD instructions processing on 128 bit registers
	//
	// ----------------------------------------------------------
	// We do not distinct between the different sizes of the registers/instructions
	// AESD, AESE, AESIMC, AESMC
	// AES (Advanced Encryption Standard) decryption/encryption.
	else if (opcode[1] == 'e')
	{
		// if AESD, then perform decryption
		if (opcode[3] == 'd')
		{
			statement->value = operand[0] + " = aes(" + operand[1] + ", 1);";
			statement->type = PATTERN_LIBCALL;
		}
		// otherwise perform encryption
		else
		{
			statement->value = operand[0] + " = aes(" + operand[1] + ", 0);";
			statement->type = PATTERN_LIBCALL;
		}
	}
	// AND, ANDS
	else if (opcode[1] == 'n')
	{
		// Ignore shift register instructions because they will not effect our malware analysis
		//
	    // and   r3, r3, #1
	    // and   r3, r3, r4
		if (operand[2] == "")
		{
			statement->value = operand[0] + " = " + operand[0] + " and " + operand[1] + ";";
			// Immediate value
			if (operand[1][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			// Register
			else
				statement->type = PATTERN_ASSIGN;
		}
	    // and   r3, r2, #1
	    // and   r3, r2, r4
		else
		{
			statement->value = operand[0] + " = " + operand[1] + " and " + operand[2] + ";";
			// Immediate value
			if (operand[2][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			// Register
			else
				statement->type = PATTERN_ASSIGN;
		}

		/*
		 *
		 * If the destination register is a PC then the instruction is a branch to the
		 * address calculated by the operation. This address can only be known at runtime
		 * (an immediate value or a register value added to the PC) and hence PATTERN_JUMP
		 * is assigned as the MAIL Pattern.
		 *
		 */
		if (operand[0] == "pc")
		{
			int value = getHexValue(operand[1]);
			if (value != VALUE_UNKNOWN)
			{
				int pc = it_n_code->instructions[i].address + it_n_code->instructions[i].size;
				value &= pc;
				char statementStr[24];
				sprintf(statementStr, "jmp 0x%x", value);
				statement->value.assign(statementStr);
				statement->type = PATTERN_JUMP_C;
				statement->branch_to_offset = value;
			}
			else
			{
				statement->value = "jmp UNKNOWN;";
				statement->type = PATTERN_JUMP;
			}
			statement = ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		}
	}
	// ASR, ASRS
	else if (opcode[1] == 's')
	{
		// Ignore shift register instructions because they will not effect our malware analysis
		//
	    // asr   r3, r3, #1
	    // asr   r3, r3, r4
		if (operand[2] == "")
		{
			statement->value = operand[0] + " = " + operand[0] + " and " + operand[1] + ";";
			// Immediate value
			if (operand[1][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			// Register
			else
				statement->type = PATTERN_ASSIGN;
		}
	    // asr   r3, r2, #1
	    // asr   r3, r2, r4
		else
		{
			statement->value = operand[0] + " = " + operand[1] + " and " + operand[2] + ";";
			// Immediate value
			if (operand[2][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			// Register
			else
				statement->type = PATTERN_ASSIGN;
		}

		/*
		 *
		 * If the destination register is a PC then the instruction is a branch to the
		 * address calculated by the operation. This address can only be known at runtime
		 * (an immediate value or a register value added to the PC) and hence PATTERN_JUMP
		 * is assigned as the MAIL Pattern.
		 *
		 */
		if (operand[0] == "pc")
		{
			int value = getHexValue(operand[1]);
			if (value != VALUE_UNKNOWN)
			{
				int pc = it_n_code->instructions[i].address + it_n_code->instructions[i].size;
				value &= pc;
				char statementStr[24];
				sprintf(statementStr, "jmp 0x%x", value);
				statement->value.assign(statementStr);
				statement->type = PATTERN_JUMP_C;
				statement->branch_to_offset = value;
			}
			else
			{
				statement->value = "jmp UNKNOWN;";
				statement->type = PATTERN_JUMP;
			}
			statement = ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		}
	}

	current_instruction_number = i;
	return (statement);
}

/*
 *
 */
Statement *ArmAsmToMAIL::Process_B_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	if (opcode[1] == 'f')
	{
		// BFC
		// clears any number of adjacent bits at any position in a register,
		// without affecting the other bits in the register.
	    // bfc   r3, #lsb, #width
		if (opcode[2] == 'c')
		{
			statement->value = "clear(" + operand[0] + ", " + operand[1] + ", " + operand[2] + ");";
			statement->type = PATTERN_LIBCALL;
		}
		// BFI
		// copies any number of low order bits from a register into the same
		// number of adjacent bits at any position in the destination register.
		// bfi   r1, r2, #lsb, #width
		else if (opcode[2] == 'i')
		{
			statement->value = operand[0] = + "bit(" + operand[1] + ", " + operand[2] + ", " + operand[3] + ");";
			statement->type = PATTERN_LIBCALL_C;
		}
	}
	// BIC, BICS
	// performs a bitwise AND of a register value and the complement of an immediate
	// value, and writes the result to the destination register. It can optionally
	// update the condition flags based on the result.
	else if (opcode[1] == 'i')
	{
		// Ignore shift register instructions because they will not effect our malware analysis
		//
	    // bic   r3, r3, #1
	    // bic   r3, r3, r4
		if (operand[2] == "")
		{
			statement->value = operand[0] + " = " + operand[0] + " and !" + operand[1] + ";";
			// Immediate value
			if (operand[1][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			// Register
			else
				statement->type = PATTERN_ASSIGN;
		}
	    // bic   r3, r2, #1
	    // bic   r3, r2, r4
		else
		{
			statement->value = operand[0] + " = " + operand[1] + " and !" + operand[2] + ";";
			// Immediate value
			if (operand[2][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			// Register
			else
				statement->type = PATTERN_ASSIGN;
		}

		/*
		 *
		 * If the destination register is a PC then the instruction is a branch to the
		 * address calculated by the operation. This address can only be known at runtime
		 * (an immediate value or a register value added to the PC) and hence PATTERN_JUMP
		 * is assigned as the MAIL Pattern.
		 *
		 */
		if (operand[0] == "pc")
		{
			int value = getHexValue(operand[1]);
			if (value != VALUE_UNKNOWN)
			{
				int pc = it_n_code->instructions[i].address + it_n_code->instructions[i].size;
				value &= pc;
				char statementStr[24];
				sprintf(statementStr, "jmp 0x%x", value);
				statement->value.assign(statementStr);
				statement->type = PATTERN_JUMP_C;
				statement->branch_to_offset = value;
			}
			else
			{
				statement->value = "jmp UNKNOWN;";
				statement->type = PATTERN_JUMP;
			}
			statement = ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		}
	}
	// BKPT - breakpoint instruction equivalent to INT 3 in x86
	// This instruction is ignored
	else if (opcode[1] == 'k')
	{
		delete (statement);
		statement = NULL;
	}
	/*
	 * ---------------------------------------------------------
	 *
	 *                    BRANCH INSTRUCTIONS
	 *
	 * ---------------------------------------------------------
	 */
	// BX{<c>}, BXJ{<c>} - depending on the condition
	// Causes a branch to an address and instruction set specified by a register.
	else if (opcode[1] == 'x')
	{
		statement->value = "jmp " + operand[0] + ";";
		if (operand[0] == "lr")
		{
			statement->branch_to_offset = END_OF_FUNCTION;
		}
		statement->type = PATTERN_JUMP;
		ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
	}
	// BL{<c>}, BLX{<c>} - depending on the condition
	// Calls a subroutine at a PC-relative address.
	//
	// B{<c>} - depending on the condition
	// Causes a branch to a target address.
	else
	{
		// Immediate value
		// BL #0x23e
		// B  #0x23e
		// address = PC + #0x23e
		// BL +338 (0x00007830)
		// address = PC + 338 = 0x00007830
		//
		// Register
		// BL r3
		// Parse the hex number from the string
		operand[0] = operand[0].substr(0, operand[0].length());
		int pos_1 = operand[0].find("0x");
		if (pos_1 != (int)string::npos)
		{
			pos_1 += 2;
			int pos_2 = operand[0].find(")");
			if (pos_2 != (int)string::npos)
				pos_2 -= pos_1;
			else
				pos_2 = operand[0].length() - pos_1;
			operand[0] = operand[0].substr(pos_1, pos_2);

			int addr = Util::hexStringToInt(operand[0]);
			char statementStr[128];

			if (opcode[1] == 'l')
			{
				sprintf(statementStr, "call 0x%x;", addr);
				statement->type = PATTERN_CALL_C;
			}
			else
			{
				sprintf(statementStr, "jmp 0x%x;", addr);
				statement->type = PATTERN_JUMP_C;
			}
			statement->branch_to_offset = addr;
			statement->value.assign(statementStr);
		}
		else
		{
			if (opcode[1] == 'l')
			{
				statement->value = "call " + operand[0] + ";";
				statement->type = PATTERN_CALL;
			}
			else
			{
				statement->value = "jmp " + operand[0] + ";";
				statement->type = PATTERN_JUMP;
			}
		}

		ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
	}

	current_instruction_number = i;
	return (statement);
}

/*
 *
 */
Statement *ArmAsmToMAIL::Process_C_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	/*
	 * ---------------------------------------------------------
	 *
	 *                    BRANCH INSTRUCTIONS
	 *
	 * ---------------------------------------------------------
	 */
	// CBNZ, CBZ
	// Compare the value in a register with zero/non-zero, and conditionally branch forward a constant value.
	if (opcode[1] == 'b')
	{
		// Parse the hex number from the string
		operand[1] = operand[1].substr(0, operand[1].length());
		int pos_1 = operand[1].find("0x");
		if (pos_1 != (int)string::npos)
		{
			pos_1 += 2;
			int pos_2 = operand[1].find(")");
			if (pos_2 != (int)string::npos)
				pos_2 -= pos_1;
			else
				pos_2 = operand[1].length() - pos_1;
			operand[1] = operand[1].substr(pos_1, pos_2);
		}

		int addr = Util::hexStringToInt(operand[1]);
		char address[24];
		sprintf(address, "%x", addr);

		if (opcode[2] == 'z')
			statement->value = "if (" + operand[0] + " == 0 jmp 0x" + address + ");";
		else
			statement->value = "if (" + operand[0] + " != 0 jmp 0x" + address + ");";
		statement->branch_to_offset = addr;
		statement->type = PATTERN_CONTROL_C;
		ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
	}

	// CDP, CDP2 - generic coprocessor instruction
	// CLREX - clears the local monitor of the executing processor, used in multitasking
	// CLZ - count the number of zero bits before the first binary one
	// We ignore these instructions
	else if (opcode[1] == 'd' || opcode[1] == 'l')
	{
		delete (statement);
		statement = NULL;
	}
	else if (opcode[1] == 'm')
	{
		// CMN
		// adds a register value and an immediate/register value.
		// It updates the condition flags based on the result, and discards the result.
		if (opcode[2] == 'n')
		{
			statement->value = operand[0] + " + " + operand[1] + ";";
			// Immediate value
			if (operand[1][0] == '#')
				statement->type = PATTERN_TEST_C;
			// Register
			else
				statement->type = PATTERN_TEST;
		}
		// CMP
		// subtracts a register value and an immediate/register value.
		// It updates the condition flags based on the result, and discards the result.
		else if (opcode[2] == 'p')
		{
			statement->value = operand[0] + " - " + operand[1] + ";";
			// Immediate value
			if (operand[1][0] == '#')
				statement->type = PATTERN_TEST_C;
			// Register
			else
				statement->type = PATTERN_TEST;
		}
	}
	// CPS, CPSID, CPSIE
	// Changes one or more of the PSTATE.{A, I, F} interrupt mask bits and,
	// optionally, the PSTATE.M mode field, without changing any other PSTATE bits.
	// CPS is treated as NOP if executed in User mode
	//
	// CRC32, CRC32C
	// Performs a cyclic redundancy check (CRC) calculation on a value held in a
	// general-purpose register. It is an OPTIONAL instruction.
	//
	// We ignore these instructions
	else if (opcode[1] == 'p' || opcode[1] == 'r')
	{
		delete (statement);
		statement = NULL;
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
Statement *ArmAsmToMAIL::Process_E_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	// EOR, EORS
	// Performs a bitwise Exclusive OR of a register value and an immediate value,
	// and writes the result to the destination register. It can optionally update
	// the condition flags based on the result.
	if (opcode[1] == 'o')
	{
		// Ignore shift register instructions because they will not effect our malware analysis
		//
	    // eor   r3, r2, #1
	    // eor   r3, r2, r4
		if (operand[2] != "")
		{
			statement->value = operand[0] + " = " + operand[1] + " xor " + operand[2] + ";";
			// Immediate value
			if (operand[1][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			// Register
			else
				statement->type = PATTERN_ASSIGN;
		}
	    // eor   r3, #1
	    // eor   r3, r4
		else
		{
			statement->value = operand[0] + " = " + operand[0] + " xor " + operand[1] + ";";
			// Immediate value
			if (operand[2][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			// Register
			else
				statement->type = PATTERN_ASSIGN;
		}

		/*
		 *
		 * If the destination register is a PC then the instruction is a branch to the
		 * address calculated by the operation. This address can only be known at runtime
		 * (an immediate value or a register value added to the PC) and hence PATTERN_JUMP
		 * is assigned as the MAIL Pattern.
		 *
		 */
		if (operand[0] == "pc")
		{
			int value = getHexValue(operand[1]);
			if (value != VALUE_UNKNOWN)
			{
				int pc = it_n_code->instructions[i].address + it_n_code->instructions[i].size;
				value ^= pc;
				char statementStr[24];
				sprintf(statementStr, "jmp 0x%x", value);
				statement->value.assign(statementStr);
				statement->type = PATTERN_JUMP_C;
				statement->branch_to_offset = value;
			}
			else
			{
				statement->value = "jmp UNKNOWN;";
				statement->type = PATTERN_JUMP;
			}
			statement = ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		}
	}
	// ERET
	// Exception Return. When executed in:
	// Hyp mode, ERET loads the PC from ELR_hyp and restores PSTATE from SPSR_hyp.
	// A PL1 mode other than System mode, ERET behaves as:
	//    — MOVS PC, LR in the A32 instruction set.
	//    — SUBS PC, LR, #0 in the T32 instruction set.
	// statement->value = "PC = LR;";
	// statement->value += "jmp UNKNOWN;";
	else if (opcode[1] == 'r')
	{
		statement->end = true;
		statement->branch_to_offset = END_OF_FUNCTION;
		statement->value = "jmp LR;";
		statement->type = PATTERN_JUMP;
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
Statement *ArmAsmToMAIL::Process_F_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	// ----------------------------------------------------------
	//
	// Advance SIMD instructions processing on 128 bit registers
	//
	// ----------------------------------------------------------
	// FLDMDBX, FLDMIAX
	// Loads multiple registers from consecutive locations in the Advanced SIMD and
	// floating-point register file using an address from a general-purpose register.
	if (opcode[1] == 'l')
	{
		if (opcode[2] == 'd')
		{
			if (opcode[3] == 'm')
			{
				string reg = Util::removeWhiteSpaces(operand[0]);
				int len = reg.length();
				bool REG_UPDATE = false;
				if (reg[len-1] == '!')
				{
					reg = reg.substr(0, len-2);
					REG_UPDATE = true;
				}

				string reg_list = operand[1];
				int pos_1 = reg_list.find('{');
				int pos_2 = reg_list.find('}');
				if (pos_2 > pos_1+2)
					reg_list = reg_list.substr(pos_1+1, pos_2-1);
				char *tokens = strtok((char *)reg_list.c_str(), ",");
				int num_tokens = 0;
				char nt[4];
				while (tokens != NULL)
				{
					num_tokens++;
					sprintf(nt, "%d", num_tokens);
					string temp_token = Util::removeWhiteSpaces(tokens);
					statement->value += temp_token + " = [" + reg + " - " + nt + "];";
					tokens = strtok(NULL, ",");
					if (tokens != NULL)
						statement->value += " ";
				}

				if (REG_UPDATE)
				{
					sprintf(nt, "%d", num_tokens);
					statement->value += reg + " = " + reg + " - " + nt + ";";
				}
				statement->type = PATTERN_ASSIGN;
			}
		}
	}
	// ----------------------------------------------------------
	//
	// Advance SIMD instructions processing on 128 bit registers
	//
	// ----------------------------------------------------------
	// FSTMDBX, FSTMIAX
	// Stores multiple registers from the Advanced SIMD and floating-point register file
	// to consecutive memory locations using an address from a general-purpose register.
	else if (opcode[1] == 's')
	{
		if (opcode[2] == 't')
		{
			if (opcode[3] == 'm')
			{
				string reg = Util::removeWhiteSpaces(operand[0]);
				int len = reg.length();
				bool REG_UPDATE = false;
				if (reg[len-1] == '!')
				{
					reg = reg.substr(0, len-2);
					REG_UPDATE = true;
				}

				string reg_list = operand[1];
				int pos_1 = reg_list.find('{');
				int pos_2 = reg_list.find('}');
				if (pos_2 > pos_1+2)
					reg_list = reg_list.substr(pos_1+1, pos_2-1);
				char *tokens = strtok((char *)reg_list.c_str(), ",");
				int num_tokens = 0;
				char nt[4];
				while (tokens != NULL)
				{
					num_tokens++;
					sprintf(nt, "%d", num_tokens);
					string temp_token = Util::removeWhiteSpaces(tokens);
					statement->value += "[" + reg + " + " + nt + "] = " + temp_token + ";";
					tokens = strtok(NULL, ",");
					if (tokens != NULL)
						statement->value += " ";
				}

				if (REG_UPDATE)
				{
					sprintf(nt, "%d", num_tokens);
					statement->value += reg + " = " + reg + " + " + nt + ";";
				}
				statement->type = PATTERN_ASSIGN;
			}
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
Statement *ArmAsmToMAIL::Process_I_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	// ISB
	// Instruction Synchronization Barrier
	// flushes the pipeline in the PE, so that all instructions following the ISB are
	// fetched from cache or memory, after the instruction has been completed.
	// It ensures that the effects of context changing operations executed before the
	// ISB instruction are visible to the instructions fetched after the ISB.
	// This instruction is ignored
	if (opcode[1] == 's')
	{
		delete (statement);
		statement = NULL;
	}
	// IT{<x>{<y>{<z>}}} <cond>
	//
	// where x, y, and z are optional, and must be either T (for "then") or E (for "else").
	// <cond> is any of the conditions such as NE or EQ or GT, etc. that are reflected in the APSR flags.
	// You always have one T following the I (the instruction is IT after all!), and then 0-3 E's or T's.
	// For each T and each E, you must have a subsequent instruction in the same order that matches up.
	// Each matching subsequent instruction must have conditions that match up with the IT instruction.
	//
	// An example:
	// ITETT NE
	// ADDNE R0, R0, R1
	// ADDEQ R0, R0, R3
	// ADDNE R2, R4, #1
	// MOVNE R5, R3
	//
	// We have THEN ELSE THEN THEN (TETT), with NE condition.
	// Notice in the 4 conditional instructions that follow
	// (4 instructions, 1 each for TETT), the "THEN" instructions
	// have the NE condition, and the "ELSE" instruction (the 2nd
	// instruction after the IT instruction - remember the E was
	// the 2nd of 4 E's and T's) has the opposite condition. It
	// cannot be anything else, i.e. it would be an error if it
	// was something like LT instead of EQ. EQ is the opposite of NE.
	// So if NE is true, then instructions 1, 3 and 4 would be executed.
	// Otherwise (EQ), only instruction 2 (ADDEQ) would be executed.
	else if (opcode[1] == 't')
	{
//-------------------------- TO DO -------------------------
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
Statement *ArmAsmToMAIL::Process_L_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	if (opcode[1] == 'd')
	{
		// LDA, LDAB, LDAH, LDAEX, LDAEX, LDAEXH, LDAEXD
		// Loads a word/byte/halfword from memory and writes it to a register.
		if (opcode[2] == 'a')
		{
			// LDAEXD
			// Loads a exlusive double word from memory and writes it to a register.
			if (opcode[5] == 'd')
				statement->value = operand[0] + ":" + operand[1] + " = " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[1] + ";";
			if (operand[1][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		// LDC, LDC2
		// Loads data from consecutive memory addresses to a conceptual coprocessor.
		// These instructions are ignored
		else if (opcode[2] == 'c')
		{
			delete (statement);
			statement = NULL;
		}
		// LDM, LBMIA, LDMFD, LDMDA, LDMFA, LDMDB, LDMEA. LDMIB, LDMED
		// Loads multiple registers from consecutive memory locations
		// using an address from a base register. The consecutive memory
		// locations start at this address. The loaded registers can include
		// PC, i.e, a jump can occur.
		else if (opcode[2] == 'm')
		{
			string reg = Util::removeWhiteSpaces(operand[0]);
			int len = reg.length();
			bool REG_UPDATE = false;
			if (reg[len-1] == '!')
			{
				reg = reg.substr(0, len-2);
				REG_UPDATE = true;
			}

			string reg_list = operand[1];
			int pos_1 = reg_list.find('{');
			int pos_2 = reg_list.find('}');
			if (pos_2 > pos_1+2)
				reg_list = reg_list.substr(pos_1+1, pos_2-1);
			char *tokens = strtok((char *)reg_list.c_str(), ",");
			bool PC = false;
			int num_tokens = 0;
			char nt[4];
			while (tokens != NULL)
			{
				num_tokens++;
				sprintf(nt, "%d", num_tokens);
				string temp_token = Util::removeWhiteSpaces(tokens);
				if (temp_token[0] == 'p' && temp_token[1] == 'c')
					PC = true;
				statement->value += temp_token + " = [" + reg + " - " + nt + "];";
				tokens = strtok(NULL, ",");
				if (tokens != NULL)
					statement->value += " ";
			}

			if (REG_UPDATE)
			{
				sprintf(nt, "%d", num_tokens);
				statement->value += reg + " = " + reg + " - " + nt + ";";
			}
			if (reg == "sp")
			{
				statement->type = PATTERN_STACK;
			}
			else if (PC)
			{
				int value = getHexValue(operand[1]);
				if (value != VALUE_UNKNOWN)
				{
					char statementStr[24];
					sprintf(statementStr, "jmp 0x%x", value);
					statement->value.assign(statementStr);
					statement->type = PATTERN_JUMP_C;
					statement->branch_to_offset = value;
				}
				else
				{
					statement->value = "jmp UNKNOWN;";
					statement->type = PATTERN_JUMP;
				}
				statement = ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
			}
			else
			{
				statement->type = PATTERN_ASSIGN;
			}
		}
		// LDR, LDRB, LDRBT, LDRD, LDREX, LDREXB, LDREXD, LDREXH, LDRH, LDRHT, LDRSB, LDRSBT, LDRSH, LDRSHT, LDRT
		// Loads a word from memory, and writes it to a register
		// ldr r3, [r1]
		// ldr r3, [r1, #123] - pre-indexed
		// ldr r3, [r1], #123 - post-indexed
		// ldr r3, <label>
		else if (opcode[2] == 'r')
		{
			// LDREX . . .
			if (opcode.length() > 2 && opcode[3] == 'e')
			{
				// LDREXD
				if (opcode.length() > 4 && opcode[5] == 'd')
				{
					statement->value = operand[1] + ":" + operand[2] + " = " + operand[3] + ";";
				}
				else
				{
					if (operand[3] != "")
						statement->value = operand[1] + " = " + operand[2] + "," + operand[3] + ";";
					else
						statement->value = operand[1] + " = " + operand[2] + ";";
				}
			}
			// LDRD
			// Loads two words from memory, and writes it to two registers
			else if (opcode.length() > 2 && opcode[3] == 'd')
			{
				if (operand[3] != "")
					statement->value = operand[0] + ":" + operand[1] + " = " + operand[2] + "," + operand[3] + ";";
				else
					statement->value = operand[0] + ":" + operand[1] + " = " + operand[2] + ";";
			}
			else
			{
				if (operand[2] != "")
					statement->value = operand[0] + " = " + operand[1] + "," + operand[2] + ";";
				else
					statement->value = operand[0] + " = " + operand[1] + ";";
			}

			if (operand[1].find("sp") != string::npos)
			{
				statement->value += "sp = sp - 0x1;";
				statement->type = PATTERN_STACK;
			}
			/*
			 *
			 * If the destination register is a PC then the instruction is a branch to the
			 * address calculated by the operation. This address can only be known at runtime
			 * (an immediate value or a register value added to the PC) and hence PATTERN_JUMP
			 * is assigned as the MAIL Pattern.
			 *
			 */
			else if (operand[0] == "pc")
			{
				int value = getHexValue(operand[1]);
				if (value != VALUE_UNKNOWN)
				{
					char statementStr[24];
					sprintf(statementStr, "jmp 0x%x", value);
					statement->value.assign(statementStr);
					statement->type = PATTERN_JUMP_C;
					statement->branch_to_offset = value;
				}
				else
				{
					statement->value = "jmp UNKNOWN;";
					statement->type = PATTERN_JUMP;
				}
				statement = ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
			}
			// pre-indexed and post-indexed immediate offset
			else if (operand[1][0] != '['
					|| operand[1].find('#') != string::npos
					|| operand[2].find('#') != string::npos
					|| operand[3].find('#') != string::npos
					)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	// LSL, LSLS, LSR, LSRS
	// Shifts a register value left by a number (immediate or in register) of bits,
	// and writes the result to the destination register.
	// lsl
	else if (opcode[1] == 's')
	{
		string shift = " << ";
		if (opcode[2] == 'r')
			shift = " >> ";

		// lsl/lsr   r3, r3, #1
		// lsl/lsr   r3, r3, r4
		if (operand[2] == "")
		{
			statement->value = operand[0] + " = " + operand[0] + " " + shift + " " + operand[1] + ";";
			// Immediate value
			if (operand[1][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			// Register
			else
				statement->type = PATTERN_ASSIGN;
		}
		// lsl/lsr   r3, r2, #1
		// lsl/lsr   r3, r2, r4
		else
		{
			statement->value = operand[0] + " = " + operand[1] + " " + shift + " " + operand[2] + ";";
			// Immediate value
			if (operand[2][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			// Register
			else
				statement->type = PATTERN_ASSIGN;
		}

		/*
		 *
		 * If the destination register is a PC then the instruction is a branch to the
		 * address calculated by the operation. This address can only be known at runtime
		 * (an immediate value or a register value added to the PC) and hence PATTERN_JUMP
		 * is assigned as the MAIL Pattern.
		 *
		 */
		if (operand[0] == "pc")
		{
			int value = getHexValue(operand[1]);
			if (value != VALUE_UNKNOWN)
			{
				char statementStr[24];
				sprintf(statementStr, "jmp 0x%x", value);
				statement->value.assign(statementStr);
				statement->type = PATTERN_JUMP_C;
				statement->branch_to_offset = value;
			}
			else
			{
				statement->value = "jmp UNKNOWN;";
				statement->type = PATTERN_JUMP;
			}
			statement = ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
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
Statement *ArmAsmToMAIL::Process_M_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	// MCR, MCR2, MCRR, MCRR2
	// generic coprocessor instruction
	// Passes the values of one/two general-purpose register(s) to a conceptual coprocessor.
	// These instructions are ignored
	if (opcode[1] == 'c')
	{
			delete (statement);
			statement = NULL;
	}
	// MLA, MLAS, MLS
	// Multiplies two register values, and adds a third register value.
	else if (opcode[1] == 'l')
	{
		if (opcode[2] == 's')
			statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + " - " + operand[3] + ";";
		else
			statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + " + " + operand[3] + ";";
		statement->type = PATTERN_ASSIGN;
	}
	// MOV, MOVS, MOVT
	// Writes an immediate/register value to the destination register.
	// mov   r3, r1
	// mov   r3, #0x123
	else if (opcode[1] == 'o')
	{
		statement->value = operand[0] + " = " + operand[1] + ";";

		/*
		 *
		 * If the destination register is a PC then the instruction is a branch to the
		 * address calculated by the operation. This address can only be known at runtime
		 * (an immediate value or a register value added to the PC) and hence PATTERN_JUMP
		 * is assigned as the MAIL Pattern.
		 *
		 */
		if (operand[0] == "pc")
		{
			int value = getHexValue(operand[1]);
			if (value != VALUE_UNKNOWN)
			{
				char statementStr[24];
				sprintf(statementStr, "jmp 0x%x", value);
				statement->value.assign(statementStr);
				statement->type = PATTERN_JUMP_C;
				statement->branch_to_offset = value;
			}
			else
			{
				statement->value = "jmp UNKNOWN;";
				statement->type = PATTERN_JUMP;
			}
			statement = ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		}
		else if (operand[1][0] == '#')
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'r')
	{
		// MRS
		// Move Special/Banked register to general-purpose register. Moves the value of
		// the APSR, CPSR, or SPSR_<current_mode> into a general-purpose register.
		// List of possible Banked registers are given in the manual.
		// mrs r0, spsr
		if (opcode[2] == 's')
		{
			statement->value = operand[0] + " = " + operand[1] + ";";
			statement->type = PATTERN_ASSIGN;
		}
		// MRC, MRC2, MRRC, MRRC2
		// Causes a conceptual coprocessor to transfer a value to one/two general-purpose register(s).
		// These instructions are ignored
		else
		{
			delete (statement);
			statement = NULL;
		}
	}
	// MSR
	// Move immediate/register value to a Special/Banked register
	// mrs spsr, r0
	// mrs spsr, #123
	else if (opcode[1] == 's')
	{
		statement->value = operand[0] + " = " + operand[1] + ";";
		if (operand[1][0] == '#')
			statement->type = PATTERN_ASSIGN_C;
		else
			statement->type = PATTERN_ASSIGN;
	}
	// MUL, MULS
	// Multiplies two register values.
	// mul   r1, r2, r3  -- r1 = r2 * r3
	// mul   r1, r2      -- r1 = r2 * r1
	else if (opcode[1] == 'u')
	{
		if (operand[2] == "")
			statement->value = operand[0] + " = " + operand[1] + " * " + operand[0] + ";";
		else
			statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + ";";
		statement->type = PATTERN_ASSIGN;
	}
	// MVN, MVNS
	// Writes the bitwise inverse of an immediate/register value to the destination register.
	// mvn r3, r0
	// mvn r3, #123
	else if (opcode[1] == 'v')
	{
		statement->value = operand[0] + " = !" + operand[1] + ";";
		if (operand[1][0] == '#')
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
Statement *ArmAsmToMAIL::Process_O_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	// ORN, ORNS
	// Performs a bitwise (inclusive) OR of an immediate/register value and the complement of an
	// immediate value, and writes the result to the destination register.
	// orn   r2, r3, #123  -- gr_1 = !#123; r2 = r3 OR gr_1
	// orn   r3, #123      -- gr_1 = !#123; r3 = r3 OR gr_1
	// orn   r2, r3, r4    -- gr_1 = !r4; r2 = r3 OR gr_1
	// orn   r3, r4        -- gr_1 = !r4; r3 = r3 OR gr_1
	//
	// ORR, ORRS
	// Performs a bitwise (inclusive) OR of an immediate/register value,
	// and writes the result to the destination register.
	// orr   r2, r3, #123  -- r2 = r3 OR #123
	// orr   r3, #123      -- r3 = r3 OR #123
	// orr   r2, r3, r4    -- r2 = r3 OR r4
	// orr   r3, r4        -- r3 = r3 OR r4
	if (opcode[1] == 'r')
	{
		if (operand[2] == "")
		{
			if (opcode[2] == 'r')
			{
				statement->value = operand[0] + " = " + operand[0] + " or " + operand[1] + ";";
			}
			else
			{
				stringstream ss;
				ss << dec << register_number++;
				string gr = "gr_" + ss.str();
				statement->value = gr + " = !" + operand[1] + ";";
				statement->value = operand[0] + " = " + operand[0] + " or " + gr + ";";
			}
			if (operand[1][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		else
		{
			if (opcode[2] == 'r')
			{
				statement->value = operand[0] + " = " + operand[1] + " or " + operand[2] + ";";
			}
			else
			{
				stringstream ss;
				ss << dec << register_number++;
				string gr = "gr_" + ss.str();
				statement->value = gr + " = !" + operand[2] + ";";
				statement->value = operand[0] + " = " + operand[1] + " or " + gr + ";";
			}
			if (operand[2][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			else
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
 */
Statement *ArmAsmToMAIL::Process_P_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	// PKHBT, PKHTB
	// Combines one halfword of its first operand with the other halfword of its shifted second operand.
	if (opcode[1] == 'k')
	{
		if (operand[2] != "")
			statement->value = operand[0] + " = " + operand[1] + ":" + operand[2] + ";";
		else
				statement->value = operand[0] + " = " + operand[0] + ":" + operand[1] + ";";
		statement->type = PATTERN_ASSIGN;
	}
	// PLD, PLDW, PLI
	// Signals the memory system that data memory accesses from a specified address are likely
	// in the near future. The memory system can respond by taking actions that are expected
	// to speed up the memory accesses when they do occur, such as preloading the cache line
	// containing the specified address into the data cache.
	// These instructions are ignored
	else if (opcode[1] == 'l')
	{
		delete (statement);
		statement = NULL;
	}
	// POP
	// Pop Multiple Registers from Stack.
	// Loads multiple general-purpose registers from the stack, loading from consecutive memory
	// locations starting at the address in SP, and updates SP to point just above the loaded data.
	else if (opcode[1] == 'o')
	{
		string reg_list = operand[0];
		int pos_1 = reg_list.find('{');
		int pos_2 = reg_list.find('}');
		if (pos_2 > pos_1+2)
			reg_list = reg_list.substr(pos_1+1, pos_2-1);
		char *tokens = strtok((char *)reg_list.c_str(), ",");
		bool PC = false;
		int num_tokens = 0;
		while (tokens != NULL)
		{
			num_tokens++;
			string temp_token = Util::removeWhiteSpaces(tokens);
			if (temp_token[0] == 'p' && temp_token[1] == 'c')
				PC = true;
			statement->value += temp_token + " = [sp=sp-0x1];";
			tokens = strtok(NULL, ",");
		}
		if (PC)
		{
			statement->value += "jmp UNKNOWN;";
			statement->type = PATTERN_JUMP_S;
			statement->end = true;
			statement->branch_to_offset = END_OF_FUNCTION;
		}
		else
			statement->type = PATTERN_STACK;
	}
	// PUSH
	// Push Multiple Registers to Stack.
	// Store multiple general-purpose registers to the stack, storing at consecutive memory
	// locations starting at the address in SP, and updates SP to point just below the loaded data.
	else if (opcode[1] == 'u')
	{
		string reg_list = operand[0];
		int pos_1 = reg_list.find('{');
		int pos_2 = reg_list.find('}');
		if (pos_2 > pos_1+2)
			reg_list = reg_list.substr(pos_1+1, pos_2-1);
		char *tokens = strtok((char *)reg_list.c_str(), ",");
		int num_tokens = 0;
		while (tokens != NULL)
		{
			num_tokens++;
			string temp_token = Util::removeWhiteSpaces(tokens);
			statement->value += "[sp=sp+0x1] = " + temp_token + ";";
			tokens = strtok(NULL, ",");
		}
		statement->type = PATTERN_STACK;
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
Statement *ArmAsmToMAIL::Process_Q_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	if (opcode[1] == 'a')
	{
		// QADD, QADD16, QADD8
	    // qadd   r2, r3, r4 -- r2 = r3 + r4
	    // qadd   r2, r4     -- r2 = r2 + r4
		if (opcode[2] == 'd')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
		}
		// QASX
		// add and subtract two registers and store the value into the destination register
		else if (opcode[2] == 's')
		{
			if (operand[2] != "")
			{
				statement->value = "H" + operand[0] + " = H" + operand[1] + " + L" + operand[2] + ";";
				statement->value = "L" + operand[0] + " = L" + operand[1] + " - H" + operand[2] + ";";
			}
			else
			{
				statement->value = "H" + operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
				statement->value = "L" + operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
			}
		}
		statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'd')
	{
		// QDADD
		// add two registers and store the value into the destination register
		if (opcode[2] == 'a')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
		}
		// QDSUB
		// subtracts two registers and store the value into the destination register
		else if (opcode[2] == 's')
		{
			if (operand[1] != "")
				statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
		}
		statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 's')
	{
		// QSAX
		// subtract and add two registers and store the value into the destination register
		if (opcode[2] == 'a')
		{
			if (operand[2] != "")
			{
				statement->value = "L" + operand[0] + " = L" + operand[1] + " + H" + operand[2] + ";";
				statement->value = "H" + operand[0] + " = H" + operand[1] + " - L" + operand[2] + ";";
			}
			else
			{
				statement->value = "L" + operand[0] + " = L" + operand[0] + " + H" + operand[1] + ";";
				statement->value = "H" + operand[0] + " = H" + operand[0] + " - L" + operand[1] + ";";
			}
		}
		// QSUB, QSUB16
		// subtract two registers and store the value into the destination register
		else if (opcode[2] == 'u')
		{
			if (operand[1] != "")
				statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
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
Statement *ArmAsmToMAIL::Process_R_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	// RBIT, REV, REV16, REVSH
	// Reverse the bit order
	if (opcode[1] == 'b' || opcode[1] == 'e')
	{
		statement->value = operand[0] + " = rev(" + operand[1] + ");";
		statement->type = PATTERN_LIBCALL;
	}
	// RFE, RFEDA, RFEDB, RFEIA, RFEIB
	// Return From Exception.
	// Loads two consecutive memory locations using an address in a base register:
	//    - The word loaded from the lower address is treated as an instruction address.
	//      The PE branches to it.
	//    - The word loaded from the higher address is used to restore PSTATE. This word
	//      must be in the format of an SPSR.
	else if (opcode[1] == 'f')
	{
		string reg = Util::removeWhiteSpaces(operand[0]);
		int len = reg.length();
		if (reg[len-1] == '!')
		{
			reg = reg.substr(0, len-2);
			statement->value = reg + " = " + reg + " + 1;";
		}

		statement->value += "PC = bit(" + reg + ", 0, 15);";
		statement->value += "eflags = bit(" + reg + ", 16, 31);";
		statement->value += "jmp UNKNOWN;";
		statement->end = true;
		statement->branch_to_offset = END_OF_FUNCTION;
		statement->type = PATTERN_JUMP;
	}
	// ROR, RORS
	// Rotate right by a value
	else if (opcode[1] == 'o')
	{
		if (operand[2] != "")
		{
			statement->value = operand[0] + " = " + operand[1] + " >> " + operand[2] + ";";
			if (operand[2][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		else
		{
			statement->value = operand[0] + " = " + operand[0] + " >> " + operand[1] + ";";
			if (operand[1][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	// RRX, RRXS
	// Rotate right one place
	else if (opcode[1] == 'r')
	{
		if (operand[1] != "")
			statement->value = operand[0] + " = " + operand[1] + " >> 1";
		else
			statement->value = operand[0] + " = " + operand[0] + " >> 1";
		statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 's')
	{
		// RSB, RSBS
		// Subtracts a register value from a value,
		// and writes the result to the destination register.
		if (opcode[2] == 'b')
		{
			if (operand[2] != "")
			{
				statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + ";";
				if (operand[2][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			else
			{
				statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
				if (operand[1][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}

			/*
			 *
			 * If the destination register is a PC then the instruction is a branch to the
			 * address calculated by the operation. This address can only be known at runtime
			 * (an immediate value or a register value added to the PC) and hence PATTERN_JUMP
			 * is assigned as the MAIL Pattern.
			 *
			 */
			if (operand[0] == "pc")
			{
				int value = getHexValue(operand[1]);
				if (value != VALUE_UNKNOWN)
				{
					int pc = it_n_code->instructions[i].address + it_n_code->instructions[i].size;
					value -= pc;
					char statementStr[24];
					sprintf(statementStr, "jmp 0x%x", value);
					statement->value.assign(statementStr);
					statement->type = PATTERN_JUMP_C;
					statement->branch_to_offset = value;
				}
				else
				{
					statement->value = "jmp UNKNOWN;";
					statement->type = PATTERN_JUMP;
				}
				statement = ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
			}
		}
		// RSC, RSCS
		// Subtracts a register value from a value and the value of carry falg,
		// and writes the result to the destination register.
		else if (opcode[2] == 'c')
		{
			if (operand[2] != "")
			{
				statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + " + CF;";
				if (operand[2][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			else
			{
				statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + " + CF;";
				if (operand[1][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}

			/*
			 *
			 * If the destination register is a PC then the instruction is a branch to the
			 * address calculated by the operation. This address can only be known at runtime
			 * (an immediate value or a register value added to the PC) and hence PATTERN_JUMP
			 * is assigned as the MAIL Pattern.
			 *
			 */
			if (operand[0] == "pc")
			{
				int value = getHexValue(operand[1]);
				if (value != VALUE_UNKNOWN)
				{
					int pc = it_n_code->instructions[i].address + it_n_code->instructions[i].size;
					value -= pc;
					char statementStr[24];
					sprintf(statementStr, "jmp 0x%x", value);
					statement->value.assign(statementStr);
					statement->type = PATTERN_JUMP_C;
					statement->branch_to_offset = value;
				}
				else
				{
					statement->value = "jmp UNKNOWN;";
					statement->type = PATTERN_JUMP;
				}
				statement = ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
			}
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
Statement *ArmAsmToMAIL::Process_S_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	if (opcode[1] == 'a')
	{
		// SADD16, SADD8
		// Performs signed integer additions, and writes the results to the destination register.
		if (opcode[2] == 'd')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
		}
		// SASX
		// Performs add and subtract, and writes the results to the destination register.
		if (opcode[2] == 's')
		{
			if (operand[2] != "")
			{
				statement->value = "L" + operand[0] + " = L" + operand[1] + " - H" + operand[2] + ";";
				statement->value = "H" + operand[0] + " = H" + operand[1] + " + L" + operand[2] + ";";
			}
			else
			{
				statement->value = "L" + operand[0] + " = L" + operand[0] + " - H" + operand[1] + ";";
				statement->value = "H" + operand[0] + " = H" + operand[0] + " + L" + operand[1] + ";";
			}
		}
		statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'b')
	{
		// SBC, SBCS
		// Subtracts a register value from a value and the value of carry falg,
		// and writes the result to the destination register.
		if (opcode[2] == 'C')
		{
			if (operand[2] != "")
			{
				statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + " + CF;";
				if (operand[2][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			else
			{
				statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + " + CF;";
				if (operand[1][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}

			/*
			 *
			 * If the destination register is a PC then the instruction is a branch to the
			 * address calculated by the operation. This address can only be known at runtime
			 * (an immediate value or a register value added to the PC) and hence PATTERN_JUMP
			 * is assigned as the MAIL Pattern.
			 *
			 */
			if (operand[0] == "pc")
			{
				int value = getHexValue(operand[1]);
				if (value != VALUE_UNKNOWN)
				{
					int pc = it_n_code->instructions[i].address + it_n_code->instructions[i].size;
					value -= pc;
					char statementStr[24];
					sprintf(statementStr, "jmp 0x%x", value);
					statement->value.assign(statementStr);
					statement->type = PATTERN_JUMP_C;
					statement->branch_to_offset = value;
				}
				else
				{
					statement->value = "jmp UNKNOWN;";
					statement->type = PATTERN_JUMP;
				}
				statement = ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
			}
		}
		// SBFX
		// copies any number of low order bits from a register into the destination register.
		// sbfx   r1, r2, #lsb, #width
		else if (opcode[2] == 'f')
		{
			statement->value = operand[0] = + "bit(" + operand[1] + ", " + operand[2] + ", " + operand[3] + ");";
			statement->type = PATTERN_LIBCALL_C;
		}
	}
	// SDIV
	// Divides a signed integer register value by a signed integer
	// register value, and writes the result to the destination register.
	else if (opcode[2] == 'd')
	{
		if (operand[2] != "")
			statement->value = operand[0] + " = " + operand[1] + " / " + operand[2] + ";";
		else
			statement->value = operand[0] + " = " + operand[0] + " / " + operand[1] + ";";
		statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'e')
	{
		// SEL
		// Selects each byte of its result from either its first operand
		// or its second operand, according to the values of the PSTATE.GE flags.
		// Here we just make it a simple assignment statement ignoring flags.
		if (opcode[2] == 'l')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = " + operand[1] + ";";
			else
				statement->value = operand[0] + " = " + operand[1] + ";";
			statement->type = PATTERN_ASSIGN;
		}
		// SETEND
		// Set Endianness
		//
		// SEV
		// Set Event Local
		//
		// These instructions are ignored
		else if (opcode[2] == 't' || opcode[2] == 'v')
		{
			delete (statement);
			statement = NULL;
		}
	}
	else if (opcode[1] == 'h')
	{
		if (opcode[2] == 'a')
		{
			// SHADD16, SHADD8
			// performs two signed integer additions, halves the results,
			// and writes the results to the destination register.
			// We make it simple add instruction ignoring the halving part.
			if (opcode[3] == 'd')
			{
				if (operand[2] != "")
					statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + ";";
				else
					statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
			}
			// SHASX
			// Performs add and subtract, and writes the results to the destination register.
			else if (opcode[3] == 's')
			{
				if (operand[2] != "")
				{
					statement->value = "L" + operand[0] + " = L" + operand[1] + " - H" + operand[2] + ";";
					statement->value = "H" + operand[0] + " = H" + operand[1] + " + L" + operand[2] + ";";
				}
				else
				{
					statement->value = "L" + operand[0] + " = L" + operand[0] + " - H" + operand[1] + ";";
					statement->value = "H" + operand[0] + " = H" + operand[0] + " + L" + operand[1] + ";";
				}
			}
			// ----------------------------------------------------------
			//
			// Advance SIMD instructions processing on 128 bit registers
			//
			// ----------------------------------------------------------
			// SHA1C, SHA1H, SHA1M, SHA1P, SHA1SU0, SHA1SU1, SHA256H, SHA256H2, SHA256SU0, SHA256SU1
			// Implements Secure Hash Algorithm
			// These instruction are ignored
			else
			{
				delete (statement);
				statement = NULL;
			}
		}
		// SHSAX
		// Performs subtract and add, and writes the results to the destination register.
		else if (opcode[2] == 's')
		{
			if (opcode[3] == 'a')
			{
				if (operand[2] != "")
				{
					statement->value = "L" + operand[0] + " = L" + operand[1] + " + H" + operand[2] + ";";
					statement->value = "H" + operand[0] + " = H" + operand[1] + " - L" + operand[2] + ";";
				}
				else
				{
					statement->value = "L" + operand[0] + " = L" + operand[0] + " + H" + operand[1] + ";";
					statement->value = "H" + operand[0] + " = H" + operand[0] + " - L" + operand[1] + ";";
				}
			}
			// SHSUB16, SHSUB8
			// performs two signed integer subtractions, halves the results,
			// and writes the results to the destination register.
			// We make it simple subtraction instruction ignoring the halving part.
			else if (opcode[3] == 'u')
			{
				if (operand[2] != "")
					statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + ";";
				else
					statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
			}
		}
		statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'm')
	{
		// SMC
		// Secure Monitor Call
		// This instruction is ignored
		if (opcode[2] == 'c')
		{
			delete (statement);
			statement = NULL;
		}
		else if (opcode[2] == 'l')
		{
			if (opcode[3] == 'a')
			{
				// SMLABB, SMLABT, SMLATB, SMLATT, SMLAWB, SMLAWT
				// operand0 = operand1 * operand2 + R[a](operand3);
				if (opcode[4] == 'b' || opcode[4] == 't' || opcode[4] == 'w')
					statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + " + " + operand[3] + ";";
				// SMLAD, SMLADX
				// prod1 = Lop1 * Lop2;
				// prod2 = Hop1 * HLop2;
				// operand0 = prod1 + prod2 + R[a](operand3);
				else if (opcode[4] == 'd')
				{
					stringstream ss1, ss2;
					ss1 << dec << register_number++;
					string gr1 = "gr_" + ss1.str();
					ss2 << dec << register_number++;
					string gr2 = "gr_" + ss2.str();
					statement->value = gr1 + " = L" + operand[1] + " * L" + operand[2] + ";";
					statement->value += gr2 + " = H" + operand[1] + " * H" + operand[2] + ";";
					statement->value += operand[0] + " = " + gr1 + " + " + gr2 + " + " + operand[3] + ";";
				}
				// SMLAL, SMLALS, SMLALBB, SMLALBT, SMLALTB, SMLALTT, SMLALD, SMLALDX
				// operand[0]:operand[1] = operand2 * operand3 + operand[0]:operand[1]
				else if (opcode[4] == 'l')
				{
					statement->value = operand[0] + " = " + operand[2] + " * " + operand[3] + " + " + operand[0] + ";";
				}
			}
			else if (opcode[3] == 's')
			{
				// SMLSD, SMLSDX
				// prod1 = Lop1 * Lop2;
				// prod2 = Hop1 * HLop2;
				// operand0 = prod1 - prod2 + R[a](operand3);
				if (opcode[4] == 'd')
				{
					stringstream ss1, ss2;
					ss1 << dec << register_number++;
					string gr1 = "gr_" + ss1.str();
					ss2 << dec << register_number++;
					string gr2 = "gr_" + ss2.str();
					statement->value = gr1 + " = L" + operand[1] + " * L" + operand[2] + ";";
					statement->value += gr2 + " = H" + operand[1] + " * H" + operand[2] + ";";
					statement->value += operand[0] + " = " + gr1 + " - " + gr2 + " + " + operand[3] + ";";
				}
				// SMLSLD, SMLSLDX
				// prod1 = Lop1 * Lop2;
				// prod2 = Hop1 * HLop2;
				// operand0 = prod1 - prod2 + operand0;
				else if (opcode[4] == 'l')
				{
					stringstream ss1, ss2;
					ss1 << dec << register_number++;
					string gr1 = "gr_" + ss1.str();
					ss2 << dec << register_number++;
					string gr2 = "gr_" + ss2.str();
					statement->value = gr1 + " = L" + operand[2] + " * L" + operand[3] + ";";
					statement->value += gr2 + " = H" + operand[2] + " * H" + operand[3] + ";";
					statement->value += operand[0] + " = " + gr1 + " - " + gr2 + " + " + operand[0] + ";";
				}
			}
		}
		else if (opcode[2] == 'm')
		{
			if (opcode[3] == 'l')
			{
				// SMMLA, SMMLAR
				// operand0 = operand3 + operand2 * operand1;
				if (opcode[4] == 'a')
				{
					statement->value = operand[0] + " = " + operand[3] + " + " + operand[2] + " * " + operand[1] + ";";
				}
				// SMMLS, SMMLSR
				// operand0 = operand3 - operand2 * operand1;
				else if (opcode[4] == 's')
				{
					statement->value = operand[0] + " = " + operand[3] + " - " + operand[2] + " * " + operand[1] + ";";
				}
			}
			// SMMUL, SMMULR
			// smmul   r0, r1, r2
			// smmul   r0, r2
			else if (opcode[3] == 'u')
			{
				if (operand[2] != "")
					statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + ";";
				else
					statement->value = operand[0] + " = " + operand[0] + " * " + operand[1] + ";";
			}
		}
		else if (opcode[2] == 'u')
		{
			// SMULBB, SMULBT, SMULTB, SMULTT, SMULL, SMULLS, SMULWB, SMULWT
			// smull   r0, r1, r2
			// smull   r0, r2
			if (opcode[3] == 'l')
			{
				if (operand[2] != "")
					statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + ";";
				else
					statement->value = operand[0] + " = " + operand[0] + " * " + operand[1] + ";";
			}
			else if (opcode[4] == 'd')
			{
				stringstream ss1, ss2;
				ss1 << dec << register_number++;
				string gr1 = "gr_" + ss1.str();
				ss2 << dec << register_number++;
				string gr2 = "gr_" + ss2.str();
				// SMUAD, SMUADX
				// prod1 = operand1<15:0>) * operand2<15:0>;
				// prod2 = operand1<31:16>) * operand2<31:16);
				// operand0 = prod1 + prod2;
				if (opcode[3] == 'a')
				{
					if (operand[2] != "")
					{
						statement->value = gr1 + " = L" + operand[1] + " * L" + operand[2] + ";";
						statement->value += gr2 + " = H" + operand[1] + " * H" + operand[2] + ";";
						statement->value += operand[0] + " = " + gr1 + " + " + gr2 + ";";
					}
					else
					{
						statement->value = gr1 + " = L" + operand[0] + " * L" + operand[1] + ";";
						statement->value += gr2 + " = H" + operand[0] + " * H" + operand[1] + ";";
						statement->value += operand[0] + " = " + gr1 + " + " + gr2 + ";";
					}
				}
				// SMUSD, SMUSDX
				// prod1 = operand1<15:0>) * operand2<15:0>;
				// prod2 = operand1<31:16>) * operand2<31:16);
				// operand0 = prod1 - prod2;
				else if (opcode[3] == 's')
				{
					if (operand[2] != "")
					{
						statement->value = gr1 + " = L" + operand[1] + " * L" + operand[2] + ";";
						statement->value += gr2 + " = H" + operand[1] + " * H" + operand[2] + ";";
						statement->value += operand[0] + " = " + gr1 + " - " + gr2 + ";";
					}
					else
					{
						statement->value = gr1 + " = L" + operand[0] + " * L" + operand[1] + ";";
						statement->value += gr2 + " = H" + operand[0] + " * H" + operand[1] + ";";
						statement->value += operand[0] + " = " + gr1 + " - " + gr2 + ";";
					}
				}
			}
		}
		if (statement != NULL)
			statement->type = PATTERN_ASSIGN;
	}
	// SRS, SRSDA, SRSDB, SRSIA, SRSIB
	// Store Return State
	// SRS   SP!, #<mode>
	// SRS   SP, #<mode>
	else if (opcode[1] == 'r')
	{
		statement->value = "[sp] = lr;";
		statement->value = "[sp+1] = eflags;";

		string sp = Util::removeWhiteSpaces(operand[0]);
		int len = sp.length();
		if (sp[len-1] == '!')
		{
			sp = sp.substr(0, len-2);
			statement->value += sp + " = " + sp + " + 1;";
		}
		statement->type = PATTERN_STACK;
	}
	else if (opcode[1] == 's')
	{
		if (opcode[2] == 'a')
		{
			// SSAT, SSAT16
			// Some instructions perform saturating arithmetic, that is, if the result of
			// the arithmetic overflows the destination signed or unsigned N-bit integer range,
			// the result produced is the largest or smallest value in that range.
			// These instructions are ignored
			if (opcode[3] == 't')
			{
				delete (statement);
				statement = NULL;
			}
			// SSAX
			// add and subtract two registers and store the value into the destination register
			else if (opcode[3] == 'x')
			{
				if (operand[2] != "")
				{
					statement->value = "H" + operand[0] + " = L" + operand[1] + " + H" + operand[2] + ";";
					statement->value = "L" + operand[0] + " = H" + operand[1] + " - L" + operand[2] + ";";
				}
				else
				{
					statement->value = "H" + operand[0] + " = L" + operand[0] + " + H" + operand[1] + ";";
					statement->value = "L" + operand[0] + " = H" + operand[0] + " - L" + operand[1] + ";";
				}
			}
		}
		// SSUB16, SSUB8
		// Performs subtraction and writes the results to the destination register.
		else if (opcode[2] == 'u')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
		}
		if (statement != NULL)
			statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 't')
	{
		// STC, STC2
		// Store Coprocessor
		// These instructions are ignored
		if (opcode[2] == 'c')
		{
			delete (statement);
			statement = NULL;
		}
		else if (opcode[2] == 'l')
		{
			// STLEX, STLEXB, STLEXH
			// Store register to memory and returns the status in destination register
			// stlex   r1, r2, [r3] -- [r3] = r2 and r1 = either 0 (if succesfull) or 1 (if not succesfull)
			// We do not update the destination register while translating
			if (opcode[3] == 'e')
			{
				if (operand[3] != "")
					statement->value = operand[3] + " = " + operand[1] + ":" + operand[2] + ";";
				else
					statement->value = operand[2] + " = " + operand[1] + ";";
			}
			// STL, STLB, STLH
			// Store register to memory
			// stl   r1, [r3]
			else
			{
				statement->value = operand[1] + " = " + operand[0] + ";";
			}
			statement->type = PATTERN_ASSIGN;
		}
		// STM, STMIA, STMEA, STMDA, STMED, STMDB, STMFD, STMIB, STMFA
		// Store Multiple. Stores multiple registers to consecutive memory locations using
		// an address from a base register.
		// stm   r1, {r3,r4,r5}
		else if (opcode[2] == 'm')
		{
			string reg = Util::removeWhiteSpaces(operand[0]);
			int len = reg.length();
			bool REG_UPDATE = false;
			if (reg[len-1] == '!')
			{
				reg = reg.substr(0, len-2);
				REG_UPDATE = true;
			}

			string reg_list = operand[1];
			int pos_1 = reg_list.find('{');
			int pos_2 = reg_list.find('}');
			if (pos_2 > pos_1+2)
			{
				reg_list = reg_list.substr(pos_1+1, pos_2-1);
				char *tokens = strtok((char *)reg_list.c_str(), ",");
				int num_tokens = 0;
				char nt[4];
				while (tokens != NULL)
				{
					num_tokens++;
					sprintf(nt, "%d", num_tokens);
					string temp_token = Util::removeWhiteSpaces(tokens);
					statement->value += "[" + reg + " + " + nt + "] = " + temp_token + ";";
					tokens = strtok(NULL, ",");
					if (tokens != NULL)
						statement->value += " ";
				}

				if (REG_UPDATE)
				{
					sprintf(nt, "%d", num_tokens);
					statement->value += reg + " = " + reg + " + " + nt + ";";
				}
				if (reg == "SP")
				{
					statement->type = PATTERN_STACK;
				}
				else
				{
					statement->type = PATTERN_ASSIGN;
				}
			}
			else
			{
				statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
				statement->type = PATTERN_UNKNOWN;
			}
		}
		// STR, STRB, STRBT, STRD, STREX, STREXB, STREXD, STREXH, STRH, STRHT, STRT
		// Stores a word from register to memory
		// str r3, [r1]
		// str r3, [r1, #123] - pre-indexed
		// str r3, [r1], #123 - post-indexed
		// str r3, <label>
		else if (opcode[2] == 'r')
		{
			// STREX . . .
			if (opcode.length() > 2 && opcode[3] == 'e')
			{
				// STREXD
				if (opcode.length() > 4 && opcode[5] == 'd')
				{
						statement->value = operand[3]  + " = " + operand[1] + ":" + operand[2] + ";";
				}
				else
				{
					if (operand[3] != "")
						statement->value = operand[2] + "," + operand[3] + " = " + operand[1] + ";";
					else
						statement->value = operand[2] + " = " + operand[1] + ";";
				}
			}
			// STRD
			// Loads two words from memory, and writes it to two registers
			else if (opcode.length() > 2 && opcode[3] == 'd')
			{
				if (operand[3] != "")
					statement->value = operand[2] + "," + operand[3] + " = " + operand[0] + ":" + operand[1] + ";";
				else
					statement->value = operand[2] + " = " + operand[0] + ":" + operand[1] + ";";
			}
			else
			{
				if (operand[2] != "")
					statement->value = operand[1] + "," + operand[2] + " = " + operand[0] + ";";
				else
					statement->value = operand[1] + " = " + operand[0] + ";";
			}

			if (operand[1].find("sp") != string::npos)
			{
				statement->value += "sp = sp - 0x1;";
				statement->type = PATTERN_STACK;
			}
			// pre-indexed and post-indexed immediate offset
			else if (operand[1][0] != '['
					|| operand[1].find('#') != string::npos
					|| operand[2].find('#') != string::npos
					|| operand[3].find('#') != string::npos
					)
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	// SUB, SUBS
	// Subtracts a value from a register value, and writes the result to the destination register.
	// sub   r1, r2, r3
	// sub   r1, r2, #123
	// sub   r1, #123
	// sub   pc, #123
	else if (opcode[1] == 'u')
	{
		if (operand[2] != "")
		{
			statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + ";";
			if (operand[2][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
		else
		{
			statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
			if (operand[1][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}

		/*
		 *
		 * If the destination register is a PC then the instruction is a branch to the
		 * address calculated by the operation. This address can only be known at runtime
		 * (an immediate value or a register value added to the PC) and hence PATTERN_JUMP
		 * is assigned as the MAIL Pattern.
		 *
		 */
		if (operand[0] == "pc")
		{
			int value = getHexValue(operand[1]);
			if (value != VALUE_UNKNOWN)
			{
				int pc = it_n_code->instructions[i].address + it_n_code->instructions[i].size;
				value -= pc;
				char statementStr[24];
				sprintf(statementStr, "jmp 0x%x", value);
				statement->value.assign(statementStr);
				statement->type = PATTERN_JUMP_C;
				statement->branch_to_offset = value;
			}
			else
			{
				statement->value = "jmp UNKNOWN;";
				statement->type = PATTERN_JUMP;
			}
			statement = ProcessJumpStatement(statement, it_n_code, i, number_of_statements, prev_statement, jump_offsets);
		}
		else if (operand[0] == "sp")
		{
			statement->type = PATTERN_STACK;
		}
	}
	// SVC
	// Supervisor Call
	// This instruction is ignored
	else if (opcode[1] == 'v')
	{
		delete (statement);
		statement = NULL;
	}
	// SXTB, SXTB16, SXTH
	// Add value from a register to the value in another register,
	// and writes the final result to the destination register.
	else if (opcode[1] == 'x')
	{
		// SXTB, SXTB16
		if (opcode[3] == 'b')
		{
			if (opcode.length() > 3 && opcode[4] == '1')
			{
				if (operand[2] != "")
				{
					statement->value = "L" + operand[0] + " = bit(" + operand[1] + ", 0, 7);";
					statement->value = "H" + operand[0] + " = bit(" + operand[1] + ", 16, 23);";
				}
				else
				{
					statement->value = "L" + operand[0] + " = bit(" + operand[0] + ", 0, 7);";
					statement->value = "H" + operand[0] + " = bit(" + operand[0] + ", 16, 23);";
				}
				statement->type = PATTERN_ASSIGN;
			}
			else
			{
				if (operand[2] != "")
					statement->value = operand[0] + " = bit(" + operand[1] + ", 0, 7);";
				else
					statement->value = operand[0] + " = bit(" + operand[0] + ", 0, 7);";
				statement->type = PATTERN_ASSIGN;
			}
		}
		// SXTH
		else if (opcode[3] == 'h')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = bit(" + operand[1] + ", 0, 15);";
			else
				statement->value = operand[0] + " = bit(" + operand[0] + ", 0, 15);";
			statement->type = PATTERN_ASSIGN;
		}
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
Statement *ArmAsmToMAIL::Process_T_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	// TBB, TBH
	// TBB    <Rn> <Rm>
	// These instructions cause a PC-relative forward branch using a table
	// of single byte offsets for TBB, or halfword offsets for TBH. Rn provides
	// a pointer to the table, and Rm supplies an index into the table. For TBB
	// the branch offset is twice the unsigned value of the byte returned from
	// the table, and for TBH the branch offset is twice the unsigned value of
	// the halfword returned from the table. The branch occurs to the address
	// at that offset from the address of the byte immediately after the
	// TBB or TBH instruction.
	// We translate this to a simple jump statement
	if (opcode[1] == 'b')
	{
//		statement->value = "jmp " + operand[0] + ";";
		statement->value = "jmp UNKNOWN;";
		statement->type = PATTERN_JUMP;
		statement->end = true;
	}
	// TEQ
	// Test Equivalence
	// Performs a bitwise exclusive OR operation on a register value
	// and an optionally-shifted register value. It updates the
	// condition flags based on the result, and discards the result.
	else if (opcode[2] == 'e')
	{
		statement->value = operand[0] + " xor " + operand[1] + ";";
		if (operand[1][0] == '#')
			statement->type = PATTERN_TEST_C;
		else
			statement->type = PATTERN_TEST;
	}
	// TST
	// Test
	// Performs a bitwise AND operation on a register value and an
	// optionally-shifted register value. It updates the condition
	// flags based on the result, and discards the result.
	else if (opcode[2] == 's')
	{
		statement->value = operand[0] + " and " + operand[1] + ";";
		if (operand[1][0] == '#')
			statement->type = PATTERN_TEST_C;
		else
			statement->type = PATTERN_TEST;
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
Statement *ArmAsmToMAIL::Process_U_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	if (opcode[1] == 'a')
	{
		// UADD16, UADD8
		// Performs addition and writes the results to the destination register.
		// uadd16   r1, r2, r3
		// uadd16   r2, r3
		if (opcode[2] == 'd')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
		}
		// UASX
		// add and subtract two registers and store the value into the destination register
		else if (opcode[2] == 's')
		{
			if (operand[2] != "")
			{
				statement->value = "H" + operand[0] + " = H" + operand[1] + " + L" + operand[2] + ";";
				statement->value = "L" + operand[0] + " = L" + operand[1] + " - H" + operand[2] + ";";
			}
			else
			{
				statement->value = "H" + operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
				statement->value = "L" + operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
			}
		}
		statement->type = PATTERN_ASSIGN;
	}
	// UBFX
	// Extracts any number of adjacent bits at any position from a register
	// and writes the result to the destination register.
	else if (opcode[1] == 'b')
	{
		statement->value = operand[0] + " = bit(" + operand[1] + ", " + operand[2] + ", " + operand[3] + ");";
		statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'd')
	{
		// UDF
		// Permanently Undefined generates an Undefined Instruction exception.
		if (opcode[2] == 'f')
		{
			statement->value = opcode + " " + operand[0] + " " + operand[1] + " " + operand[2] + " UNKNOWN;";
			statement->type = PATTERN_UNKNOWN;
		}
		// UDIV
		else if (opcode[2] == 'i')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = " + operand[1] + " / " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " / " + operand[1] + ";";
			statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'h')
	{
		if (opcode[2] == 'a')
		{
			// UHADD16, UHADD8
			// Performs addition and writes the results to the destination register.
			// uadd16   r1, r2, r3
			// uadd16   r2, r3
			if (opcode[3] == 'd')
			{
				if (operand[2] != "")
					statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + ";";
				else
					statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
			}
			// UHASX
			// add and subtract two registers and store the value into the destination register
			else if (opcode[3] == 's')
			{
				if (operand[2] != "")
				{
					statement->value = "H" + operand[0] + " = H" + operand[1] + " + L" + operand[2] + ";";
					statement->value = "L" + operand[0] + " = L" + operand[1] + " - H" + operand[2] + ";";
				}
				else
				{
					statement->value = "H" + operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
					statement->value = "L" + operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
				}
			}
			statement->type = PATTERN_ASSIGN;
		}
		else if (opcode[2] == 's')
		{
			// UHSAX
			// add and subtract two registers and store the value into the destination register
			if (opcode[3] == 'a')
			{
				if (operand[2] != "")
				{
					statement->value = "H" + operand[0] + " = H" + operand[1] + " - L" + operand[2] + ";";
					statement->value = "L" + operand[0] + " = L" + operand[1] + " + H" + operand[2] + ";";
				}
				else
				{
					statement->value = "H" + operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
					statement->value = "L" + operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
				}
			}
			// UHSUB16, UHSUB8
			// Performs subtraction and writes the results to the destination register.
			// uadd16   r1, r2, r3
			// uadd16   r2, r3
			else if (opcode[4] == 'u')
			{
				if (operand[2] != "")
					statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + ";";
				else
					statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
			}
			statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'm')
	{
		// UMAAL, UMLAL, UMLALS
		// operand0:operand1 = operand2 * operand3 + operand0:operand1;
		if (opcode[2] == 'a' || opcode[2] == 'l')
		{
			statement->value = operand[0] + ":" + operand[1] + " = " + operand[2] + " * " + operand[3] + operand[0] + ":" + operand[1] + ";";
		}
		// UMULL, UMULLS
		// operand0:operand1 = operand2 * operand3 + operand0:operand1;
		else if (opcode[2] == 'u')
		{
			statement->value = operand[0] + ":" + operand[1] + " = " + operand[2] + " * " + operand[3] + ";";
		}
		statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'q')
	{
		if (opcode[2] == 'a')
		{
			// UQADD16, UQADD8
			// Performs addition and writes the results to the destination register.
			// uqadd16   r1, r2, r3
			// uqadd16   r2, r3
			if (opcode[3] == 'd')
			{
				if (operand[2] != "")
					statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + ";";
				else
					statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
			}
			// UQASX
			else if (opcode[3] == 's')
			{
				if (operand[2] != "")
				{
					statement->value = "H" + operand[0] + " = H" + operand[1] + " + L" + operand[2] + ";";
					statement->value = "L" + operand[0] + " = L" + operand[1] + " - H" + operand[2] + ";";
				}
				else
				{
					statement->value = "H" + operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
					statement->value = "L" + operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
				}
			}
		}
		else if (opcode[2] == 's')
		{
			// UQSAX
			// add and subtract two registers and store the value into the destination register
			if (opcode[3] == 'a')
			{
				if (operand[2] != "")
				{
					statement->value = "H" + operand[0] + " = H" + operand[1] + " - L" + operand[2] + ";";
					statement->value = "L" + operand[0] + " = L" + operand[1] + " + H" + operand[2] + ";";
				}
				else
				{
					statement->value = "H" + operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
					statement->value = "L" + operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
				}
			}
			// UQSUB16, UQSUB8
			// Performs subtraction and writes the results to the destination register.
			// uadd16   r1, r2, r3
			// uadd16   r2, r3
			else if (opcode[4] == 'u')
			{
				if (operand[2] != "")
					statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + ";";
				else
					statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
			}
		}
		statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 's')
	{
		if (opcode[2] == 'a')
		{
			if (opcode[3] == 'd')
			{
				// USADA8
				// operand0 = operand1 - operand2 + operand3;
				if (opcode.length() > 4 && opcode[4] == 'a')
				{
					statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + " + " + operand[3] + ";";
				}
				// USAD8
				// operand0 = operand1 - operand2;
				// operand0 = operand0 - operand1;
				else
				{
					if (operand[2] != "")
						statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + ";";
					else
						statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
				}
			}
			// USAT, USAT16
			// Saturate
			// This instruction is ignored
			else if (opcode[3] == 't')
			{
				delete (statement);
				statement = NULL;
			}
			// USAX
			// add and subtract two registers and store the value into the destination register
			else if (opcode[3] == 'x')
			{
				statement->value = "H" + operand[0] + " = H" + operand[1] + " - L" + operand[2] + ";";
				statement->value = "L" + operand[0] + " = L" + operand[1] + " + H" + operand[2] + ";";
			}
		}
		// USUB16, USUB8
		// Performs subtraction and writes the results to the destination register.
		// uadd16   r1, r2, r3
		// uadd16   r2, r3
		else if (opcode[2] == 'u')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
		}
		if (statement != NULL)
			statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'x')
	{
		if (opcode[2] == 't' )
		{
			// UXTAB, UXTAB16, UXTAH
			// Extracts an 8-bit/16-bit value from a register, zero-extends it to 32 bits, adds the result to
			// the value in another register, and writes the final result to the destination register.
			if (opcode[3] == 'a')
			{
				stringstream ss;
				ss << dec << register_number++;
				string gr = "gr_" + ss.str();
				if (opcode[4] == 'b')
				{
					if (operand[3] != "")
					{
						statement->value = gr + " = bit(" + operand[2] + ", 0, 8);";
						statement->value = operand[0] + " = " + operand[1] + " + " + gr + ";";
					}
					else
					{
						statement->value = gr + " = bit(" + operand[1] + ", 0, 8);";
						statement->value = operand[0] + " = " + operand[0] + " + " + gr + ";";
					}
				}
				else if (opcode[4] == 'h')
				{
					if (operand[3] != "")
					{
						statement->value = gr + " = bit(" + operand[2] + ", 0, 16);";
						statement->value = operand[0] + " = " + operand[1] + " + " + gr + ";";
					}
					else
					{
						statement->value = gr + " = bit(" + operand[1] + ", 0, 16);";
						statement->value = operand[0] + " = " + operand[0] + " + " + gr + ";";
					}
				}
			}
			// UXTB, UXTB16
			// Extracts an 8-bit value from a register, zero-extends it to 32 bits, adds the result to
			// the value in another register, and writes the final result to the destination register.
			else if (opcode[3] == 'b')
			{
				if (operand[1].find("ror") == string::npos)
					statement->value = operand[0] + " = bit(" + operand[1] + ", 0, 8);";
				else
					statement->value = operand[0] + " = bit(" + operand[0] + ", 0, 8);";
			}
			// UXTH
			// Extracts an 16-bit value from a register, zero-extends it to 32 bits, adds the result to
			// the value in another register, and writes the final result to the destination register.
			else if (opcode[3] == 'h')
			{
				if (operand[1].find("ror") == string::npos)
					statement->value = operand[0] + " = bit(" + operand[1] + ", 0, 16);";
				else
					statement->value = operand[0] + " = bit(" + operand[0] + ", 0, 16);";
			}
		}
		statement->type = PATTERN_ASSIGN;
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
Statement *ArmAsmToMAIL::Process_V_Statements(Statement *statement, string opcode, string *operand, uint64_t &register_number,
										vector<_code>::iterator it_n_code, uint64_t &current_instruction_number,
										uint64_t number_of_statements, Statement *prev_statement, map<uint64_t, Statement *> &jump_offsets)
{
	uint64_t i = current_instruction_number;

	// -------------------------------------------------------------
	//
	// Advance SIMD instructions processing on 64/128 bit registers
	//
	// -------------------------------------------------------------
	if (opcode[1] == 'a')
	{
		if (opcode[2] == 'b')
		{
			// VABA, VABAL
			// Vector Absolute Difference and Accumulate subtracts the elements of
			// one vector from the corresponding elements of another vector, and
			// accumulates the absolute values of the results into the elements
			// of the destination vector.
			if (opcode[3] == 'a')
			{
				statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + " + " + operand[0] + ";";
			}
			// VABD, VABDL
			// Vector Absolute Difference subtracts the elements of one vector from
			// the corresponding elements of another vector, and places the absolute
			// values of the results in the elements of the destination vector.
			else if (opcode[3] == 'd')
			{
				if (operand[2] != "")
					statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + ";";
				else
					statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
			}
			// VABS
			// Vector Absolute takes the absolute value of each element in a vector,
			// and places the results in a second vector.
			else if (opcode[3] == 's')
			{
				statement->value = operand[0] + " = abs(" + operand[1] + ");";
			}
			statement->type = PATTERN_ASSIGN;
		}
		else if (opcode[2] == 'c')
		{
			// VACGE, VACLE, VACGT, VACLT
			// Vector Absolute Compare (>=, <=, >, <) takes the absolute value
			// of each element in a vector, and compares it with the absolute value of
			// the corresponding element of a second vector. If the first is greater
			// than or equal to the second, the corresponding element in the destination
			// vector is set to all ones. Otherwise, it is set to all zeros.
			// We make it simple (just a set operation) while translating this instruction to MAIL
			statement->value = operand[0] + " = set(" + operand[0] + ", 0, 128);";
			statement->type = PATTERN_LIBCALL;
		}
		// VADD, VADDHN, VADDL, VADDW
		// Vector Add adds corresponding elements in two vectors,
		// and places the results in the destination vector.
		else if (opcode[1] == 'd')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
			statement->type = PATTERN_ASSIGN;
		}
		// VAND
		// Vector Bitwise AND (immediate) performs a bitwise AND between a register value
		// and an immediate/register value, and returns the result into the destination vector.
		else if (opcode[1] == 'n')
		{
			if (operand[2] != "")
			{
				statement->value = operand[0] + " = " + operand[1] + " and " + operand[2] + ";";
				if (operand[2][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			else
			{
				statement->value = operand[0] + " = " + operand[0] + " and " + operand[1] + ";";
				if (operand[1][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
	}
	else if (opcode[1] == 'b')
	{
		// VBIC
		// Vector Bitwise Bit Clear performs a bitwise AND between a register value and the complement
		// of an immediate/register value, and returns the result into the destination vector.
		if (opcode[2] == 'I' && opcode[3] == 'C')
		{
			if (operand[2] != "")
			{
				statement->value = operand[0] + " = " + operand[1] + " and !" + operand[2] + ";";
				if (operand[2][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			else
			{
				statement->value = operand[0] + " = " + operand[0] + " and !" + operand[1] + ";";
				if (operand[1][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
		// VBIF, VBIT
		// Vector Bitwise Insert if False/True.
		if (opcode[2] == 'i' && (opcode[3] == 'f' || opcode[3] == 't'))
		{
			statement->value = operand[0] + " = set(" + operand[0] + ", 0, 128);";
			statement->type = PATTERN_LIBCALL;
		}
		// VBSL
		// Vector Bitwise Select.
		else if (opcode[2] == 's')
		{
			statement->value = operand[0] + " = set(" + operand[0] + ", 0, 128);";
			statement->type = PATTERN_LIBCALL;
		}
	}
	else if (opcode[1] == 'c')
	{
		// VCLS, VCLZ
		// Vector Count Bits
		if (opcode[2] == 'l')
		{
			if (opcode[3] == 's' || opcode[2] == 'z')
			{
				statement->value = operand[0] + " = count(" + operand[1] + ");";
				statement->type = PATTERN_LIBCALL;
			}
			// VCLT
			// Vector Compare (==, >=, >, <=) to Zero
			else if (opcode[3] == 't')
			{
				statement->value = operand[0] + " = set(" + operand[0] + ", 0, 128);";
				if (operand[1][0] == '#' || operand[2][0] == '#')
					statement->type = PATTERN_LIBCALL_C;
				else
					statement->type = PATTERN_LIBCALL;
			}
		}
		// VCMP, VCMPE
		// Vector Compare compares two floating-point registers,
		// or one floating-point register and zero.
		else if (opcode[2] == 'm')
		{
			statement->value = "compare(" + operand[0] + ", " + operand[1] + ");";
			if (operand[1][0] == '#')
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
		// VCNT
		// Vector Count Bits
		else if (opcode[2] == 'n')
		{
			statement->value = operand[0] + " = count(" + operand[1] + ");";
			statement->type = PATTERN_LIBCALL;
		}
		// VCVT, VCVTA, VCVTB, VCVTM, VCVTN, VCVTP, VCVTR, VCVTT
		// Convert to or from
		// These instructions are ignored
		else if (opcode[2] == 'v')
		{
			delete (statement);
			statement = NULL;
		}
		// VCEQ, VCGE, VCGT, VCLE
		// Vector Compare (==, >=, >, <=) to Zero
		else
		{
			statement->value = operand[0] + " = set(" + operand[0] + ", 0, 128);";
			if (operand[1][0] == '#' || operand[2][0] == '#')
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
	}
	else if (opcode[1] == 'd')
	{
		// VDIV
		// Divides one floating-point value by another floating-point
		// value and writes the result to a third floating-point register.
		if (opcode[2] == 'i')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = " + operand[1] + " / " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " / " + operand[1] + ";";
			statement->type = PATTERN_ASSIGN;
		}
		// VDUP
		else if (opcode[2] == 'u')
		{
			statement->value = operand[0] + " = bit(" + operand[1] + ", 0, 128);";
			// If scalar
			if (operand[1].find("[") != string::npos && operand[1].find("]") != string::npos)
				statement->type = PATTERN_LIBCALL_C;
			else
				statement->type = PATTERN_LIBCALL;
		}
	}
	else if (opcode[1] == 'e')
	{
		// VEOR
		// Performs a bitwise Exclusive OR operation between two registers,
		// and places the result in the destination register.
		if (opcode[2] == 'o')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = " + operand[1] + " xor " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " xor " + operand[1] + ";";
			statement->type = PATTERN_ASSIGN;
		}
		// VEXT
		// Vector extract
		// This instruction is ignored
		else if (opcode[2] == 'x')
		{
			delete (statement);
			statement = NULL;
		}
	}
	// VFMA, VFMS, VFNMA, VFNMS
	// Vector Fused
	// We change these instruction to simple multiplication instruction
	else if (opcode[1] == 'f')
	{
		statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + ";";
		statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'h')
	{
		// VHADD
		// Adds corresponding elements in two vectors of integers.
		if (opcode[2] == 'a')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
			statement->type = PATTERN_ASSIGN;
		}
		// VHSUB
		// Subtracts corresponding elements in two vectors of integers.
		else if (opcode[2] == 's')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
			statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'L')
	{
		if (opcode[2] == 'd')
		{
			// VLDM, VLDMDB, VLDMIA
			// Load Multiple SIMD&FP registers loads multiple registers from
			// consecutive locations in the Advanced SIMD and floating-point
			// register file using an address from a general-purpose register.
			if (opcode[3] == 'm')
			{
				string reg = Util::removeWhiteSpaces(operand[0]);
				int len = reg.length();
				bool REG_UPDATE = false;
				if (reg[len-1] == '!')
				{
					reg = reg.substr(0, len-2);
					REG_UPDATE = true;
				}

				string reg_list = operand[1];
				int pos_1 = reg_list.find('{');
				int pos_2 = reg_list.find('}');
				if (pos_2 > pos_1+2)
					reg_list = reg_list.substr(pos_1+1, pos_2-1);
				char *tokens = strtok((char *)reg_list.c_str(), ",");
				int num_tokens = 0;
				char nt[4];
				while (tokens != NULL)
				{
					num_tokens++;
					sprintf(nt, "%d", num_tokens);
					string temp_token = Util::removeWhiteSpaces(tokens);
					statement->value += temp_token + " = [" + reg + " - " + nt + "];";
					tokens = strtok(NULL, ",");
					if (tokens != NULL)
						statement->value += " ";
				}

				if (REG_UPDATE)
					statement->value += reg + " = " + reg + " - " + nt + ";";
				statement->type = PATTERN_ASSIGN;
			}
			// VLDR
			// Loads a single register from the Advanced SIMD and floating-point register file,
			// using an address from a general-purpose register, with an optional offset.
			else if (opcode[3] == 'r')
			{
				if (operand[2] != "")
					statement->value = operand[0] + " = " + operand[1] + "," + operand[2] + ";";
				else
					statement->value = operand[0] + " = " + operand[1] + ";";

				if (operand[1].find("sp") != string::npos)
				{
					statement->value += "sp = sp - 0x1;";
					statement->type = PATTERN_STACK;
				}
				// pre-indexed and post-indexed immediate offset
				else if (operand[1][0] != '['
						|| operand[1].find('#') != string::npos
						|| operand[2].find('#') != string::npos
						|| operand[3].find('#') != string::npos
						)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			// VLD1, VLD2, VLD3, VLD4
			// Load single 1/2/3/4 element structure
			// These instructions are ignored
			else
			{
				delete (statement);
				statement = NULL;
			}
		}
	}
	else if (opcode[1] == 'm')
	{
		// VMAX, VMAXNM, VMIN, VMINNM
		// Vector Maximum compares corresponding elements in two vectors.
		if (opcode[2] == 'a' || opcode[2] == 'i')
		{
			if (operand[2] != "")
				statement->value = "compare(" + operand[1] + ", " + operand[2] + ");";
			else
				statement->value = "compare(" + operand[0] + ", " + operand[1] + ");";
			statement->type = PATTERN_LIBCALL;
		}
		else if (opcode[2] == 'l')
		{
			// VMLA, VMLAL
			// Vector Multiply Accumulate
			// Multiplies corresponding elements in two vectors, and accumulates
			// the results into the elements of the destination vector.
			if (opcode[3] == 'a')
			{
				statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + " + " + operand[0] + ";";

				// If scalar
				if (operand[1].find("[") != string::npos && operand[1].find("]") != string::npos)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			// VMLS, VMLSL
			// Vector Multiply Accumulate
			// Multiplies corresponding elements in two vectors, and subtracts
			// the results into the elements of the destination vector.
			else if (opcode[3] == 's')
			{
				statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + " - " + operand[0] + ";";

				// If scalar
				if (operand[1].find("[") != string::npos && operand[1].find("]") != string::npos)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
		// VMOV, VMOVL, VMOVN, VMRS, VMSR
		else if (opcode[2] == 'o' || opcode[2] == 'r' || opcode[2] == 's')
		{
			// Copy two GP (general-purpose) registers to or from two SIMD&FP registers
			if (operand[3] != "")
			{
				statement->value = operand[0] + " = " + operand[2] + ";";
				statement->value += operand[1] + " = " + operand[3] + ";";
				statement->type = PATTERN_ASSIGN;
			}
			// Copy two GP (general-purpose) registers to or from a SIMD&FP register
			if (operand[2] != "")
			{
				statement->value = "L" + operand[0] + " = " + operand[1] + ";";
				statement->value += "H" + operand[0] + " = " + operand[2] + ";";
				statement->type = PATTERN_ASSIGN;
			}
			else
			{
				// Copy SIMD&FP register to SIMD&FP register
				// Copy immediate value to SIMD&FP register
				// Copy scalar to or from SIMD&FP register
				statement->value = operand[0] + " = " + operand[1] + ";";
				// If immediate
				if (operand[1][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				// If scalar
				if (operand[1].find("[") != string::npos && operand[1].find("]") != string::npos)
					statement->type = PATTERN_ASSIGN_C;
				// If scalar
				if (operand[0].find("[") != string::npos && operand[0].find("]") != string::npos)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
		// VMUL, VMULL
		// Vector Multiply multiplies corresponding elements in two vectors,
		// and places the results in the destination vector.
		else if (opcode[2] == 'u')
		{
			if (operand[2] != "")
			{
				statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + ";";
				// If scalar
				if (operand[2].find("[") != string::npos && operand[2].find("]") != string::npos)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			else
			{
				statement->value = operand[0] + " = " + operand[0] + " * " + operand[1] + ";";
				// If scalar
				if (operand[1].find("[") != string::npos && operand[1].find("]") != string::npos)
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
		// VMVN
		// Vector Bitwise NOT (register/immediate) takes a value from a register, inverts
		// the value of each bit, and places the result in the destination register.
		else if (opcode[2] == 'v')
		{
			statement->value = operand[0] + " = !" + operand[1] + ";";
			// If immediate
			if (operand[1][0] == '#')
				statement->type = PATTERN_ASSIGN_C;
			else
				statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'n')
	{
		// VNEG
		// Vector Negate negates each element in a vector, and places the results in a second vector.
		if (opcode[2] == 'e')
		{
			statement->value = operand[0] + " = !" + operand[1] + ";";
		}
		else if (opcode[2] == 'm')
		{
			// VNMLA, VNMLS
			// Vector Negate Multiply Accumulate/Subtract
			// multiplies together two floating-point register values, adds/subtracts the negation of the
			// floating-point value in the destination register to the negation of the product,
			// and writes the result back to the destination register.
			if (opcode[3] == 'l')
			{
				stringstream ss;
				ss << dec << register_number++;
				string gr = "gr_" + ss.str();
				statement->value = gr + " = " + operand[1] + " * " + operand[2] + ";";
				if (opcode[4] == 'A')
					statement->value += operand[0] + " = !" + gr + " + !" + operand[0] + ";";
				else if (opcode[4] == 'S')
					statement->value += operand[0] + " = !" + gr + " - !" + operand[0] + ";";
			}
			// VNMUL
			// Vector Negate Multiply multiplies together two floating-point register values,
			// and writes the negation of the result to the destination register.
			else if (opcode[3] == 'u')
			{
				stringstream ss;
				ss << dec << register_number++;
				string gr = "gr_" + ss.str();
				if (operand[2] != "")
					statement->value = gr + " = " + operand[1] + " * " + operand[2] + ";";
				else
					statement->value = gr + " = " + operand[0] + " * " + operand[1] + ";";
				statement->value += operand[0] + " = !" + gr + ";";
			}
		}

		statement->type = PATTERN_ASSIGN;
	}
	else if (opcode[1] == 'o')
	{
		// VORN
		// Vector Bitwise OR NOT (immediate/register) performs a bitwise OR between a register value and the
		// complement of an immediate/register value, and returns the result into the destination vector.
		// VORR
		// Vector Bitwise OR NOT (immediate/register) performs a bitwise OR between a register value
		// an immediate/register value, and returns the result into the destination vector.
		if (opcode[2] == 'r')
		{
			if (operand[2] != "")
			{
				// VORN
				if (opcode[3] == 'n')
					statement->value = operand[0] + " = " + operand[1] + " or !" + operand[2] + ";";
				// VORR
				else
					statement->value = operand[0] + " = " + operand[1] + " or " + operand[2] + ";";

				if (operand[2][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			else
			{
				// VORN
				if (opcode[3] == 'n')
					statement->value = operand[0] + " = " + operand[0] + " or !" + operand[1] + ";";
				// VORR
				else
					statement->value = operand[0] + " = " + operand[0] + " or " + operand[1] + ";";

				if (operand[1][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
	}
	else if (opcode[1] == 'p')
	{
		// VPADAL, VPADD, VPADDL
		// Adds adjacent pairs of elements of two vectors, and places the results in the destination vector.
		if (opcode[2] == 'a')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
			statement->type = PATTERN_ASSIGN;
		}
		else if (opcode[2] == 'm')
		{
			// VPMAX
			// compares adjacent pairs of elements in two doubleword vectors, and copies the larger
			// of each pair into the corresponding element in the destination doubleword vector.
			if (opcode[3] == 'a')
			{
				if (operand[2] != "")
					statement->value = operand[0] + " = max(" + operand[1] + ", " + operand[2] + ");";
				else
					statement->value = operand[0] + " = max(" + operand[0] + ", " + operand[1] + ");";
				statement->type = PATTERN_LIBCALL;
			}
			// VPMIN
			// compares adjacent pairs of elements in two doubleword vectors, and copies the larger
			// of each pair into the corresponding element in the destination doubleword vector.
			else if (opcode[3] == 'i')
			{
				if (operand[2] != "")
					statement->value = operand[0] + " = min(" + operand[1] + ", " + operand[2] + ");";
				else
					statement->value = operand[0] + " = min(" + operand[0] + ", " + operand[1] + ");";
				statement->type = PATTERN_LIBCALL;
			}
		}
		// VPOP
		// Loads multiple consecutive Advanced SIMD and floating-point
		// register file registers from the stack.
		else if (opcode[2] == 'o')
		{
			string reg = Util::removeWhiteSpaces(operand[0]);
			int len = reg.length();
			bool REG_UPDATE = false;
			if (reg[len-1] == '!')
			{
				reg = reg.substr(0, len-2);
				REG_UPDATE = true;
			}

			string reg_list = operand[1];
			int pos_1 = reg_list.find('{');
			int pos_2 = reg_list.find('}');
			if (pos_2 > pos_1+2)
				reg_list = reg_list.substr(pos_1+1, pos_2-1);
			char *tokens = strtok((char *)reg_list.c_str(), ",");
			int num_tokens = 0;
			char nt[4];
			while (tokens != NULL)
			{
				num_tokens++;
				sprintf(nt, "%d", num_tokens);
				string temp_token = Util::removeWhiteSpaces(tokens);
				statement->value += temp_token + " = [" + reg + " - " + nt + "];";
				tokens = strtok(NULL, ",");
				if (tokens != NULL)
					statement->value += " ";
			}

			if (REG_UPDATE)
			{
				sprintf(nt, "%d", num_tokens);
				statement->value += reg + " = " + reg + " - " + nt + ";";
			}
			statement->type = PATTERN_ASSIGN;
		}
		// VPUSH
		// Stores multiple consecutive registers from the Advanced SIMD and
		// floating-point register file to the stack.
		else if (opcode[2] == 'u')
		{
			string reg = Util::removeWhiteSpaces(operand[0]);
			int len = reg.length();
			bool REG_UPDATE = false;
			if (reg[len-1] == '!')
			{
				reg = reg.substr(0, len-2);
				REG_UPDATE = true;
			}

			string reg_list = operand[1];
			int pos_1 = reg_list.find('{');
			int pos_2 = reg_list.find('}');
			if (pos_2 > pos_1+2)
				reg_list = reg_list.substr(pos_1+1, pos_2-1);
			char *tokens = strtok((char *)reg_list.c_str(), ",");
			int num_tokens = 0;
			char nt[4];
			while (tokens != NULL)
			{
				num_tokens++;
				sprintf(nt, "%d", num_tokens);
				string temp_token = Util::removeWhiteSpaces(tokens);
				statement->value += "[" + reg + " + " + nt + "] = " + temp_token + ";";
				tokens = strtok(NULL, ",");
				if (tokens != NULL)
					statement->value += " ";
			}

			if (REG_UPDATE)
			{
				sprintf(nt, "%d", num_tokens);
				statement->value += reg + " = " + reg + " + " + nt + ";";
			}
			statement->type = PATTERN_ASSIGN;
		}
	}
	else if (opcode[1] == 'q')
	{
		if (opcode[2] == 'a')
		{
			// VQABS
			// Takes the absolute value of each element in a vector,
			// and places the results in the destination vector.
			if (opcode[3] == 'b')
			{
				statement->value = operand[0] + " = abs(" + operand[1] + ");";
				statement->type = PATTERN_LIBCALL;
			}
			// VQADD
			// Adds the values of corresponding elements of two vectors,
			// and places the results in the destination vector.
			else if (opcode[3] == 'd')
			{
				if (operand[2] != "")
					statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + ";";
				else
					statement->value = operand[0] + " = " + operand[0] + " + " + operand[1] + ";";
				statement->type = PATTERN_ASSIGN;
			}
		}
		else if (opcode[2] == 'd')
		{
			if (opcode[4] == 'l')
			{
				// VQDMLAL
				// Vector Saturating Doubling Multiply Accumulate Long
				if (opcode[5] == 'a')
				{
					statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + " + " + operand[0] + ";";
					if (operand[2].find("[") != string::npos && operand[2].find("]") != string::npos)
						statement->type = PATTERN_ASSIGN_C;
					else
						statement->type = PATTERN_ASSIGN;
				}
				// VQDMLSL
				// Vector Saturating Doubling Multiply Subtract Long
				if (opcode[5] == 's')
				{
					statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + " - " + operand[0] + ";";
					if (operand[2].find("[") != string::npos && operand[2].find("]") != string::npos)
						statement->type = PATTERN_ASSIGN_C;
					else
						statement->type = PATTERN_ASSIGN;
				}
			}
			// VQDMULH, VQDMULL
			// Vector Saturating Doubling Multiply
			else if (opcode[4] == 'u')
			{
				if (operand[2] != "")
				{
					statement->value = operand[0] + " = " + operand[1] + " * " + operand[2] + ";";
					if (operand[2].find("[") != string::npos && operand[2].find("]") != string::npos)
						statement->type = PATTERN_ASSIGN_C;
					else
						statement->type = PATTERN_ASSIGN;
				}
				else
				{
					statement->value = operand[0] + " = " + operand[0] + " * " + operand[1] + ";";
					statement->type = PATTERN_ASSIGN;
				}
			}
		}
		// VQMOVN, VQMOVUN
		// Vector Saturating Move
		// These instructions are ignored
		else if (opcode[2] == 'm')
		{
			delete (statement);
			statement = NULL;
		}
		// VQNEG
		// Negates each element in a vector, and places the results in the destination vector.
		else if (opcode[2] == 'n')
		{
			statement->value = operand[0] + " = !" + operand[1] + ";";
			statement->type = PATTERN_ASSIGN;
		}
		// VQRDMULH, VQRSHL, VQRSHRN, VQRSHRN, VQRSHRUN, VQRSHRUN,
		// Vector Saturating
		// These instructions are ignored
		else if (opcode[2] == 'r')
		{
			delete (statement);
			statement = NULL;
		}
		else if (opcode[2] == 's')
		{
			// VQSHL, VQSHLU, VQSHL, VQSHRN, VQSHRN, VQSHRUN, VQSHRUN
			// Vector Saturating
			// These instructions are ignored
			if (opcode[3] == 'h')
			{
				delete (statement);
				statement = NULL;
			}
			// VQSUB
			// Subtracts the elements of the second operand vector from the corresponding elements of
			// the first operand vector, and places the results in the destination vector.
			else if (opcode[3] == 'u')
			{
				if (operand[2] != "")
					statement->value = operand[0] + " = " + operand[1] + " - " + operand[2] + ";";
				else
					statement->value = operand[0] + " = " + operand[0] + " - " + operand[1] + ";";
				statement->type = PATTERN_ASSIGN;
			}
		}
	}
	else if (opcode[1] == 'r')
	{
		// VRADDHN
		// Adds corresponding elements in two quadword vectors, and places the result in a vector.
		if (opcode[2] == 'a')
		{
			statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + ";";
			statement->type = PATTERN_ASSIGN;
		}
		// VRECPE, VRECPS, VREV16, VREV32, VREV64
		// Vector Reverse
		else if (opcode[2] == 'e')
		{
			statement->value = operand[0] + " = rev(" + operand[1] + ");";
			statement->type = PATTERN_LIBCALL;
		}
		// VRHADD
		// Adds corresponding elements in two quadword vectors, and places the result in a vector.
		else if (opcode[2] == 'h')
		{
			statement->value = operand[0] + " = " + operand[1] + " + " + operand[2] + ";";
			statement->type = PATTERN_ASSIGN;
		}
		// VRINTA, VRINTM, VRINTN, VRINTP, VRINTR, VRINTX, VRINTZ
		// Vector Round
		// These instructions are ignored
		else if (opcode[2] == 'i')
		{
			delete (statement);
			statement = NULL;
		}
		else if (opcode[2] == 's')
		{
			// VRSHL, VRSHR, VRSHRN, VRSRA, VRSUBHN
			// Vector Rounding
			// These instructions are ignored
			if (opcode[3] == 'h' || opcode[3] == 'r')
			{
				delete (statement);
				statement = NULL;
			}
			// VRSQRTE, VRSQRTS
			// Vector Reciprocal Square Root
			else if (opcode[3] == 'q')
			{
				statement->value = operand[0] + " = sqrt(" + operand[1] + ");";
				statement->type = PATTERN_LIBCALL;
			}
		}
	}
	else if (opcode[1] == 's')
	{
		// VSELEQ, VSELGE, VSELGT, VSELVS
		// Floating-point Conditional Select
		// We make it simple by ignoring the condition
		if (opcode[2] == 'e')
		{
			statement->value = operand[0] + " = sel(" + operand[1] + ");";
			statement->type = PATTERN_ASSIGN;
		}
		else if (opcode[2] == 'h')
		{
			if (operand[2] != "")
			{
				// VSHL, VSHLL
				// Vector Shift Left
				if (opcode[3] == 'l')
					statement->value = operand[0] + " = " + operand[1] + " << " + operand[2] + ";";
				// VSHR, VSHRN
				// Vector Shift Right
				else if (opcode[3] == 'r')
					statement->value = operand[0] + " = " + operand[1] + " >> " + operand[2] + ";";

				if (operand[2][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
			else
			{
				// VSHL, VSHLL
				// Vector Shift Left
				if (opcode[3] == 'l')
					statement->value = operand[0] + " = " + operand[0] + " << " + operand[1] + ";";
				// VSHR, VSHRN
				// Vector Shift Right
				else if (opcode[3] == 'r')
					statement->value = operand[0] + " = " + operand[0] + " >> " + operand[1] + ";";

				if (operand[1][0] == '#')
					statement->type = PATTERN_ASSIGN_C;
				else
					statement->type = PATTERN_ASSIGN;
			}
		}
		// VSLI
		// Vector Shift Left and Insert
		// Always immediate
		else if (opcode[2] == 'l')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = " + operand[1] + " << " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " << " + operand[1] + ";";
			statement->type = PATTERN_ASSIGN_C;
		}
		// VSQRT
		// Vector SQRT
		else if (opcode[2] == 'q')
		{
			statement->value = operand[0] + " = sqrt(" + operand[1] + ");";
			statement->type = PATTERN_LIBCALL;
		}
		// VSRA, VSRI
		// Vector Shift Right and Accumulate/Insert
		// Always immediate
		else if (opcode[2] == 'r')
		{
			if (operand[2] != "")
			{
				if (opcode[3] == 'a')
					statement->value = operand[0] + " = " + operand[1] + " >> " + operand[2] + " + " + operand[0] + ";";
				else
					statement->value = operand[0] + " = " + operand[1] + " >> " + operand[2] + ";";
			}
			else
			{
				if (opcode[3] == 'a')
					statement->value = operand[0] + " = " + operand[0] + " >> " + operand[1] + " + " + operand[0] + ";";
				else
					statement->value = operand[0] + " = " + operand[0] + " >> " + operand[1] + ";";
			}
			statement->type = PATTERN_ASSIGN_C;
		}
		else if (opcode[2] == 't')
		{
			// VSTM, VSTMDB, VSTMIA
			// Store multiple SIMD&FP registers stores multiple registers from the
			// Advanced SIMD and floating-point register file to consecutive memory
			// locations using an address from a general-purpose register.
			if (opcode[3] == 'm')
			{
				string reg = Util::removeWhiteSpaces(operand[0]);
				int len = reg.length();
				bool REG_UPDATE = false;
				if (reg[len-1] == '!')
				{
					reg = reg.substr(0, len-2);
					REG_UPDATE = true;
				}

				string reg_list = operand[1];
				int pos_1 = reg_list.find('{');
				int pos_2 = reg_list.find('}');
				if (pos_2 > pos_1+2)
					reg_list = reg_list.substr(pos_1+1, pos_2-1);
				char *tokens = strtok((char *)reg_list.c_str(), ",");
				int num_tokens = 0;
				char nt[4];
				while (tokens != NULL)
				{
					num_tokens++;
					sprintf(nt, "%d", num_tokens);
					string temp_token = Util::removeWhiteSpaces(tokens);
					statement->value += "[" + reg + " + " + nt + "] = " + temp_token + ";";
					tokens = strtok(NULL, ",");
					if (tokens != NULL)
						statement->value += " ";
				}

				if (REG_UPDATE)
				{
					sprintf(nt, "%d", num_tokens);
					statement->value += reg + " = " + reg + " + " + nt + ";";
				}
				statement->type = PATTERN_ASSIGN;
			}
			// VSTR
			// Store SIMD&FP register stores a single register from the
			// Advanced SIMD and floating-point register file to memory,
			// using an address from a general-purpose register, with an optional offset.
			else if (opcode[3] == 'r')
			{
				statement->value = operand[0] + " = " + operand[1] + ";";
				statement->type = PATTERN_ASSIGN;
			}
			// VST1, VST2, VST3, VST4
			// Store single/multiple 1/2/3 element structures
			// These instructions are ignored
			else
			{
				delete (statement);
				statement = NULL;
			}
		}
		// VSUB, VSUBHN, VSUBL, VSUBW
		// Vector Subtract
		else if (opcode[2] == 'u')
		{
			if (operand[2] != "")
				statement->value = operand[0] + " = " + operand[1] + " << " + operand[2] + ";";
			else
				statement->value = operand[0] + " = " + operand[0] + " << " + operand[1] + ";";
			statement->type = PATTERN_ASSIGN;
		}
		// VSWAP
		else if (opcode[2] == 'w')
		{
			statement->value = operand[0] + " = swap(" + operand[1] + ");";
			statement->type = PATTERN_LIBCALL;
		}
	}
	else if (opcode[1] == 't')
	{
		// VTST
		if (opcode[2] == 's')
		{
			if (operand[2] != "")
				statement->value = operand[1] + " and " + operand[2] + ";";
			else
				statement->value = operand[0] + " and " + operand[1] + ";";
			statement->type = PATTERN_TEST;
		}
		// VTBL, VTBX
		// Vector Table Lookup
		//
		// VTRN
		// Vector Transpose
		//
		// VUZP
		// Vector Unzip
		//
		// VZIP
		// Vector Zip
		//
		// These instructions are ignored
		else
		{
			delete (statement);
			statement = NULL;
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
 * Get the hex value in the following string
 * e.g:
 * #0x23e / 0x23e / 23e
 * #+0x23e / -0x23e
 * +0x23e / -0x23e
 * +23e / -23e
 *
 */
int64_t ArmAsmToMAIL::getHexValue(string hexString)
{
	int64_t hex = VALUE_UNKNOWN;
	string str = Util::removeWhiteSpaces(hexString);
	if (str[0] == '#')
		str = str.substr(1, str.length());

	int pos = str.find("0x");
	if (pos >= 0)
		str = str.erase(pos, 2);

	int8_t sign = 1;
	if (str[0] == '-') { str = str.substr(1, str.length()); sign = -1; }
	else if (str[0] == '+') { str = str.substr(1, str.length()); }

	hex = Util::hexStringToInt(str);
	if (hex >= 0)
		return (sign * hex);
	else
		return (VALUE_UNKNOWN);
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
 *       jmp [pc+0x200b6c]    = PC+0x200b6c
 * (2)
 *    Can be any other value:
 *    e.g:
 *    0x4007c1+0x200
 * </p>
 *
 */
int64_t ArmAsmToMAIL::getValue(uint64_t ic, vector<_code>::iterator it_n_code)
{
	int64_t value = VALUE_UNKNOWN;
	string instr = (char *)it_n_code->instructions[ic].op_str;
	instr = Util::removeWhiteSpaces(instr);
	int c = 0;

#ifdef __DEBUG__
	cout << "ArmAsmToMAIL::getValue: " << instr << " @ offset: " << hex << it_n_code->instructions[ic].address << endl;
#endif

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
		c = instr.find_first_of('[');
		if (c >= 0)
		{
			int temp = instr.find_last_of(']');
			if (temp > 1)
			{
				instr = instr.substr(c+1, temp-c-1);
				value = computeValue(it_n_code, instr, ic);
			}
			else
				cerr << "ArmAsmToMAIL::getValue:Wrong value: " << instr << endl;
		}
		else
		{
			c = instr.find_first_of(' ');
			if (c < (int)instr.size())
			{
				instr = instr.substr(c+1, instr.size()-c);
				value = computeValue(it_n_code, instr, ic);
			}
			else
				cerr << "ArmAsmToMAIL::getValue:Wrong value: " << instr << endl;
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
		value = computeValue(it_n_code, instr, ic);
		break;
	default:
		break;
	}

#ifdef __DEBUG__
	if (value == VALUE_UNKNOWN)
		cout << "ArmAsmToMAIL::getValue: Found: VALUE_UNKNOWN" << endl;
	else
		cout << "ArmAsmToMAIL::getValue: Found: " << value << endl;
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
int64_t ArmAsmToMAIL::computeValue(vector<_code>::iterator it_n_code, string addr, uint64_t ic)
{
	int64_t value = 0;

	Expression *ex = new Expression();
	vector<string> expr = ex->ArithmeticExpression(addr);
#ifdef __DEBUG__
	printf("Printing Expression %s\n", addr.c_str());
	printf("Printing Parsed Expression: ");
	for (int i = 0; i < (int)expr.size(); i++)
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
			value = getRegisterValue(expr[0], it_n_code, ic);
	}

	if (value <= 0)
		return VALUE_UNKNOWN;

	for (int e = 1; e < (int)expr.size(); e++)
	{
		Operator op_c;
		int16_t op;
		if (( op = op_c.IsArithmetic(expr[e]) ) <= 0 )
		{
			cout << "Error:ArmAsmToMAIL::computeValue: Operation [ " << expr[e] << " ] not supported\n";
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
			temp_value = getRegisterValue(expr[e], it_n_code, ic);

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
			else cout << "Warning:ArmAsmToMAIL::computeValue: Operation not supported\n";
		}
	}

	if (value <= 0)
	{
		value = VALUE_UNKNOWN;
		cout << "Warning:ArmAsmToMAIL::computeValue:Value not available/computed:Instruction: " << hex << it_n_code->instructions[ic].address << " " << it_n_code->instructions[ic].bytes << " " << it_n_code->instructions[ic].mnemonic << " " << it_n_code->instructions[ic].op_str << endl;
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
 * the PC i.e: the address of the next instruction.
 */
int64_t ArmAsmToMAIL::getRegisterValue(string reg, vector<_code>::iterator it_n_code, uint64_t ic)
{
	int64_t value = 0;

	if (reg.compare("PC") == 0)
	{
		value = it_n_code->instructions[ic].address + it_n_code->instructions[ic].size;
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

void ArmAsmToMAIL::Print()
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
