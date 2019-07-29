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

#ifndef __CFG_H__
#define __CFG_H__

#include <algorithm>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include <map>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "../include/distorm.h"
#include "../include/mnemonics.h"
#include "../include/common.h"
#include "../util/util.h"
#include "../mail/patterns.h"
#include "../parser/expression.h"
#include "../parser/instruction.h"

using namespace std;

/**
 * <p>
 * This class implements the CFG class.
 * It takes a list (vector) of blocks
 * and builds a control flow graph
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since March 03, 2012
 */
class CFG
{
private:
	vector<Block *> blocks;
	vector<BackEdge *> backEdges;
	vector<Function *> functions;
	string filename;
	vector<Loop *> loops;

	stringstream print_s;
	bool CONNECTED;

	void trace_back(Block *block, uint64_t parent_num, uint64_t child_num, uint64_t max_nodes, uint64_t MAX_LEVEL, bool &found);
	bool shouldMerge(Block *block1, Block *block2);
	void merge(Block *block1, Block *block2, uint64_t currentBlock);//map<uint64_t, Edge*> MapIncomingEdges);
	void buildFunctions();
	void isConnected(Block *start, Block *end, bool &connected);
	void isConnectedAndLoops(Block *block, Block *end, Loop *loop, vector<Block *> *visited);
	void findLoops(Function *function);
	void updateNestedLoops(Function *function);
	string colorLoops(Function *function);
	void DFS(Block *block, vector<int> path);
	void printLoop(Loop *loop, uint64_t ln);

public:
	CFG(vector<Block *> blocks, vector<BackEdge *> backEdges, string filename);
	~CFG();
	void Shrink();
	void Build(string filename);
	void WriteToFile(vector<CFG *> cfgs, string filename);
	vector<CFG *> ReadFromFile(string filename);
	vector<Block *> GetBlocks();
	vector<BackEdge *> GetBackEdges();
	vector<Function *> GetFunctions();
	string GetFilename();
	void Print(string filename, bool stmts, bool dot);
	string printDOT(char *filename, Function *function);
	void PrintBlock(Block *b);
	void PrintBlock(Block *b, bool only_statements);
};

#endif // __CFG_H__
