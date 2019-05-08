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

#include "cfg.h"

/*
 * Constructor
 */
CFG::CFG(vector<Block *> blocks, vector<BackEdge *> backEdges, string filename)
{
	this->blocks = blocks;
	this->backEdges = backEdges;
	this->filename.assign(filename);
	CONNECTED = false;
}

/*
 * Destructor
 */
CFG::~CFG()
{
#ifdef __GRAPH_MATCHING__
	for (int i = 0; i < (int)functions.size(); i++)
	{
		for (int b = 0; b < (int)blocks.size(); b++)
		{
			for (int e = 0; e < (int)blocks[b]->edges.size(); e++)
			{
#ifdef __DEBUG__
				cerr << "CFG::~CFG: block number: " << blocks[b]->number << " Deleting edge: " << blocks[b]->edges[e]->tail->number << " --> " << blocks[b]->edges[e]->head->number << endl;
				cout << "CFG::~CFG: block number: " << blocks[b]->number << " Deleting edge: " << blocks[b]->edges[e]->tail->number << " --> " << blocks[b]->edges[e]->head->number << endl;
#endif
				delete (blocks[b]->edges[e]);
			}
			blocks[b]->edges.erase(blocks[b]->edges.begin(), blocks[b]->edges.end());
			blocks[b]->in_edges.erase(blocks[b]->in_edges.begin(), blocks[b]->in_edges.end());

			vector<Statement *> statements = blocks[b]->statements;
			for (int s = 0; s < (int)statements.size(); s++)
				delete (statements[s]);
			statements.erase(statements.begin(), statements.end());

#ifdef __DEBUG__
			cerr << "CFG::~CFG: Deleting block number: " << blocks[b]->number << endl;
			cout << "CFG::~CFG: Deleting block number: " << blocks[b]->number << endl;
#endif
			delete (blocks[b]);
		}
		blocks.erase(blocks.begin(), blocks.end());

		functions[i]->backEdges.erase(functions[i]->backEdges.begin(), functions[i]->backEdges.end());
		delete (functions[i]);
	}

	blocks.erase(blocks.begin(), blocks.end());
	functions.erase(functions.begin(), functions.end());
#endif

	for (int l = 0; l < (int)loops.size(); l++)
		delete (loops[l]);
	loops.erase(loops.begin(), loops.end());
}

#ifdef __PROGRAM_CFG_TRACING_OUTPUT_ENABLED__

/*
 *
 * Write the CFGs to a file
 *
 */
void CFG::WriteToFile(vector<CFG *> cfgs, string filename)
{
	ofstream file(filename.c_str(), ios::out | ios::binary | ios::app);
	if (file.is_open())
	{
		for (vector<CFG *>::iterator cfgi = cfgs.begin() ; cfgi != cfgs.end(); cfgi++)
		{
			CFG *cfg = *cfgi;
			blocks = cfg->GetBlocks();

			file << "CFG_START\n";
			file << "(" << cfg->filename << ")\n";
			for (int b = 0; b < blocks.size(); b++)
			{
				file << "BLOCK_START\n";
				file << blocks[b]->type << "\n";
				file << blocks[b]->function_number << "\n";
				for (int e = 0; e < (int)blocks[b]->edges.size(); e++)
				{
					int t = blocks[b]->edges[e]->tail->number;
					if (t != b)
					{
						cout << "Error:DroidNative:CFG::WriteToFile: Edge (tail) in Block " << b << " != " << t << " in file " << filename << "\n";
						continue;
					}
					int h = blocks[b]->edges[e]->head->number;
					file << "EO:" << t << ":" << h << "\n";
				}
				for (int e = 0; e < (int)blocks[b]->in_edges.size(); e++)
				{
					int t = blocks[b]->in_edges[e]->tail->number;
					if (t != b)
					{
						cout << "Error:DroidNative:CFG::WriteToFile: Edge (tail) in Block " << b << " != " << t << " in file " << filename << "\n";
						continue;
					}
					int h = blocks[b]->in_edges[e]->head->number;
					file << "EI:" << t << ":" << h << "\n";
				}
				vector<Statement *> statements = blocks[b]->statements;
				for (int s = 0; s < (int)statements.size(); s++)
				{
					file << "S:" << statements[s]->offset << "\n";
					file << "S:" << statements[s]->value << "\n";
					file << "S:" << statements[s]->start << "\n";
					file << "S:" << statements[s]->end << "\n";
					file << "S:" << statements[s]->branch_to_offset  << "\n";
					file << "S:" << statements[s]->type << "\n";
				}
				file << "BLOCK_END\n";
			}
			file << "CFG_END\n";
		}
		file.close();
	}
	else
		cout << "Error:DroidNative:CFG::WriteToFile: Cannot open the file: " << filename << "\n";
}

/*
 *
 * Read the CFGs from a file
 *
 */
vector<CFG *> CFG::ReadFromFile(string filename)
{
	vector<CFG *> cfgs;
	/*
	 * Open binary file for reading with the file pointer pointing at the end (ate)
	 */
	ifstream file(filename.c_str(), ios::in | ios::binary | ios::ate);
	if (file.is_open())
	{
		unsigned int fileSize = (unsigned int)file.tellg();                // How much buffer we need for the file
		file.seekg (0, ios::beg);
		char *fileBuffer = new char[fileSize+1];
		file.read(fileBuffer, fileSize);                                   // Read the file into the buffer
		file.close();
		fileBuffer[fileSize] = '\0';
		stringstream buffer;
		buffer << fileBuffer;

		string line;
		while(getline(buffer, line))
		{
			// CFG_START
			if (line.compare("CFG_START") == 0)
			{
				getline(buffer, line);
				string filename;
				filename.assign(line);
				uint64_t bn = 0;
				vector<Block *> blocks;
				vector<BackEdge *> backEdges;

				bool CFG_END = false;
				bool BLOCK_END = true;
				while(getline(buffer, line))
				{
					if (line.length() < 3)
						continue;
					if (BLOCK_END == true && line.compare("BLOCK_START") == 0)
					{
						BLOCK_END = false;
						Block *block = new Block();
						blocks.push_back(block);
						blocks[bn]->number = bn;
						getline(buffer, line);
						blocks[bn]->type = atoi(line.c_str());
						getline(buffer, line);
						blocks[bn]->function_number = atoi(line.c_str());
					}
					else if (line[0] == 'E')
					{
						if (blocks.size() <= bn)
						{
							cout << "Error:DroidNative:CFG::ReadFromFile: Block not added " << blocks.size() << " <= " << bn << " in file " << filename << "\n";
							continue;
						}
						string tail, head;
						int n = 3;
						bool is_digit = false;
						for(;;) { char c = line[n++]; if (c == ':' || c == '\0') break; if (!isdigit(c)) { is_digit=false; break; } is_digit = true; tail += c; }
						if (!is_digit)
						{
							cout << "Error:DroidNative:CFG::ReadFromFile: Edge (tail) in Block << bn << is corrupted in file " << filename << "\n";
							continue;
						}
						int t = atol(tail.c_str());
						for(;;) { char c = line[n++]; if (c == '\0') break; if (!isdigit(c)) { is_digit=false; break; } is_digit = true; head += c; }
						if (!is_digit)
						{
							cout << "Error:DroidNative:CFG::ReadFromFile: Edge (head) in Block " << bn << " is corrupted in file " << filename << "\n";
							continue;
						}
						int h = atol(head.c_str());
						if (t != bn)
						{
							cout << "Error:DroidNative:CFG::ReadFromFile: Edge (tail) in Block " << bn << " != " << t << " in file " << filename << "\n";
							continue;
						}
						Edge *edge = new Edge();
						edge->tail = blocks[t];
						edge->head = blocks[h];
						if (line[1] == 'O')
							blocks[bn]->edges.push_back(edge);
						else
							blocks[bn]->in_edges.push_back(edge);
					}
					else if (line[0] == 'S')
					{
						if (blocks.size() <= bn)
						{
							cout << "Error:DroidNative:CFG::ReadFromFile: Block not added " << blocks.size() << " <= " << bn << " in file " << filename << "\n";
							continue;
						}
						Statement *statement = new Statement();             // new statement
						string s = line.substr(2, string::npos);
						statement->offset = atol(s.c_str());                // offset
						getline(buffer, line);
						s = line.substr(2, string::npos);
						statement->value.assign(s);                         // value
						getline(buffer, line);
						s = line.substr(2, string::npos);
						statement->start = atoi(s.c_str());                 // start
						getline(buffer, line);
						s = line.substr(2, string::npos);
						statement->end = atoi(s.c_str());                   // end
						getline(buffer, line);
						s = line.substr(2, string::npos);
						statement->branch_to_offset = atol(s.c_str());      // branch_to_offset
						getline(buffer, line);
						s = line.substr(2, string::npos);
						statement->type = atoi(s.c_str());                  // type
						blocks[bn]->statements.push_back(statement);
					}
					else if (BLOCK_END == false && line.compare("BLOCK_END") == 0)
					{
						BLOCK_END = true;
						bn++;
					}
					else if (line.compare("CFG_END") == 0)
					{
						if (BLOCK_END == false)
						{
							for (int e = 0; e < (int)blocks[bn]->edges.size(); e++)
								delete (blocks[bn]->edges[e]);
							blocks[bn]->edges.erase(blocks[bn]->edges.begin(), blocks[bn]->edges.end());
							vector<Statement *> statements = blocks[bn]->statements;
							for (int s = 0; s < (int)statements.size(); s++)
								delete (statements[s]);
							statements.erase(statements.begin(), statements.end());
							delete (blocks[bn]);
							cout << "Error:DroidNative:CFG::ReadFromFile: Block " << bn << " is corrupted in file " << filename << "\n";
							bn--;
						}
						CFG_END = true;
						break;
					}
					else if (line.compare("CFG_START") == 0)
						break;
				}

				if (CFG_END == true)
				{
					if (blocks.size() > 0)
					{
						CFG *cfg = new CFG(blocks, backEdges, filename);
						cfgs.push_back(cfg);
					}
				}
				else
				{
					if (bn > 0)
					{
						for (int b = 0; b < blocks.size(); b++)
						{
							for (int e = 0; e < (int)blocks[b]->edges.size(); e++)
								delete (blocks[b]->edges[e]);
							blocks[b]->edges.erase(blocks[b]->edges.begin(), blocks[b]->edges.end());
							for (int e = 0; e < (int)blocks[b]->in_edges.size(); e++)
								delete (blocks[b]->in_edges[e]);
							blocks[b]->in_edges.erase(blocks[b]->edges.begin(), blocks[b]->edges.end());
							vector<Statement *> statements = blocks[b]->statements;
							for (int s = 0; s < (int)statements.size(); s++)
								delete (statements[s]);
							statements.erase(statements.begin(), statements.end());
							delete (blocks[b]);
						}
					}
					blocks.erase(blocks.begin(), blocks.end());
					cout << "Error:DroidNative:CFG::ReadFromFile: CFG is corrupted in file " << filename << "\n";
					break;
				}
			}
		}

		delete (fileBuffer);
	}
	else
		cout << "Error:DroidNative:CFG::ReadFromFile: Cannot open the file: " << filename << "\n";

	return cfgs;
}

#else

/*
 *
 * Write the CFGs to a file
 *
 */
void CFG::WriteToFile(vector<CFG *> cfgs, string filename)
{
	ofstream file(filename.c_str(), ios::out | ios::binary | ios::app);
	if (file.is_open())
	{
		for (vector<CFG *>::iterator cfgi = cfgs.begin() ; cfgi != cfgs.end(); cfgi++)
		{
			CFG *cfg = *cfgi;
			blocks = cfg->GetBlocks();

			file << "CFG_START\n";
			file << "(" << cfg->filename << ")\n";
			for (int b = 0; b < blocks.size(); b++)
			{
				file << "BLOCK_START\n";
				for (int e = 0; e < (int)blocks[b]->edges.size(); e++)
				{
					int t = blocks[b]->edges[e]->tail->number;
					if (t != b)
					{
						cout << "Error:DroidNative:CFG::WriteToFile: Edge (tail) in Block " << b << " != " << t << " in file " << filename << "\n";
						continue;
					}
					int h = blocks[b]->edges[e]->head->number;
					file << "E:" << t << ":" << h << "\n";
				}
				vector<Statement *> statements = blocks[b]->statements;
				for (int s = 0; s < (int)statements.size(); s++)
					file << "S:" << statements[s]->type << "\n";
				file << "BLOCK_END\n";
			}
			file << "CFG_END\n";
		}
	}
	else
		cout << "Error:DroidNative:CFG::WriteToFile: Cannot open the file: " << filename << "\n";
}

/*
 *
 * Read the CFGs from a file
 *
 */
vector<CFG *> CFG::ReadFromFile(string filename)
{
	vector<CFG *> cfgs;
	/*
	 * Open binary file for reading with the file pointer pointing at the end (ate)
	 */
	ifstream file(filename.c_str(), ios::in | ios::binary | ios::ate);
	if (file.is_open())
	{
		unsigned int fileSize = (unsigned int)file.tellg();                // How much buffer we need for the file
		file.seekg (0, ios::beg);
		char *fileBuffer = new char[fileSize+1];
		file.read(fileBuffer, fileSize);                                   // Read the file into the buffer
		file.close();
		fileBuffer[fileSize] = '\0';
		stringstream buffer;
		buffer << fileBuffer;

		string line;
		while(getline(buffer, line))
		{
			// CFG_START
			if (line.compare("CFG_START") == 0)
			{
				getline(buffer, line);
				string filename;
				filename.assign(line);
				uint64_t bn = 0;
				vector<Block *> blocks;
				vector<BackEdge *> backEdges;

				bool CFG_END = false;
				bool BLOCK_END = true;
				while(getline(buffer, line))
				{
					if (line.length() < 3)
						continue;
					if (BLOCK_END == true && line.compare("BLOCK_START") == 0)
					{
						BLOCK_END = false;
						Block *block = new Block();
						blocks.push_back(block);
						blocks[bn]->number = bn;
					}
					else if (line[0] == 'E')
					{
						if (blocks.size() <= bn)
						{
							cout << "Error:DroidNative:CFG::ReadFromFile: Block not added " << blocks.size() << " <= " << bn << " in file " << filename << "\n";
							continue;
						}
						string tail, head;
						int n = 2;
						bool is_digit = false;
						for(;;) { char c = line[n++]; if (c == ':' || c == '\0') break; if (!isdigit(c)) { is_digit=false; break; } is_digit = true; tail += c; }
						if (!is_digit)
						{
							cout << "Error:DroidNative:CFG::ReadFromFile: Edge (tail) in Block << bn << is corrupted in file " << filename << "\n";
							continue;
						}
						int t = atol(tail.c_str());
						for(;;) { char c = line[n++]; if (c == '\0') break; if (!isdigit(c)) { is_digit=false; break; } is_digit = true; head += c; }
						if (!is_digit)
						{
							cout << "Error:DroidNative:CFG::ReadFromFile: Edge (head) in Block " << bn << " is corrupted in file " << filename << "\n";
							continue;
						}
						int h = atol(head.c_str());
						if (t != bn)
						{
							cout << "Error:DroidNative:CFG::ReadFromFile: Edge (tail) in Block " << bn << " != " << t << " in file " << filename << "\n";
							continue;
						}
						Edge *edge = new Edge();
						edge->tail = blocks[t];
						edge->head = blocks[h];
						blocks[bn]->edges.push_back(edge);
					}
					else if (line[0] == 'S')
					{
						if (blocks.size() <= bn)
						{
							cout << "Error:DroidNative:CFG::ReadFromFile: Block not added " << blocks.size() << " <= " << bn << " in file " << filename << "\n";
							continue;
						}
						string s = line.substr(2, string::npos);
						Statement *statement = new Statement();
						statement->type = atoi(s.c_str());
						blocks[bn]->statements.push_back(statement);
					}
					else if (BLOCK_END == false && line.compare("BLOCK_END") == 0)
					{
						BLOCK_END = true;
						bn++;
					}
					else if (line.compare("CFG_END") == 0)
					{
						if (BLOCK_END == false)
						{
							for (int e = 0; e < (int)blocks[bn]->edges.size(); e++)
								delete (blocks[bn]->edges[e]);
							blocks[bn]->edges.erase(blocks[bn]->edges.begin(), blocks[bn]->edges.end());
							vector<Statement *> statements = blocks[bn]->statements;
							for (int s = 0; s < (int)statements.size(); s++)
								delete (statements[s]);
							statements.erase(statements.begin(), statements.end());
							delete (blocks[bn]);
							cout << "Error:DroidNative:CFG::ReadFromFile: Block " << bn << " is corrupted in file " << filename << "\n";
							bn--;
						}
						CFG_END = true;
						break;
					}
					else if (line.compare("CFG_START") == 0)
						break;
				}

				if (CFG_END == true)
				{
					if (blocks.size() > 0)
					{
						CFG *cfg = new CFG(blocks, backEdges, filename);
						cfgs.push_back(cfg);
					}
				}
				else
				{
					if (bn > 0)
					{
						for (int b = 0; b < blocks.size(); b++)
						{
							for (int e = 0; e < (int)blocks[b]->edges.size(); e++)
								delete (blocks[b]->edges[e]);
							blocks[b]->edges.erase(blocks[b]->edges.begin(), blocks[b]->edges.end());
							for (int e = 0; e < (int)blocks[b]->in_edges.size(); e++)
								delete (blocks[b]->in_edges[e]);
							blocks[b]->in_edges.erase(blocks[b]->edges.begin(), blocks[b]->edges.end());
							vector<Statement *> statements = blocks[b]->statements;
							for (int s = 0; s < (int)statements.size(); s++)
								delete (statements[s]);
							statements.erase(statements.begin(), statements.end());
							delete (blocks[b]);
						}
					}
					blocks.erase(blocks.begin(), blocks.end());
					cout << "Error:DroidNative:CFG::ReadFromFile: CFG is corrupted in file " << filename << "\n";
					break;
				}
			}
		}

		delete (fileBuffer);
	}
	else
		cout << "Error:DroidNative:CFG::ReadFromFile: Cannot open the file: " << filename << "\n";

	return cfgs;
}

#endif

/*
 *
 * Check if the two blocks 'start' and 'end' are connected
 *
 */
void CFG::isConnected(Block *start, Block *end, bool &connected)
{
	if (start->number == end->number)
	{
		connected = true;
	}
	else if (!connected)
	{
		for (uint64_t e = 0; e < start->edges.size(); e++)
		{
			if (!start->edges[e]->visited)
			{
				start->edges[e]->visited = true;
				if (start->edges[e]->head->number == end->number)
				{
					connected = true;
					break;
				}
				else
					isConnected(start->edges[e]->head, end, connected);
			}
		}
	}
}

/*
 *
 * Given two blocks A and B in a CFG:
 * If all the paths that reach node B pass through block A
 * and all the children of A are reachable through B
 * then A and B are merged.
 *
 * please read my paper --- TO DO --- for more details.
 *
 * block2 is to be merged to block1
 *
 */ 
bool CFG::shouldMerge(Block *block1, Block *block2)
{
#ifdef __NO_CFG_SHRINKING__
	return false;
#endif
	/*
	 * If only one edge
	 */
	if (block2->in_edges.size() == 1 && block1->edges.size() == 1)
		return true;

#ifdef __SIMPLE_CFG_SHRINKING__
	return false;
#endif
	/*
	 * If more than one edge
	 * See if the child can reach all the other children of the parent
	 */
	bool merge = false;
	uint64_t all_children_reachable = 0;
	for (int e = 0; e < (int)block1->edges.size(); e++)
	{
		// If not the children under check for merging
		if (block2->number != block1->edges[e]->head->number)
		{
			for (unsigned int b = 0; b < blocks.size()-1; b++)
			{
				blocks[b]->visited = false;
				for (unsigned int e = 0; e < blocks[b]->edges.size(); e++)
					blocks[b]->edges[e]->visited = false;
			}
			bool connected = false;
			isConnected(block2, block1->edges[e]->head, connected);
			if (connected)
				all_children_reachable++;
		}
	}
	if (all_children_reachable == block1->edges.size()-1)
		merge = true;

	return merge;
}

/*
 *
 * Given two blocks A and B in a CFG:
 * If all the paths that reach node B pass through block A
 * and all the children of A are reachable through B
 * then A and B are merged.
 *
 * please read the paper on SWOD-CFWeight --- TO DO --- for more details.
 *
 */ 
void CFG::Shrink()
{
	for (uint64_t b = 1; b < blocks.size(); b++)
	{
		Edge *edge = blocks[b]->in_edges[0];
		if (blocks[b]->number != edge->head->number)
			cerr << "Error:CFG::shrink: " << blocks[b]->number << " != " << blocks[b]->in_edges[0]->head->number << endl;
		Block *block1 = edge->tail;
		Block *block2 = blocks[b];
		if (shouldMerge(block1, block2))
		{
			merge(block1, block2, b);
			/*
			 * Delete block2
			 */
			delete (block2);
			blocks.erase(blocks.begin()+b);
			b--;
		}
	}

	for (unsigned int b = 0; b < blocks.size(); b++)
	{
		if (blocks[b]->number != b)
		{
			blocks[b]->number = b;
			/*
			 * Update the tail of outgoing edges
			 */
			for (unsigned int e = 0; e < blocks[b]->edges.size(); e++)
				blocks[b]->edges[e]->tail->number = b;
			/*
			 * Update the head of incoming edges
			 */
			for (unsigned int e = 0; e < blocks[b]->in_edges.size(); e++)
				blocks[b]->in_edges[e]->head->number = b;
		}
	}
}

/*
 * Merge block2 (b2) into block1 (b1)
 *
 *      --------
 *      |  b1  |
 *      --------
 *       |    |
 *   -----    |
 *   |        |
 *   |        v
 *   |     --------
 *   |     |  b2  |
 *   |     --------
 *   |       |  |
 *   |   -----  -----
 *   |   |          |
 *   v   v          v
 * --------     --------
 * |  b3  |     |  b4  |
 * --------     --------
 *
 *        MERGED
 *
 *      --------
 *      |  b1  |
 *      |  b2  |
 *      --------
 *        |  |
 *    -----  -----
 *    |          |
 *    v          v
 * --------   --------
 * |  b3  |   |  b4  |
 * --------   --------
 *
 */
void CFG::merge(Block *block1, Block *block2, uint64_t currentBlock)//map<uint64_t, Edge*> MapIncomingEdges)
{
#ifdef __DEBUG__
	cout << "----------------------- Merging blocks: " << block1->number << " : " << block2->number << " -----------------------" << endl;
	PrintBlock(block1, false);
	PrintBlock(block2, false);
#endif
	/*
	 * Merge all the statements of block2 into block1
	 */
	for (unsigned int s = 0; s < block2->statements.size(); s++)
		block1->statements.push_back(block2->statements[s]);

	/*
	 *
	 * Merge block2 into block1 and:
	 * (1) Erase the outgoing edge from block1 to block2
	 * (2) Delete and erase the incoming edge to block2
	 * (3) Update all the incoming and outgoing edges of block2
	 *
	 */

	// (1)
	for (unsigned int e = 0; e < block1->edges.size(); e++)
	{
		if (block2->number == block1->edges[e]->head->number)
		{
#ifdef __DEBUG__
			cout << "Erasing edge: " << block1->edges[e]->tail->number << " --> " << block1->edges[e]->head->number << endl;
#endif
			block1->edges.erase(block1->edges.begin()+e);
			break;
		}
	}

	// (2)
	for (unsigned int e = 0; e < block2->in_edges.size(); e++)
	{
		if (block1->number == block2->in_edges[e]->tail->number)
		{
#ifdef __DEBUG__
			cout << "Deleting edge: " << block2->in_edges[e]->tail->number << " --> " << block2->in_edges[e]->head->number << endl;
#endif
			delete (block2->in_edges[e]);
			block2->in_edges.erase(block2->in_edges.begin()+e);
			break;
		}
	}

	/*
	 * (3)
	 * Go through and update all the incoming edges of block2
	 */
	for (unsigned int e = 0; e < block2->in_edges.size(); e++)
	{
		block2->in_edges[e]->head = block1;
		block1->in_edges.push_back(block2->in_edges[e]);
#ifdef __DEBUG__
		cout << "--- Incoming edges changed to " << block1->number << ": " << block2->in_edges[e]->tail->number << " --> " << block2->in_edges[e]->head->number << endl;
#endif
	}
	// Erase all the incoming edges from block2
	block2->in_edges.erase(block2->in_edges.begin(), block2->in_edges.end());

	/*
	 * (3)
	 * Go through and update all the outgoing edges of block2
	 */
	for (unsigned int e = 0; e < block2->edges.size(); e++)
	{
#ifdef __DEBUG__
		cout << "SIZE: " << block2->edges.size() << " --- " << block2->edges[e]->head->number << endl;
#endif
		// Delete if there is a self loop
		if (block2->edges[e]->head->number == block1->number)
		{
			for (unsigned int e1 = 0; e1 < block1->in_edges.size(); e1++)
			{
				if (block1->in_edges[e1]->tail->number == block2->number)
				{
					block1->in_edges.erase(block1->in_edges.begin()+e1);
					break;
				}
			}
#ifdef __DEBUG__
			cout << "-  Deleting edge: " << block2->edges[e]->tail->number << " --> " << block2->edges[e]->head->number << endl;
#endif
			delete (block2->edges[e]);
		}
		else
		{
			bool EDGE_EXIST = false;
			for (unsigned int e1 = 0; e1 < block1->edges.size(); e1++)
			{
				if (block1->edges[e1]->head->number == block2->edges[e]->head->number)
				{
					EDGE_EXIST = true;
					Block *block = block2->edges[e]->head;
					for (unsigned int e2 = 0; e2 < block->in_edges.size(); e2++)
					{
						if (block->in_edges[e2]->tail->number == block1->number)
						{
							block->in_edges.erase(block->in_edges.begin()+e2);
							break;
						}
					}
#ifdef __DEBUG__
					cout << "-- Deleting edge: " << block1->edges[e1]->tail->number << " --> " << block1->edges[e1]->head->number << endl;
#endif
					delete (block1->edges[e1]);
					block1->edges.erase(block1->edges.begin()+e1);
					break;
				}
			}
			block2->edges[e]->tail = block1;
			block1->edges.push_back(block2->edges[e]);
#ifdef __DEBUG__
			cout << "--- Outgoing edges changed to : " << block2->edges[e]->tail->number << " --> " << block2->edges[e]->head->number << endl;
#endif
		}
	}
	// Erase all the outgoing edges from block2
	block2->edges.erase(block2->edges.begin(), block2->edges.end());
}

/*
 *
 * This function builds all the functions' CFGs
 *
 */
void CFG::Build(string filename)
{
	for (int f = 0; f < (int)functions.size(); f++)
		findLoops(functions[f]);
	findLoops(NULL);

#ifdef __DEBUG__
	bool stmts = true;
	bool dot = true;
	Print(filename, stmts, dot);
#endif
}

vector<Block *> CFG::GetBlocks()
{
	return (blocks);
}

vector<BackEdge *> CFG::GetBackEdges()
{
	return (backEdges);
}

vector<Function *> CFG::GetFunctions()
{
	return (functions);
}

string CFG::GetFilename()
{
	return (filename);
}

/*
 *
 * Check if the two blocks block (start) and end are connected and in
 * turn find all the blocks in the loops tail = start and head = end
 *
 */
void CFG::isConnectedAndLoops(Block *block, Block *end, Loop *loop, vector<Block *> *visited)
{
	if (block == NULL || block->type == BLOCK_END_OF_FUNCTION || block->type == BLOCK_END_OF_PROGRAM)
	{
#ifdef __DEBUG__
      cerr << dec << "END REACHED\n";
      if (visited->size() > 0)
         cout << "\nDELETING: ";
#endif
		for (int b = 0; b < (int)visited->size(); b++)
		{
			Block *block = visited->at(b);
         block->visited = false;
#ifdef __DEBUG__
         cout << "b" << block->number << ":";
#endif
		}
#ifdef __DEBUG__
      if (visited->size() > 0)
         cout << endl;
#endif
		visited->erase(visited->begin(), visited->end());
	}
	else if (block != end)
	{
		for (uint64_t e = 0; e < block->edges.size(); e++)
		{
			if (!block->edges[e]->tail->visited)
			{
			   block->edges[e]->tail->visited = true;
			   visited->push_back(block->edges[e]->tail);
			}
			if (block->edges[e]->head->visited)
			{
            if (CONNECTED
				&& block->edges[e]->tail->number < block->edges[e]->head->number
                  && !block->edges[e]->tail->inLoop && block->edges[e]->head->inLoop)
            {
#ifdef __DEBUG__
               if (visited->size() > 0)
                  cout << dec << "\nENTERING: ";
               cout << block->edges[e]->tail->number << " --> " << block->edges[e]->head->number << ": ";
#endif
               for (int b = 0; b < (int)visited->size(); b++)
               {
                  Block *block = visited->at(b);
                  block->inLoop = true;
                  loop->blocks.push_back(block);
#ifdef __DEBUG__
                  cout << "b" << block->number << ":";
#endif
               }
#ifdef __DEBUG__
               if (visited->size() > 0)
                  cout << endl;
#endif
               visited->erase(visited->begin(), visited->end());
            }
			}
			else if (!block->edges[e]->visited && block->edges[e]->tail->number < block->edges[e]->head->number)
			{
#ifdef __DEBUG__
            cout << "b" << block->edges[e]->tail->number << ":b" << block->edges[e]->head->number << " ";
#endif
            isConnectedAndLoops (block->edges[e]->head, end, loop, visited);
            block->edges[e]->visited = true;
			}
		}
	}
	else
	{
	   CONNECTED = true;
#ifdef __DEBUG__
      if (visited->size() > 0)
    	  cout << "\nENTERING: " << dec << CONNECTED << ": ";
#endif
	   if (!end->visited)
	   {
         visited->push_back(end);
         end->visited = true;
      }
		for (int b = 0; b < (int)visited->size(); b++)
		{
			Block *block = visited->at(b);
			block->inLoop = true;
			loop->blocks.push_back(block);
#ifdef __DEBUG__
         cout << "b" << block->number << ":";
#endif
		}
#ifdef __DEBUG__
      if (visited->size() > 0)
         cout << endl;
#endif
		visited->erase(visited->begin(), visited->end());
	}
}

/*
 *
 * Find loops (all the blocks in a loop) by checking each back edge
 *
 */
void CFG::findLoops(Function *function)
{
	vector<BackEdge *> be;
	if (function != NULL)
		be = function->backEdges;
	else
		be = backEdges;

	for (unsigned int e = 0; e < be.size(); e++)
	{
#ifdef __DEBUG__
		cout << "\n------------------------------\n" << function->blocks[0]->function_number << endl;
		cout << "\nBACK EDGE: " << dec << be[e]->head->number << ":" << be[e]->tail->number << endl;
#endif
		vector<Block *> blks;
		if (function != NULL)
			blks = function->blocks;
		else
			blks = blocks;
		for (unsigned int b = 0; b < blks.size(); b++)
		{
			blks[b]->inLoop = false;
			blks[b]->visited = false;
			for (unsigned int e = 0; e < blks[b]->edges.size(); e++)
				blks[b]->edges[e]->visited = false;
		}
		Loop *loop = new Loop();
		/*
		 * head = end and tail = start
		 */
		vector<Block *> visited;
		CONNECTED = false;
		isConnectedAndLoops(be[e]->tail, be[e]->head, loop, &visited);
		/*
		* If connected i.e; there are loops
		*/
		if (loop->blocks.size() > 0)
		{
			/*
			 * Here we only update the function the loop belongs to.
			 * The nested loops will be updated when all the loops are found.
			 */
			loop->backEdge = be[e];
			if (function != NULL)
				function->loops.push_back(loop);
			else
				loops.push_back(loop);

#ifdef __DEBUG__
			cout << "b" << be[e]->tail->statements[0]->offset << " ";
			for (int p = 0; p < loop->nestedLoops.size(); p++)
				cout << "-";
			cout << "> " << "b" << backEdges[e]->head->number << " -> " << backEdges[e]->tail->number << endl;
#endif
		}
		else
			delete (loop);
#ifdef __DEBUG__
		cerr << "\n------------------------------\n";
#endif
	}
	updateNestedLoops(function);
}

/*
 *
 * Checks for the nested loops in a function
 *
 * e.g:
 *
 * for the following loops
 * 1  2  3
 *
 * 1:2, 1:3 and 2:3
 * (it checks 1 against 2 and 3 and then 2 against 3)
 *
 * A loop is a nested loop within another loop if it's
 * a subset of that loop
 * e.g:
 *
 * if
 * loop A = { 1, 2, 3, 4, 5, 6 }
 * loop B = { 2, 3, 4 }
 * where 1, 2, 3 . . . are the basic block numbers
 * then loop B is nested within loop A
 *
 */
void CFG::updateNestedLoops(Function *function)
{
	vector<Loop *> loop_s;
	if (function != NULL)
		loop_s = function->loops;
	else
		loop_s = loops;

	for (int ln_1 = 0; ln_1 < (int)loop_s.size(); ln_1++)
	{
		Loop *loop_1 = loop_s.at(ln_1);
		vector<Block *> loop_1_blocks = loop_1->blocks;
		uint64_t loop_1_blocks_size = loop_1_blocks.size();
		uint64_t EQUAL_COUNT;

		for (int ln_2 = ln_1+1; ln_2 < (int)loop_s.size(); ln_2++)
		{
			EQUAL_COUNT = 0;
			Loop *loop_2 = loop_s.at(ln_2);
			vector<Block *> loop_2_blocks = loop_2->blocks;
			uint64_t loop_2_blocks_size = loop_2->blocks.size();

			for (int b_1 = 0; b_1 < (int)loop_1_blocks_size; b_1++)
			{
				for (int b_2 = 0; b_2 < (int)loop_2_blocks_size; b_2++)
				{
					if (loop_1_blocks[b_1] == loop_2_blocks[b_2])
						EQUAL_COUNT++;
				}
				if (EQUAL_COUNT == loop_1_blocks_size)
				{
					loop_2->nestedLoops.push_back(loop_1);
					break;
				}
				else if (EQUAL_COUNT == loop_2_blocks_size)
				{
					loop_1->nestedLoops.push_back(loop_2);
					break;
				}
			}
		}
	}
}

/*
 *
 * Local method for comparing two loops for sorting
 *
 */
static bool compareLoops(const Loop *loop_1, const Loop *loop_2)
{
	return (loop_2->blocks.size() < loop_1->blocks.size());
}

/*
 *
 * Color all the loops using the dot format.
 *
 * It first sorts the loop in ascending order
 * so that the nested loops get different
 * colors and then color the loops selecting
 * colors from the array one by one.
 *
 */
string CFG::colorLoops(Function *function)
{
	stringstream loop_str;
	string colors[] = { "cyan3",
                       "red",
                       "green",
                       "blue",
                       "cyan",
                       "khaki",
                       "ivory",
                       "skyblue",
                       "tan",
                       "brown1",
                       "wheat",
                       "yellow",
                       "magenta",
                       "salmon",
                       "orange",
                       "coral",
                       "thistle",
                       "red4",
                       "green4",
                       "blue4",
                       "cyan4",
                       "khaki4",
                       "ivory4",
                       "skyblue4",
                       "tan4",
                       "brown4",
                       "wheat4",
                       "yellow4",
                       "magenta4",
                       "salmon4",
                       "orange4",
                       "coral4",
                       "thistle4"
                     };

	vector<Loop *> loop_s;
	if (function != NULL)
		loop_s = function->loops;
	else
		loop_s = loops;

	sort(loop_s.begin(), loop_s.end(), compareLoops);

	int cn = 0;
	loop_str.str("");
	for (unsigned int ln = 0; ln < loop_s.size(); ln++, cn++)
	{
		for (unsigned int b = 0; b < loop_s[ln]->blocks.size(); b++)
		{
			/*
			 * We are at the end of the color array so
			 * start the color list from the beginning
			 */
			if (cn >= (int)sizeof(colors)/(int)sizeof(colors[0]))
				cn = 0;
			Block *block = loop_s[ln]->blocks[b];
			loop_str << "b" << dec << block->number << " [label=b" << block->number << ", color="<< colors[cn] << ", fontcolor=black" << ", width=0.2, height=0.1];\n";
		}
	}
	return loop_str.str();
}

/*
 *
 */
void CFG::Print(string filename, bool stmts, bool dot)
{
	string dot_graph;

	// PRINTING CFG (BLOCKS) FOR ALL THE FUNCTIONS FOR TESTING
	for (int f = 0; f < (int)functions.size(); f++)
	{
		printf ("|----------------------------------------------------------------\n");
		printf ("|   Function number      Number of blocks      Number of loops\n");
		printf ("|        %5d               %5d                %5d\n", f, (int)functions[f]->blocks.size(), (int)functions[f]->loops.size());
		printf ("|----------------------------------------------------------------\n");
		printf ("|   Printing blocks:\n");
		vector<Block *> blcks = functions[f]->blocks;
		if (stmts)
		{
			for (unsigned int b = 0; b < blcks.size(); b++)
			{
				printf ("Printing block number: %5d   ", b);
				if (blcks[b]->type == BLOCK_START_OF_PROGRAM)
					printf ("%20s", "START_OF_PROGRAM");
				else if (blcks[b]->type == BLOCK_START_OF_FUNCTION)
				{
					printf ("%20s", "[START_OF_FUNCTION");
   					printf ("%5d]", blcks[b]->function_number);
				}
				else if (blcks[b]->type == BLOCK_END_OF_FUNCTION)
				{
					printf ("%20s", "[END_OF_FUNCTION");
					printf ("%5d]", blcks[b]->function_number);
				}
				else if (blcks[b]->type == BLOCK_END_OF_PROGRAM)
				{
					printf ("%20s", "[END_OF_PROGRAM");
					printf ("%5d]", blcks[b]->function_number);
				}
				else
					printf ("   [%5d]   ", blcks[b]->function_number);
				printf ("Edges: %d: ", (int)blcks[b]->edges.size());
				for (int n = 0; n < (int)blcks[b]->edges.size(); n++)
					printf ("%d -> %d : ", (int)blcks[b]->edges[n]->tail->number, (int)blcks[b]->edges[n]->head->number);
				printf ("\n");
				if (blcks[b]->statements.size() > 0)
				{
					for (int i = 0; i < (int)blcks[b]->statements.size(); i++)
					{
						Statement *stmt = blcks[b]->statements[i];
						printf ("     %12x", (int)stmt->offset);
						printf ("%55s", stmt->value.c_str());
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
					printf ("Error:initBlcks::Print: Block [%d:%d] without instructions\n", b, (int)blcks[b]->function_number);
			}
			printf ("\n");
			vector<Loop *> loop_s = functions[f]->loops;
			for (uint64_t ln = 0; ln < loop_s.size(); ln++)
			{
				printLoop(loop_s[ln], ln);
				printf("\n");
			}
		}
		if (dot)
		{
			char temp_str[MAX_FILENAME_LENGTH+1];
			sprintf(temp_str, "%s_function_%d.dot", filename.c_str(), f);
			dot_graph += printDOT((char *)temp_str, functions[f]);
		}
	}
	if (dot)
	{
		char temp_str[MAX_FILENAME_LENGTH+1];
		sprintf(temp_str, "%s.dot", filename.c_str());
		dot_graph += printDOT((char *)temp_str, NULL);

		ofstream file("build_graph.bat", ios::out | ios::binary | ios::ate);
		file.write((const char *)dot_graph.c_str(), dot_graph.length());
	}
}

/*
 *
 * Recursively prints the loops and the nested loops
 * keeping in the maximum limit of the nested loop count
 * as defined in common.h
 *
 */
void CFG::printLoop(Loop *loop, uint64_t ln)
{
   printf("\n----------------------------------------------------------------------------------------------\n");
   printf("|   Printing Loop # %d\n", (int)ln);
   printf("|      Back Edge: b%d : b%d\n", (int)loop->backEdge->head->number, (int)loop->backEdge->tail->number);
   vector<Block *> blocks;
   blocks = loop->blocks;
   printf("|      Printing blocks: %d", (int)blocks.size());
   printf("\n");
   printf("|      b%d", (int)blocks[0]->number);
   for (int b = 1; b < (int)blocks.size(); b++)
      printf(":b%d", (int)blocks[b]->number);
   printf("\n");

   if (loop->nestedLoops.size() > 0)
   {
      printf("|   Printing %d Nested Loops\n", (int)loop->nestedLoops.size());
      vector<Loop *> nloops = loop->nestedLoops;
      for (int nl = 0; nl < (int)nloops.size(); nl++)
      {
         printf("   -------------------------------\n");
         printf("   |   Printing Nested Loop # %d\n", (int)nl);
         printf("   |   Back Edge: b%d : b%d\n", (int)nloops[nl]->backEdge->head->number, (int)nloops[nl]->backEdge->tail->number);
         blocks = nloops[nl]->blocks;
         printf("   |   Printing blocks: %d", (int)blocks.size());
         printf("\n");
         printf("   |   b%d", (int)blocks[0]->number);
         for (int b = 1; b < (int)blocks.size(); b++)
            printf(":b%d", (int)blocks[b]->number);
         printf("\n   -------------------------------\n");
      }
   }
   printf("----------------------------------------------------------------------------------------------\n");
}

/*
 *
 * Find all the paths in the CFG and print
 * them in a string to be printed for debugging.
 *
 * It uses DFS to walk through the CFG.
 *
 */
void CFG::DFS(Block *block, vector<int> path)
{
	for (uint64_t e = 0; e < block->edges.size(); e++)
	{
		if (!block->edges[e]->visited)
		{
			print_s << dec << "b" << block->edges[e]->tail->number << " -> ";
			block->edges[e]->visited = true;
			DFS (block->edges[e]->head, path);
		}
	}
	print_s << "b" << block->number << "\n";
}

/*
 *
 */
string CFG::printDOT(char *filename, Function *function)
{
	stringstream dot_graph;
	ofstream file(filename, ios::out | ios::binary | ios::ate);

	if (file.is_open())
	{
		vector<Block *> blcks;
		uint64_t start;
		uint64_t end;
		if (function != NULL)
		{
			blcks = function->blocks;
			start = blcks[0]->number;
			end = blcks[blcks.size()-1]->number;
		}
		else
		{
			blcks = blocks;
			start = blcks[0]->number;
			end = blcks[blcks.size()-1]->number;
		}
		for (unsigned int b = 0; b < blcks.size()-1; b++)
		{
			blcks[b]->visited = false;
			for (unsigned int e = 0; e < blcks[b]->edges.size(); e++)
				blcks[b]->edges[e]->visited = false;
		}
#ifdef __DEBUG__
		cout << "File : " << filename << " opened\n";
#endif
      string colors[] = { "cyan3",
                          "red",
                          "green",
                          "blue",
                          "cyan",
                          "khaki",
                          "ivory",
                          "skyblue",
                          "tan",
                          "brown1",
                          "wheat",
                          "yellow",
                          "magenta",
                          "salmon",
                          "orange",
                          "coral",
                          "thistle",
                          "red4",
                          "green4",
                          "blue4",
                          "cyan4",
                          "khaki4",
                          "ivory4",
                          "skyblue4",
                          "tan4",
                          "brown4",
                          "wheat4",
                          "yellow4",
                          "magenta4",
                          "salmon4",
                          "orange4",
                          "coral4",
                          "thistle4"
                        };
		stringstream block_s;
		block_s << "digraph CFG\n";
		block_s << "{\n";
		block_s << " // graph [fontname=Helvetica, overlaps=false, ratio=auto, page=\"11,17\"];\n";
		block_s << " node [shape=box, style=filled, fontsize=14, color=black, fontcolor=white, width=0.2, height=0.1];\n";
		block_s << " edge [color=black, fontsize=5, fontcolor=black];\n\n";

		block_s << " entry [label=Entry, color=cyan, width=0.2, height=0.1];\n";
		block_s << " exit [label=Exit, color=cyan, width=0.2, height=0.1];\n";
		bool COLOR_LOOPS = true;
		if (COLOR_LOOPS)
		{
			string loop_s = colorLoops(function);
			block_s << loop_s;
		}
		else
		{
			for (int b = 0; b < (int)blcks.size()-1; b++)
			{
				Block *bl = blcks[b];
				if (bl->type == BLOCK_START_OF_FUNCTION)
					block_s << " b" << bl->number << " [label=b" << bl->number << ", color=blue, fontcolor=yellow, width=0.2, height=0.1];\n";
				else if (bl->type == BLOCK_END_OF_FUNCTION)
					block_s << " b" << bl->number << " [label=b" << bl->number << ", color=red, fontcolor=yellow, width=0.2, height=0.1];\n";
				else if (bl->type == BLOCK_START_OF_PROGRAM)
					block_s << " b" << bl->number << " [label=b" << bl->number << ", color=cyan, fontcolor=black, width=0.2, height=0.1];\n";
				else if (bl->type == BLOCK_END_OF_PROGRAM)
					block_s << " b" << bl->number << " [label=b" << bl->number << ", color=black, fontcolor=cyan, width=0.2, height=0.1];\n";
				else
				{
#ifdef COLORED_GRAPH
					int c = blcks[b]->function_number;
					if (c >= 33)
						c = c % 33;
					block_s << dec << " b" << bl->number << " [label=b" << bl->number << ", color="<< colors[c] <<", fontcolor=white, width=0.2, height=0.1];\n";
#elif GREY_GRAPH
					block_s << dec << " b" << bl->number << " [label=b" << bl->number << ", color=grey, fontcolor=white, width=0.2, height=0.1];\n";
#else
					block_s << dec << " b" << bl->number << " [label=b" << bl->number << ", color=black, fontcolor=white, width=0.2, height=0.1];\n";
#endif
				}
			}
		}
		block_s << "\n";
		block_s << "entry -> b" << blcks[0]->number << "\n";

		print_s.str("");
		for (uint64_t b = 0; b < blcks.size()-1; b++)
		{
			for (uint64_t e = 0; e < blcks[b]->edges.size(); e++)
			{
				uint64_t tail = blcks[b]->edges[e]->tail->number;
				uint64_t head = blcks[b]->edges[e]->head->number;
				if (head >= start && head <= end)
					print_s << dec << "b" << tail << " -> b" << head << "\n";
			}
 		}

#ifdef __DEBUG__
			cout << "Running DFS\n";
#endif
#ifdef __DEBUG__
		cout << "DFS completed\n";
#endif

		block_s << print_s.str();
		block_s << "\n";

		block_s << "b" << blcks[blcks.size()-1]->number << " -> exit\n";
		block_s << "}\n";

		file.write((const char *)block_s.str().c_str(), block_s.str().length());
		if (blcks.size() < 100)
			dot_graph << "dot -Tpdf " << filename << " -o " << filename << ".pdf\n";
		else
			dot_graph << "twopi -Tpdf " << filename << " -o " << filename << ".pdf\n";
#ifdef __DEBUG__
		cout << "Written " << block_s.str().length() << " bytes to file: " << filename << endl;
#endif
	}

	file.close();
	return (dot_graph.str());
}


/*
 *
 */
void CFG::PrintBlock(Block *b)
{
	printf ("Printing block number: %5d:\n", (int)b->number);
	printf ("\n Number    Offset                                                                                                      MAIL Statement                                                                                         Pattern    Block/Function   Jump To\n\n");
	for (int i = 0; i < (int)b->statements.size(); i++)
	{
		Statement *stmt = b->statements[i];
		printf ("%5d", i);
		printf ("%12x", (int)stmt->offset);
		printf ("%200s [%12s]", stmt->value.c_str(), PatternsNames[stmt->type]);
		if (stmt->start)
			printf("%12s", "START");
		if (stmt->end)
			printf("%12s", "END");
		if (stmt->branch_to_offset == END_OF_FUNCTION)
			printf ("%16s", "END_OF_FUNCTION");
		if (stmt->branch_to_offset != BRANCH_TO_UNKNOWN && stmt->branch_to_offset != END_OF_FUNCTION)
			printf ("%16x", (int)stmt->branch_to_offset);
		printf ("\n");
	}
}


/*
 *
 */
void CFG::PrintBlock(Block *b, bool statements)
{
	printf ("Printing block number: %5d:\n", (int)b->number);
	if (b->type == BLOCK_START_OF_PROGRAM)
		printf ("%20s", "START_OF_PROGRAM");
	else if (b->type == BLOCK_START_OF_FUNCTION)
	{
		printf ("%20s", "[START_OF_FUNCTION");
		printf ("%5d]", b->function_number);
	}
	else if (b->type == BLOCK_END_OF_FUNCTION)
	{
		printf ("%20s", "[END_OF_FUNCTION");
		printf ("%5d]", b->function_number);
	}
	else if (b->type == BLOCK_END_OF_PROGRAM)
	{
		printf ("%20s", "[END_OF_PROGRAM");
		printf ("%5d]", b->function_number);
	}
	else
		printf ("   [%5d]   ", b->function_number);
	printf ("Outgoing Edges: %d: ", (int)b->edges.size());
	for (int n = 0; n < (int)b->edges.size(); n++)
		printf ("%d -> %d : ", (int)b->edges[n]->tail->number, (int)b->edges[n]->head->number);
	printf ("Incoming Edges: %d: ", (int)b->in_edges.size());
	for (int n = 0; n < (int)b->in_edges.size(); n++)
		printf ("%d -> %d : ", (int)b->in_edges[n]->tail->number, (int)b->in_edges[n]->head->number);
	printf ("\n");

	if (statements)
	{
		if (b->statements.size() > 0)
		{
			for (int i = 0; i < (int)b->statements.size(); i++)
			{
				Statement *stmt = b->statements[i];
				printf ("     %12x", (int)stmt->offset);
				if (stmt->value.size() > 0)
					printf ("%55s", stmt->value.c_str());
				if (stmt->start)
					printf("%12s", "START");
				if (stmt->end)
					printf("%12s", "END");
				if (stmt->branch_to_offset >= 0)
					printf ("%12x", (int)stmt->branch_to_offset);
				printf (" %3d", (int)stmt->type);
				printf ("\n");
			}
		}
		else
			printf ("Error:PrintBlock: [%d:%d] without statements\n", (int)b->number, (int)b->function_number);
	}
}
