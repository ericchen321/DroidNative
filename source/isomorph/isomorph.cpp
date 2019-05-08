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

#include "isomorph.h"

IsoMorph::IsoMorph()
{
}

IsoMorph::~IsoMorph()
{
}

/*
 *
 */
bool IsoMorph::MatchGraphs(CFG *cfg1, CFG *cfg2)
{
	ARGEdit ed1, ed2;

	vector<Block *> blocks1 = cfg1->GetBlocks();
	for (int b = 0; b < blocks1.size(); b++)
	{
		ed1.InsertNode(NULL);
		for (int e = 0; e < blocks1[b]->edges.size(); e++)
		{
			uint16_t tail = blocks1[b]->edges[e]->tail->number;
			uint16_t head = blocks1[b]->edges[e]->head->number;
			if (head != tail)
				ed1.InsertEdge(tail, head, NULL);
		}
	}

	vector<Block *> blocks2 = cfg2->GetBlocks();
	for (int b = 0; b < blocks2.size(); b++)
	{
		ed2.InsertNode(NULL);
		for (int e = 0; e < blocks2[b]->edges.size(); e++)
		{
			uint16_t tail = blocks2[b]->edges[e]->tail->number;
			uint16_t head = blocks2[b]->edges[e]->head->number;
			if (head != tail)
				ed2.InsertEdge(tail, head, NULL);
		}
	}

	Graph g1(&ed1);
	Graph g2(&ed2);
	VF2SubState s(&g1, &g2);

	int n = 0;
	node_id n1[MAX_NODES], n2[MAX_NODES];

	set_counter();
	if (match(&s, &n, n1, n2, 0))
	{
		uint32_t totalCount = cfg1->GetBlocks().size();
		uint32_t matchCount = n;
		uint32_t percentageCount = (100 * matchCount) / totalCount;

		for (int i = 0; i < n; i++)
		{
			cout << "\tNode " << n1[i] << " of graph 1 is paired with node " << n2[i] << " graph 2\n";
		}

		if (percentageCount >= THRESHOLD_FOR_MALWARE_NODE_MATCHING_OUT_OF_100)
			return true;
	}
#ifdef __DEBUG__
	else
		cout << "Found matching with " << n << " nodes" << endl;
#endif

	return false;
}

/*
 *
 */
bool IsoMorph::MatchGraphs(Graph *g1, CFG *cfg1, Graph *g2, CFG *cfg2)
{
	VF2SubState s(g1, g2);

	int n = 0;
	node_id n1[MAX_NODES], n2[MAX_NODES];

	int id = 0;
	set_counter();
	if (match(&s, &n, n1, n2, id))
	{
		/*
		 * We want to see here if all the nodes of the first graph
		 * matches with the same number of nodes of the second graph.
		 * If this is the case then we match the corresponding blocks
		 * of the CFGs. This is helpful if the first graph (g1) is a
		 * malware sample and we want to see if it's found in the
		 * second graph (g2). Even if all the nodes match we still
		 * match the MAIL patterns in the corresponding block to make
		 * sure there is a match. The reason being: it's possible for
		 * a small CFG (e.g: 3 nodes) of a malware to be matched
		 * against a large CFG of a benign program. We check if any
		 * of the matched nodes does not match using the pattern
		 * matching techniques. If only one of the nodes does not
		 * match we return false matching.
		 */
		if (n == g1->NodeCount())
		{
#ifdef __DEBUG__
			cout << "Found matching with " << n << " nodes" << endl;
#endif
			vector<Block *> blocks1 = cfg1->GetBlocks();
			vector<Block *> blocks2 = cfg2->GetBlocks();
			uint64_t bn1 = 0;
			uint64_t bn2 = 0;
			for (int i = 0; i < n; i++)
			{
				bn1 = n1[i];
				bn2 = n2[i];
				if (!patternMatch(blocks1[bn1], blocks2[bn2]))
					return false;
			}
#ifdef __DEBUG__
cerr << "--- MATCH START ---\n";
			cout << "--- MATCH START ---\n";
			cout << "Node " << bn1 << " of graph 1 is paired with node " << bn2 << " of graph 2\n";
			bool only_statements = true;
			cfg1->PrintBlock(blocks1[bn1], only_statements);
			cfg2->PrintBlock(blocks2[bn2], only_statements);
			cout << "--- MATCH ENDS ---\n\n";
#endif
			return true;
		}
		else
		{
			uint32_t totalCount = cfg1->GetBlocks().size();
			uint32_t matchCount = n;
			uint32_t percentageCount = (100 * matchCount) / totalCount;
			if (percentageCount >= THRESHOLD_FOR_MALWARE_NODE_MATCHING_OUT_OF_100)
			{
				vector<Block *> blocks1 = cfg1->GetBlocks();
				vector<Block *> blocks2 = cfg2->GetBlocks();
				uint64_t bn1 = 0;
				uint64_t bn2 = 0;
				for (int i = 0; i < n; i++)
				{
					bn1 = n1[i];
					bn2 = n2[i];
					if (!patternMatch(blocks1[bn1], blocks2[bn2]))
						return false;
				}
#ifdef __DEBUG__
				cout << "--- MATCH START ---\n";
				cout << "Node " << bn1 << " of graph 1 is paired with node " << bn2 << " of graph 2\n";
				bool only_statements = true;
				cfg1->PrintBlock(blocks1[bn1], only_statements);
				cfg2->PrintBlock(blocks2[bn2], only_statements);
				cout << "--- MATCH ENDS ---\n\n";
#endif
				return true;
			}
		}
	}
#ifdef __DEBUG__
	else
		cout << "Found matching with " << n << " nodes" << endl;
#endif

	return false;
}

/*
 * Every statement has a type that corresponds to a pattern.
 * If all the statements in blocks have a different pattern (type)
 * then this function returns false, i.e: there is no match.
 */
bool IsoMorph::patternMatch(Block *b1, Block *b2)
{
	uint16_t diff = abs((int)b2->statements.size() - (int)b1->statements.size());
	if (diff > STATEMENTS_DIFF_LIMIT_FOR_PATTERN_MATCHING)
		return false;

	uint32_t size = (b1->statements.size() < b2->statements.size()) ? b1->statements.size() : b2->statements.size();
	for (int s = 0; s < (int)size; s++)
	{
#ifdef __DEBUG__
		cerr << b1->statements[s]->type << " ?= " << b2->statements[s]->type << endl;
		cout << b1->statements[s]->type << " ?= " << b2->statements[s]->type << endl;
#endif
		if (b1->statements[s]->type != b2->statements[s]->type)
			return false;
	}
	return true;
}

/*
 *
 */
Graph *IsoMorph::BuildGraph(CFG *cfg)
{
	ARGEdit *ed = new ARGEdit();
	vector<Block *> blocks = cfg->GetBlocks();
	for (int b = 0; b < (int)blocks.size(); b++)
	{
		ed->InsertNode(NULL);
		for (int e = 0; e < (int)blocks[b]->edges.size(); e++)
		{
			uint16_t tail = blocks[b]->edges[e]->tail->number;
			uint16_t head = blocks[b]->edges[e]->head->number;
			if (head != tail)
				ed->InsertEdge(tail, head, NULL);
		}
	}

	Graph *g = new Graph(ed);
	delete (ed);
	return (g);
}
