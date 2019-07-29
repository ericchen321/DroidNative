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

#ifndef __ISOMORPH_H__
#define __ISOMORPH_H__

#include "../cfg/cfg.h"
#include "argraph.h"
#include "argedit.h"
#include "vf2_sub_state.h"
#include "match.h"

#define THRESHOLD_FOR_MALWARE_NODE_MATCHING_OUT_OF_100      90
#define STATEMENTS_DIFF_LIMIT_FOR_PATTERN_MATCHING          0
#define MAX_NODES                                           65535

using namespace std;

/**
 * <p>
 *
 * This class implements the IsoMorph class.
 * It checks the two control flow graphs (CFGs)
 * for matching (isomorphism). If one of the graphs
 * is a smaller graph then it checks for the subgraph
 * matching (isomorphism).
 *
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since March 30, 2013
 *
 */
class IsoMorph
{
private:
	bool patternMatch(Block *b1, Block *b2);
	void findPattern(Statement *stmt);

public:
	IsoMorph();
	~IsoMorph();
	bool MatchGraphs(CFG *cfg1, CFG *cfg2);
	bool MatchGraphs(Graph *g1, CFG *cfg1, Graph *g2, CFG *cfg2);
	Graph *BuildGraph(CFG *cfg);
};

#endif // __ISOMORPH_H__
