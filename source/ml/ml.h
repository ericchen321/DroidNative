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

#ifndef __ML_H__
#define __ML_H__

#ifdef __WIN32__
#include <windows.h>
#elif __LINUX__
#include <unistd.h>
#endif

#include "../cfg/cfg.h"
#include "../isomorph/argraph.h"
#include "../isomorph/argedit.h"
#include "../isomorph/isomorph.h"
#include "../mail/signature.h"

#define MAX_THREADS_LIMIT                                   2048
/*
 * WINDOWS multithreaded definitions
 */
//#define __MULTI_THREAD__                                    1
#define __SINGLE_THREAD__                                   1

typedef struct
{
	Graph *gs;
	CFG *cfgs;
} _SignaturesACFG;

#ifdef __WIN32__
typedef struct
{
	HANDLE managerThread;
	vector <Graph *> gs;
	vector <CFG *> cfgs;
	uint32_t fn;
	uint32_t number_of_threads;
	uint32_t THREAD_COUNT_UP;
	uint32_t THREAD_COUNT_DOWN;
} ThreadPool, *ThreadPoolP;
#endif

typedef struct
{
	_SignaturesACFG *sig;
	vector <CFG *> cfgs;
#ifdef __WIN32__
	ThreadPool *tp;
#endif
} Graphs, *GraphsP;

typedef struct
{
	string filename;
	uint32_t filenumber;
	bool benign;
	double simscore;
} FileReport;

using namespace std;

/**
 * <p>
 *
 * This class implements the ML class.
 *
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since March 30, 2013
 *
 */
class ML
{
private:
	uint32_t numCPU;
	uint32_t THREAD_POOL_COUNT;
   uint64_t COMMON_CFGS;

public:
	ML(uint32_t max_threads, double THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING);
	~ML();
	void BuildDataUsingGraphMatching(vector <CFG *> cfgs);
	void BenignUsingGraphMatching(vector <Graph *> gs, vector <CFG *> cfgs, uint32_t filenumber);
	void BuildDataUsingSignatureMatching(SIGNATURE *sig, double VERTICAL_SIGNATURE_DIFF, double HORIZONTAL_SIGNATURE_DIFF);
	void BenignUsingSignatureMatching(SIGNATURE *sig, uint32_t filenumber, double VERTICAL_SIGNATURE_DIFF, double HORIZONTAL_SIGNATURE_DIFF);
	void SaveACFGSignatures(string filename);
	uint64_t LoadACFGSignatures(string filename);
	uint64_t LoadMalwareACFGSignaturesPerSample(string filename);
	vector<CFG *> LoadTestingACFGSignatures(string filename);
	void SaveSWODSignatures(string filename); // NOT IMPLEMENTED
	uint64_t LoadSWODSignatures(string filename); // NOT IMPLEMENTED
	uint64_t GetDistinguishCFGs();
	uint64_t GetCommonCFGs();
};

#endif // __ML_H__
