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

#include "ml.h"

extern uint64_t PATTERNS_WEIGHT[NUMBER_OF_PATTERNS];

//#define __MULTI_THREAD__

#ifdef __WIN32__
CRITICAL_SECTION cs, cs_m;
#endif

/*
 * WINDOWS multithreaded definitions
 */
int32_t MAX_THREADS;
int32_t MANAGER_THREAD_COUNT;
int32_t THREAD_COUNT;
vector<FileReport *> FileReports;
vector<CFG *> SignaturesACFG;
vector<Graph *> SignaturesGraph;
vector<SIGNATURE *> MalwareSignatures;

static double THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING_PASSED = 25;

ML::ML(uint32_t max_threads, double THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING)
{
	COMMON_CFGS = 0;
	THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING_PASSED = THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING;
	MANAGER_THREAD_COUNT = 0;
	THREAD_COUNT = 0;
	THREAD_POOL_COUNT = 0;
	numCPU = 20;
#ifdef __WIN32__
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	numCPU = sysinfo.dwNumberOfProcessors;
	InitializeCriticalSection(&cs);
	InitializeCriticalSection(&cs_m);
#elif __LINUX__
	numCPU = sysconf(_SC_NPROCESSORS_ONLN);
#endif

	if (max_threads <= 0)
		MAX_THREADS = pow(numCPU, 3);
	else
		MAX_THREADS = max_threads;
	if (MAX_THREADS > MAX_THREADS_LIMIT)
		MAX_THREADS = MAX_THREADS_LIMIT;

#ifdef __PROGRAM_OUTPUT_ENABLED__
	cout << "Number of CPUs available: " << numCPU << endl;
	cout << "Number of maximum threads: " << MAX_THREADS << endl;
#endif
}

ML::~ML()
{
	for (int s = 0; s < (int)MalwareSignatures.size(); s++)
	{
		if (MalwareSignatures[s]->size > 0)
			delete (MalwareSignatures[s]->signature);
		delete (MalwareSignatures[s]);
	}
	MalwareSignatures.erase(MalwareSignatures.begin(), MalwareSignatures.end());
	MalwareSignatures.clear();

	for (int i = 0; i < SignaturesACFG.size(); i++)
		delete (SignaturesACFG[i]);
	for (int i = 0; i < SignaturesGraph.size(); i++)
		delete (SignaturesGraph[i]);
	SignaturesACFG.erase(SignaturesACFG.begin(), SignaturesACFG.end());
	SignaturesACFG.clear();
	SignaturesGraph.erase(SignaturesGraph.begin(), SignaturesGraph.end());
	SignaturesGraph.clear();

	for (int f = 0; f < (int)FileReports.size(); f++)
		delete (FileReports[f]);
	FileReports.erase(FileReports.begin(), FileReports.end());
	FileReports.clear();

#ifdef __WIN32__
	DeleteCriticalSection(&cs);
	DeleteCriticalSection(&cs_m);
#endif
}

uint64_t ML::GetDistinguishCFGs()
{
	return (SignaturesACFG.size());
}

uint64_t ML::GetCommonCFGs()
{
	return COMMON_CFGS;
}


/*
 *
 * Save the training signatures to a file
 *
 */
void ML::SaveACFGSignatures(string filename)
{
	vector<Block *> blocks;
	vector<BackEdge *> backEdges;
	CFG *_cfg = new CFG(blocks, backEdges, filename);
	_cfg->WriteToFile(SignaturesACFG, filename);
	printf("%d Signatures saved\n", (int)SignaturesACFG.size());
	delete(_cfg);
}

/*
 *
 * Load the training signatures from a file
 *
 */
uint64_t ML::LoadACFGSignatures(string filename)
{
	for (int i = 0; i < SignaturesACFG.size(); i++)
		delete (SignaturesACFG[i]);
	for (int i = 0; i < SignaturesGraph.size(); i++)
		delete (SignaturesGraph[i]);
	SignaturesACFG.erase(SignaturesACFG.begin(), SignaturesACFG.end());
	SignaturesACFG.clear();
	SignaturesGraph.erase(SignaturesGraph.begin(), SignaturesGraph.end());
	SignaturesGraph.clear();

	vector<Block *> blocks;
	vector<BackEdge *> backEdges;
	CFG *_cfg = new CFG(blocks, backEdges, filename);
	vector<CFG *> cfgs = _cfg->ReadFromFile(filename);
	delete(_cfg);
	IsoMorph *isom = new IsoMorph();

	for (vector<CFG *>::iterator cfgi = cfgs.begin() ; cfgi != cfgs.end(); cfgi++)
	{
		CFG *cfg = *cfgi;
		Graph *g = isom->BuildGraph(cfg);
		SignaturesACFG.push_back(cfg);
		SignaturesGraph.push_back(g);
	}
	printf("%d Signatures loaded\n", (int)SignaturesACFG.size());

	delete (isom);
	return (SignaturesACFG.size());
}

/*
 *
 * Save the training signatures to a file
 *
 */
void ML::SaveSWODSignatures(string filename)
{
	ofstream file(filename.c_str(), ios::out | ios::binary | ios::app);
	if (file.is_open())
	{
		file << "PAT\n";
		int p = 0;
		for ( ; p < ((int)NUMBER_OF_PATTERNS-1); p++)
		{
			file << (int)PATTERNS_WEIGHT[p] << ":";
		}
		file << (int)PATTERNS_WEIGHT[p] << "\n";
		for (int s = 0; s < (int)MalwareSignatures.size(); s++)
		{
			file << "SIG" << (int)MalwareSignatures[s]->size << "\n";
			int i = 0;
			for ( ; i < ((int)MalwareSignatures[s]->size-1); i++)
			{
				file << MalwareSignatures[s]->signature[i] << ":";
			}
			file << MalwareSignatures[s]->signature[i] << "\n";
		}
		file.close();
	}
	else
		cout << "Error:DroidNative:ML::SaveSWODSignatures: Cannot open the file: " << filename << "\n";
}

/*
 *
 * Load the training signatures from a file
 *
 */
uint64_t ML::LoadSWODSignatures(string filename)
{
	for (int s = 0; s < (int)MalwareSignatures.size(); s++)
	{
		if (MalwareSignatures[s]->size > 0)
			delete (MalwareSignatures[s]->signature);
		delete (MalwareSignatures[s]);
	}
	MalwareSignatures.erase(MalwareSignatures.begin(), MalwareSignatures.end());
	MalwareSignatures.clear();

	bool ARE_WEIGHTS_ASSIGNED = false;
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
			// Signatures are stored as two lines
			// The first line starts with tag SIG and the size of the signature as
			// SIG11
			string tag = line.substr(0, 3);
			if (tag == "SIG")
			{
				tag = line.substr(3, line.size());
				int size = atoi(tag.c_str());
				if (size > 0)
				{
					SIGNATURE *sig = new SIGNATURE();
					sig->non_zeros = 1;
					sig->size = (uint32_t)size;
					sig->signature = new uint32_t[sig->size];
					// The second line is the signature stored as
					// 3:9:17:5:0:0:1:4:2:1:0
					int size = 0;
					while (getline(buffer, tag, ':'))
					{
						if (size >= sig->size)
							break;
						sig->signature[size] = (uint32_t)atoi(tag.c_str());
						if (sig->signature[size] > 0)
							sig->non_zeros++;
						size++;
					}
					if (size < sig->size)
						cout << "Error:DroidNative:ML::LoadSWODSignatures: Size of SIG given " << sig->size << " > " << size << " than the signature stored" << "\n";
					MalwareSignatures.push_back(sig);
				}
			}
			else if (tag == "PAT")
			{
				int p = 0;
				while (getline(buffer, tag, ':'))
				{
					if (p >= (int)NUMBER_OF_PATTERNS)
						break;
					PATTERNS_WEIGHT[p] = (uint32_t)atoi(tag.c_str());
					p++;
				}
				if (p < (int)NUMBER_OF_PATTERNS)
					cout << "Error:DroidNative:ML::LoadSWODSignatures: Less number (" << p << ") of patterns stored\n";
				else
					ARE_WEIGHTS_ASSIGNED = true;
			}
		}
		delete (fileBuffer);
	}
	else
		cout << "Error:DroidNative:ML::LoadSWODSignatures: Cannot open the file: " << filename << "\n";

	if (ARE_WEIGHTS_ASSIGNED == true)
		return (MalwareSignatures.size());
	else
	{
		for (int s = 0; s < (int)MalwareSignatures.size(); s++)
		{
			if (MalwareSignatures[s]->size > 0)
				delete (MalwareSignatures[s]->signature);
			delete (MalwareSignatures[s]);
		}
		MalwareSignatures.erase(MalwareSignatures.begin(), MalwareSignatures.end());
		MalwareSignatures.clear();
		return (0);
	}
}

void ML::BuildDataUsingGraphMatching(vector <CFG *> cfgs)
{
	IsoMorph *isom = new IsoMorph();

	for (vector<CFG *>::iterator cfgi = cfgs.begin() ; cfgi != cfgs.end(); cfgi++)
	{
		CFG *cfg = *cfgi;
		Graph *g = isom->BuildGraph(cfg);
		bool MATCH = false;
		for (int s = 0; s < (int)SignaturesACFG.size(); s++)
		{
			if (isom->MatchGraphs(SignaturesGraph[s], SignaturesACFG[s], g, cfg))
			{
				COMMON_CFGS++;
				MATCH = true;
				delete (g);
				delete (cfg);
				break;
			}
		}
		if (MATCH == false)
		{
			SignaturesACFG.push_back(cfg);
			SignaturesGraph.push_back(g);
		}
	}

   delete (isom);

#ifdef __DEBUG__
	printf("ML::BuildDataUsingGraphMatching\n");
	cout  << "sig->cfgs.size(): " << sig->cfgs.size() << endl;
	for (int c = 0; c < (int)sig->cfgs.size(); c++)
	{
		vector<Block *> blocks = sig->cfgs[c]->GetBlocks();
		for (int b = 0; b < (int)blocks.size(); b++)
			sig->cfgs[c]->PrintBlock(blocks[b], true);
	}
#endif
}

#ifdef __MULTI_THREAD__
DWORD WINAPI MatchGraphs_T(LPVOID lpParam)
{
	DWORD id = GetCurrentThreadId();
	GraphsP graphs = (GraphsP)lpParam;
	IsoMorph *isom = new IsoMorph();
	ThreadPool *tp = graphs->tp;

	vector <CFG *> sig_cfgs = graphs->sig->cfgs;
	vector <Graph *> sig_gs = graphs->sig->gs;
	uint32_t totalCount = sig_cfgs.size();
	uint32_t matchCount = 0;
	bool LOCAL_DONE = false;
	for (int ss = 0; ss < sig_cfgs.size(); ss++)
	{
		for (int c = 0; c < tp->cfgs.size(); c++)
		{
			if (FileReports[tp->fn]->benign == false)
			{
				LOCAL_DONE = true;
				break;
			}
			else if (isom->MatchGraphs(sig_gs[ss], sig_cfgs[ss], tp->gs[c], tp->cfgs[c]))
			{
				matchCount++;
				break;
			}
		}
		uint32_t percentageCount = (100 * matchCount) / totalCount;
		if (LOCAL_DONE || percentageCount >= THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING_PASSED)
		{
			EnterCriticalSection(&cs);
			if (FileReports[tp->fn]->benign)
			{
#ifdef __DEBUG__
				cout << "Printing report: < " << FileReports[tp->fn]->filename << " > is not benign\n";
#endif
				FileReports[tp->fn]->benign = false;
			}
			THREAD_COUNT--;
			tp->THREAD_COUNT_DOWN--;
			LeaveCriticalSection(&cs);
			LOCAL_DONE = true;
			break;
		}
	}

	delete (isom);
	if (LOCAL_DONE == false)
	{
		EnterCriticalSection(&cs);
		THREAD_COUNT--;
		tp->THREAD_COUNT_DOWN--;
		LeaveCriticalSection(&cs);
	}

	return 0;
}

DWORD WINAPI ManageThreadPool_UsingGraphMatchingT(LPVOID lpParam)
{
	DWORD id = GetCurrentThreadId();
	ThreadPoolP tp = (ThreadPoolP)lpParam;
	tp->THREAD_COUNT_UP = 0;
	tp->number_of_threads = Signatures_ACFG.size();
	tp->THREAD_COUNT_DOWN = tp->number_of_threads;
	HANDLE *hThread = new HANDLE[tp->number_of_threads];
	GraphsP *graphs = new GraphsP[tp->number_of_threads];

	if (tp->number_of_threads <= MAX_THREADS)
	{
		for (unsigned int s = 0 ; s < tp->number_of_threads; s++)
		{
			graphs[s] = (GraphsP) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Graphs));
			graphs[s]->sig = Signatures_ACFG[s];
			graphs[s]->tp = tp;
			hThread[s] = CreateThread(NULL, 0, MatchGraphs_T, graphs[s], 0, &id);
			if (hThread[s] == NULL)
				cout << "Error creating thread " << s << endl;
			else
			{
				EnterCriticalSection(&cs);
				THREAD_COUNT++;
				tp->THREAD_COUNT_UP++;
				LeaveCriticalSection(&cs);
			}
		}
	}
	else
	{
		for (unsigned int s = 0 ; s < tp->number_of_threads; s++)
		{
			int32_t thread_count = tp->THREAD_COUNT_UP - (tp->number_of_threads - tp->THREAD_COUNT_DOWN);
			while (thread_count > MAX_THREADS)
			{
				Sleep (10);
				thread_count = tp->THREAD_COUNT_UP - (tp->number_of_threads - tp->THREAD_COUNT_DOWN);
			}
			graphs[s] = (GraphsP) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(Graphs));
			graphs[s]->sig = Signatures_ACFG[s];
			graphs[s]->tp = tp;
			hThread[s] = CreateThread(NULL, 0, MatchGraphs_T, graphs[s], 0, &id);
			if (hThread[s] == NULL)
				cout << "Error creating thread " << s << endl;
			else
			{
				EnterCriticalSection(&cs);
				THREAD_COUNT++;
				tp->THREAD_COUNT_UP++;
				LeaveCriticalSection(&cs);
			}
		}
	}

	while (tp->THREAD_COUNT_DOWN > 0)
	{
		Sleep (10);
	}

	CloseHandle(hThread);
	delete (hThread);
	delete (graphs);
	for (int c = 0; c < tp->cfgs.size(); c++)
	{
		delete (tp->cfgs[c]);
		delete (tp->gs[c]);
	}
	CloseHandle(tp->managerThread);
	HeapFree(GetProcessHeap(), 0, tp);
#ifdef __DEBUG__
	cerr << "Filenumber " << dec << tp->fn << " is checked\n";
#endif
	EnterCriticalSection(&cs_m);
	MANAGER_THREAD_COUNT--;
#ifdef __DEBUG__
	cout << FileReports[tp->fn]->filename << ": " << dec << id << ": " << tp->fn << " : " << MANAGER_THREAD_COUNT << ":" << endl;
#endif
	LeaveCriticalSection(&cs_m);
	return 0;
}
#endif

/*
 *
 * This function creates a graph and then matches this graph
 * with the other sampled graphs (signatures). If the size
 * of the number of samples to be matched is larger, then
 * this function may take quite some time. We need to
 * optimize this function.
 *
 * For optimization we parallelize this function using threads.
 *
 */
void ML::BenignUsingGraphMatching(vector <Graph *> gs, vector <CFG *> cfgs, uint32_t filenumber)
{
#ifdef __MULTI_THREAD__
//--------------------------------------------------
//                   MULTI THREAD
//--------------------------------------------------
	DWORD id;

	tp->gs = _gs;
	tp->cfgs = _cfgs;
	tp->fn = filenumber;
	tp->managerThread = CreateThread(NULL, 0, ManageThreadPool_UsingGraphMatchingT, tp, 0, &id);
	if (tp->managerThread == NULL)
		cout << "Error creating thread " << THREAD_POOL_COUNT << endl;
	else
	{
		EnterCriticalSection(&cs_m);
		MANAGER_THREAD_COUNT++;
		LeaveCriticalSection(&cs_m);
		THREAD_POOL_COUNT++;
	}
#else
//--------------------------------------------------
//                   SINGLE THREAD
//--------------------------------------------------
	IsoMorph *isom = new IsoMorph();
	double percentageCount = 0.0;
    uint32_t totalCount = cfgs.size();
    uint32_t matchCount = 0;

	FileReports[filenumber]->simscore = percentageCount;
    for (int s = 0; s < (int)SignaturesACFG.size(); s++)
	{
#ifdef __DEBUG__
		printf("ML::BenignUsingGraphMatching\n");
		cout  << "_cfgs.size(): " << _cfgs.size() << endl;
		for (int c = 0; c < (int)_cfgs.size(); c++)
		{
			vector<Block *> blocks = _cfgs[c]->GetBlocks();
			for (int b = 0; b < (int)blocks.size(); b++)
				_cfgs[c]->PrintBlock(blocks[b], true);
		}
		cout  << "sig_cfgs.size(): " << sig_cfgs.size() << endl;
		for (int c = 0; c < (int)sig_cfgs.size(); c++)
		{
			vector<Block *> blocks = sig_cfgs[c]->GetBlocks();
			for (int b = 0; b < (int)blocks.size(); b++)
				sig_cfgs[c]->PrintBlock(blocks[b], true);
		}
#endif
		for (int c = 0; c < (int)cfgs.size(); c++)
		{
				if (isom->MatchGraphs(SignaturesGraph[s], SignaturesACFG[s], gs[c], cfgs[c]))
				{
#ifdef __PROGRAM_CFG_MATCH_OUTPUT_ENABLED__
					printf("|                        |\n");
					printf("| Printing Matching CFGs |\n");
					printf("|                        |\n");
					printf("----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
					string filename;
					CFG *cfg_testing = cfgs[c];
					filename.assign(cfg_testing->GetFilename());
					printf("CFG from testing file (%s)\n", filename.c_str());
					vector<Block *> blocks = cfg_testing->GetBlocks();
					for (int b = 0; b < (int)blocks.size(); b++)
						cfg_testing->PrintBlock(blocks[b]);
					CFG *cfg_training = SignaturesACFG[s];
					filename.assign(cfg_training->GetFilename());
					printf("CFG from training file %s\n", filename.c_str());
					blocks = cfg_training->GetBlocks();
					for (int b = 0; b < (int)blocks.size(); b++)
						cfg_training->PrintBlock(blocks[b]);
					printf("----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------\n");
#endif
					matchCount++;
				}
		}
		if (matchCount > 0)
		{
			percentageCount = (100.0 * matchCount) / totalCount;
			FileReports[filenumber]->simscore = percentageCount;
			if (percentageCount >= THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING_PASSED)
			{
#ifdef __PROGRAM_CFG_TRACING_OUTPUT_ENABLED__
				printf("Testing file (%s)\n", FileReports[filenumber]->filename.c_str());
				CFG *cfg_training = SignaturesACFG[s];
				printf("Training file %s\n", cfg_training->GetFilename().c_str());
				printf("Sim score: %f percent\n", FileReports[filenumber]->simscore);
#endif
				FileReports[filenumber]->benign = false;
#ifdef __DEBUG__
				cerr << " === " << FileReports[filenumber]->filename << ": " << dec << percentageCount << " ===" << endl;
				cout << "Printing report: < " << FileReports[filenumber]->filename << " > is not benign\n";
				cerr << "Printing report: < " << FileReports[filenumber]->filename << " > is not benign\n";
#endif
				break;
			}
		}
		if (percentageCount >= THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING_PASSED)
			break;
	}

	delete (isom);
#ifdef __DEBUG__
	cerr << "ML::BenignUsingGraphMatching: END: MAX THREADS: " << dec << MAX_THREADS << endl;
#endif
	return;
#endif
}

void ML::BuildDataUsingSignatureMatching(SIGNATURE *sig, double VERTICAL_SIGNATURE_DIFF, double HORIZONTAL_SIGNATURE_DIFF)
{
	bool ALREADY_PRESENT = false;
	Signature sig_c;
	double percentScore = 0.0;

	for (int s = 0; s < (int)MalwareSignatures.size(); s++)
	{
		double percentScore = sig_c.AlmostEqual(MalwareSignatures[s], sig, VERTICAL_SIGNATURE_DIFF, HORIZONTAL_SIGNATURE_DIFF);
		if (percentScore >= HORIZONTAL_SIGNATURE_DIFF)
		{
			ALREADY_PRESENT = true;
			break;
		}
	}

	if (ALREADY_PRESENT == false)
		MalwareSignatures.push_back(sig);
}

/*
 * -------   TODO   -------
 *
 * Check and implement so that the sig is matched against all the
 * MalwareSignatures and then a percentage is calculated from the
 * the number of MalwareSignatures samples matched for detection.
 *
 * -------   TODO   -------
 */
void ML::BenignUsingSignatureMatching(SIGNATURE *sig, uint32_t filenumber, double VERTICAL_SIGNATURE_DIFF, double HORIZONTAL_SIGNATURE_DIFF)
{
#ifdef __DEBUG__
	cerr << "ML::BenignUsingSignatureMatching: MAX THREADS: " << dec << MAX_THREADS << endl;
#endif
#ifdef __MULTI_THREAD__
//--------------------------------------------------
//                   MULTI THREAD
//--------------------------------------------------
#ifdef __WIN32__
#endif
#else
//--------------------------------------------------
//                   SINGLE THREAD
//--------------------------------------------------
	Signature sig_c;
	double percentScore = 0.0;
	FileReports[filenumber]->simscore = percentScore;
	for (int s = 0; s < (int)MalwareSignatures.size(); s++)
	{
		double percentScore = sig_c.AlmostEqual(MalwareSignatures[s], sig, VERTICAL_SIGNATURE_DIFF, HORIZONTAL_SIGNATURE_DIFF);
		FileReports[filenumber]->simscore = percentScore;
		if (percentScore >= HORIZONTAL_SIGNATURE_DIFF)
		{
			FileReports[filenumber]->benign = false;
			break;
		}
	}
#endif
}
