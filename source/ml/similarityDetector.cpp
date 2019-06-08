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

#include "similarityDetector.h"

extern int32_t MAX_THREADS;
extern vector<_SignaturesACFG *> Signatures;
extern vector<SIGNATURE *> MalwareSignatures;
extern int32_t MANAGER_THREAD_COUNT;
extern int32_t THREAD_COUNT;
extern vector<FileReport *> FileReports;

int32_t THREAD_BUILD_GRAPHS;
#ifdef __WIN32__
CRITICAL_SECTION cs_s;
#endif

/*
 * ------------------------------------------------------------------------------------------------------
 *
 * SimilarityDetector::SimilarityDetector
 *
 * ------------------------------------------------------------------------------------------------------
 */
SimilarityDetector::SimilarityDetector()
{
	total_assigning_weight_time = 0.0;
	total_training_time = 0.0;
	total_testing_time = 0.0;

	THREAD_BUILD_GRAPHS = 0;
	ARE_WEIGHTS_ASSIGNED = false;
#ifdef __WIN32__
	InitializeCriticalSection(&cs_s);
#endif
}

/*
 * ------------------------------------------------------------------------------------------------------
 *
 * SimilarityDetector::~SimilarityDetector
 *
 * ------------------------------------------------------------------------------------------------------
 */
SimilarityDetector::~SimilarityDetector()
{
}

void SimilarityDetector::SetSizeSWOD(float vwod, float hwod, float threshold_vwod, float threshold_hwod, float threshold_vsd, float threshold_hsd)
{
	VERTICAL_WINDOW_OF_DIFF = vwod * threshold_vwod;
	HORIZONTAL_WINDOW_OF_DIFF = hwod * threshold_hwod;
	VERTICAL_SIGNATURE_DIFF = threshold_vsd;
	HORIZONTAL_SIGNATURE_DIFF = threshold_hsd;
}

void SimilarityDetector::SetThreshold(float threshold_gm)
{
	THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING = threshold_gm;
}

/*
 * ------------------------------------------------------------------------------------------------------
 *
 * SimilarityDetector::TrainDataUsingSignatureMatching
 *
 * ------------------------------------------------------------------------------------------------------
 */
void SimilarityDetector::TrainDataUsingSignatureMatching(string filenameP, ML *ml)
{
#ifdef __TRAINING_TIME__
	clock_t start = 0, end = 0;
	double time = 0.0;
#endif

	ifstream fileP(filenameP.c_str(), ios::in | ios::binary | ios::ate);
	if (fileP.is_open())
	{
		unsigned int fileSize = (unsigned int)fileP.tellg();                // How much buffer we need for the file
		fileP.seekg (0, ios::beg);
		char *fileBufferP = new char[fileSize+1];
		fileP.read(fileBufferP, fileSize);                                  // Read the file into the buffer
		fileP.close();
		fileBufferP[fileSize] = '\0';

		char filename[3*MAX_FILENAME+1];
		int c = 0;
		for (unsigned int n = 0; n < fileSize; n++)
		{
			if ( (c < 3*MAX_FILENAME) && (fileBufferP[n] == '\n' || fileBufferP[n] == '\r') )
			{
				filename[c] = '\0';
				ifstream file(filename, ios::in | ios::binary | ios::ate);
				if (file.is_open())
				{
					unsigned int size = (unsigned int)file.tellg();         // How much buffer we need for the file
#ifdef __PROGRAM_OUTPUT_ENABLED__
					printf("Training Data Using Signature Matching processing file: %s\n", filename);
					fflush(stdout);
#endif
					file.seekg (0, ios::beg);
					char *fileBuffer = new char[size+1];
					file.read(fileBuffer, size);                           // Read the file into the buffer
					file.close();
					fileBuffer[size] = '\0';

#ifdef __TRAINING_TIME__
					start = clock();
#endif
					Parser *parser = new Parser((uint8_t *)fileBuffer, size);
					parser->Parse(filename);
					SIGNATURE *sig = BuildSignature(parser->mail);
					ml->BuildDataUsingSignatureMatching(sig, VERTICAL_SIGNATURE_DIFF, HORIZONTAL_SIGNATURE_DIFF);

					delete (parser);
					delete (fileBuffer);
#ifdef __TRAINING_TIME__
					end = clock();
					time += (end - start);
#endif
				}
				else
					cout << "Error:SimilarityDetector::TrainDataUsingSignatureMatching:  Cannot open the file: " << filename << "\n";

				c = 0;
				filename[c] = '\0';
				if ( n < (fileSize-1) && (fileBufferP[n+1] == '\n' || fileBufferP[n+1] == '\r') )
					n++;
			}
			else if (c < 3*MAX_FILENAME)
				filename[c++] = fileBufferP[n];
			else
				c = 0;
		}
		delete (fileBufferP);
	}
	else
		cout << "Error:SimilarityDetector::TrainDataUsingSignatureMatching:  Cannot open the file: " << filenameP << "\n";

	string filename = filenameP + "." + TRAINING_FILE_EXTENSION + ".SWOD";
	printf("Writing training file %s\n", filename.c_str());
	ml->SaveSWODSignatures(filename);
	printf("Reading training file %s\n", filename.c_str());
	ml->LoadSWODSignatures(filename);

#ifdef __DEBUG__
	for (int s = 0; s < Signatures.size(); s++)
	{
		vector<CFG *> cfgs = Signatures[s]->cfgs;
		for (int c = 0; c < cfgs.size(); c++)
		{
			vector<Block *> blocks = cfgs[c]->GetBlocks();
			for (int b = 0; b < blocks.size(); b++)
				cfgs[c]->PrintBlock(blocks[b], true);
		}
	}
#endif

#ifdef __TRAINING_TIME__
	total_training_time = ((double)(time))/CLOCKS_PER_SEC;
	cerr << "\nSimilarityDetector::TrainDataUsingSignatureMatching: Total Training (building all signatures) time: " << total_training_time << " second(s)\n";
#endif
}

/*
 * ------------------------------------------------------------------------------------------------------
 *
 * SimilarityDetector::CheckBinariesUsingSignatureMatching
 *
 * More details in the following paper:
 * A Framework for Metamorphic Malware Analysis and
 * Real-Time Detection
 * DOI: http://dx.doi.org/10.1016/j.cose.2014.10.011
 *
 * ------------------------------------------------------------------------------------------------------
 */
void SimilarityDetector::CheckBinariesUsingSignatureMatching(string malware_samples, string benign_samples, string virus_samples, string files_to_check, unsigned int max_threads)
{
	ML *ml = new ML(max_threads, THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING);
#ifdef __PROGRAM_OUTPUT_ENABLED__
	cout << "--------------------------------------------------------------------\n";
	cout << "Train Data Using Signature Matching . . .\nVirus sample file: " << virus_samples << " . . .\n";
	cout << "--------------------------------------------------------------------\n";
#endif
	string training_filename = virus_samples + "." + TRAINING_FILE_EXTENSION + ".SWOD";
	if (ml->LoadSWODSignatures(training_filename) <= 0)
	{
		if (ARE_WEIGHTS_ASSIGNED == false)
		{
	#ifdef __PROGRAM_OUTPUT_ENABLED__
			cout << "--------------------------------------------------------------------\n";
			cout << "Assigning Weight to Patterns . . .\nMalware sample file: " << malware_samples << " Benign sample file: "<< benign_samples << " . . .\n";
			cout << "--------------------------------------------------------------------\n";
	#endif
			AssignWeights(malware_samples, benign_samples);
		}
		TrainDataUsingSignatureMatching(virus_samples, ml);
	}
	else
		printf("Training data read from file %s\n", training_filename.c_str());

#ifdef __TESTING_TIME__
	clock_t start = 0, end = 0;
	double time = 0.0;
#endif

#ifdef __PROGRAM_OUTPUT_ENABLED__
	cout << "--------------------------------------------------------------------\n";
	cout << "Check Binaries Using Signature Matching . . .\nFiles to check file: " << files_to_check << " . . .\n";
	cout << "--------------------------------------------------------------------\n";
#endif

		/*
		 * Open binary file for reading with the file pointer pointing at the end (ate)
		 */
		ifstream fileP(files_to_check.c_str(), ios::in | ios::binary | ios::ate);
		if (fileP.is_open())
		{
			unsigned int fileSize = (unsigned int)fileP.tellg();                // How much buffer we need for the file
			fileP.seekg (0, ios::beg);
			char *fileBufferP = new char[fileSize+1];
			fileP.read(fileBufferP, fileSize);                                  // Read the file into the buffer
			fileP.close();
			fileBufferP[fileSize] = '\0';

			char filename[3*MAX_FILENAME+1];
			int c = 0;
			int64_t number_of_signatures = (int)MalwareSignatures.size();

			if (number_of_signatures > MAX_THREADS)
				number_of_signatures = 0;
			uint32_t filenumber = 0;
			for (unsigned int n = 0; n < fileSize; n++)
			{
				if ( (c < 3*MAX_FILENAME) && (fileBufferP[n] == '\n' || fileBufferP[n] == '\r') )
				{
					filename[c] = '\0';
#ifdef __DEBUG__
					cerr << "SimilarityDetector::CheckBinariesUsingSignatureMatching: Checking file: " << filename << "\n";
#endif
					ifstream file(filename, ios::in | ios::binary | ios::ate);
					if (file.is_open())
					{
						unsigned int size = (unsigned int)file.tellg();         // How much buffer we need for the file
						file.seekg (0, ios::beg);
						char *fileBuffer = new char[size+1];
						file.read(fileBuffer, size);                            // Read the file into the buffer
						file.close();
						fileBuffer[size] = '\0';

#ifdef __PROGRAM_OUTPUT_ENABLED__
						printf("Building Signature of %s\n", filename);
						fflush(stdout);
#endif
#ifdef __TESTING_TIME__
						start = clock();
#endif
						Parser *parser = new Parser((uint8_t *)fileBuffer, size);
						parser->Parse(filename);
						SIGNATURE *sig = BuildSignature(parser->mail);
#ifdef __TESTING_TIME__
						end = clock();
						time += (end - start);
#endif

						FileReport *fr = new FileReport();
						fr->filename = filename;
						fr->filenumber = filenumber;
						fr->benign = true;
						FileReports.push_back(fr);
#ifdef __MULTI_THREAD__
						while (THREAD_COUNT > (MAX_THREADS - number_of_signatures))
						{
							Sleep (10);
						}
#endif
#ifdef __PROGRAM_OUTPUT_ENABLED__
						printf("Matching Signature of %s\n", filename);
						fflush(stdout);
#endif
#ifdef __DEBUG__
						cerr << "SimilarityDetector::CheckBinariesUsingSignatureMatching: Matching START\n";
#endif
#ifdef __TESTING_TIME__
						start = clock();
#endif
						ml->BenignUsingSignatureMatching(sig, filenumber, VERTICAL_SIGNATURE_DIFF, HORIZONTAL_SIGNATURE_DIFF);
#ifdef __TESTING_TIME__
						end = clock();
						time += (end - start);
#endif
#ifdef __DEBUG__
						cerr << "SimilarityDetector::CheckBinariesUsingSignatureMatching: Matching END\n";
#endif
#ifdef __PROGRAM_OUTPUT_ENABLED__
						if (FileReports[filenumber]->benign)
							printf("File %s is benign\n\n", filename);
						else
							printf("File %s is/contain malware\n\n", filename);
						fflush(stdout);
#endif
						filenumber++;
#ifdef __TESTING_TIME__
						start = clock();
#endif
						if (sig->size > 0)
							delete (sig->signature);
						delete (sig);
						delete (parser);
#ifdef __TESTING_TIME__
						end = clock();
						time += (end - start);
#endif
						delete (fileBuffer);
					}
					else
						cout << "Error:SimilarityDetector::CheckBinariesUsingSignatureMatching: Cannot open the file: " << filename << "\n";

					c = 0;
					filename[c] = '\0';
					if ( n < (fileSize-1) && (fileBufferP[n+1] == '\n' || fileBufferP[n+1] == '\r') )
						n++;
				}
				else if (c < 3*MAX_FILENAME)
					filename[c++] = fileBufferP[n];
				else
					c = 0;
			}
			delete (fileBufferP);
		}
		else
			cout << "Error:SimilarityDetector::CheckBinariesUsingSignatureMatching: Cannot open the file: " << files_to_check << "\n";

#ifdef __TESTING_TIME__
		start = clock();
#endif
#ifdef __MULTI_THREAD__
		while (MANAGER_THREAD_COUNT > 0)
		{
#ifdef __WIN32__
			Sleep (10);
#endif
cerr << "Waiting: MANAGER_THREAD_COUNT: " << dec << MANAGER_THREAD_COUNT << endl;
		}
#endif
#ifdef __TESTING_TIME__
		end = clock();
		time += (end - start);
#endif

#ifdef __PRINT_REPORT__
		cout << endl;
		cout << "--------------------------------------------------------------------\n";
		cout << "|                                                                  |\n";
		cout << "|              Printing Report For Signature Matching              |\n";
		cout << "|                            Files Used                            |\n";
		cout << "|                                                                  |\n";
		cout << "  1. Malware: " << malware_samples << "\n";
		cout << "  2. Benign: " << benign_samples << "\n";
		cout << "  3. Virus: " << virus_samples << "\n";
		cout << "  4. Check: " << files_to_check << "\n";
		cout << "|                                                                  |\n";
		cout << "| 1 and 2 were used for assigning weight to each MAIL Pattern.     |\n";
		cout << "| 3 and 4 were used for training and testing respectively.         |\n";
		cout << "|                                                                  |\n";
		cout << "--------------------------------------------------------------------\n";
		printf ("%180s %7s %5s %5s\n", "Filename", "Number", "Score", "Benign");
		for (unsigned int f = 0; f < FileReports.size(); f++)
		{
			//printf ("%180s %7d %5d\n", FileReports[f]->filename.c_str(), (int)FileReports[f]->filenumber, (int)FileReports[f]->benign);
			printf ("%180s %7d %5.2f %5d\n", FileReports[f]->filename.c_str(), (int)FileReports[f]->filenumber, FileReports[f]->simscore, (int)FileReports[f]->benign);
		}
		printf("\nSize of SWOD:\nVWOD = %5.5f\nHWOD = %5.5f\n", VERTICAL_WINDOW_OF_DIFF, HORIZONTAL_WINDOW_OF_DIFF);
		printf("VSD = %5.5f\nHSD = %5.5f\n", VERTICAL_SIGNATURE_DIFF, HORIZONTAL_SIGNATURE_DIFF);
#endif

#ifdef __TESTING_TIME__
		start = clock();
#endif

		delete (ml);

#ifdef __TESTING_TIME__
		end = clock();
		time += (end - start);
		total_testing_time = ((double)(time))/CLOCKS_PER_SEC;
#endif

#ifdef __ASSIGNING_WEIGHT_TIME__
	printf("Total Assigning Weights time:                                     %15.5f second(s)\n", total_assigning_weight_time);
#endif
#ifdef __TRAINING_TIME__
	printf("Total Training (building all signatures) time:                    %15.5f second(s)\n", total_training_time);
#endif
#ifdef __TESTING_TIME__
	printf("Total Testing (matching each signature with all signatures) time: %15.5f second(s)\n", total_testing_time);
#endif
}

#ifdef __WIN32__
DWORD WINAPI BuildGraphs_T(LPVOID lpParam)
{
	DWORD id = GetCurrentThreadId();
#ifdef __DEBUG__
	cout << "\n-- Opening THREAD_BUILD_GRAPHS: " << THREAD_BUILD_GRAPHS << " ID: " << id << endl;
#endif
	ThreadDataP td = (ThreadDataP)lpParam;

	Parser *parser = new Parser((uint8_t *)td->fileBuffer, td->size);
	string fn;
	fn.append(td->filename);
	parser->Parse(fn);
	vector <CFG *> cfgs = parser->BuildCFGs();
	td->ml->BuildDataUsingGraphMatching(cfgs);

	delete (parser);
	delete (td->fileBuffer);
#ifdef __DEBUG__
	cout << "\n-- Closing THREAD_BUILD_GRAPHS: " << THREAD_BUILD_GRAPHS << " ID: " << id << endl;
#endif

	EnterCriticalSection(&cs_s);
	THREAD_BUILD_GRAPHS--;
	LeaveCriticalSection(&cs_s);
	HeapFree(GetProcessHeap(), 0, td);
	HANDLE hThread = GetCurrentThread();
	CloseHandle(hThread);

	return 0;
}

/*
 *
 */
void SimilarityDetector::BuildGraphs(ML *ml, char *filename, char *fileBuffer, unsigned int size)
{
	while (THREAD_BUILD_GRAPHS >= MAX_THREADS)
	{
		Sleep (10);
	}
	DWORD id;
	ThreadDataP td;
	td = (ThreadDataP) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ThreadData));
	td->ml = ml;
	td->filename = filename;
	td->fileBuffer = fileBuffer;
	td->size = size;
	HANDLE hThread = CreateThread(NULL, 0, BuildGraphs_T, td, 0, &id);

	if (hThread == NULL)
		cout << "Error creating thread " << id << endl;
	else
	{
		EnterCriticalSection(&cs_s);
		THREAD_BUILD_GRAPHS++;
		LeaveCriticalSection(&cs_s);
	}
}
#endif

/*
 * ------------------------------------------------------------------------------------------------------
 *
 * SimilarityDetector::TrainDataUsingGraphMatching
 *
 * ------------------------------------------------------------------------------------------------------
 */
void SimilarityDetector::TrainDataUsingGraphMatching(string filenameP, ML *ml)
{
#ifdef __TRAINING_TIME__
	clock_t start = 0, end = 0;
	double time = 0.0;
#endif

#ifdef __MULTI_THREAD__
	uint64_t CountSignatures = 0;
#endif
	ifstream fileP(filenameP.c_str(), ios::in | ios::binary | ios::ate);
	if (fileP.is_open())
	{
		unsigned int fileSize = (unsigned int)fileP.tellg();                // How much buffer we need for the file
		fileP.seekg (0, ios::beg);
		char *fileBufferP = new char[fileSize+1];
		fileP.read(fileBufferP, fileSize);                                  // Read the file into the buffer
		fileP.close();
		fileBufferP[fileSize] = '\0';

		char filename[3*MAX_FILENAME+1];
		int c = 0;
		for (unsigned int n = 0; n < fileSize; n++)
		{
			if ( (c < 3*MAX_FILENAME) && (fileBufferP[n] == '\n' || fileBufferP[n] == '\r') )
			{
				filename[c] = '\0';
				ifstream file(filename, ios::in | ios::binary | ios::ate);
				if (file.is_open())
				{
					unsigned int size = (unsigned int)file.tellg();         // How much buffer we need for the file
#ifdef __PROGRAM_OUTPUT_ENABLED__
					printf("Training Data Using Graph Matching processing file: %s\n", filename);
					fflush(stdout);
#endif
					file.seekg (0, ios::beg);
					char *fileBuffer = new char[size+1];
					file.read(fileBuffer, size);                           // Read the file into the buffer
					file.close();
					fileBuffer[size] = '\0';

#ifdef __TRAINING_TIME__
					start = clock();
#endif
#ifdef __MULTI_THREAD__
					BuildGraphs(ml, filename, fileBuffer, size);
					CountSignatures++;
#else
					Parser *parser = new Parser((uint8_t *)fileBuffer, size);
					parser->Parse(filename);
					vector <CFG *> cfgs = parser->BuildCFGs();
					ml->BuildDataUsingGraphMatching(cfgs);

					delete (parser);
					delete (fileBuffer);
#endif
#ifdef __TRAINING_TIME__
					end = clock();
					time += (end - start);
#endif
				}
				else
					cout << "Error:SimilarityDetector::TrainDataUsingGraphMatching: Cannot open the file: " << filename << "\n";

				c = 0;
				filename[c] = '\0';
				if ( n < (fileSize-1) && (fileBufferP[n+1] == '\n' || fileBufferP[n+1] == '\r') )
					n++;
			}
			else if (c < 3*MAX_FILENAME)
				filename[c++] = fileBufferP[n];
			else
				c = 0;
		}
		delete (fileBufferP);

#ifdef __DEBUG__
		for (int s = 0; s < (int)Signatures.size(); s++)
		{
			vector <CFG *> sig_cfgs = Signatures[s]->cfgs;
printf("SimilarityDetector::TrainDataUsingGraphMatching\n");
cout  << "sig_cfgs.size(): " << sig_cfgs.size() << endl;
			for (int c = 0; c < (int)sig_cfgs.size(); c++)
			{
				vector<Block *> blocks = sig_cfgs[c]->GetBlocks();
				for (int b = 0; b < (int)blocks.size(); b++)
					sig_cfgs[c]->PrintBlock(blocks[b], true);
			}
		}
#endif
	}
	else
		cout << "Error:SimilarityDetector::TrainDataUsingGraphMatching: Cannot open the file: " << filenameP << "\n";

	string filename = filenameP + "." + TRAINING_FILE_EXTENSION + ".ACFG";
	printf("Writing training file %s\n", filename.c_str());
	ml->SaveACFGSignatures(filename);
	printf("Reading training file %s\n", filename.c_str());
	ml->LoadACFGSignatures(filename);

#ifdef __TRAINING_TIME__
	start = clock();
#endif
#ifdef __MULTI_THREAD__
	while (THREAD_BUILD_GRAPHS > 0)
	{
#ifdef __WIN32__
		Sleep (10);
#endif
#ifdef __DEBUG__
		cout << "THREAD_BUILD_GRAPHS: " << THREAD_BUILD_GRAPHS << endl;
#endif
	}
#endif
#ifdef __TRAINING_TIME__
	end = clock();
	time += (end - start);
	total_training_time = ((double)(time))/CLOCKS_PER_SEC;
	cout << "\nCommon CFGs = " << ml->GetCommonCFGs() << endl;
	cout << "Distinguish CFGs = " << ml->GetDistinguishCFGs() << endl;
	cout << "SimilarityDetector::TrainDataUsingGraphMatching: Total Training (building all signatures) time: " << total_training_time << " second(s)\n";
#endif

#ifdef __DEBUG__
	for (int s = 0; s < Signatures.size(); s++)
	{
		vector <CFG *> sig_cfgs = Signatures[s]->cfgs;
printf("SimilarityDetector::TrainDataUsingGraphMatching\n");
cout  << "sig_cfgs.size(): " << sig_cfgs.size() << endl;
		for (int c = 0; c < (int)sig_cfgs.size(); c++)
		{
			vector<Block *> blocks = sig_cfgs[c]->GetBlocks();
			for (int b = 0; b < (int)blocks.size(); b++)
				sig_cfgs[c]->PrintBlock(blocks[b], true);
		}
	}
#endif
}

/*
 * ------------------------------------------------------------------------------------------------------
 *
 * SimilarityDetector::CheckBinariesUsingGraphMatching
 * Training file used to store is 'virus_samples.training.dat'
 * If this file is present and the data is valid, the function
 * loads the training data from this file otherwise it trains
 * the data and store it in file 'virus_samples.training.dat'.
 *
 * ------------------------------------------------------------------------------------------------------
 */
void SimilarityDetector::CheckBinariesUsingGraphMatching(string virus_samples, string files_to_check, unsigned int max_threads)
{
		ML *ml = new ML(max_threads, THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING);
#ifdef __PROGRAM_OUTPUT_ENABLED__
	cout << "--------------------------------------------------------------------\n";
	cout << "Train Data Using Graph Matching . . .\nVirus sample file: " << virus_samples << " . . .\n";
	cout << "--------------------------------------------------------------------\n";
#endif
	string training_filename = virus_samples + "." + TRAINING_FILE_EXTENSION + ".ACFG";
	if (ml->LoadACFGSignatures(training_filename) <= 0)
		TrainDataUsingGraphMatching(virus_samples, ml);
	else
		printf("Training data read from file %s\n", training_filename.c_str());

#ifdef __TESTING_TIME__
	clock_t start = 0, end = 0;
	double time = 0.0;
#endif

#ifdef __PROGRAM_OUTPUT_ENABLED__
	cout << "--------------------------------------------------------------------\n";
	cout << "Check Binaries Using Graph Matching . . .\nFiles to check file: " << files_to_check << " . . .\n";
	cout << "--------------------------------------------------------------------\n";
#endif

		/*
		 * Open binary file for reading with the file pointer pointing at the end (ate)
		 */
		ifstream fileP(files_to_check.c_str(), ios::in | ios::binary | ios::ate);
		if (fileP.is_open())
		{
			unsigned int fileSize = (unsigned int)fileP.tellg();                // How much buffer we need for the file
			fileP.seekg (0, ios::beg);
			char *fileBufferP = new char[fileSize+1];
			fileP.read(fileBufferP, fileSize);                                  // Read the file into the buffer
			fileP.close();
			fileBufferP[fileSize] = '\0';

			char filename[3*MAX_FILENAME+1];
			int c = 0;
			uint64_t number_of_signatures = Signatures.size();

			if ((int)number_of_signatures > MAX_THREADS)
				number_of_signatures = 0;
			uint32_t filenumber = 0;
			for (unsigned int n = 0; n < fileSize; n++)
			{
				if ( (c < 3*MAX_FILENAME) && (fileBufferP[n] == '\n' || fileBufferP[n] == '\r') )
				{
					filename[c] = '\0';
#ifdef __DEBUG__
					cerr << "SimilarityDetector::CheckBinariesUsingGraphMatching: Checking file: " << filename << "\n";
#endif
					ifstream file(filename, ios::in | ios::binary | ios::ate);
					if (file.is_open())
					{
						unsigned int size = (unsigned int)file.tellg();         // How much buffer we need for the file
						file.seekg (0, ios::beg);
						char *fileBuffer = new char[size+1];
						file.read(fileBuffer, size);                            // Read the file into the buffer
						file.close();
						fileBuffer[size] = '\0';

#ifdef __PROGRAM_OUTPUT_ENABLED__
						printf("Building Signature of %s\n", filename);
						fflush(stdout);
#endif
#ifdef __TESTING_TIME__
						start = clock();
#endif
						Parser *parser = new Parser((uint8_t *)fileBuffer, size);
						parser->Parse(filename);
						vector <CFG *> cfgs = parser->BuildCFGs();

//#define CHECK_BINARIES 1
//#ifdef CHECK_BINARIES
#ifdef __DEBUG__
						cerr << "SimilarityDetector::CheckBinariesUsingGraphMatching: Start building graph\n";
#endif
						vector <Graph *> gs;
						IsoMorph *isom = new IsoMorph();
						for (int c = 0; c < (int)cfgs.size(); c++)
						{
							Graph *g = isom->BuildGraph(cfgs[c]);
							gs.push_back(g);
						}
						delete (isom);
#ifdef __DEBUG__
						cerr << "SimilarityDetector::CheckBinariesUsingGraphMatching: Graph done\n";
#endif

						FileReport *fr = new FileReport();
						fr->filename = filename;
						fr->filenumber = filenumber;
						fr->benign = true;
						FileReports.push_back(fr);
						start = clock();
#ifdef __MULTI_THREAD__
						while (THREAD_COUNT > (int)(MAX_THREADS - number_of_signatures))
						{
#ifdef __WIN32__
							Sleep (10);
#endif
#ifdef __DEBUG__
							cerr << "THREAD_COUNT: " << dec << THREAD_COUNT << endl;
#endif
						}
#endif
						ml->BenignUsingGraphMatching(gs, cfgs, filenumber);
#ifdef __PROGRAM_OUTPUT_ENABLED__
						if (FileReports[filenumber]->benign)
							printf("File %s is benign\n\n", filename);
						else
							printf("File %s is/contain malware\n\n", filename);
						fflush(stdout);
#endif
						filenumber++;
#ifdef __DEBUG__
						cerr << "SimilarityDetector::CheckBinariesUsingGraphMatching: Done\n";
#endif
#ifdef __TESTING_TIME__
						end = clock();
						time += (end - start);
#endif
#ifdef __SINGLE_THREAD__
						for (int c = 0; c < (int)cfgs.size(); c++)
						{
							delete (cfgs[c]);
							delete (gs[c]);
						}
#endif
//#endif
						delete (parser);
						delete (fileBuffer);
					}
					else
						cout << "Error:main: Cannot open the file: " << filename << "\n";

					c = 0;
					filename[c] = '\0';
					if ( n < (fileSize-1) && (fileBufferP[n+1] == '\n' || fileBufferP[n+1] == '\r') )
						n++;
				}
				else if (c < 3*MAX_FILENAME)
					filename[c++] = fileBufferP[n];
				else
					c = 0;
			}
			delete (fileBufferP);
		}
		else
			cout << "Error:SimilarityDetector::CheckBinariesUsingGraphMatching: Cannot open the file: " << files_to_check << "\n";

#ifdef __TESTING_TIME__
		start = clock();
#endif
#ifdef __MULTI_THREAD__
		while (MANAGER_THREAD_COUNT > 0)
		{
#ifdef __WIN32__
			Sleep (10);
#endif
#ifdef __DEBUG__
			cerr << "Waiting: MANAGER_THREAD_COUNT: " << dec << MANAGER_THREAD_COUNT << endl;
#endif
		}
#endif
#ifdef __TESTING_TIME__
		end = clock();
		time += (end - start);
#endif

#ifdef __PRINT_REPORT__
		cout << endl;
		cout << "--------------------------------------------------------------------\n";
		cout << "|                                                                  |\n";
		cout << "|                Printing Report For Graph Matching                |\n";
		cout << "|                            Files Used                            |\n";
		cout << "|                                                                  |\n";
		cout << "  1. Virus: " << virus_samples << "\n";
		cout << "  2. Check: " << files_to_check << "\n";
		cout << "|                                                                  |\n";
		cout << "| 1 and 2 were used for training and testing respectively.         |\n";
		cout << "|                                                                  |\n";
		cout << "--------------------------------------------------------------------\n";
		printf ("%180s %7s %5s %5s\n", "Filename", "Number", "Score", "Benign");
		for (unsigned int f = 0; f < FileReports.size(); f++)
		{
			//printf ("%180s %7d %5d\n", FileReports[f]->filename.c_str(), (int)FileReports[f]->filenumber, (int)FileReports[f]->benign);
			printf ("%180s %7d %5.2f %5d\n", FileReports[f]->filename.c_str(), (int)FileReports[f]->filenumber, FileReports[f]->simscore, (int)FileReports[f]->benign);
		}
		printf("\nSize of THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING = %5.5f\n", THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING);
#endif

		delete (ml);

#ifdef __TESTING_TIME__
		end = clock();
		time += (end - start);
		total_testing_time = ((double)(time))/CLOCKS_PER_SEC;
#endif

#ifdef __ASSIGNING_WEIGHT_TIME__
	printf("Total Assigning Weights time:                                     %15.5f second(s)\n", total_assigning_weight_time);
#endif
#ifdef __TRAINING_TIME__
	printf("Total Training (building all signatures) time:                    %15.5f second(s)\n", total_training_time);
#endif
#ifdef __TESTING_TIME__
	printf("Total Testing (matching each signature with all signatures) time: %15.5f second(s)\n", total_testing_time);
#endif
}

/*
 * ------------------------------------------------------------------------------------------------------
 *
 * Assign weight to patterns
 * For detail algorithm for assigning weights read Signature::AssignWeightToPatterns()
 *
 * ------------------------------------------------------------------------------------------------------
 */
void SimilarityDetector::AssignWeights(string malware_samples, string benign_samples)
{
	Signature sig_c;
	total_assigning_weight_time = sig_c.AssignWeightToPatterns(malware_samples, benign_samples, VERTICAL_WINDOW_OF_DIFF, HORIZONTAL_WINDOW_OF_DIFF);
	ARE_WEIGHTS_ASSIGNED = true;
}

/*
 * ------------------------------------------------------------------------------------------------------
 *
 * Build signature
 * For detail algorithm for building the signature read Signature::Build()
 *
 * ------------------------------------------------------------------------------------------------------
 */
SIGNATURE *SimilarityDetector::BuildSignature(MAIL *mail)
{
	Signature sig_c;
	SIGNATURE *sig = sig_c.Build(mail);

	return (sig);
}

/* generate signatures for all malware samples in the given partition;
 * save signature to all given training data files
 */
void SimilarityDetector::GenerateSignaturesOfPartition(unsigned int partition_index, vector<string> training_data_files_used, ML* ml){
	char buff[100];
  	snprintf(buff, sizeof(buff), "malware_samples_%02d", partition_index);
  	string malware_samples_i = buff;
#ifdef __TRAINING_TIME__
	clock_t start = 0, end = 0;
	double time = 0.0;
#endif

#ifdef __MULTI_THREAD__
	uint64_t CountSignatures = 0;
#endif
	ifstream fileP(malware_samples_i.c_str(), ios::in | ios::binary | ios::ate);
	if (fileP.is_open())
	{
		unsigned int fileSize = (unsigned int)fileP.tellg();                // How much buffer we need for the file
		fileP.seekg (0, ios::beg);
		char *fileBufferP = new char[fileSize+1];
		fileP.read(fileBufferP, fileSize);                                  // Read the file into the buffer
		fileP.close();
		fileBufferP[fileSize] = '\0';

		char filename[3*MAX_FILENAME+1];
		int c = 0;
		for (unsigned int n = 0; n < fileSize; n++)
		{
			if ( (c < 3*MAX_FILENAME) && (fileBufferP[n] == '\n' || fileBufferP[n] == '\r') )
			{
				filename[c] = '\0';
				ifstream file(filename, ios::in | ios::binary | ios::ate);
				if (file.is_open())
				{
					unsigned int size = (unsigned int)file.tellg();         // How much buffer we need for the file
#ifdef __PROGRAM_OUTPUT_ENABLED__
					printf("Generating malware signatures from file: %s\n", filename);
					fflush(stdout);
#endif
					file.seekg (0, ios::beg);
					char *fileBuffer = new char[size+1];
					file.read(fileBuffer, size);                           // Read the file into the buffer
					file.close();
					fileBuffer[size] = '\0';

#ifdef __TRAINING_TIME__
					start = clock();
#endif
#ifdef __MULTI_THREAD__
					BuildGraphs(ml, filename, fileBuffer, size);
					CountSignatures++;
#else
					Parser *parser = new Parser((uint8_t *)fileBuffer, size);
					parser->Parse(filename);
					vector <CFG *> cfgs = parser->BuildCFGs();
					ml->BuildDataUsingGraphMatching(cfgs);

					delete (parser);
					delete (fileBuffer);
#endif
#ifdef __TRAINING_TIME__
					end = clock();
					time += (end - start);
#endif
				}
				else
					cout << "Error:SimilarityDetector::TrainDataUsingGraphMatching: Cannot open the file: " << filename << "\n";

				c = 0;
				filename[c] = '\0';
				if ( n < (fileSize-1) && (fileBufferP[n+1] == '\n' || fileBufferP[n+1] == '\r') )
					n++;
			}
			else if (c < 3*MAX_FILENAME)
				filename[c++] = fileBufferP[n];
			else
				c = 0;
		}
		delete (fileBufferP);

#ifdef __DEBUG__
		for (int s = 0; s < (int)Signatures.size(); s++)
		{
			vector <CFG *> sig_cfgs = Signatures[s]->cfgs;
printf("SimilarityDetector::TrainDataUsingGraphMatching\n");
cout  << "sig_cfgs.size(): " << sig_cfgs.size() << endl;
			for (int c = 0; c < (int)sig_cfgs.size(); c++)
			{
				vector<Block *> blocks = sig_cfgs[c]->GetBlocks();
				for (int b = 0; b < (int)blocks.size(); b++)
					sig_cfgs[c]->PrintBlock(blocks[b], true);
			}
		}
#endif
	}
	else
		cout << "Error:SimilarityDetector::TrainDataUsingGraphMatching: Cannot open the file: " << malware_samples_i << "\n";

	for(unsigned int i=0; i<training_data_files_used.size(); i++){
		ml->SaveACFGSignatures(training_data_files_used[i]);
	}

#ifdef __TRAINING_TIME__
	start = clock();
#endif
#ifdef __MULTI_THREAD__
	while (THREAD_BUILD_GRAPHS > 0)
	{
#ifdef __WIN32__
		Sleep (10);
#endif
#ifdef __DEBUG__
		cout << "THREAD_BUILD_GRAPHS: " << THREAD_BUILD_GRAPHS << endl;
#endif
	}
#endif
#ifdef __TRAINING_TIME__
	end = clock();
	time += (end - start);
	total_training_time = ((double)(time))/CLOCKS_PER_SEC;
	cout << "Common CFGs = " << ml->GetCommonCFGs() << endl;
	cout << "Distinguish CFGs = " << ml->GetDistinguishCFGs() << endl;
	cout << "SimilarityDetector::TrainDataUsingGraphMatching: Total Training (building all signatures) time: " << total_training_time << " second(s)\n";
#endif

#ifdef __DEBUG__
	for (int s = 0; s < Signatures.size(); s++)
	{
		vector <CFG *> sig_cfgs = Signatures[s]->cfgs;
printf("SimilarityDetector::TrainDataUsingGraphMatching\n");
cout  << "sig_cfgs.size(): " << sig_cfgs.size() << endl;
		for (int c = 0; c < (int)sig_cfgs.size(); c++)
		{
			vector<Block *> blocks = sig_cfgs[c]->GetBlocks();
			for (int b = 0; b < (int)blocks.size(); b++)
				sig_cfgs[c]->PrintBlock(blocks[b], true);
		}
	}
#endif
}