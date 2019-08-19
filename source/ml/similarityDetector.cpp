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
		delete[] fileBufferP;
	}
	else
		cout << "Error:SimilarityDetector::TrainDataUsingSignatureMatching:  Cannot open the file: " << filenameP << "\n";

	string filename = filenameP + "." + SIGNATURE_FILE_EXTENSION + ".SWOD";
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
	string training_filename = virus_samples + "." + SIGNATURE_FILE_EXTENSION + ".SWOD";
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
							printf("File %s is benign\n", filename);
						else
							printf("File %s is/contain malware\n", filename);
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
			delete[] fileBufferP;
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
 * SimilarityDetector::LoadMalwareSignaturesFromTrainingModel
 * Load training data from 'virus_samples.training.dat.ACFG'
 * requires this file being present
 *
 * ------------------------------------------------------------------------------------------------------
 */
void SimilarityDetector::LoadMalwareSignaturesFromTrainingModel(string virus_samples_training_data_filename, ML* ml){
#ifdef __PROGRAM_OUTPUT_ENABLED__
	cout << "--------------------------------------------------------------------\n";
	cout << "Train Data Using Graph Matching . . .\nTraining model file: " << virus_samples_training_data_filename << " . . .\n";
	cout << "--------------------------------------------------------------------\n";
#endif
		ml->LoadACFGSignatures(virus_samples_training_data_filename);
}

/* load malware signatures of samples in virus_samples to given ML object
 */
void SimilarityDetector::LoadMalwareSignaturesFromSignatureFiles(string virus_samples, string sig_temp_dir, ML* ml){
#ifdef __PROGRAM_OUTPUT_ENABLED__
	cout << "--------------------------------------------------------------------\n";
	cout << "Train Data Using Graph Matching . . .\nVirus sample file: " << virus_samples << " . . .\n";
	cout << "--------------------------------------------------------------------\n";
#endif
		/*
		* Open binary file for reading with the file pointer pointing at the end (ate)
		*/
		ifstream fileP(virus_samples.c_str(), ios::in | ios::binary | ios::ate);
		if (fileP.is_open())
		{
			uint64_t fileSize = (uint64_t)fileP.tellg();                // How much buffer we need for the file
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
			for (uint64_t n = 0; n < fileSize; n++)
			{
				// iterate over malware samples listed in virus_samples, load their signatures to ml
				if ( (c < 3*MAX_FILENAME) && (fileBufferP[n] == '\n' || fileBufferP[n] == '\r') )
				{
#ifdef __TESTING_TIME__
		clock_t start = 0, end = 0;
		double malware_load_sig_time = 0;
#endif
					filename[c] = '\0';
	#ifdef __DEBUG__
					cerr << "SimilarityDetector::CheckBinariesUsingGraphMatching: Checking file: " << filename << "\n";
	#endif
					// unzip the compressed signature file to current dir
					char unzip_command[3*MAX_FILENAME+7];
					strcpy(unzip_command, "unzip -o -q -j ");
					int i;
					for(i=0; filename[i] != '\0'; i++){
						unzip_command[i+15] = filename[i];
					}
					unzip_command[i+15] = '\0';
					strcat(unzip_command, " -d ");
					strcat(unzip_command, sig_temp_dir.c_str());
#ifdef __PROGRAM_OUTPUT_ENABLED__
					std::cout << "Unzipping signature file: " << unzip_command << endl;
#endif
					int cmd_status = system(unzip_command);
					if(cmd_status == UNZIP_STATUS_NO_ERROR){
						std::cout << "File unzipped successfully" << endl;
					}
					else{
						std::cout << "File unzipping failed; status code: " << cmd_status << endl;
					}

					// load in malware signature
					string filename_base = getBaseName(filename);
					string testing_filename(sig_temp_dir + "/" + filename_base.substr(0, filename_base.size()-4));
#ifdef __TESTING_TIME__
		start = clock();
#endif
					ml->LoadMalwareACFGSignaturesPerSample(testing_filename);
#ifdef __TESTING_TIME__
		end = clock();
		malware_load_sig_time = end - start;
		double malware_load_sig_time_sec = malware_load_sig_time/CLOCKS_PER_SEC;
		ifstream malware_sig_file(testing_filename.c_str(), ifstream::in | ifstream::binary);
		if(malware_sig_file.is_open())
    	{
			malware_sig_file.seekg(0, ios::end);
    		long malware_sig_file_size = malware_sig_file.tellg();
			double malware_sig_file_size_MB = (double)malware_sig_file_size / 1048576.0;
    		malware_sig_file.close();
			std::cerr << std::fixed;
    		std::cerr << std::setprecision(4);
        	std::cerr << "malware signature size and loading time," << testing_filename << "," << malware_sig_file_size_MB << "," << malware_load_sig_time_sec << endl;
    	}
		else{
			std::cerr << std::fixed;
    		std::cerr << std::setprecision(4);
			std::cerr << "malware signature size and loading time," << testing_filename << ","  << "," << malware_load_sig_time_sec << endl;
		}
#endif

					// remove decompressed signature file
					string remove_command("rm " + testing_filename);
#ifdef __PROGRAM_OUTPUT_ENABLED__
					std::cout << "Removing signature file: " << remove_command << endl;
#endif
					system(remove_command.c_str());

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
			delete[] fileBufferP;
		}
		else
			cout << "Error:SimilarityDetector::LoadMalwareSignaturesFromSignatureFiles: Cannot open the file: " << virus_samples << "\n";
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
void SimilarityDetector::CheckBinariesUsingGraphMatching(string virus_samples, string files_to_check, string sig_temp_dir, string sig_file_path, unsigned int max_threads)
{
#ifdef __TESTING_TIME__
	clock_t start = 0, end = 0;
	double time = 0.0;
	start = clock();
#endif

		ML *ml = new ML(max_threads, THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING);
		ifstream training_data_file(sig_file_path.c_str(), ios::in | ios::binary | ios::ate);
		if(training_data_file.is_open()){
			training_data_file.close();
			cout << "Loading training model from " << sig_file_path << "..." << endl;
			LoadMalwareSignaturesFromTrainingModel(sig_file_path, ml);
		}
		else{
			cout << "Training model not found. Generating training model from individual signature file..." << endl;
			LoadMalwareSignaturesFromSignatureFiles(virus_samples, sig_temp_dir, ml);
		}

#ifdef __TESTING_TIME__
	end = clock();
	time += end - start;
	double sig_loading_time_total_sec = time/CLOCKS_PER_SEC;
	std::cerr << "Total malware signatures loading time," << "," << "," << sig_loading_time_total_sec << endl;
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
			// iterate over testing samples listed in files_to_check: load each sample's sigature
			// to ml, then in ml compare signature with signatures from training stage
			for (unsigned int n = 0; n < fileSize; n++)
			{
				if ( (c < 3*MAX_FILENAME) && (fileBufferP[n] == '\n' || fileBufferP[n] == '\r') )
				{
					filename[c] = '\0';
#ifdef __TESTING_TIME__
		clock_t start_per_file = 0, end_per_file = 0;
		double testing_time_per_file = 0;
#endif

#ifdef __DEBUG__
					cerr << "SimilarityDetector::CheckBinariesUsingGraphMatching: Checking file: " << filename << "\n";
#endif
					// unzip the compressed signature file to current dir
					char unzip_command[3*MAX_FILENAME+7];
					strcpy(unzip_command, "unzip -o -q -j ");
					int i;
					for(i=0; filename[i] != '\0'; i++){
						unzip_command[i+15] = filename[i];
					}
					unzip_command[i+15] = '\0';
					strcat(unzip_command, " -d ");
					strcat(unzip_command, sig_temp_dir.c_str());
#ifdef __PROGRAM_OUTPUT_ENABLED__
					std::cout << "Unzipping signature file: " << unzip_command << endl;
#endif
					int cmd_status = system(unzip_command);
					if(cmd_status == UNZIP_STATUS_NO_ERROR){
						std::cout << "File unzipped successfully" << endl;
					}
					else{
						std::cout << "File unzipping failed; status code: " << cmd_status << endl;
					}
#ifdef __PROGRAM_OUTPUT_ENABLED__
					printf("Loading Signature of %s\n", filename);
					fflush(stdout);
#endif
					// loading tested sample's signatures
					string filename_base = getBaseName(filename);
					string testing_filename(sig_temp_dir + "/" + filename_base.substr(0, filename_base.size()-4));
#ifdef __TESTING_TIME__
		start = clock();
#endif
#ifdef __TESTING_TIME__
		start_per_file = clock();
#endif
					vector <CFG *> cfgs = ml->LoadTestingACFGSignatures(testing_filename);
//#define CHECK_BINARIES 1
//#ifdef CHECK_BINARIES
#ifdef __DEBUG__
	cerr << "SimilarityDetector::CheckBinariesUsingGraphMatching: Start building graph\n";
#endif
					vector <Graph *> gs;
					IsoMorph *isom = new IsoMorph();
					for (int k = 0; k < (int)cfgs.size(); k++)
					{
						Graph *g = isom->BuildGraph(cfgs[k]);
						gs.push_back(g);
					}
					delete (isom);
#ifdef __DEBUG__
	cerr << "SimilarityDetector::CheckBinariesUsingGraphMatching: Graph done\n";
#endif
#ifdef __TESTING_TIME__
		end = clock();
		time += (end - start);
#endif
#ifdef __TESTING_TIME__
		end_per_file = clock();
		testing_time_per_file += end_per_file - start_per_file;
#endif

					FileReport *fr = new FileReport();
					fr->filename = filename;
					fr->filenumber = filenumber;
					fr->benign = true;
					FileReports.push_back(fr);
#ifdef __TESTING_TIME__
		start = clock();
#endif
#ifdef __TESTING_TIME__
		start_per_file = clock();
#endif
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
#ifdef __TESTING_TIME__
		end = clock();
		time += (end - start);
#endif
#ifdef __TESTING_TIME__
		end_per_file = clock();
		testing_time_per_file += end_per_file - start_per_file;
		double testing_time_per_file_sec = testing_time_per_file/CLOCKS_PER_SEC;
		ifstream testing_sig_file(testing_filename.c_str(), ifstream::in | ifstream::binary);
		if(testing_sig_file.is_open())
    	{
			testing_sig_file.seekg(0, ios::end);
    		long testing_sig_file_size = testing_sig_file.tellg();
			double testing_sig_file_size_MB = (double)testing_sig_file_size / 1048576.0;
    		testing_sig_file.close();
			std::cerr << std::fixed;
    		std::cerr << std::setprecision(4);
        	std::cerr << "testing signature size and loading time," << testing_filename << "," << testing_sig_file_size_MB << "," << testing_time_per_file_sec << endl;
    	}
		else{
			std::cerr << std::fixed;
    		std::cerr << std::setprecision(4);
			std::cerr << "testing signature size and loading time," << testing_filename << ","  << "," << testing_time_per_file_sec << endl;
		}
#endif
#ifdef __PROGRAM_OUTPUT_ENABLED__
					if (FileReports[filenumber]->benign)
						printf("File %s has sim score: %5.2f, is benign\n", filename, FileReports[filenumber]->simscore);
					else
						printf("File %s has sim score: %5.2f, is/contain malware\n", filename, FileReports[filenumber]->simscore);
					fflush(stdout);
#endif
					filenumber++;
#ifdef __DEBUG__
						cerr << "SimilarityDetector::CheckBinariesUsingGraphMatching: Done\n";
#endif
#ifdef __SINGLE_THREAD__
					for (int k = 0; k < (int)cfgs.size(); k++)
					{
						delete (cfgs[k]);
						delete (gs[k]);
					}

					// remove decompressed signature file
					string remove_command("rm " + testing_filename);
#ifdef __PROGRAM_OUTPUT_ENABLED__
					std::cout << "Removing signature file: " << remove_command << "\n" << endl;
#endif
					system(remove_command.c_str());
#endif
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
			delete[] fileBufferP;
		}
		else
			cout << "Error:SimilarityDetector::CheckBinariesUsingGraphMatching: Cannot open the file: " << files_to_check << "\n";

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
	std::cerr << "Total Testing (matching each signature with all signatures) time," << "," << "," << total_testing_time << endl;
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

/* get base name of given path to file
 * from https://www.oreilly.com/library/view/c-cookbook/0596007612/ch10s15.html
 */
string SimilarityDetector::getBaseName(const string& s) {
   char sep = '/';

#ifdef _WIN32
   sep = '\\';
#endif

   size_t i = s.rfind(sep, s.length());
   if (i != string::npos) {
      return(s.substr(i+1, s.length() - i));
   }

   return("");
}

/* get directory path of given full path to file
 * from http://www.cplusplus.com/reference/string/string/find_last_of/
 */
string SimilarityDetector::getFolderPath(const string& str)
{
  size_t found;
  cout << "Splitting: " << str << endl;
  found=str.find_last_of("/\\");
  return str.substr(0,found);
}

/*
 * ------------------------------------------------------------------------------------------------------
 *
 * SimilarityDetector::GenerateSignatures
 * generate signatures for all malware samples; save signatures of each sample to 
 * one training data file
 *
 * ------------------------------------------------------------------------------------------------------
 */
void SimilarityDetector::GenerateSignatures(string sample, int max_threads, string sig_dir){
#ifdef __TRAINING_TIME__
	clock_t start = 0, end = 0;
	double time = 0.0;
#endif

#ifdef __MULTI_THREAD__
	uint64_t CountSignatures = 0;
#endif
		int i;
		char filename[3*MAX_FILENAME+1];
		strcpy(filename, sample.c_str());
		char filename_txt_outside[3*MAX_FILENAME+1];
		for (i=0; filename[i] != '\0'; i++){
			filename_txt_outside[i] = filename[i];
		}
		filename_txt_outside[i-4] = '\0';
		string filename_txt(getBaseName(filename_txt_outside));
		// std::cout << "filename_txt is " << filename_txt << '\n';

		// extract txt file inside zip file
		char unzip_command[(3*MAX_FILENAME+1)*2+7];
		strcpy(unzip_command, "unzip ");
		for(i=0; filename[i] != '\0'; i++){
			unzip_command[i+6] = filename[i];
		}
		unzip_command[i+6] = '\0';
		std::cout << "Unzipping disassembly file: " << unzip_command << endl;
		int cmd_status = system(unzip_command);
		if(cmd_status == UNZIP_STATUS_NO_ERROR){
			std::cout << "File unzipped successfully" << endl;
		}
		else{
			std::cout << "File unzipping failed; status code: " << cmd_status << endl;
		}

		ifstream file(filename_txt.c_str(), ios::in | ios::binary | ios::ate);
		if (file.is_open())
		{
			unsigned int size = (unsigned int)file.tellg();         // How much buffer we need for the file
#ifdef __PROGRAM_OUTPUT_ENABLED__
			printf("Generating signatures from file: %s\n", filename_txt.c_str());
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
			ML *ml = new ML(max_threads, THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING);
			Parser *parser = new Parser((uint8_t *)fileBuffer, size);
			parser->Parse(filename_txt);
			vector <CFG *> cfgs = parser->BuildCFGs();
			ml->BuildDataUsingGraphMatching(cfgs);

			delete (parser);
			delete (fileBuffer);
#endif
			// save signatures of sample to its signature file
			string training_data_filename(sig_dir + "/" + filename_txt + "." + SIGNATURE_FILE_EXTENSION + ".ACFG");
			// std::cout << "training data filename is: " << training_data_filename << endl;
			ml->SaveACFGSignatures(training_data_filename);
			delete(ml);
#ifdef __TRAINING_TIME__
			end = clock();
			time += (end - start);
#endif
			// zip signature file
			string training_data_filename_zipped(training_data_filename + ".zip");
			string zip_training_data_command("zip " + training_data_filename_zipped + " " + training_data_filename);
			std::cout << "Zipping signature file: " << zip_training_data_command << endl;
			system(zip_training_data_command.c_str());

			// remove unzipped signature file
			string remove_unzipped_sig_command("rm " + training_data_filename);
			system(remove_unzipped_sig_command.c_str());
		}
		else{
			std::cout << "Error:SimilarityDetector::GenerateSignatures: Cannot open the file: " << filename_txt << "\n";
		}
		// remove txt file
		char remove_txt_command[3*MAX_FILENAME+4];
		strcpy(remove_txt_command, "rm ");
		for(i=0; filename_txt[i] != '\0'; i++){
			remove_txt_command[i+3] = filename_txt[i];
		}
		remove_txt_command[i+3] = '\0';
		std::cout << "Removed disassembly file: " << remove_txt_command << endl;
		system(remove_txt_command);
#ifdef __DEBUG__
		for (int s = 0; s < (int)Signatures.size(); s++)
		{
			vector <CFG *> sig_cfgs = Signatures[s]->cfgs;
printf("SimilarityDetector::GenerateSignatures\n");
cout  << "sig_cfgs.size(): " << sig_cfgs.size() << endl;
			for (int c = 0; c < (int)sig_cfgs.size(); c++)
			{
				vector<Block *> blocks = sig_cfgs[c]->GetBlocks();
				for (int b = 0; b < (int)blocks.size(); b++)
					sig_cfgs[c]->PrintBlock(blocks[b], true);
			}
		}
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
	total_training_time = ((double)(time))/CLOCKS_PER_SEC;
	cout << "SimilarityDetector::GenerateSignatures: Feature extraction time of this sample: " << total_training_time << " second(s)\n\n";
#endif

#ifdef __DEBUG__
	for (int s = 0; s < Signatures.size(); s++)
	{
		vector <CFG *> sig_cfgs = Signatures[s]->cfgs;
printf("SimilarityDetector::GenerateSignatures\n");
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
 * SimilarityDetector::SaveSignaturesToModel
 * Save signatures from compressed signature files listed in
 * <training_sigs_filename> into a single training model file:
 * <training_data_filename>. Exclude duplicated CFGs.
 * ------------------------------------------------------------------------------------------------------
 */
void SimilarityDetector::SaveSignaturesToModel(string training_sigs_filename, string training_data_filename, string sig_temp_dir, unsigned int max_threads){	
#ifdef __TESTING_TIME__
	clock_t start = 0, end = 0;
	double time = 0.0;
	start = clock();
#endif
		ML *ml = new ML(max_threads, THRESHOLD_FOR_MALWARE_SAMPLE_GRAPH_MATCHING);
		LoadMalwareSignaturesFromSignatureFiles(training_sigs_filename, sig_temp_dir, ml);

#ifdef __TESTING_TIME__
	end = clock();
	time = end - start;
	double sig_loading_time_total_sec = time/CLOCKS_PER_SEC;
	std::cerr << "Total malware signatures loading time," << "," << "," << sig_loading_time_total_sec << endl;
#endif
#ifdef __TESTING_TIME__
	start = clock();
#endif
		ml->SaveACFGSignatures(training_data_filename);
#ifdef __TESTING_TIME__
	end = clock();
	time = end - start;
	double sig_saving_time_total_sec = time/CLOCKS_PER_SEC;
	std::cerr << "Total malware signatures savinging time," << "," << "," << sig_saving_time_total_sec << endl;
#endif
}