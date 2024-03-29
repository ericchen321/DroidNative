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

#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <stdint.h>
#include <time.h>

#include "ml/ml.h"
#include "ml/similarityDetector.h"
#include "parser/parser.h"
#include "isomorph/isomorph.h"
#include "mail/mail.h"
#include "mail/patterns.h"
#include "include/swod.h"

using namespace std;

/**
 *
 * <p>
 * This implements the main method of DroidNative.
 * DroidNative uses MAIL and implements ACFG and SWOD-CFWeight.
 * More details in the paper about DroidNative.
 * <p>
 *
 *
 * <p>
 * The program does not check for the correctness and order of command line parameters.
 * It's the responsibility of the user to provide correct parameters in order provided below for each technique.
 * <p>
 *
 * <p>
 * For running ACFG:
 *    DroidNative <max_threads> <threshold_gm> <virus_samples> <file_to_check>
 * For running SWOD:
 *    DroidNative <max_threads> <vwod> <hwod> <threshold_vwod> <threshold_hwod> <threshold_vsd> <threshold_hsd> <virus_samples> <file_to_check>
 * <p>
 *
 *
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since December 04, 2014
 *
 */
int main(int argc, char **argv, char **envp)
{
	//
	// For signature (SWOD-CFWeight) matching
	//
	if (argc == 12)
	{
		float vwod = 1.0;             // default value
		float hwod = 25.0;            // default value
		float threshold_vwod = 1.0;   // default value
		float threshold_hwod = 1.0;   // default value
		float threshold_vsd = 1.0;
		float threshold_hsd = 10.0;
		unsigned int max_threads;
		max_threads = atoi(argv[1]);
		string malware_samples, benign_samples, virus_samples, files_to_check;

		vwod = atof(argv[2]);
		hwod = atof(argv[3]);
		threshold_vwod = atof(argv[4]);
		threshold_hwod = atof(argv[5]);
		threshold_vsd = atof(argv[6]);
		threshold_hsd = atof(argv[7]);
		// Malware samples for computing SWOD
		malware_samples.assign(argv[8]);
		// Benign samples for computing SWOD
		benign_samples.assign(argv[9]);
		// Training malware samples
		virus_samples.assign(argv[10]);
		// Files to be checked and tagged as malware/benign
		files_to_check.assign(argv[11]);

		SimilarityDetector *sd = new SimilarityDetector();
		sd->SetSizeSWOD(vwod, hwod, threshold_vwod, threshold_hwod, threshold_vsd, threshold_hsd);
		sd->CheckBinariesUsingSignatureMatching(malware_samples, benign_samples, virus_samples, files_to_check, max_threads);
		delete(sd);
	}
	//
	// For graph signature (ACFG) matching
	// the third argument is ignored if the 7th is provided
	//
	else if (argc == 6 || argc == 7)
	{
		unsigned int max_threads;
		max_threads = atoi(argv[1]);
		float threshold_gm = atof(argv[2]);
		string virus_samples, files_to_check, sig_temp_dir, sig_file_path;
		// Training malware samples
		virus_samples.assign(argv[3]);
		// Files to be checked and tagged as malware/benign
		files_to_check.assign(argv[4]);
		// Path to temp folder to store signature files
		sig_temp_dir.assign(argv[5]);
		if(argc == 7)
			sig_file_path.assign(argv[6]);
		else
			sig_file_path.assign("");
		SimilarityDetector *sd = new SimilarityDetector();
		sd->SetThreshold(threshold_gm);
		sd->CheckBinariesUsingGraphMatching(virus_samples, files_to_check, sig_temp_dir, sig_file_path, max_threads);
		delete(sd);
	}
	//
	// For graph signature (ACFG) matching, load training signatures into
	// a single training model file
	//
	else if (argc == 5){
		unsigned int max_threads;
		max_threads = atoi(argv[1]);
		string training_sigs_filename = argv[2];
		string training_data_filename = argv[3];
		string sig_temp_dir = argv[4];
		SimilarityDetector *sd = new SimilarityDetector();
		sd->SaveSignaturesToModel(training_sigs_filename, training_data_filename, sig_temp_dir, max_threads);
		delete(sd);
	}
	//
	// For graph signature (ACFG) matching, but build signatures only
	//
	else if (argc == 4)
	{
		unsigned int max_threads;
		max_threads = atoi(argv[1]);
		string sig_dir = argv[2];
		string filename = argv[3];

		// General signatures of all samples given
		SimilarityDetector *sd = new SimilarityDetector();
		
		sd->GenerateSignatures(filename, max_threads, sig_dir);
	}
#ifdef __PRINT_ONLY_MAIL__
	//
	// For testing and debugging and printing MAIL statements
	//
	else if (argc == 2)
	{
		string filename;
		filename.assign(argv[1]);

		/*
		 * Open binary file for reading with the file pointer pointing at the end (ate)
		 */
		ifstream file(filename.c_str(), ios::in | ios::binary | ios::ate);
		if (file.is_open())
		{
			unsigned int fileSize = (unsigned int)file.tellg();                // How much buffer we need for the file
			file.seekg (0, ios::beg);
			char *fileBuffer = new char[fileSize+1];
			file.read(fileBuffer, fileSize);                                  // Read the file into the buffer
			file.close();
			fileBuffer[fileSize] = '\0';

			Parser *parser = new Parser((uint8_t *)fileBuffer, fileSize);
			parser->Parse(filename);
			vector <CFG *> cfgs = parser->BuildCFGs();
			for (int c = 0; c < (int)cfgs.size(); c++)
				delete (cfgs[c]);
			delete (parser);
			delete (fileBuffer);
		}
		else
			cout << "Error:DroidNative:main: Cannot open the file: " << filename << "\n";
	}
#endif
	else
	{
		cout << "Error:DroidNative:main: Wrong parameters.\n";
		cout << "The program does not check for the correctness and order of parameters.\n";
		cout << "It's the responsibility of the user to provide correct parameters in order provided below.\n";
#ifdef __PRINT_ONLY_MAIL__
		cout << "Usage: DroidNative <filename>\n";
#else
		cout << "Usage for running ACFG: DroidNative <max_threads> <threshold_gm> <virus_samples> <file_to_check>\n";
		cout << "Usage for running SWOD: DroidNative <max_threads> <vwod> <hwod> <threshold_vwod> <threshold_hwod> <threshold_vsd> <threshold_hsd> <malware_samples> <benign_samples> <virus_samples> <file_to_check>\n";
#endif
	}

	return 0;
}
