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

#ifndef __SIMILARITY_DETECTOR_H__
#define __SIMILARITY_DETECTOR_H__

#ifdef __WIN32__
#include <windows.h>
#elif __LINUX__
#include <unistd.h>
#endif

#include "ml.h"
#include "../parser/parser.h"
#include "../isomorph/isomorph.h"
#include "../mail/mail.h"
#include "../mail/patterns.h"
#include "../mail/signature.h"
#include "../include/swod.h"
#include <stdlib.h>
#include <string.h>

typedef struct
{
	ML *ml;
	char *filename;
	char *fileBuffer;
	unsigned int size;
} ThreadData, *ThreadDataP;

using namespace std;

/**
 * <p>
 *
 * This class implements the SimilarityDetector class.
 *
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since December 24, 2013
 *
 */
class SimilarityDetector
{
private:
	bool ARE_WEIGHTS_ASSIGNED;
	double 	total_assigning_weight_time, total_training_time, total_testing_time;
	void AssignWeights(string malware_samples, string benign_samples);
	SIGNATURE *BuildSignature(MAIL *mail);
	void LoadMalwareSignatures(string virus_samples, string sig_temp_dir, ML* ml);
	void TrainDataUsingSignatureMatching(string filenameP, ML *ml);
	void BuildGraphs(ML *ml, char *filename, char *fileBuffer, unsigned int size);
	string getBaseName(const string& s);
	string getFolderPath(const string& s);

public:
	SimilarityDetector();
	~SimilarityDetector();
	void SetSizeSWOD(float vwod, float hwod, float threshold_vwod, float threshold_hwod, float threshold_vsd, float threshold_hsd);
	void SetThreshold(float threshold_gm);
	void CheckBinariesUsingGraphMatching(string virus_samples, string files_to_check, string sig_temp_dir, unsigned int max_threads);
	void CheckBinariesUsingSignatureMatching(string malware_samples, string benign_samples, string virus_samples, string files_to_check, unsigned int max_threads);
	void GenerateSignatures(string sample, int max_threads, string sig_dir);
};

#endif // __SIMILARITY_DETECTOR_H__
