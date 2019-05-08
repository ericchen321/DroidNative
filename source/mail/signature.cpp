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

#include "signature.h"

uint64_t PATTERNS_WEIGHT[NUMBER_OF_PATTERNS];

Signature::Signature()
{
}

Signature::~Signature()
{
}

/*
 *
 * This function takes a MAIL program and builds the signature as follows:
 *
 * Assign numbers to each pattern in the MAIL language.
 * These numbers are assigned to build the signature for a MAIL program.
 * This function assumes that each pattern has already been assign a weight
 * using the function AssignWeightToPatterns.
 *
 * The control flow patterns are assigned weight based on the following algorithm:
 *
 *   Each block's last statement gets a weight of 1.
 *   Each JUMP_* and CALL_* statement gets a weight of 1.
 *   Each CONTROL_* statement gets a weight of 2.
 *   Each control flow change (JUMP, CONTROL or CALL) gets weight equal to the length of the jump.
 *   A back jump (possibly a loop) weight is double the length of the jump.
 *   A jump outside of the function gets a weight equal to it's distance from the last block + 1.
 *
 * Every statement in a MAIL program is assigned the weight as above. These weights are
 * sorted in ascending order. These ascending ordered weights become the signature of the
 * MAIL program (malware/benign), and can be used to detect malware.
 *
 * For example, the following signature:
 * 
 *    1 1 1 1 1 3 3 3 4 4 7 7 7 7 7 7 7 15 15 15 15 21 21 21 23 23 23 23 23 37 37
 *    is stored as:
 *    -----------------------------------------------------------------------------
 *    |0|5|0|3|2|0|0|7|0|0|0|0|0|0|0|4|0|0|0|0|0|3|0|5|0|0|0|0|0|0|0|0|0|0|0|0|0|2|
 *    -----------------------------------------------------------------------------
 *    i.e:
 *    there are 5 1's, 3 3's, 2 4's, 7 7's, 4 15's and so on
 *
 * The reason for storing the signature in this format is for easy and fast comparison.
 *
 */
SIGNATURE *Signature::Build(MAIL *mail)
{
	vector<uint32_t> sigs;

	if (mail != NULL)
	{
		vector <Function *> functions = mail->GetFunctions();

		/*
		 * Compute and assign signature to each function
		 */
		for (int f = 0; f < (int)functions.size(); f++)
		{
			vector <Block *> blocks;

			blocks = functions[f]->blocks;
			// Go through each of the block
			for (unsigned int b = 0; b < blocks.size(); b++)
			{
				// Go through each statement in the block
				for (int s = 0; s < (int)blocks[b]->statements.size(); s++)
				{
					Statement *stmt = blocks[b]->statements[s];
					uint32_t weight = PATTERNS_WEIGHT[stmt->type];

					// If this is the CONTROL statement add 2 to the weight
					if (stmt->type == PATTERN_CONTROL)
					{
						weight += 2;
						// Compute and add weight for each outgoing edge in the statement
						// Weight will be equal to length of the jump
						int e = 0;
						for ( ; e < (int)blocks[b]->edges.size(); e++)
						{
							int w = blocks[b]->edges[e]->head->number - blocks[b]->edges[e]->tail->number;
							// A back jump weight is double the length of the jump
							if (w < 0)
								w = -2 * w;
							weight += w;
						}
						// If jump is outside the function
						if (e <= 2)
							weight += blocks.size() - blocks[b]->number;
					}
					// If this is the CONTROL statement add 2 to the weight
					else if (stmt->type == PATTERN_CONTROL_C)
					{
						weight += 2;
						// Compute and add weight for each outgoing edge in the statement
						// Weight will be equal to length of the jump
						int e = 0;
						for ( ; e < (int)blocks[b]->edges.size(); e++)
						{
							int w = blocks[b]->edges[e]->head->number - blocks[b]->edges[e]->tail->number;
							// A back jump weight is double the length of the jump
							if (w < 0)
								w = -2 * w;
							weight += w;
						}
						// If jump is outside the function
						if (e <= 2)
							weight += blocks.size() - blocks[b]->number;
					}
					// If this is the CALL statement add 1 to the weight
					else if (stmt->type == PATTERN_CALL)
					{
						weight++;
						// Compute and add weight for each outgoing edge in the statement
						// Weight will be equal to length of the jump
						int e = 0;
						for ( ; e < (int)blocks[b]->edges.size(); e++)
						{
							int w = blocks[b]->edges[e]->head->number - blocks[b]->edges[e]->tail->number;
							// A back jump weight is double the length of the jump
							if (w < 0)
								w = -2 * w;
							weight += w;
						}
						// If jump is outside the function
						if (e <= 2)
							weight += blocks.size() - blocks[b]->number;
					}
					// If this is the CALL statement add 1 to the weight
					else if (stmt->type == PATTERN_CALL_C)
					{
						weight++;
						// Compute and add weight for each outgoing edge in the statement
						// Weight will be equal to length of the jump
						int e = 0;
						for ( ; e < (int)blocks[b]->edges.size(); e++)
						{
							int w = blocks[b]->edges[e]->head->number - blocks[b]->edges[e]->tail->number;
							// A back jump weight is double the length of the jump
							if (w < 0)
								w = -2 * w;
							weight += w;
						}
						// If jump is outside the function
						if (e <= 2)
							weight += blocks.size() - blocks[b]->number;
					}
					// If this is the JUMP statement add 1 to the weight
					else if (stmt->type == PATTERN_JUMP)
					{
						weight++;
						// Compute and add weight for each outgoing edge in the statement
						// Weight will be equal to length of the jump
						int e = 0;
						for ( ; e < (int)blocks[b]->edges.size(); e++)
						{
							int w = blocks[b]->edges[e]->head->number - blocks[b]->edges[e]->tail->number;
							// A back jump weight is double the length of the jump
							if (w < 0)
								w = -2 * w;
							weight += w;
						}
						// If jump is outside the function
						if (e <= 2)
							weight += blocks.size() - blocks[b]->number;
					}
					// If this is the JUMP statement add 1 to the weight
					else if (stmt->type == PATTERN_JUMP_C)
					{
						weight++;
						// Compute and add weight for each outgoing edge in the statement
						// Weight will be equal to length of the jump
						int e = 0;
						for ( ; e < (int)blocks[b]->edges.size(); e++)
						{
							int w = blocks[b]->edges[e]->head->number - blocks[b]->edges[e]->tail->number;
							// A back jump weight is double the length of the jump
							if (w < 0)
								w = -2 * w;
							weight += w;
						}
						// If jump is outside the function
						if (e <= 2)
							weight += blocks.size() - blocks[b]->number;
					}
					// If this is the JUMP statement add 1 to the weight
					else if (stmt->type == PATTERN_JUMP_S)
					{
						weight++;
						// Compute and add weight for each outgoing edge in the statement
						// Weight will be equal to length of the jump
						int e = 0;
						for ( ; e < (int)blocks[b]->edges.size(); e++)
						{
							int w = blocks[b]->edges[e]->head->number - blocks[b]->edges[e]->tail->number;
							// A back jump weight is double the length of the jump
							if (w < 0)
								w = -2 * w;
							weight += w;
						}
						// If jump is outside the function
						if (e <= 2)
							weight += blocks.size() - blocks[b]->number;
					}
					// If this is the last statement and not the control statement (CONTROL, CALL and JUMP) add 1 to the weight
					else if (s == (int)blocks[b]->statements.size()-1)
						weight++;

					// There is no need to store weight 0 as a signature
					if (weight > 0)
						sigs.push_back(weight);
				}
			}
		}
	}

	SIGNATURE *sig = new SIGNATURE();
	if (sigs.size() > 0)
	{
		// Storing the signature
		std::sort (sigs.begin(), sigs.end());
		sig->non_zeros = 1;
		sig->size = sigs[sigs.size()-1] + 1;
		sig->signature = new uint32_t[sig->size];
		for (int s = 0; s < (int)sig->size; s++)
			sig->signature[s] = 0;
		int prev = sigs[0];
		for (int n = 0; n < (int)sigs.size(); n++)
		{
			if (sigs[n] < sig->size)
				sig->signature[sigs[n]] += 1;
			else
				printf("Error::Signature::Build(): Signature list is not sorted properly\n");
			if ((int)sigs[n] > prev)
				sig->non_zeros++;
			prev = sigs[n];
		}
		sigs.erase(sigs.begin(), sigs.end());

#ifdef __DEBUG__
		cout << "\n----- Printing the Stored Signature -----\n";
		for (int i = 0; i < (int)sig->size; i++)
		{
			if (sig->signature[i] > 0)
				printf("%d = %d : ", i, sig->signature[i]);
		}
		printf("\n\n");
#endif
	}

	return (sig);
}

bool sort_function(double i, double j)
{
	return (i > j);
}

/*
 *
 */
double Signature::AssignWeightToPatterns(string virus_samples, string benign_samples, double VERTICAL_WINDOW_OF_DIFF, double HORIZONTAL_WINDOW_OF_DIFF)
{
#ifdef __DEBUG__
	cerr << "-----------------------------------------------------------------------------------------------------------------------\n\n";
	cerr << "Signature::AssignWeightToPatterns: Start using " << virus_samples << " and " << benign_samples << "\n\n";
	cerr << "-----------------------------------------------------------------------------------------------------------------------\n";
	cerr << "VWOD: " << VERTICAL_WINDOW_OF_DIFF << " HWOD: " << HORIZONTAL_WINDOW_OF_DIFF << endl;
	cout << "-----------------------------------------------------------------------------------------------------------------------\n\n";
	cout << "Signature::AssignWeightToPatterns: Start using " << virus_samples << " and " << benign_samples << "\n\n";
	cout << "-----------------------------------------------------------------------------------------------------------------------\n";
	cout << "VWOD: " << VERTICAL_WINDOW_OF_DIFF << " HWOD: " << HORIZONTAL_WINDOW_OF_DIFF << endl;
#endif
	string file_samples[2];
	file_samples[0] = virus_samples;
	file_samples[1] = benign_samples;

	// Initialize pattern's priorities
	for (int p = 0; p < (int)NUMBER_OF_PATTERNS; p++)
		PATTERNS_WEIGHT[p] = 0;

#ifdef __ASSIGNING_WEIGHT_TIME__
	clock_t start = 0, end = 0;
	double time = 0.0;
#endif
	vector<PatternsWeight> pwListMalware, pwListBenign;
	for (int i = 0; i < 2; i++)
	{
#ifdef __DEBUG__
		cerr << "-----------------------------------------------------------------------------------------------------------------------\n";
		cerr << i << " Signature::AssignWeightToPatterns: Checking file: " << file_samples[i] << "\n";
		cout << "-----------------------------------------------------------------------------------------------------------------------\n";
		cout << i << " Signature::AssignWeightToPatterns: Checking file: " << file_samples[i] << "\n";
#endif
		/*
		 * Open binary file for reading with the file pointer pointing at the end (ate)
		 */
		ifstream fileP(file_samples[i].c_str(), ios::in | ios::binary | ios::ate);
		if (fileP.is_open())
		{
			unsigned int fileSize = (unsigned int)fileP.tellg();                // How much buffer we need for the file
			fileP.seekg (0, ios::beg);
			char *fileBufferP = new char[fileSize+1];
			fileP.read(fileBufferP, fileSize);                // Read the file into the buffer
			fileP.close();
			fileBufferP[fileSize] = '\0';

			char filename[3*MAX_FILENAME+1];
			int c = 0;

			for (unsigned int n = 0; n < fileSize; n++)
			{
				if ( (c < 3*MAX_FILENAME) && (fileBufferP[n] == '\n' || fileBufferP[n] == '\r') )
				{
					filename[c] = '\0';
#ifdef __DEBUG__
					cerr << "-----------------------------------------------------------------------------------------------------------------------\n";
					cerr << i << " Signature::AssignWeightToPatterns: file: " << filename << "\n";
					cout << "-----------------------------------------------------------------------------------------------------------------------\n";
					cout << i << " Signature::AssignWeightToPatterns: file: " << filename << "\n";
#endif
#ifdef __PROGRAM_OUTPUT_ENABLED__
					printf("Assign Weight To Patterns processing file: %s\n", filename);
					fflush(stdout);
#endif
					ifstream file(filename, ios::in | ios::binary | ios::ate);
					if (file.is_open())
					{
						unsigned int size = (unsigned int)file.tellg();                // How much buffer we need for the file
						file.seekg (0, ios::beg);
						char *fileBuffer = new char[size+1];
						file.read(fileBuffer, size);                 // Read the file into the buffer
						file.close();
						fileBuffer[size] = '\0';

#ifdef __ASSIGNING_WEIGHT_TIME__
						start = clock();
#endif
						Parser *parser = new Parser((uint8_t *)fileBuffer, size);
						parser->Parse(filename);
						if (parser->mail != NULL)
						{
							PatternsWeight pw;
							pw.total_statements = 0;
							for (int p = 0; p < (int)NUMBER_OF_PATTERNS; p++)
								pw.PW[p][1] = 0;
							vector <Function *> functions = parser->mail->GetFunctions();
							for (int f = 0; f < (int)functions.size(); f++)
							{
								vector <Block *> blocks;
#ifdef __SHRINKING_ENABLED__
								vector <BackEdge *> backEdges;
								blocks = functions[f]->blocks;
								backEdges = functions[f]->backEdges;
								CFG *cfg = new CFG(blocks, backEdges, filename);
								cfg->Shrink();
								functions[f]->blocks = cfg->GetBlocks();
								delete (cfg);
#endif
								blocks = functions[f]->blocks;
								// Go through each of the block
								for (unsigned int b = 0; b < blocks.size(); b++)
								{
									// Go through each statement in the block
									for (int s = 0; s < (int)blocks[b]->statements.size(); s++)
									{
										Statement *stmt = blocks[b]->statements[s];
										uint16_t pattern = stmt->type;
										if (pattern < NUMBER_OF_PATTERNS)
										{
											pw.PW[pattern][1] += 1;
											pw.total_statements += 1;
										}
										else
											cerr << "Error: Wrong Pattern, not recorded";
									}
								}
							}
							/*
							 * Compute the percentage of each pattern present in the sample
							 * out of the total statements in the sample
							 */
							if (pw.total_statements > 0)
							{
								for (int p = 0; p < (int)NUMBER_OF_PATTERNS; p++)
									pw.PW[p][1]  = (pw.PW[p][1] / pw.total_statements) * 100.0;
							}
							// Malware samples
							if (i == 0)
								pwListMalware.push_back(pw);
							// Benign samples
							else if (i == 1)
								pwListBenign.push_back(pw);
						}
						delete (parser);
#ifdef __ASSIGNING_WEIGHT_TIME__
						end = clock();
						time += (end - start);
#endif
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
			cout << "Error:Signature::AssignWeightToPatterns: Cannot open the file: " << benign_samples << "\n";
	}

#ifdef __ASSIGNING_WEIGHT_TIME__
	start = clock();
#endif
	/*
	 * SORTING THE PATTERNS BASED ON WEIGHTS ASSIGNED ABOVE
	 */
	vector<PatternsWeight> pwSortedListMalware, pwSortedListBenign;
	// Sort the patterns in List Malware
	vector<double> weightsMalware[NUMBER_OF_PATTERNS];
	for (int n = 0; n < (int)pwListMalware.size(); n++)
	{
		PatternsWeight pw = pwListMalware[n];
		for (int p = 0; p < (int)NUMBER_OF_PATTERNS; p++)
			weightsMalware[p].push_back(pw.PW[p][1]);
	}
	for (int p = 0; p < (int)NUMBER_OF_PATTERNS; p++)
		std::sort (weightsMalware[p].begin(), weightsMalware[p].end(), sort_function);
	for (int n = (int)pwListMalware.size()-1; n >= 0; n--)
	{
		PatternsWeight pw;
		for (int p = 0; p < (int)NUMBER_OF_PATTERNS; p++)
			pw.PW[p][1] = weightsMalware[p][n];
		pwSortedListMalware.push_back(pw);
	}
	// Sort the patterns in List Benign
	vector<double> weightsBenign[NUMBER_OF_PATTERNS];
	for (int n = 0; n < (int)pwListBenign.size(); n++)
	{
		PatternsWeight pw = pwListBenign[n];
		for (int p = 0; p < (int)NUMBER_OF_PATTERNS; p++)
			weightsBenign[p].push_back(pw.PW[p][1]);
	}
	for (int p = 0; p < (int)NUMBER_OF_PATTERNS; p++)
		std::sort (weightsBenign[p].begin(), weightsBenign[p].end(), sort_function);
	for (int n = pwListBenign.size()-1; n >= 0; n--)
	{
		PatternsWeight pw;
		for (int p = 0; p < (int)NUMBER_OF_PATTERNS; p++)
			pw.PW[p][1] = weightsBenign[p][n];
		pwSortedListBenign.push_back(pw);
	}

	/*
	 *
	 * HEURISTICS TO COMPUTE WEIGHT FOR EACH MAIL PATTERN
	 *
	 * Calculate windows of differences between a Malware pattern and a Benign pattern as follows:
	 *
	 * First we have computed (above) the percentage of patterns (weights) in each malware sample
	 * Now we want to compute the difference between a Malware pattern and a Benign pattern
	 * to assign a priority to each pattern. We divide each pattern's weights into NUMBER_OF_PATTERNS
	 * different windows.
	 * If the difference of weights (in %age) of HORIZONTAL_WINDOW_OF_DIFF% of the weights for each
	 * window is greater than or equal to VERTICAL_WINDOW_OF_DIFF(%), then that window is added to
	 * the pattern's window of difference (WOD).
	 * A pattern with highest number of WODs gets the highest weight and a pattern with lowest
	 * number of WODs gets the lowest weight, and so on.
	 *
	 * We give priority to the samples that have more occurences of a MAIL pattern
	 * and that's why we first sort the list in descending order.
	 * Now first it divides the data into Windows and then find the difference
	 * for these Windows. So if one list is greater than the other, it stops
	 * with the shorter list.
	 *
	 */
	uint64_t dividerMalware = pwSortedListMalware.size();
	if (dividerMalware > NUMBER_OF_PATTERNS)
		dividerMalware = pwSortedListMalware.size() / NUMBER_OF_PATTERNS;

	for (int p = 0; p < (int)NUMBER_OF_PATTERNS; p++)
	{
		uint64_t WOD = 0;
		for (int m = 0; m < (int)pwSortedListMalware.size(); m += dividerMalware)
		{
			for (int i = m; i < (int)(m+NUMBER_OF_PATTERNS); i++)
			{
				if (i >= (int)pwSortedListMalware.size() || i >= (int)pwSortedListBenign.size())
					break;
				double diff = std::abs(weightsMalware[p][i] - weightsBenign[p][i]);
				if (diff >= VERTICAL_WINDOW_OF_DIFF)
				{
					diff = i - m;
					diff = (diff / NUMBER_OF_PATTERNS) * 100.0;
					if (diff >= HORIZONTAL_WINDOW_OF_DIFF)
					{
						WOD++;
						break;
					}
				}
			}
		}
		PATTERNS_WEIGHT[p] = WOD;
	}
#ifdef __ASSIGNING_WEIGHT_TIME__
	end = clock();
	time += (end - start);
#endif

#ifdef __PRINT__ASSIGNED_WEIGHT__
	printf("Patterns with there Weights/Priorities\n");
	for (int p = 0; p < (int)NUMBER_OF_PATTERNS; p++)
		printf("Pattern %12s   Weight/Priority %5d\n", PatternsNames[p], (int)PATTERNS_WEIGHT[p]);
	printf("\n");
#endif

#ifdef __DEBUG__
	printf("       Malware Samples       \n");
	int n2 = 0;
	for (int n1 = 0; n1 < pwSortedListMalware.size(); n1++)
	{
		if ( (pwSortedListMalware.size() - n1) >= (pwSortedListBenign.size() - n2) )
			n2++;
		else
			n2 += 3;
		if (n1%10 == 0)
		{
			PatternsWeight pw1 = pwSortedListMalware[n1];
			printf("%7d", n1);
			printf("%7.2f", pw1.PW[0][1]);
			printf("%7.2f", pw1.PW[5][1]);
			printf("%7.2f", pw1.PW[16][1]);
			if (n2 < pwSortedListBenign.size())
			{
				PatternsWeight pw2 = pwSortedListBenign[n2];
				printf("%7.2f", pw2.PW[0][1]);
				printf("%7.2f", pw2.PW[5][1]);
				printf("%7.2f", pw2.PW[16][1]);
			}
			printf("\n");
		}
	}
	printf("\n");
#endif

#ifdef __DEBUG__
// ------------------------------------------------------
// Print Sorted Lists
// ------------------------------------------------------
	printf("       Malware Samples       \n");
	printf("               Name of the sample               ");
	printf("       ");
	for (int p = 0; p < NUMBER_OF_PATTERNS; p++)
		printf("%7d", p);
	printf("\n");
	for (int p = 0; p < NUMBER_OF_PATTERNS; p++)
		printf("-----");
	printf("\n");
	for (int n = 0; n < pwSortedListMalware.size(); n++)
	{
		PatternsWeight pw = pwSortedListMalware[n];
		printf("%48s", pw->sample_name);
		printf("%7d", n);
		for (int p = 0; p < NUMBER_OF_PATTERNS; p++)
		{
			printf("%7.2f", pw.PW[p][1]);
		}
		printf("\n");
	}
	printf("\n");

	printf("       Benign Samples       \n");
	printf("               Name of the sample               ");
	printf("       ");
	for (int p = 0; p < NUMBER_OF_PATTERNS; p++)
		printf("%7d", p);
	printf("\n");
	for (int p = 0; p < NUMBER_OF_PATTERNS; p++)
		printf("-----");
	printf("\n");
	for (int n = 0; n < pwSortedListBenign.size(); n++)
	{
		PatternsWeight pw = pwSortedListBenign[n];
		printf("%48s", pw->sample_name);
		printf("%7d", n);
		for (int p = 0; p < NUMBER_OF_PATTERNS; p++)
		{
			printf("%7.2f", pw.PW[p][1]);
		}
		printf("\n");
	}

// ------------------------------------------------------
// Print Unsorted Lists
// ------------------------------------------------------

	printf("       Malware Samples       \n");
	printf("               Name of the sample               ");
	printf("       ");
	for (int p = 0; p < NUMBER_OF_PATTERNS; p++)
		printf("%7d", p);
	printf("\n");
	for (int p = 0; p < NUMBER_OF_PATTERNS; p++)
		printf("-----");
	printf("\n");
	for (int n = 0; n < pwListMalware.size(); n++)
	{
		PatternsWeight pw = pwListMalware[n];
		printf("%48s", pw->sample_name);
		printf("%7d", n);
		for (int p = 0; p < NUMBER_OF_PATTERNS; p++)
		{
			printf("%7.2f", pw.PW[p][1]);
		}
		printf("\n");
	}
	printf("\n");

	printf("       Benign Samples       \n");
	printf("               Name of the sample               ");
	printf("       ");
	for (int p = 0; p < NUMBER_OF_PATTERNS; p++)
		printf("%7d", p);
	printf("\n");
	for (int p = 0; p < NUMBER_OF_PATTERNS; p++)
		printf("-----");
	printf("\n");
	for (int n = 0; n < pwListBenign.size(); n++)
	{
		PatternsWeight pw = pwListBenign[n];
		printf("%48s", pw->sample_name);
		printf("%7d", n);
		for (int p = 0; p < NUMBER_OF_PATTERNS; p++)
		{
			printf("%7.2f", pw.PW[p][1]);
		}
		printf("\n");
	}
#endif

#ifdef __ASSIGNING_WEIGHT_TIME__
	start = clock();
#endif
	pwListMalware.erase(pwListMalware.begin(), pwListMalware.end());
	pwListMalware.clear();
	pwListBenign.erase(pwListBenign.begin(), pwListBenign.end());
	pwListBenign.clear();
	pwSortedListMalware.erase(pwSortedListMalware.begin(), pwSortedListMalware.end());
	pwSortedListMalware.clear();
	pwSortedListBenign.erase(pwSortedListBenign.begin(), pwSortedListBenign.end());
	pwSortedListBenign.clear();
	for (int p = 0; p < (int)NUMBER_OF_PATTERNS; p++)
	{
		weightsMalware[p].erase(weightsMalware[p].begin(), weightsMalware[p].end());
		weightsMalware[p].clear();
		weightsBenign[p].erase(weightsBenign[p].begin(), weightsBenign[p].end());
		weightsBenign[p].clear();
	}
	double total_assigning_weight_time = 0.0;
#ifdef __ASSIGNING_WEIGHT_TIME__
	end = clock();
	time += (end - start);
	total_assigning_weight_time = ((double)(time))/CLOCKS_PER_SEC;
	printf("Total  Assigning Weights time : %15.5f second(s)\n", total_assigning_weight_time);
#endif
#ifdef __DEBUG__
	cerr << "----------------------------------------\n\n";
	cerr << "Signature::AssignWeightToPatterns: End\n\n";
	cerr << "----------------------------------------\n";
	cout << "----------------------------------------\n\n";
	cout << "Signature::AssignWeightToPatterns: End\n\n";
	cout << "----------------------------------------\n";
#endif

	return (total_assigning_weight_time);
}

/*
 *
 * Compare two signatures and returns true or false depending on the comparison score, as follows:
 * 
 * First start from the smallest and compare each element value.
 * If the difference (percentage out of the larger value) in values is <= VERTICAL_WINDOW_OF_DIFF increment the score.
 * Compute the percent score out of the total number of elements compared.
 * If the percent score is >= HORIZONTAL_WINDOW_OF_DIFF then return true.
 * 
 * For example:
 *         ---------------------
 * sig1:   |0|9|1|3|2|0|0|7|0|0|
 *         ---------------------
 *         ------------------------------
 * sig2:   |0|5|1|5|7|0|0|6|0|0|0|0|0|3|0
 *         ------------------------------
 * It starts at index 9 and goes down to 0, comparing each element.
 * Value at index 7 gives a difference of 1 which is less than DIFF*3 (assume DIFF = 5%)
 * percent of the larger value (i.e 7) and score is incremented by 1. In this way with
 * each comparison we increment the score. When the score >= PERCENT_DIFF/2 percent of the
 * number of non zero values in the larger signature, we return true otherwise we return false.
 * In this example score becomes >= PERCENT_DIFF/3 (assume PERCENT_DIFF = 50%) at index 2.
 * 50%/2 = 25% and there are 6 non zero values in sig2 (the larger signature). 25% of 6 is 1.5.
 * At least two values need to match according to the above criteria to make it >= 25%(1.5).
 * There are two values at indices 2 and 7 that fulfill this criteria.
 * 
 */
double Signature::AlmostEqual(SIGNATURE *sig1, SIGNATURE *sig2, double VERTICAL_SIGNATURE_DIFF, double HORIZONTAL_SIGNATURE_DIFF)
{
	double score = 0.0;
	// start with the samller size signature
	int start = (sig1->size < sig2->size) ? sig1->size : sig2->size;
	SIGNATURE *larger = (sig1->size > sig2->size) ? sig1 : sig2;

#ifdef __PRINT_SIGNATURE__
	cout << "\n----- Signature::AlmostEqual: Printing the Stored Signature 1 -----\n";
	int n = 0;
	for (int i = 0; i < (int)sig1->size; i++)
	{
		if (sig1->signature[i] > 0)
			printf("%d %d = %d : ", n, i, sig1->signature[i]);
	}
	printf("\n");
	cout << "\n----- Signature::AlmostEqual: Printing the Stored Signature 2 -----\n";
	for (int i = 0; i < (int)sig2->size; i++)
	{
		if (sig2->signature[i] > 0)
			printf("%d = %d : ", i, sig2->signature[i]);
	}
	printf("\n\n");
#endif
#ifdef __DEBUG__
	cerr << "VSD:  " << VERTICAL_SIGNATURE_DIFF << " HSD:  " << HORIZONTAL_SIGNATURE_DIFF << endl;
	cout << "VSD:  " << VERTICAL_SIGNATURE_DIFF << " HSD:  " << HORIZONTAL_SIGNATURE_DIFF << endl;
#endif

	double percentScore = 0.0;
	for (int s = start-1; s >= 0; s--)
	{
		if (sig1->signature[s] != 0 && sig2->signature[s] != 0)
		{
			double diff = sig1->signature[s] - sig2->signature[s];
			uint32_t current_larger_value = sig2->signature[s];
			if (diff < 0)
				current_larger_value = sig2->signature[s];
			diff = std::abs(diff);
			diff = (diff / current_larger_value) * 100.0;
			if (diff <= VERTICAL_SIGNATURE_DIFF)
			{
				score++;
				percentScore = (score / larger->non_zeros) * 100.0;
				if (percentScore >= HORIZONTAL_SIGNATURE_DIFF)
					break;
			}
		}
	}

	return (percentScore);
}
