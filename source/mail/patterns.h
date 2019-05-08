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

#ifndef __PATTERNS_H__
#define __PATTERNS_H__

enum Patterns
{
	PATTERN_ASSIGN = 0,
	PATTERN_ASSIGN_C,
	PATTERN_CONTROL,
	PATTERN_CONTROL_C,
	PATTERN_CALL,
	PATTERN_CALL_C,
	PATTERN_FLAG,
	PATTERN_FLAG_S,
	PATTERN_HALT,
	PATTERN_JUMP,
	PATTERN_JUMP_C,
	PATTERN_JUMP_S,
	PATTERN_LIBCALL,
	PATTERN_LIBCALL_C,
	PATTERN_LOCK,
	PATTERN_STACK,
	PATTERN_STACK_C,
	PATTERN_TEST,
	PATTERN_TEST_C,
	PATTERN_UNKNOWN,
	PATTERN_NOTDEFINED
};


static char PatternsNames[][128] =
{
	"ASSIGN",
	"ASSIGN_C",
	"CONTROL",
	"CONTROL_C",
	"CALL",
	"CALL_C",
	"FLAG",
	"FLAG_S",
	"HALT",
	"JUMP",
	"JUMP_C",
	"JUMP_S",
	"LIBCALL",
	"LIBCALL_C",
	"LOCK",
	"STACK",
	"STACK_C",
	"TEST",
	"TEST_C",
	"UNKNOWN",
	"NOTDEFINED"
};


const uint64_t NUMBER_OF_PATTERNS = sizeof(PatternsNames) / 128;

#ifdef __cplusplus
struct PatternsWeight
#else
typedef struct PatternsWeight
#endif
{
#ifdef __DEBUG__
	char sample_name[1024];
#endif
	uint64_t total_statements;
	double PW[NUMBER_OF_PATTERNS][2];
};


#endif // __PATTERNS_H__
