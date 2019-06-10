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

#ifndef __COMMON_H__
#define __COMMON_H__

#include <vector>
#include <string>
#include <ctype.h>

#include "distorm.h"
#include "../include/capstone.h"

#define NULL_CHAR '\0'

#define __PRINT_REPORT__                            1
#define __PROGRAM_OUTPUT_ENABLED__                  1
#define __PRINT__ASSIGNED_WEIGHT__                  1
//#define __PRINT_SIGNATURE__                         1
//#define __DEBUG__                                   1

// Moved to the Makefile
//#define __SHRINKING_ENABLED__                       1
//#define __SIGNATURE_MATCHING__                      1
//#define __GRAPH_MATCHING__                          1

//#define __BUILD_DOT_GRAPH__                         1
//#define COLORED_GRAPH                               1
//#define GREY_GRAPH                                  1
#define __ASSIGNING_WEIGHT_TIME__                   1
#define __TRAINING_TIME__                           1
#define __TESTING_TIME__                            1
//#define __TRANSLATION_TIME__                        1

#define MAX_FILENAME                                1024   // (2^10)
#define ADDRESS_SIZE_FOR_STORAGE                    sizeof(uint32_t)

#define ONLY_COLLECT_DATA                           true
#define OMIT_LONG_JUMP                              false//true
#define LONG_JUMP                                   10
#define MAX_CALL_LIMIT                              1000
#define MAX_SYMBOL_NAME                             128
#define MAX_OPERANDS                                5
#define MAX_NESTED_LOOP_COUNT                       256    // (2^8)
#define MAX_FILENAME_LENGTH                         256

#define BRANCH_TO_UNKNOWN                           -101
#define OFFSET_UNKNOWN                              -102
#define END_OF_FUNCTION                             -103
#define END_OF_PROGRAM                              -104
#define VALUE_UNKNOWN                               -1     //0xEFFFFFFFFFFFFFFF

#define BLOCK_START_OF_FUNCTION                     301
#define BLOCK_END_OF_FUNCTION                       302
#define BLOCK_START_OF_PROGRAM                      303
#define BLOCK_END_OF_PROGRAM                        304
#define BLOCK_NORMAL                                305

#define INSTRUMENT_KIND_JUMP_ONLY                   401
#define INSTRUMENT_KIND_MEMORY_ONLY                 402
#define INSTRUMENT_KIND_RETURN_ONLY                 403
#define INSTRUMENT_KIND_FUNCTION_ONLY               404

#define X86_ASSEMBLY_LANGUAGE                       501
#define ARM_ASSEMBLY_LANGUAGE                       502
#define MAIL_LANGUAGE                               503

#define FUNCTION_CALL_COUNTER                       "CTR"
#define STRING_ADDED                                "_ADDED_"

#define SIGNATURE_FILE_EXTENSION                     "training.dat"

/*
 * Forward declarations
 */
struct Edge;

#ifdef __cplusplus
struct Register
#else
typedef struct Register
#endif
{
	std::string name;
	std::string value;
	uint64_t size;
};

#ifdef __cplusplus
struct Statement
#else
typedef struct Statement
#endif
{
	bool start;
	bool end;
	uint16_t type;
	uint64_t offset;
	int64_t branch_to_offset;
	std::string value;
};

#ifdef __cplusplus
struct Instruction
#else
typedef struct Instruction
#endif
{
	bool start;
	bool end;
	uint64_t offset;
	uint64_t block_number;
	uint32_t function_number;
	int64_t branch_to_offset;
	int64_t branch_to_block_number;
	unsigned char hex[MAX_TEXT_SIZE];
	unsigned char opcode[MAX_TEXT_SIZE];
	unsigned char operands[MAX_TEXT_SIZE];
};

#ifdef __cplusplus
struct Block
#else
typedef struct Block
#endif
{
	bool visited;
	bool inLoop;
	uint16_t type;
	uint64_t number;
	uint32_t function_number;
	std::vector<Block *> prev;
	std::vector<Edge *> edges;
	std::vector<Edge *> in_edges;
	std::vector<Statement *> statements;
};

#ifdef __cplusplus
struct Edge
#else
typedef struct Edge
#endif
{
	bool visited;
	Block *head;
	Block *tail;
};

#ifdef __cplusplus
struct BackEdge
#else
typedef struct BackEdge
#endif
{
	Block *head;
	Block *tail;
};

#ifdef __cplusplus
struct Loop
#else
typedef struct Loop
#endif
{
	BackEdge *backEdge;
	std::vector<Block *> blocks;
	std::vector<Loop *> nestedLoops;
};

#ifdef __cplusplus
struct Path
#else
typedef struct Path
#endif
{
	std::vector<Block *> blocks;
};

#ifdef __cplusplus
struct _address
#else
typedef struct _address
#endif
{
	uint64_t offset;
	uint64_t data;
};

#ifdef __cplusplus
struct _smart_data
#else
typedef struct _smart_data
#endif
{
	uint8_t byte;
	bool written;
};

#ifdef __cplusplus
struct _buffer
#else
typedef struct _buffer
#endif
{
	_smart_data *data;
	uint64_t current;
	uint64_t size;
};

#ifdef __cplusplus
struct _code
#else
typedef struct _code
#endif
{
	cs_insn *instructions;
	_DecodedInst *decoded;
	uint8_t *buffer;
	uint64_t buffer_size;
	uint64_t code_size;
	uint64_t offset;
	uint64_t addr_align;
	std::string name;
};

#ifdef __cplusplus
struct _data
#else
typedef struct _data
#endif
{
	uint8_t *buffer;
	uint64_t data_size;
	uint64_t offset;
	uint64_t addr_align;
	std::string name;
};

#ifdef __cplusplus
struct Function
#else
typedef struct Function
#endif
{
	char name[MAX_SYMBOL_NAME];
	std::vector<Block *> blocks;
	std::vector<BackEdge *> backEdges;
	std::vector<Loop *> loops;
};

#ifdef __cplusplus
struct SIGNATURE
#else
typedef struct SIGNATURE
#endif
{
	uint32_t size;
	uint32_t non_zeros;
	uint32_t *signature;
};

using namespace std;

#endif // __COMMON_H__
