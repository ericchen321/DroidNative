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

#ifndef __INSTRUCTION_H__
#define __INSTRUCTION_H__

#include <string>
#include <map>

#include "../include/mnemonics.h"
#include "../parser/expression.h"
#include "../util/util.h"

#define INSTRUCTION_TYPE_UNDEFINED                  101
#define INSTRUCTION_TYPE_BRANCH                     102
#define INSTRUCTION_TYPE_UNCONDITIONAL_BRANCH       103
#define INSTRUCTION_TYPE_INDIRECT_BRANCH            104
#define INSTRUCTION_TYPE_CALL                       105
#define INSTRUCTION_TYPE_RETURN                     106
#define INSTRUCTION_TYPE_INTERRUPT_RETURN           107
#define INSTRUCTION_TYPE_SYS_CALL                   108
#define INSTRUCTION_TYPE_SYS_ENTER                  109
#define INSTRUCTION_TYPE_SYS_EXIT                   110
#define INSTRUCTION_TYPE_SYS_RET                    111
#define INSTRUCTION_TYPE_HALT                       112
#define INSTRUCTION_TYPE_NOP                        113
#define INSTRUCTION_TYPE_LOCK                       114
#define INSTRUCTION_TYPE_LOAD                       115
#define INSTRUCTION_TYPE_ARITHMETIC                 116
#define INSTRUCTION_TYPE_ADDED                      117
#define INSTRUCTION_TYPE_INTERRUPT                  118
#define INSTRUCTION_TYPE_INTERRUPT_THREE            119
#define INSTRUCTION_TYPE_CONDITION                  120
#define INSTRUCTION_TYPE_CONDITIONAL_MOV            121
#define INSTRUCTION_TYPE_SET                        122
#define INSTRUCTION_TYPE_PUSH                       123
#define INSTRUCTION_TYPE_POP                        124
#define INSTRUCTION_TYPE_OTHERS                     125

#define INSTRUCTION_TYPE_CONTROL_BRANCH             201
#define INSTRUCTION_TYPE_CONTROL_RETURN             202
#define INSTRUCTION_TYPE_MEMORY                     203

#define TOTAL_REGISTERS_EFFECTIVE_ADDRESS           8
#define TOTAL_TARGET_REGISTERS                      32

using namespace std;

/**
 * <p>
 * This class implements the Expression class.
 * It parses different expressions and returns a Vector<string> (Array of strings).
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since April 22, 2012
 *
 */
class InstructionClass
{
private:
	map<string, uint16_t> RegisterNames;

public:
	InstructionClass();
	~InstructionClass();

   uint64_t FindRIPAddress(_DecodedInst *instr, Expression *ex);
   vector<uint16_t> ReadRegisters(string operand);
	uint16_t Type(_DecodedInst *instruction, uint16_t &major_type, bool &is8bit, bool &is8bit_displacement);
	int64_t ReadSegmentRelativeOffset(const string operand);
	int16_t GetRegisterNumber(const string name);
   string GetRegisterName(uint16_t reg_num);
   vector<uint16_t> FindNextDependentRegisters(_code *code, uint16_t original_reg_num,
                                                uint64_t &instruction_number,
                                                uint64_t how_much_to_fallback);
   bool IsRegisterPresent(uint16_t reg_num, vector<uint16_t> registers);
   bool IsRegisterEqual(uint16_t reg_num_1, uint16_t reg_num_2);
};

#endif // __INSTRUCTION_H__
