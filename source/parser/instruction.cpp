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

#include "instruction.h"

/*
 * 64 bit mode only
 */
string REGISTERS[TOTAL_TARGET_REGISTERS] =
{
   "RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI",
   "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15",
   "XMM0", "XMM1", "XMM2", "XMM3", "XMM4", "XMM5", "XMM6", "XMM7",
   "EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"
};

/*
 *
 * It builds the following map when called for the first time:
 *
 * reg_name --> reg_number
 *
 */
InstructionClass::InstructionClass()
{
	for (int i = 0; i < TOTAL_TARGET_REGISTERS; i++)
	{
		RegisterNames.insert(pair<string, uint16_t>(REGISTERS[i], i));
#ifdef __DEBUG
      cout << "Adding to register map: " << REGISTERS[i] << " --> " << dec << i << endl;
#endif
	}
}

InstructionClass::~InstructionClass()
{
	RegisterNames.erase(RegisterNames.begin(), RegisterNames.end());
}

/*
 * <p>
 * Returns the major and minor types of instruction that are
 * used in instrumenting and updating the binary code.
 * For now we only check the size (encoding) for control instructions.
 * </p>
 */
uint16_t InstructionClass::Type(_DecodedInst *instruction, uint16_t &major_type, bool &is8bit_encoding, bool &is8bit_displacement)
{
	uint16_t minor_type = INSTRUCTION_TYPE_OTHERS;
	major_type = minor_type;
	/*
	 *
	 * Only check for control instructions.
	 * This tells us only the size of the instruction encoding
	 * excluding any other encoding included in the machine
	 * code dump.
	 * e.g:
	 *
    * 0x40057c       0f 85 b6 01 00 00       JNZ   0x400738
    *
    * 0f85 is the machine encoding for JNZ far jump and
    * occupies 16 bits.
    *
	 */
	is8bit_encoding = false;
	is8bit_displacement = false;
	string hex_dump, opcode;

	hex_dump.assign((char *)instruction->instructionHex.p);
	opcode.assign((char *)instruction->mnemonic.p);
	Util::removeWhiteSpaces(hex_dump);
	Util::removeWhiteSpaces(opcode);

	if (opcode.find(STRING_ADDED) != string::npos)
		return INSTRUCTION_TYPE_ADDED;
	else if(opcode.find("SET") == 0)
	{
		minor_type = INSTRUCTION_TYPE_SET;
		major_type = INSTRUCTION_TYPE_SET;
	}
	else if (opcode[0] == 'J')
	{
		if (opcode[1] == 'M' && opcode[2] == 'P')
		{
			minor_type = INSTRUCTION_TYPE_UNCONDITIONAL_BRANCH;
			/*
          * The machine code of all x86 unconditional branch
          * instructions in 64 bit mode whose machine code
          * starts with '0f' occupies more than 8 bits.
          * The machine code 'eb' is for 8 bit displacement.
			 */
         is8bit_encoding = true;
         if (hex_dump[0] == 'e' && hex_dump[1] == 'b')
            is8bit_displacement = true;
         else if (hex_dump[0] == 'f' && hex_dump[1] == 'f')
            is8bit_encoding = false;
		}
		else
		{
			minor_type = INSTRUCTION_TYPE_BRANCH;
			/*
          * The machine code of all x86 conditional branch
          * instructions in 64 bit mode whose machine code
          * starts with '0f' occupies more than 8 bits
          * The machine code 'of' is for more than 8 bit
          * displacement.
			 */
         is8bit_encoding = true;
         is8bit_displacement = true;
         if (hex_dump[0] == '0' && hex_dump[1] == 'f')
         {
            is8bit_encoding = false;
            is8bit_displacement = false;
         }
		}
		major_type = INSTRUCTION_TYPE_CONTROL_BRANCH;
	}
	else if (opcode.find("LOOP") == 0)
	{
		minor_type = INSTRUCTION_TYPE_BRANCH;
		major_type = INSTRUCTION_TYPE_CONTROL_BRANCH;
		/*
		 * The machine code of all x86 LOOP instructions
		 * in 64 bit mode occupies 8 bits and the
		 * displacement is also 8 bit.
		 */
      is8bit_encoding = true;
      is8bit_displacement = true;
	}
	else if (opcode.find("CALL") == 0)
	{
		minor_type = INSTRUCTION_TYPE_CALL;
		major_type = INSTRUCTION_TYPE_CONTROL_BRANCH;
		/*
		 * The machine code of all x86 CALL instructions
		 * in 64 bit mode whose machine code starts with
		 * 'e8' occupies 8 bits else occupies more than
		 * 8 bits. The displacement is always more than
		 * 8 bits.
		 */
      is8bit_displacement = false;
      if (hex_dump[0] == 'e' && hex_dump[1] == '8')
         is8bit_encoding = true;
	}
	else if (opcode.find("RET") == 0)
	{
		minor_type = INSTRUCTION_TYPE_RETURN;
		major_type = INSTRUCTION_TYPE_CONTROL_RETURN;
	}
	else if (opcode.find("IRET") == 0)
	{
		minor_type = INSTRUCTION_TYPE_INTERRUPT_RETURN;
		major_type = INSTRUCTION_TYPE_CONTROL_RETURN;
	}
	else if (opcode.find("HLT") == 0)
	{
		minor_type = INSTRUCTION_TYPE_HALT;
		major_type = INSTRUCTION_TYPE_CONTROL_RETURN;
	}
	else if (opcode.find("SYS") == 0)
	{
		if (opcode[1] == 'C' && opcode[2] == 'A' && opcode[3] == 'L' && opcode[4] == 'L')
		{
			minor_type = INSTRUCTION_TYPE_SYS_CALL;
			major_type = INSTRUCTION_TYPE_CONTROL_BRANCH;
		}
		else if (opcode[1] == 'E' && opcode[2] == 'N' && opcode[3] == 'T' && opcode[4] == 'E' && opcode[5] == 'R')
			minor_type = INSTRUCTION_TYPE_SYS_ENTER;
		else if (opcode[1] == 'E' && opcode[2] == 'X' && opcode[3] == 'I' && opcode[4] == 'T')
			minor_type = INSTRUCTION_TYPE_SYS_EXIT;
		else if (opcode[1] == 'R' && opcode[2] == 'E' && opcode[3] == 'T')
			minor_type = INSTRUCTION_TYPE_SYS_RET;
	}
	else if (opcode.find("NOP") == 0)
		minor_type = INSTRUCTION_TYPE_NOP;
	else if (opcode.find("LOCK") == 0)
		minor_type = INSTRUCTION_TYPE_LOCK;
	else if (opcode.find("MOV") == 0
			|| opcode.find("PMOV") == 0
			|| opcode.find("MASKMOV") == 0
			|| opcode.find("LOAD") == 0
			|| opcode.find("LEA") == 0
			|| opcode.find("LDDQU") == 0
			|| opcode.find("LDS") == 0
			|| opcode.find("LES") == 0
			|| opcode.find("LFS") == 0
			|| opcode.find("LGS") == 0
			|| opcode.find("LSS") == 0
			|| opcode.find("LEA") == 0
			|| opcode.find("LDMXCSR") == 0
			|| opcode.find("PREFETCH") == 0
			|| opcode.find("VMPTRLD") == 0
			|| opcode.find("VMPTRST") == 0
			|| opcode.find("VMREAD") == 0
			|| opcode.find("VMWRITE") == 0)
	{
		minor_type = INSTRUCTION_TYPE_LOAD;
		major_type = INSTRUCTION_TYPE_LOAD;
	}
	else if (opcode.find("ADD") == 0
			|| opcode.find("ADC") == 0
			|| opcode.find("SUB") == 0
			|| opcode.find("MUL") == 0
			|| opcode.find("DIV") == 0
			|| opcode.find("DEC") == 0
			|| opcode.find("INC") == 0
			|| opcode.find("SHR") == 0
			|| opcode.find("SAR") == 0
			|| opcode.find("SHL") == 0
			|| opcode.find("SAL") == 0
			|| opcode.find("NEG") == 0
			|| opcode.find("AND") == 0
			|| opcode.find("OR") == 0
			|| opcode.find("XOR") == 0
			|| opcode.find("AVG") == 0
			|| opcode.find("MIN") == 0
			|| opcode.find("MAX") == 0
			|| opcode.find("DPP") == 0        // Dot product
			|| opcode.find("PSL") == 0        // Shift Left Logical
			|| opcode.find("PSR") == 0        // Shift Right Logical
			|| opcode.find("MADD") == 0       // Multiply and add
			|| opcode.find("RCP") == 0        // Compute Reciprocals
			|| opcode.find("SQRT") == 0       // Compute Square Roots
			|| opcode.find("RSQRT") == 0      // Compute Reciprocals of Square Roots
			|| opcode.find("PSADBW") == 0     // Compute Sum of Absolute Differences
			|| opcode.find("MPSADBW") == 0)   // Compute Multiple Packed Sums of Absolute Difference
	{
	   minor_type = INSTRUCTION_TYPE_ARITHMETIC;
		major_type = INSTRUCTION_TYPE_ARITHMETIC;
	}
	else if (opcode.find("CMP") == 0
			|| opcode.find("TEST") == 0)
	{
	   minor_type = INSTRUCTION_TYPE_CONDITION;
		major_type = INSTRUCTION_TYPE_CONDITION;
	}
	else if (opcode.find("CMOV") == 0
			|| opcode.find("FCMOV") == 0)
	{
		minor_type = INSTRUCTION_TYPE_CONDITIONAL_MOV;
		major_type = INSTRUCTION_TYPE_CONDITIONAL_MOV;
	}
	else if (opcode.find("INT") == 0)
	{
		if (opcode.find("INT 3") == 0)
			minor_type = INSTRUCTION_TYPE_INTERRUPT_THREE;
		else
			minor_type = INSTRUCTION_TYPE_INTERRUPT;
		major_type = INSTRUCTION_TYPE_INTERRUPT;
	}
	else if (opcode.find("PUSH") == 0)
	{
		minor_type = INSTRUCTION_TYPE_PUSH;
		major_type = INSTRUCTION_TYPE_PUSH;
	}
	else if (opcode.find("POP") == 0)
	{
		minor_type = INSTRUCTION_TYPE_POP;
		major_type = INSTRUCTION_TYPE_POP;
	}

	return minor_type;
}

/*
 *
 * NOT YET IMPLEMENTED
 *
 */
int64_t InstructionClass::ReadSegmentRelativeOffset(const string operand)
{
	int64_t offset = -1;
	return (offset);
}

/*
 *
 * Given the name of the register, it returns the register number.
 *
 */
int16_t InstructionClass::GetRegisterNumber(const string name)
{
	int16_t reg_number = -1;

	map<string, uint16_t>::iterator it_reg = RegisterNames.find(name);
	if (it_reg != RegisterNames.end())
      reg_number = (int16_t)it_reg->second;

	return (reg_number);
}

/*
 *
 * Given the number of the register, it returns the name of the register.
 *
 */
string InstructionClass::GetRegisterName(uint16_t reg_num)
{
   if (reg_num >= 0 && reg_num < TOTAL_TARGET_REGISTERS)
      return (REGISTERS[reg_num]);
   else
      return "";
}

/*
 * Read registers from an oerand string
 * Returns there numbers in a vector
 *
 */
vector<uint16_t> InstructionClass::ReadRegisters(string operand)
{
   vector<uint16_t> registers;
   string reg;
   int16_t reg_num;

   for (uint16_t pos = 0; pos < operand.size(); )
   {
      if (operand[pos] == 'R')
      {
         reg = operand.substr(pos, 3);
         reg_num = GetRegisterNumber(reg);
         if (reg_num >= 0)
         {
            registers.push_back(reg_num);
            pos += 3;
         }
         else
         {
            reg = operand.substr(pos, 2);
            reg_num = GetRegisterNumber(reg);
            if (reg_num >= 0)
            {
               registers.push_back(reg_num);
               pos += 2;
            }
            pos++;
         }
      }
      else if (operand[pos] == 'E')
      {
         reg = operand.substr(pos, 3);
         reg_num = GetRegisterNumber(reg);
         if (reg_num >= 0)
         {
            registers.push_back(reg_num);
            pos += 3;
         }
         else
            pos++;
      }
      else if (operand[pos] == 'X')
      {
         reg = operand.substr(pos, 4);
         reg_num = GetRegisterNumber(reg);
         if (reg_num >= 0)
         {
            registers.push_back(reg_num);
            pos += 4;
         }
         else
            pos++;
      }
      else
         pos++;
   }

   return (registers);
}

/*
 * Read registers from an operand string
 * Returns there numbers in a vector
 *
 */
uint64_t InstructionClass::FindRIPAddress(_DecodedInst *instr, Expression *ex)
{
   uint64_t rip_address = 0;
	string operand;
	operand.assign((char *)instr->operands.p);
	Util::removeWhiteSpaces(operand);
	uint64_t rip = instr->offset + instr->size;

	/*
	 *
	 * In the follwoing RIP expression:
	 * [RIP - 0xd05]
	 *
	 * rip_e[0] = RIP
	 * rip_e[1] = -
	 * rip_e[2] = 0xd05
	 *
	 */
	int pos_1 = operand.find("RIP");
	int pos_2 = operand.find_last_of(']') - pos_1;
	if (pos_2 < 0)
	{
		pos_2 = operand.find_last_of(',') - pos_1;
		if (pos_2 < 0)
			pos_2 = operand.size() - pos_1;
	}

	string old_rip = operand.substr(pos_1, pos_2);
	vector<string> rip_e = ex->ArithmeticExpression(old_rip);

   if (rip_e.size() == 3 && Util::isHexString(rip_e[2]))
   {
		int32_t hex_n = 0;
      stringstream ss;
		ss << hex << rip_e[2];
		ss >> hex_n;

		/*
		 * RIP operations are either '+' or '-'.
		 * We are not reading the hex dump so
		 * if there is a '-' sign then the number
		 * is negative and will be stored as a
		 * signed number.
		 */
      char operation = rip_e[1][0];
		if (operation == '-')
		   rip_address = rip - hex_n;
      else
		   rip_address = rip + hex_n;
   }

   return (rip_address);
}

vector<uint16_t> InstructionClass::FindNextDependentRegisters(_code *code, uint16_t original_reg_num,
                                                               uint64_t &instruction_number,
                                                               uint64_t how_much_to_fallback)
{
   vector<uint16_t> registers;

   bool IS_JUMP_INSTRUCTION_SEEN = false;

   uint64_t i = instruction_number;
   for ( ; i >= 0; i--)
   {
		uint16_t minor_type, major_type;
		bool is8bit_encoding = false, is8bit_displacement = false;
		minor_type = Type(&code->decoded[i], major_type, is8bit_encoding, is8bit_displacement);

      string opcode;
      opcode.assign((char *)code->decoded[i].mnemonic.p);
      Util::removeWhiteSpaces(opcode);

      if (major_type == INSTRUCTION_TYPE_CONTROL_BRANCH || major_type == INSTRUCTION_TYPE_CONTROL_RETURN)
         break;
      else if (opcode.find("PUSH") == 0)
         break;
      else if ((instruction_number - i) <= how_much_to_fallback)
      {
         string operand;
         operand.assign((char *)code->decoded[i].operands.p);
         Util::removeWhiteSpaces(operand);
			uint64_t pos = operand.find_first_of(',');
			if (pos != string::npos)
			{
            string reg = operand.substr(0, pos);
            uint16_t reg_num = GetRegisterNumber(reg);
            if (original_reg_num == reg_num && minor_type == INSTRUCTION_TYPE_LOAD)
            {
               string right_operand;
               right_operand.assign(operand.substr(pos, operand.size()));
               Util::removeWhiteSpaces(right_operand);
               registers = ReadRegisters(right_operand);
               break;
            }
			}
      }
      else
         break;
   }

   instruction_number = i;
   return (registers);
}

/*
 * Checks if specific register number is
 * present in the list of register numbers.
 */
bool InstructionClass::IsRegisterPresent(uint16_t reg_num, vector<uint16_t> registers)
{
   for (int r = 0; r < registers.size(); r++)
   {
      if (reg_num == registers[r])
         return true;
   }
   return false;
}

/*
 * Checks if two registers are equal.
 *
 * If the register number >= 24
 * then it subtracts 16 and check for
 * the equality.
 * This is to make the EAX == RAX and so on.
 *
 */
bool InstructionClass::IsRegisterEqual(uint16_t reg_num_1, uint16_t reg_num_2)
{
   if (reg_num_1 == reg_num_2)
      return true;
   else if(reg_num_1 >= 24)
      return ( (reg_num_1 - 16) == reg_num_2 );
   else if(reg_num_2 >= 24)
      return ( reg_num_1 == (reg_num_2 - 16) );

   return false;
}
