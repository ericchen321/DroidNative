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

#ifndef __MAIL_H__
#define __MAIL_H__

#include <vector>

#include "../mail/x86AsmToMAIL.h"
#include "../mail/armAsmToMAIL.h"
#include "../include/common.h"

#define PLUS                      1001
#define MINUS                     1002
#define MULTIPLICATION            1003
#define DIVISION                  1004
#define LEFT_SHIFT                1005
#define RIGHT_SHIFT               1006

using namespace std;

/**
 * <p>
 * This class implements the Mail class.
 * It implements the language MAIL as defined in the following paper:
 *
 *
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since March 10, 2013
 *
 */
class MAIL
{
private:
	x86AsmToMAIL *trX86;
	ArmAsmToMAIL *trARM;

public:
	MAIL(int asm_language, uint64_t entryPointAddress, vector<_code> *codes, vector<_data> *datas);
	~MAIL();
	vector<Function *> GetFunctions();
	vector<Statement *> GetStatements();
	vector<Block *> GetBlocks();
	vector<BackEdge *> GetBackEdges();
	void Print();
};

#endif // __MAIL_H__
