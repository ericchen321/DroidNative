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

#ifndef __EXPRESSION_H__
#define __EXPRESSION_H__

#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <string>
#include <string.h>

#include "../util/util.h"

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
class Expression
{
private:
   void insert(vector<string> *expr, string operandP, string operatorP);
public:
	vector<string> ArithmeticExpression(string str);
};

#endif // __EXPRESSION_H__
