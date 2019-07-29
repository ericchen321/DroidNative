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

#include "expression.h"

/*
 * It assumes that the operator precedence is already taken care of.
 * It doesn't check the syntax of the expression and just returns
 * the expression as it is.
 *    r12 + r8 * rax >> rbx << 5
 *    is returned as:
 *    { "r12", "+", "r8", "*", "rax", ">>", "rbx", "<<" , "5" }
 * where:
 *    >> --> right shift operator
 *    << --> left shift operator
 *
 * Operators included:
 *    plus, minus, multiply, divide, left shift and right shift
 */
vector<string> Expression::ArithmeticExpression(string str)
{
	vector<string> expr;

	int c = 0, last = 0;
	for ( ; c < (int)str.size(); c++)
	{
		switch (str[c])
		{
		case '+':
         insert(&expr, str.substr(last, c-last), "+");
			last = c + 1;
			break;
		case '-':
         insert(&expr, str.substr(last, c-last), "-");
			last = c + 1;
			break;
		case '*':
         insert(&expr, str.substr(last, c-last), "*");
			last = c + 1;
			break;
		case '/':
         insert(&expr, str.substr(last, c-last), "/");
			last = c + 1;
			break;
		case '<':
			if (c < (int)str.size()-1 && str[c+1] == '<')
			{
				c++;
				insert(&expr, str.substr(last, c-last-1), "<<");
				last = c + 1;
			}
			break;
		case '>':
			if (c < (int)str.size()-1 && str[c+1] == '>')
			{
				c++;
				insert(&expr, str.substr(last, c-last-1), ">>");
				last = c + 1;
			}
			break;
		}
	}
	if (last < (int)str.size())
		insert(&expr, str.substr(last, c-last), "");

	return expr;
}

void Expression::insert(vector<string> *expr, string operandP, string operatorP)
{
   string operandL = Util::removeWhiteSpaces(operandP);
   if (operandL.size() > 0)
   {
      expr->push_back(operandL);
      if (operatorP.size() > 0)
         expr->push_back(operatorP);
   }
}
