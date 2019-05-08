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

#include "operator.h"

int16_t Operator::IsArithmetic(string op)
{
	if (op.size() > 0)
	{
		switch (op[0])
		{
		case '+':
			return PLUS;
		case '-':
			return MINUS;
		case '*':
			return MULTIPLICATION;
		case '/':
			return DIVISION;
		case '<':
			if (op.size() > 1 && op[1] == '<')
				return LEFT_SHIFT;
			break;
		case '>':
			if (op.size() > 1 && op[1] == '>')
				return RIGHT_SHIFT;
			break;
		}
	}

	return -1;
}

uint64_t Operator::PerformIntegerArithmetic(string op, uint64_t num1, uint64_t num2)
{
	uint64_t result = 0;

	if (op.size() > 0)
	{
		switch (op[0])
		{
		case '+':
			result = num1 + num2;
			break;
		case '-':
			result = num1 - num2;
			break;
		case '*':
			result = num1 * num2;
			break;
		case '/':
			result = num1 / num2;
			break;
		case '<':
			if (op.size() > 1 && op[1] == '<')
				result = num1 << num2;
			break;
		case '>':
			if (op.size() > 1 && op[1] == '>')
				result = num1 >> num2;
			break;
		}
	}

	return (result);
}
