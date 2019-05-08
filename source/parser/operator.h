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

#ifndef __OPERATOR_H__
#define __OPERATOR_H__

#include <iostream>
#include <stdint.h>
#include <string>
#include <string.h>

#define PLUS                      1001
#define MINUS                     1002
#define MULTIPLICATION            1003
#define DIVISION                  1004
#define LEFT_SHIFT                1005
#define RIGHT_SHIFT               1006

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
class Operator
{
private:
public:
	int16_t IsArithmetic(string op);
	uint64_t PerformIntegerArithmetic(string op, uint64_t num1, uint64_t num2);
};

#endif // __OPERATOR_H__
