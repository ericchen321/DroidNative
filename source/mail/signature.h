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

#ifndef __SIGNATURE_H__
#define __SIGNATURE_H__

#include<cmath>

#include "mail.h"
#include "patterns.h"
#include "../parser/parser.h"
#include "../include/common.h"

class Signature
{
private:

public:
	Signature();
	~Signature();
	SIGNATURE *Build(MAIL *mail);
	double AssignWeightToPatterns(string virus_samples, string benign_samples, double VERTICAL_WINDOW_OF_DIFF, double HORIZONTAL_WINDOW_OF_DIFF);
	double AlmostEqual(SIGNATURE *sig1, SIGNATURE *sig2, double VERTICAL_SIGNATURE_DIFF, double HORIZONTAL_SIGNATURE_DIFF);
};

#endif // __SIGNATURE_H__
