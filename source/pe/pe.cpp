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

#include "pe.h"

/**
 * <p>
 * Constructor
 * </p>
 */
PE::PE(uint8_t *dataPtr, uint64_t size, uint64_t coff_header_offset)
{
	isEXE = false;
	isDLL = false;
	isLittleEndian = false;
	isBigEndian = false;
	data = dataPtr;
	this->size = size;
	this->coff_header_offset = coff_header_offset;
	current = 0;
	code_size = 0;
	uint16_t magic = readShort();
	current += 2;
	if (magic != MAGIC)
		cerr << "PE::PE: File does not start with the magic number 0x4D5A\n";
	else
	{
		ReadCoffHeader();
		ReadOptionalHeader();
		ReadSectionHeaders();
	}
}

/*
 *
 */
PE::~PE()
{
	for (uint32_t i = 0; i < coffHdr.NumberOfSections; i++)
	{
		delete (sectionHdr[i]->buffer);
		delete (sectionHdr[i]);
	}
	optionalHdr.deallocateDataDirectory();
	bytesWritten.erase(bytesWritten.begin(), bytesWritten.end());
}

/**
 * <p>
 * Reads the COFF header starting from coff_header_offset
 * </p>
 */
void PE::ReadCoffHeader()
{
	current = coff_header_offset;
	coffHdr.Machine              = readShort();
	coffHdr.NumberOfSections     = readShort();
	coffHdr.TimeDateStamp        = readInt();
	coffHdr.PointerToSymbolTable = readInt();
	coffHdr.NumberOfSymbols      = readInt();
	coffHdr.SizeOfOptionalHeader = readShort();
	coffHdr.Characteristics      = readShort();

	isEXE = coffHdr.isEXE();
	isDLL = coffHdr.isDLL();
	isLittleEndian = coffHdr.isLittleEndian();
	isBigEndian = coffHdr.isBigEndian();
#ifdef __DEBUG__
	cout << "\nPrinting COFF Header:\n";
	coffHdr.Print();
#endif
}

/**
 * <p>
 * Reads the Optional header stored after the COFF header
 * Read and store only the standard fields and
 * skips the rest of the optional header
 * </p>
 */
void PE::ReadOptionalHeader()
{
	uint64_t start = current;
	if (coffHdr.SizeOfOptionalHeader >= 224)
	{
		optionalHdr.isPE64 = false;
		optionalHdr.isPE32 = false;
		optionalHdr.isROM  = false;

		optionalHdr.Magic                   = readShort();
		if (optionalHdr.Magic == PE_64_MAGIC_NUMBER)
			optionalHdr.isPE64 = true;
		else if (optionalHdr.Magic == PE_32_MAGIC_NUMBER)
			optionalHdr.isPE32 = true;
		else if (optionalHdr.Magic == PE_32_MAGIC_NUMBER)
			optionalHdr.isROM = true;
		optionalHdr.MajorLinkerVersion      = readByte();
		optionalHdr.MinorLinkerVersion      = readByte();
		optionalHdr.SizeOfCode              = readInt();
		optionalHdr.SizeOfInitializedData   = readInt();
		optionalHdr.SizeOfUninitializedData = readInt();
		optionalHdr.AddressOfEntryPoint     = readInt();
		optionalHdr.BaseOfCode              = readInt();
		if (optionalHdr.isPE32)
			optionalHdr.BaseOfData          = readInt();
		// Windows additional fields
		if (optionalHdr.isPE64)
			optionalHdr.ImageBase                   = readLong();
		else
			optionalHdr.ImageBase                   = readInt();
		optionalHdr.SectionAlignment            = readInt();
		optionalHdr.FileAlignment               = readInt();
		optionalHdr.MajorOperatingSystemVersion = readShort();
		optionalHdr.MinorOperatingSystemVersion = readShort();
		optionalHdr.MajorImageVersion           = readShort();
		optionalHdr.MinorImageVersion           = readShort();
		optionalHdr.MajorSubsystemVersion       = readShort();
		optionalHdr.MinorSubsystemVersion       = readShort();
		optionalHdr.Win32VersionValue           = readInt();
		optionalHdr.SizeOfImage                 = readInt();
		optionalHdr.SizeOfHeaders               = readInt();
		optionalHdr.CheckSum                    = readInt();
		optionalHdr.Subsystem                   = readShort();
		optionalHdr.DllCharacteristics          = readShort();
		if (optionalHdr.isPE64)
		{
			optionalHdr.SizeOfStackReserve          = readLong();
			optionalHdr.SizeOfStackCommit           = readLong();
			optionalHdr.SizeOfHeapReserve           = readLong();
			optionalHdr.SizeOfHeapCommit            = readLong();
		}
		else
		{
			optionalHdr.SizeOfStackReserve          = readInt();
			optionalHdr.SizeOfStackCommit           = readInt();
			optionalHdr.SizeOfHeapReserve           = readInt();
			optionalHdr.SizeOfHeapCommit            = readInt();
		}
		optionalHdr.LoaderFlags                 = readInt();
		optionalHdr.NumberOfRvaAndSizes         = readInt();
		optionalHdr.allocateDataDirectory();
		for (int i = 0; i < (int)optionalHdr.NumberOfRvaAndSizes; i++)
		{
			optionalHdr.DataDirectory[i].virtualAddress = readInt();
			optionalHdr.DataDirectory[i].size = readInt();
		}

		optionalHdr.AddressOfEntryPoint += optionalHdr.ImageBase;
		uint64_t end = current;
		uint64_t skip = coffHdr.SizeOfOptionalHeader - (end - start);
		current += skip;       // Skips the rest of the optional header
#ifdef __DEBUG__
cout << "--------------------: " << hex << optionalHdr.AddressOfEntryPoint << endl;
		cout << "\nPrinting Optional Header:\n";
		optionalHdr.Print();
		cout << "Size of optional header read = " << (end - start) << " != " << coffHdr.SizeOfOptionalHeader << endl;
#endif
	}
#ifdef __DEBUG__
	else
		cout << "Not a binary image file\n";
#endif
}

/**
 * <p>
 * Reads the Section headers stored after the Optional header
 * </p>
 */
void PE::ReadSectionHeaders()
{
	sectionHdr = new SectionHeaderPE*[coffHdr.NumberOfSections];
	for (uint32_t i = 0; i < coffHdr.NumberOfSections; i++)
	{
		sectionHdr[i] = new SectionHeaderPE();
		read(sectionHdr[i]->Name, sizeof(sectionHdr[i]->Name));
		sectionHdr[i]->VirtualSize          = readInt();
		sectionHdr[i]->VirtualAddress       = (optionalHdr.ImageBase + readInt());
		sectionHdr[i]->SizeOfRawData        = readInt();
		sectionHdr[i]->PointerToRawData     = readInt();
		sectionHdr[i]->PointerToRelocations = readInt();
		sectionHdr[i]->PointerToLinenumbers = readInt();
		sectionHdr[i]->NumberOfRelocations  = readShort();
		sectionHdr[i]->NumberOfLinenumbers  = readShort();
		sectionHdr[i]->Characteristics      = readInt();
		sectionHdr[i]->alignment            = optionalHdr.SectionAlignment;

		uint32_t buffer_len = sectionHdr[i]->SizeOfRawData;
		sectionHdr[i]->buffer = new uint8_t[buffer_len];
		sectionHdr[i]->buffer_len = buffer_len;
		readAt(sectionHdr[i]->PointerToRawData, sectionHdr[i]->buffer, buffer_len);
		if (sectionHdr[i]->IsText())
			code_size += buffer_len;
#ifdef __DEBUG__
		cout << "\nPrinting Section Header:\n";
		sectionHdr[i]->Print(true);        // Print the header including the data
#endif
	}
}

SectionHeaderPE** PE::GetSectionHeaders()
{
	return sectionHdr;
}

uint32_t PE::GetNumberOfSections()
{
	return coffHdr.NumberOfSections;
}

uint64_t PE::GetEntryPointAddress()
{
	return (optionalHdr.AddressOfEntryPoint);
}

bool PE::Is64()
{
	return (optionalHdr.isPE64);
}

/*
 * Read bytes starting from 'addr' of length 'len'
 */
void PE::readAt(uint64_t addr, uint8_t *readByte, uint32_t len)
{
	uint64_t upto = addr + len;
	if (upto > size)
		cerr << "PE::readAt: Out of bounds " << upto << " > " << size << endl;
	else
	{
		uint64_t c = 0;
		while (addr < upto)
			readByte[c++] = data[addr++];
	}
}

/*
 * Read bytes of length len starting from current
 */
void PE::read(uint8_t *readByte, uint32_t len)
{
	uint64_t upto = current + len;
	if (upto > size)
		cerr << "PE::read: Out of bounds " << upto << " > " << size << endl;
	else
	{
		uint64_t c = 0;
		while (current < upto)
			readByte[c++] = data[current++];
	}
}

/*
 *  Read 1 byte
 */
uint8_t PE::readByte()
{
	uint8_t b = data[current++];
	return b;
}

/*
 *  Read 2 bytes
 */
uint16_t PE::readShort()
{
	uint8_t b1 = readByte(); uint8_t b2 = readByte();
	uint16_t result = (uint16_t)( (b1&0x00FF) | ((b2&0x00FF) << 8) );
	return result;
}

/*
 *  Read 4 bytes
 */
uint32_t PE::readInt()
{
	uint8_t b1 = readByte(); uint8_t b2 = readByte();
	uint8_t b3 = readByte(); uint8_t b4 = readByte();
	uint32_t result = (uint32_t)( (b1&0x000000FF) | ((b2&0x000000FF) << 8)
								| ((b3&0x000000FF) << 16) | ((b4&0x000000FF) << 24) );
	return result;
}

/*
 *  Read 8 bytes
 */
uint64_t PE::readLong()
{
	uint8_t b1 = readByte(); uint8_t b2 = readByte();
	uint8_t b3 = readByte(); uint8_t b4 = readByte();
	uint8_t b5 = readByte(); uint8_t b6 = readByte();
	uint8_t b7 = readByte(); uint8_t b8 = readByte();
	uint64_t result = (uint64_t)(b1&0x00000000000000FF) | ((uint64_t)(b2&0x00000000000000FF) << 8)
						| ((uint64_t)(b3&0x00000000000000FF) << 16) | ((uint64_t)(b4&0x00000000000000FF) << 24)
						| ((uint64_t)(b5&0x00000000000000FF) << 32) | ((uint64_t)(b6&0x00000000000000FF) << 40)
						| ((uint64_t)(b7&0x00000000000000FF) << 48) | ((uint64_t)(b8&0x00000000000000FF) << 56);
	return result;
}

/**
 * <p>
 * Prints the PEBuffer in hex 10 bytes per line.
 * </p>
 */
void PE::Print()
{
	for (uint64_t i = 1; i < size; i++)
	{
		printf ("%X ", data[i-1]);
		if ((i % 10) == 0)
			cout << "\n";
	}
}
