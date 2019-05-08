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

#include "parser.h"

uint64_t ADDRESS_BREAKPOINT = 0x0;

/*
 * Constructor
 */
Parser::Parser(uint8_t *buffer, uint64_t size)
{
	isPE = false;
	isELF = false;
	isOAT = false;
	dynamic = false;
	this->buffer = buffer;
	this->size = size;
	cfg = NULL;
	mail = NULL;
}

/*
 * Destructor
 */
Parser::~Parser()
{
#ifdef __SIGNATURE_MATCHING__
	if (mail != NULL)
	{
		delete (mail);
		mail = NULL;
	}
#endif
	vector<_code>::iterator it_n_code;
	for (it_n_code = codes.begin(); it_n_code != codes.end(); it_n_code++)
	{
		if (it_n_code->decoded != NULL)
		{
			delete (it_n_code->decoded);
			it_n_code->decoded = NULL;
		}
		if (it_n_code->instructions != NULL)
		{
			cs_free(it_n_code->instructions, it_n_code->code_size);
			it_n_code->instructions = NULL;
		}
	}
	codes.erase(codes.begin(), codes.end());
	codes.clear();
	datas.erase(datas.begin(), datas.end());
	datas.clear();
}

/*
 *
 * Builds the CFG from the disassembled code and data
 *
 */
CFG *Parser::BuildCFG()
{
	if (mail != NULL)
	{
		cfg = new CFG(mail->GetBlocks(), mail->GetBackEdges(), filename);
		if (codes.size() > 0)
			cfg->Build(filename);
		return cfg;
	}
	else
		cerr << "ERROR:Parser::BuildCFG: Please First Parse the File " << filename << endl;

	return NULL;
}

/*
 *
 * Builds the CFGs from the disassembled code and data
 *
 */
vector <CFG *> Parser::BuildCFGs()
{
#ifdef __DEBUG__
	cout << "Parser::BuildCFGs() Start\n";
#endif

	if (mail != NULL)
	{
		vector <Function *> functions;
		functions = mail->GetFunctions();

#ifdef __DEBUG__
		cout << "Number of CFGs: " << functions.size() << endl;
#endif
#ifdef __BUILD_DOT_GRAPH__
		unsigned int found = filename.find_last_of("/\\");
		string just_filename = filename.substr(found+1);

		string dot_graph;
		char file_name[256];
		bool OPENED = false;
#endif
#ifdef __PRINT_CFG__
			cout << "\n---------------------------------------------------------------------------------------------------------\n";
			cout << "START - Printing blocks for file " << filename << " with " << functions.size() << " functions:" << "\n\n";
#endif
		for (int f = 0; f < (int)functions.size(); f++)
		{
			vector <Block *> blocks;
			vector <BackEdge *> backEdges;
			blocks = functions[f]->blocks;
			backEdges = functions[f]->backEdges;
			CFG *cfg = new CFG(blocks, backEdges, filename);
#ifdef __DEBUG__
			cout << "   BEFORE SHRINKING Number of nodes in " << f << " CFG: " << cfg->GetBlocks().size() << endl;
#endif
#ifdef __SHRINKING_ENABLED__
			cfg->Shrink();
#endif
#ifdef __DEBUG__
			cout << "   AFTER SHRINKING  Number of nodes in " << f << " CFG: " << cfg->GetBlocks().size() << endl;
#endif
#ifdef __PRINT_CFG__
			cout << "\n---------------------------------------------------------------------------------------------------------\n";
			vector <Block *> blocks_cfg = cfg->GetBlocks();
			cerr << "Printing " << blocks_cfg.size() << " blocks for function number " << f << endl;
			cout << "Printing " << blocks_cfg.size() << " blocks for function number " << f << "\n\n";
			for (int bn = 0; bn < blocks_cfg.size(); bn++)
			{
				cfg->PrintBlock(blocks_cfg[bn], true);
			}
			cout << "\n---------------------------------------------------------------------------------------------------------\n";
#endif
			cfgs.push_back(cfg);
#ifdef __BUILD_DOT_GRAPH__
			if (cfg->GetBlocks().size() >= 1)
			{
				OPENED = true;
				sprintf(file_name, "%s_%d.dot", just_filename.c_str(), f);
				dot_graph += cfg->printDOT(file_name, NULL);
			}
#endif
		}
#ifdef __PRINT_CFG__
			cout << "END - Printing blocks for file " << filename << " with " << functions.size() << " functions:" << "\n\n";
			cout << "\n---------------------------------------------------------------------------------------------------------\n\n\n";
#endif
#ifdef __BUILD_DOT_GRAPH__
		if (OPENED)
		{
			sprintf(file_name, "build_graph_%s.bat", just_filename.c_str());
			ofstream file(file_name, ios::out | ios::binary | ios::ate);
			file.write((const char *)dot_graph.c_str(), dot_graph.length());
			file.close();
		}
#endif
	}
#ifdef __DEBUG__
	else
		cout << "ERROR:Parser::BuildCFG: Please First Parse the File " << filename << endl;

	cout << "Parser::BuildCFGs() End\n";
#endif
	return cfgs;
}

/*
 *
 * Parses the PE/ELF/OAT dumped file and translates it to MAIL language
 *
 */
void Parser::Parse(string filename)
{
	this->filename = filename;

#ifdef __DEBUG__
	cout << "|\n";
	cout << "|   Parsing " << filename << "\n";
	cout << "|\n\n";
#endif

	/*
	 * Read the offset (@ 0x3C = 60) for the PE signature
	 * that contains the address of the PE signature.
	 * If offset at this location is 0x0 then check
	 * location 0x100 for the PE signature.
	 */
	uint32_t offset = (uint32_t)( buffer[0x3C]&0x000000FF );
	if (offset < 0x55)
	{
		offset += 0x100;
	}
	/*
	 *  Read the 4 bytes PE signature
	 */
	uint8_t signature[20];
	signature[0] = buffer[offset++];
	signature[1] = buffer[offset++];
	signature[2] = buffer[offset++];
	signature[3] = buffer[offset++];
	/*
	 * ------------------------------------------------------------
	 *
	 * If the file is in PE format process the file as PE image
	 *
	 * ------------------------------------------------------------
	 *
	 */
	if (size > 128 && signature[0] == 'P' && signature[1] == 'E' && (signature[2] | signature[3]) == 0)
	{
		isPE = true;
		/*
		 * Pass the fileBuffer, size and PE signature offset to the PE class
		 */
		PE *pe = new PE(buffer, size, offset);
#ifdef __DEBUG__
		cerr << "PE Buffer SIZE: " << size << endl;
		cerr << "Disassembly start\n";
#endif
		disassemblePE(pe);
#ifdef __DEBUG__
		cerr << "Disassembly done\n";
		cerr << "Translation start\n";
#endif
		if (codes.size() > 0)
			mail = new MAIL(X86_ASSEMBLY_LANGUAGE, pe->GetEntryPointAddress(), &codes, &datas);
#ifdef __DEBUG__
		else
		{
			cerr << "Parser::Parse: Parsing " << filename << "\n";
			cerr << "Error::MAIL::MAIL Nothing to translate codes->size(): " << codes.size() << endl;
			cout << "Error::MAIL::MAIL Nothing to translate codes->size(): " << codes.size() << endl;
		}
		cerr << "Translation done\n";
		cerr << "Number of blocks: " << filename << ": " << dec <<  mail->GetBlocks().size() << endl;
		cerr << "Number of functions: " << filename << ": " << dec <<  mail->GetFunctions().size() << endl;
		cout << "Number of blocks: " << filename << ": " << dec <<  mail->GetBlocks().size() << endl;
		cout << "Number of functions: " << filename << ": " << dec <<  mail->GetFunctions().size() << endl;
#endif
		delete (pe);
	}
	/*
	 * ------------------------------------------------------------
	 *
	 * If the file is in ELF format process the file as an ELF image
	 *
	 * MAGIC NUMBER = '7f''E''L''F'
	 * Only checking the magic number here
	 * The followings are checked in other functions
	 * CLASS = 2/1     --> 64bit/32bit
	 * DATA  = 2/1     --> big-endian/little-endian
	 * ABI   = 1/../.. --> HP Unix operating system
	 *
	 * ------------------------------------------------------------
	 */
	else if (size > 128)
	{
#ifdef __DEBUG__
		cout << "Parser::Parse: PE signature not found. Now checking for the ELF signature\n";
#endif
		/*
		 *  Read the 4 bytes ELF signature @ 0X0 offset
		 */
		offset = 0x0;
		signature[0] = buffer[offset++];
		signature[1] = buffer[offset++];
		signature[2] = buffer[offset++];
		signature[3] = buffer[offset++];

		if (signature[0] == 0x7f && signature[1] == 'E' && signature[2] == 'L' && signature[3] == 'F')
		{
			isELF = true;
			/*
			 * By default we set this to true,
			 * and is only used if ARM architecture
			 */
			bool isThumb = true;
			/*
			 * Pass the fileBuffer and the size to the ELF class
			 */
			ELF *elf = new ELF(buffer, size, isThumb);
			uint32_t eaddress = 0x00000000;
#ifdef __DEBUG__
			cerr << "ELF Buffer SIZE: " << size << endl;
			cerr << "Disassembly start\n";
#endif
			disassembleELF(elf);
#ifdef __DEBUG__
			cerr << "Disassembly done\n";
			cerr << "Translation start\n";
#endif
			if (elf->IS_X86)
			{
				if (codes.size() > 0)
					mail = new MAIL(X86_ASSEMBLY_LANGUAGE, eaddress, &codes, &datas);
#ifdef __DEBUG__
				else
				{
					cerr << "Parser::Parse: Parsing " << filename << "\n";
					cerr << "Error::MAIL::MAIL Nothing to translate codes->size(): " << codes.size() << endl;
					cout << "Error::MAIL::MAIL Nothing to translate codes->size(): " << codes.size() << endl;
				}
#endif
			}
			else if (elf->IS_ARM)
			{
				if (codes.size() > 0)
					mail = new MAIL(ARM_ASSEMBLY_LANGUAGE, eaddress, &codes, &datas);
#ifdef __DEBUG__
				else
				{
					cerr << "Parser::Parse: Parsing " << filename << "\n";
					cerr << "Error::MAIL::MAIL Nothing to translate codes->size(): " << codes.size() << endl;
					cout << "Error::MAIL::MAIL Nothing to translate codes->size(): " << codes.size() << endl;
				}
#endif
			}
#ifdef __DEBUG__
			cerr << "Translation done\n";
			cerr << "Number of blocks: " << filename << ": " << dec <<  mail->GetBlocks().size() << endl;
			cerr << "Number of functions: " << filename << ": " << dec <<  mail->GetFunctions().size() << endl;
			cout << "Number of blocks: " << filename << ": " << dec <<  mail->GetBlocks().size() << endl;
			cout << "Number of functions: " << filename << ": " << dec <<  mail->GetFunctions().size() << endl;
#endif

			delete (elf);
		}
		/*
		 * ------------------------------------------------------------
		 *
		 * If the file is an OAT dump
		 * MAGIC STRING:
		 * MAGIC
		 * oat
		 * 039, 045, xx
		 *
		 * This string should be present in the first 20 bytes of the file
		 *
		 * ------------------------------------------------------------
		 */
		else
		{
			signature[4]  = buffer[offset++]; signature[5]  = buffer[offset++];
			signature[6]  = buffer[offset++]; signature[7]  = buffer[offset++];
			signature[8]  = buffer[offset++]; signature[9]  = buffer[offset++];
			signature[10] = buffer[offset++]; signature[11] = buffer[offset++];
			signature[12] = buffer[offset++]; signature[13] = buffer[offset++];
			signature[14] = buffer[offset++]; signature[15] = buffer[offset++];
			signature[16] = buffer[offset++]; signature[17] = buffer[offset++];
			signature[18] = buffer[offset++]; signature[19] = buffer[offset++];

#ifdef __DEBUG__
			cout << "signature: " << signature << endl;
#endif
			isOAT = false;
			for (int i = 0; i < 20; i++)
			{
				if (signature[i] == 'm' || signature[i] == 'M')
				{
					if ((signature[i+1] == 'a' || signature[i+1] == 'A') && (signature[i+2] == 'g' || signature[i+2] == 'G')
					&& (signature[i+3] == 'i' || signature[i+3] == 'I') && (signature[i+4] == 'c' || signature[i+4] == 'C'))
					{
#ifdef __DEBUG__
						cout << "MAGIC" << endl;
#endif
						for (i += 5; i < 20; i++)
						{
							if (signature[i] == 'o' || signature[i] == 'O')
							{
								if ((signature[i+1] == 'a' || signature[i+1] == 'A') && (signature[i+2] == 't' || signature[i+2] == 'T'))
								{
									for (i += 3; i < 20; i++)
									{
										if (signature[i] == '0')
										{
											if (signature[i+1] == '3' && signature[i+2] == '9')
											{
#ifdef __DEBUG__
												cout << "oat 039" << endl;
#endif
												isOAT = true;
												break;
											}
											else if (signature[i+1] == '4' && signature[i+2] == '5')
											{
#ifdef __DEBUG__
												cout << "oat 045" << endl;
#endif
												isOAT = true;
												break;
											}
											else
											{
#ifdef __DEBUG__
												cout << "oat " << signature[i+1] << signature[i+2] << endl;
#endif
												isOAT = true;
												break;
											}
										}
									}
								}
							}
						}
					}
				}
			}
			if (isOAT)
			{
				/*
				 * Parse OAT
				 */
				uint32_t eaddress = 0x00000000;
				uint8_t arch = parseOAT();
#ifdef __DEBUG__
				if (arch == OAT_ARM)
					cout << "OAT ARM\n";
				else if (arch == OAT_X86)
					cout << "OAT X86\n";
				else if (arch == ARCHITECTURE_UNKNOWN)
					cout << "OAT ARCHITECTURE_UNKNOWN\n";
#endif
				if (arch == OAT_X86)
				{
					if (codes.size() > 0)
						mail = new MAIL(X86_ASSEMBLY_LANGUAGE, eaddress, &codes, &datas);
#ifdef __DEBUG__
					else
					{
						cerr << "Parser::Parse: Parsing " << filename << "\n";
						cerr << "Error::MAIL::MAIL Nothing to translate codes->size(): " << codes.size() << endl;
						cout << "Error::MAIL::MAIL Nothing to translate codes->size(): " << codes.size() << endl;
					}
#endif
				}
				else if (arch == OAT_ARM)
				{
					if (codes.size() > 0)
						mail = new MAIL(ARM_ASSEMBLY_LANGUAGE, eaddress, &codes, &datas);
#ifdef __DEBUG__
					else
					{
						cerr << "Parser::Parse: Parsing " << filename << "\n";
						cerr << "Error::MAIL::MAIL Nothing to translate codes->size(): " << codes.size() << endl;
						cout << "Error::MAIL::MAIL Nothing to translate codes->size(): " << codes.size() << endl;
					}
#endif
				}
				else/* if (arch == ARCHITECTURE_UNKNOWN) */
				{
#ifdef __DEBUG__
					cerr << "Parser::Parse: Parsing " << filename << "\n";
					cerr << "Parser::Parse: File format not supported\n";
					cerr << "UNKNOWN Buffer SIZE: " << size << endl;
					cerr << "Disassembly start\n";
#endif
					disassemble(false);
#ifdef __DEBUG__
					cerr << "Disassembly done\n";
					cerr << "Translation start\n";
#endif
					uint32_t eaddress = 0x00000000;
					if (codes.size() > 0)
						mail = new MAIL(ARM_ASSEMBLY_LANGUAGE, eaddress, &codes, &datas); // by default
					//	mail = new MAIL(X86_ASSEMBLY_LANGUAGE, eaddress, &codes, &datas); // can be changed to
#ifdef __DEBUG__
					else
					{
						cerr << "Error::MAIL::MAIL Nothing to translate codes->size(): " << codes.size() << endl;
						cout << "Error::MAIL::MAIL Nothing to translate codes->size(): " << codes.size() << endl;
					}
					cerr << "Translation done\n";
#endif
				}
#ifdef __DEBUG__
				if (mail != NULL)
				{
					cerr << "Number of blocks: " << filename << ": " << dec <<  mail->GetBlocks().size() << endl;
					cerr << "Number of functions: " << filename << ": " << dec <<  mail->GetFunctions().size() << endl;
					cout << "Number of blocks: " << filename << ": " << dec <<  mail->GetBlocks().size() << endl;
					cout << "Number of functions: " << filename << ": " << dec <<  mail->GetFunctions().size() << endl;
				}
#endif
			}
			/*
			* Neither PE, ELF or OAT dump and will be treated as a RAW binary file
			* and disassembled as ARM
			*/
			else
			{
#ifdef __DEBUG__
				cerr << "Parser::Parse: Parsing " << filename << "\n";
				cerr << "Parser::Parse: File format not supported\n";
				cerr << "UNKNOWN Buffer SIZE: " << size << endl;
				cerr << "Disassembly start\n";
#endif
				disassemble(false);
#ifdef __DEBUG__
				cerr << "Disassembly done\n";
				cerr << "Translation start\n";
#endif
				uint32_t eaddress = 0x00000000;
				if (codes.size() > 0)
					mail = new MAIL(ARM_ASSEMBLY_LANGUAGE, eaddress, &codes, &datas);
#ifdef __DEBUG__
				else
				{
					cerr << "Error::MAIL::MAIL Nothing to translate codes->size(): " << codes.size() << endl;
					cout << "Error::MAIL::MAIL Nothing to translate codes->size(): " << codes.size() << endl;
				}
				cerr << "Translation done\n";
#endif
			}
#ifdef __DEBUG__
			if (mail != NULL)
			{
				cerr << "Number of blocks: " << filename << ": " << dec <<  mail->GetBlocks().size() << endl;
				cerr << "Number of functions: " << filename << ": " << dec <<  mail->GetFunctions().size() << endl;
				cout << "Number of blocks: " << filename << ": " << dec <<  mail->GetBlocks().size() << endl;
				cout << "Number of functions: " << filename << ": " << dec <<  mail->GetFunctions().size() << endl;
			}
#endif
		}
	}
	/*
	* Size < 128
	*/
	else
	{
#ifdef __DEBUG__
		cerr << "Parser::Parse: Parsing " << filename << "\n";
		cerr << "Parser::Parse: File format not supported\n";
		cerr << "UNKNOWN Buffer SIZE: " << size << endl;
		cerr << "Disassembly start\n";
#endif
		disassemble(false);
#ifdef __DEBUG__
		cerr << "Disassembly done\n";
		cerr << "Translation start\n";
#endif
		uint32_t eaddress = 0x00000000;
		if (codes.size() > 0)
			mail = new MAIL(ARM_ASSEMBLY_LANGUAGE, eaddress, &codes, &datas); // default
		//	mail = new MAIL(X86_ASSEMBLY_LANGUAGE, eaddress, &codes, &datas); // can be changed to
#ifdef __DEBUG__
		else
		{
			cerr << "Error::MAIL::MAIL Nothing to translate codes->size(): " << codes.size() << endl;
			cout << "Error::MAIL::MAIL Nothing to translate codes->size(): " << codes.size() << endl;
		}
		cerr << "Translation done\n";
		if (mail != NULL)
		{
			cerr << "Number of blocks: " << filename << ": " << dec <<  mail->GetBlocks().size() << endl;
			cerr << "Number of functions: " << filename << ": " << dec <<  mail->GetFunctions().size() << endl;
			cout << "Number of blocks: " << filename << ": " << dec <<  mail->GetBlocks().size() << endl;
			cout << "Number of functions: " << filename << ": " << dec <<  mail->GetFunctions().size() << endl;
		}
#endif
	}
#ifdef __PRINT_MAIL__
   if (mail != NULL)
   {
      printf ("------------------------------------------------------------------------------------------------------------------\n");
      printf ("Printing file %s\n", filename.c_str());
      printf ("------------------------------------------------------------------------------------------------------------------\n");
      mail->Print();
   }
#endif
}

bool Parser::disassemble(bool is64)
{
	_code code;
	code.decoded = NULL;

	csh handle;
	cs_insn *instrs;
	size_t count;
	uint64_t buffer_len = size;

	cs_arch arch = CS_ARCH_ARM;
	cs_mode mode = CS_MODE_THUMB;

	cs_err err = cs_open(arch, mode, &handle);
	if (err)
		printf("Failed on cs_open() with error returned: %s\n", cs_strerror(err));

	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

	count = cs_disasm(handle, (const uint8_t *)buffer, buffer_len, 0x0, 0, &instrs);
	if (count)
	{
		code.instructions = instrs;
		code.code_size = count;
		code.buffer = buffer;
		code.buffer_size = buffer_len;
		code.addr_align = 0x0;
		code.offset = 0x0;
		code.name = "noname";
		codes.push_back(code);
	}
	else
	{
#ifdef __DEBUG__
		printf("ERROR::Parser::addCodeARMELF Failed to disassemble given code!\n");
#endif
		cs_free(instrs, count);
	}

	cs_close(&handle);
#ifdef __DEBUG__
	Util::PrintCode(&code, false);
#endif

	return true;
}

/*
 * Disassemble PE data and save it in vectors "codes" and "datas"
 */
bool Parser::disassemblePE(PE *pe)
{
	SectionHeaderPE **sh = pe->GetSectionHeaders();
	uint32_t sections = pe->GetNumberOfSections();

	for (uint32_t i = 0; i < sections; i++)
	{
		/*
		 * CODES
		 */
		if (sh[i]->IsExe())
		{
			stringstream name;
			name << sh[i]->Name;
			addCodePE(name.str(), sh[i], pe->Is64());
		}
		/*
		 * Check if packed with UPX packer
		 */
		else if (sh[i]->Name != 0)
		{
			stringstream name;
			name << sh[i]->Name;
			if (sh[i]->Name[0] == 'U' && sh[i]->Name[1] == 'P' && sh[i]->Name[2] == 'X')
				addCodePE(name.str(), sh[i], pe->Is64());
			else
				addDataPE(name.str(), sh[i]);
		}
		/*
		 * DATAS
		 */
		else
		{
			stringstream name;
			name << sh[i]->Name;
			addDataPE(name.str(), sh[i]);
		}
	}

	return true;
}

/*
 * Add code to the vector "codes"
 */
void Parser::addCodePE(string name, SectionHeaderPE *sh, bool is64)
{
	unsigned int decodedInstructionsCount = 0;
	_code code;
	code.decoded = new _DecodedInst[sh->buffer_len];
	_DecodeType type = Decode32Bits;
	if (is64)
		type = Decode64Bits;
	_DecodeResult res = distorm_decode(sh->VirtualAddress, (const unsigned char*)sh->buffer, sh->buffer_len,
										type, code.decoded, sh->buffer_len, &decodedInstructionsCount);
	code.code_size = decodedInstructionsCount;
	code.buffer = sh->buffer;
	code.buffer_size = sh->buffer_len;
	code.addr_align = sh->alignment;
	code.offset = sh->VirtualAddress;
	code.name = name;
	codes.push_back(code);
#ifdef __DEBUG__
	sh->Print(false);
	Util::PrintCode(&code, true);
#endif
}

/*
 * Add data to the vector "datas"
 */
void Parser::addDataPE(string name, SectionHeaderPE *sh)
{
	_data data;
	data.buffer = sh->buffer;
	data.data_size = sh->buffer_len;
	data.addr_align = sh->alignment;
	data.offset = sh->VirtualAddress;
	data.name = name;
	datas.push_back(data);
#ifdef __DEBUG__
	sh->Print(false);
	Util::PrintData(&data);
#endif
}

/*
 * Disassemble ELF data and save it in vectors "codes" and "datas"
 */
bool Parser::disassembleELF(ELF *elf)
{
	if (elf->IS_X86)
	{
		SectionHeaderELF **sh = elf->GetSectionHeaders();
		uint32_t sections = elf->GetNumberOfSections();

		for (uint32_t i = 0; i < sections; i++)
		{
			stringstream name;
			name << sh[i]->name;
			/*
			 * CODES / Contains program bits
			 */
			if (sh[i]->IsProgramBits())
				addCodeX86ELF(name.str(), sh[i], elf->is64);
			else
				addDataELF(name.str(), sh[i]);
		}
	}
	else if (elf->IS_ARM)
	{
		SectionHeaderELF **sh = elf->GetSectionHeaders();
		uint32_t sections = elf->GetNumberOfSections();

		for (uint32_t i = 0; i < sections; i++)
		{
			stringstream name;
			name << sh[i]->name;
			/*
			 * CODES / Contains program bits
			 */
			if (sh[i]->IsExe()) // also: if (sh[i]->IsProgramBits())
				addCodeARMELF(name.str(), sh[i], elf);
			else
				addDataELF(name.str(), sh[i]);
		}
	}
	else
	{
		printf("ERROR:Parser::disassembleELF: No Architecture specified in the file");
	}

	return true;
}

/*
 * Add code to the vector "codes"
 */
void Parser::addCodeX86ELF(string name, SectionHeaderELF *sh, bool is64)
{
	unsigned int decodedInstructionsCount = 0;
	_code code;
	code.decoded = new _DecodedInst[sh->buffer_len];
	_DecodeResult res = distorm_decode(sh->sh_addr, (const unsigned char*)sh->buffer, sh->buffer_len,
										Decode64Bits, code.decoded, sh->buffer_len, &decodedInstructionsCount);
	code.code_size = decodedInstructionsCount;
	code.buffer = sh->buffer;
	code.buffer_size = sh->buffer_len;
	code.addr_align = sh->sh_addralign;
	code.offset = sh->sh_addr;
	code.name = name;
	codes.push_back(code);
#ifdef __DEBUG__
	sh->Print(false);
	Util::PrintCode(&code, true);
#endif
}

/*
 * Add code to the vector "codes"
 */
void Parser::addCodeARMELF(string name, SectionHeaderELF *sh, ELF *elf)
{
	_code code;
	code.code_size = 0;
	code.buffer_size = 0;
	code.buffer = NULL;
	code.instructions = NULL;
	code.decoded = NULL;

	csh handle;
	cs_insn *instrs;
	size_t count;

	cs_arch arch = CS_ARCH_ARM;
	if (elf->is64)
		arch = CS_ARCH_ARM64;

	/*
	 * Set the instruction type
	 */
	cs_mode mode = CS_MODE_THUMB;
	if (sh->IStype == INSTRUCTION_SET_ARM)
		mode = CS_MODE_ARM;
	if (elf->isLittleEndian)
		mode = (cs_mode)(mode + CS_MODE_LITTLE_ENDIAN);
	else
		mode = (cs_mode)(mode + CS_MODE_BIG_ENDIAN);

	cs_err err = cs_open(arch, mode, &handle);
	if (err)
		printf("Failed on cs_open() with error returned: %s\n", cs_strerror(err));

	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

	count = cs_disasm(handle, (const uint8_t *)sh->buffer, sh->buffer_len, sh->sh_addr, 0, &instrs);
	if (count)
	{
		code.instructions = instrs;
		code.code_size = count;
		code.buffer = sh->buffer;
		code.buffer_size = sh->buffer_len;
		code.addr_align = sh->sh_addralign;
		code.offset = sh->sh_addr;
		code.name = name;
		codes.push_back(code);
	}
	else
	{
#ifdef __DEBUG__
		printf("ERROR::Parser::addCodeARMELF Failed to disassemble given code!\n");
#endif
		cs_free(instrs, count);
	}

	cs_close(&handle);
#ifdef __DEBUG__
	sh->Print(false);
	Util::PrintCode(&code, false);
#endif
}

/*
 * Add data to the vector "datas"
 */
void Parser::addDataELF(string name, SectionHeaderELF *sh)
{
	_data data;
	data.buffer = sh->buffer;
	data.data_size = sh->buffer_len;
	data.addr_align = sh->sh_addralign;
	data.offset = sh->sh_addr;
	data.name = name;
	datas.push_back(data);
#ifdef __DEBUG__
	sh->Print(false);
	Util::PrintData(&data);
#endif
}

/*
 *
 * This function parses the oatdump (an Android dump tool similar to objdump on UNIX/Linux)
 * dumped file, for the instruction set and assembly code.
 *
 * A sample OAT dumped file:
 *
 * MAGIC:
 * oat
 * 039
 * CHECKSUM:
 * 0xcbcaa753
 * INSTRUCTION SET:
 * Thumb2
 * -   -   -   -   -   -
 * -   -   -   -   -   -
 * -   -   -   -   -   -
 *     CODE: (code_offset=0x00002019 size_offset=0x00002014 size=60)...
 *       0x00002018: f5bd5c00	subs    r12, sp, #8192
 *       0x0000201c: f8dcc000	ldr.w   r12, [r12, #0]
 *       suspend point dex PC: 0x0000
 *       GC map objects:  v0 (r5)
 *       0x00002020: e92d4060	push    {r5, r6, lr}
 *       0x00002024: b085    	sub     sp, sp, #20
 *       0x00002026: 1c06    	mov     r6, r0
 *       0x00002028: 9000    	str     r0, [sp, #0]
 * -   -   -   -   -   -
 * -   -   -   -   -   -
 * -   -   -   -   -   -
 *    CODE: (code_offset=0x000020c9 size_offset=0x000020c4 size=1124)...
 *      0x000020c8: f5bd5c00	subs    r12, sp, #8192
 *      0x000020cc: f8dcc000	ldr.w   r12, [r12, #0]
 *      suspend point dex PC: 0x0000
 *      GC map objects:  v6 ([sp + #84]), v7 ([sp + #88])
 *      0x000020d0: e92d4de0	push    {r5, r6, r7, r8, r10, r11, lr}
 *      0x000020d4: b08d    	sub     sp, sp, #52
 *      0x000020d6: 1c05    	mov     r5, r0
 * -   -   -   -   -   -
 * -   -   -   -   -   -
 * -   -   -   -   -   -
 *
 */
uint8_t Parser::parseOAT()
{
	uint8_t arch = ARCHITECTURE_UNKNOWN;
	_code code;
	uint64_t instruction_count = 0;
	code.code_size = 0;
	code.buffer_size = 0;
	code.buffer = NULL;
	code.instructions = NULL;
	code.decoded = NULL;

	cs_insn *instrs = NULL;
	string oat_str;
	oat_str.append((const char *)buffer);

	// Find the instruction set to set the architecture
	// x86
	// arm
	// thumb
	uint64_t pos = oat_str.find("INSTRUCTION SET");
	if (pos != string::npos)
	{
		pos += 16;
		while (pos < size)
		{
			if (pos < (size-2) && (oat_str[pos] == 'x' || oat_str[pos] == 'X'))
			{
				if (oat_str[pos+1] == '8' && oat_str[pos+2] == '6')
					arch = OAT_X86;
				break;
			}
			else if (pos < (size-2) && (oat_str[pos] == 'a' || oat_str[pos] == 'A'))
			{
				if ((oat_str[pos+1] == 'r' || oat_str[pos+1] == 'R') && (oat_str[pos+2] == 'm' || oat_str[pos+2] == 'M'))
					arch = OAT_ARM;
				break;
			}
			else if (pos < (size-4) && (oat_str[pos] == 't' || oat_str[pos] == 'T'))
			{
				if ((oat_str[pos+1] == 'h' || oat_str[pos+1] == 'H')
				 && (oat_str[pos+2] == 'u' || oat_str[pos+2] == 'U')
				 && (oat_str[pos+3] == 'm' || oat_str[pos+3] == 'M')
				 && (oat_str[pos+4] == 'b' || oat_str[pos+4] == 'B'))
					arch = OAT_ARM;
				break;
			}

			pos++;
		}
	}
	else
		return (ARCHITECTURE_UNKNOWN);

#ifdef __DEBUG__
	if (arch == OAT_ARM)
		cerr << "OAT ARM\n";
	else if (arch == OAT_X86)
		cerr << "OAT X86\n";
	else if (arch == ARCHITECTURE_UNKNOWN)
		cerr << "OAT ARCHITECTURE_UNKNOWN\n";
#endif

	pos = 0;
	uint64_t total_size = 0, size_local = 0, size_read = 0;
	uint64_t count = 0;
	vector <_CodePos> CodePos;
	while (pos < size && count < size)
	{
		count++;
		size_local = 0;
		/*
		 * 
		 * CODE: (code_offset=0x0003401d size_offset=0x00034018 size=60)...
		 *  0x0003401c: f5bd5c00 subs    r12, sp, #8192
		 *  0x00034020: f8dcc000 ldr.w   r12, [r12, #0]
		 * 
		 */
		uint64_t pos_local = oat_str.find("size=", pos);
		if (pos_local != string::npos)
		{
			pos_local += 5;
			char size_str[12];
			uint8_t s = 0;
			bool NUMBER = false;
			for ( ; s < 12; s++)
			{
				if (pos_local >= size || oat_str[pos_local] == ')')
					break;
				char c = oat_str[pos_local++];
				if (isdigit(c))
				{
					size_str[s] = c;
					NUMBER = true;
				}
			}
			size_str[s] = '\0';

			if (NUMBER)
				size_local = atoi(size_str);
			if (size_local > 0)
			{
				pos_local += s;
				uint64_t count_local = 0;
				// The line with code (instruction) starts with 0x
				// Save this location to be used latter
				while (count_local < size_local)
				{
					count_local++;
					pos_local++;
					if (oat_str[pos_local] == '0' && oat_str[pos_local+1] == 'x')
					{
						_CodePos cp;
						cp.pos = pos_local;   // position where the first code (instructions) line starts
						cp.size = size_local; // in bytes of the machine code
						CodePos.push_back(cp);
						break;
					}
				}
			}
			total_size += size_local;
			pos = pos_local + size_local;
#ifdef __DEBUG__
			cout << "NUMBER: " << NUMBER << endl;
			printf("Parser::ParseOAT: (count) %7d ?= %12d (size) --> (pos) %12d ?= %7d (size_local) -> total_size: %12d\n", (int)count, (int)size, (int)pos, (int)size_local, (int)total_size);
#endif
		}
		else
			break;
	}
#ifdef __DEBUG__
	for (int c = 0; c < (int)CodePos.size(); c++)
		cout << "Code Pos: " << CodePos[c].pos << " Size: " << CodePos[c].size << endl;
#endif
	if (total_size == 0 || CodePos.size() <= 0)
		return (ARCHITECTURE_UNKNOWN);
	total_size /= 2;

#ifdef __DEBUG__
	cerr << "Parser::parseOAT: total_size: " << total_size << endl;
	cout << "Parser::parseOAT: total_size: " << total_size << endl;
#endif

	if (arch == OAT_X86)
		code.decoded = new _DecodedInst[total_size];
	else if (arch == OAT_ARM)
		instrs = new cs_insn[total_size];

	for (int c = 0; c < (int)CodePos.size(); c++)
	{
#ifdef __DEBUG__
		cerr << "Code Pos: " << CodePos[c].pos << " Size: " << CodePos[c].size << endl;
		cout << "Code Pos: " << CodePos[c].pos << " Size: " << CodePos[c].size << endl;
#endif
		size_local = 0;
		pos = CodePos[c].pos;
		while (size_local < CodePos[c].size && pos < (size-1))
		{
			if (oat_str[pos] == '0' && oat_str[pos+1] == 'x')
			{
				pos += 2;
				if (arch == OAT_ARM)
					instrs[instruction_count].detail = NULL;
				string str_read;
				// ---------------------------------------
				// Reading instruction's offset/address
				// ---------------------------------------
				int str_pos = 0;
				for (int c = 0; c < 64; c++)
				{
					if (pos > size || oat_str[pos] == ' ' || oat_str[pos] == '\t' || oat_str[pos] == ':' ||  oat_str[pos] == ';')
						break;
					str_read[str_pos++] = oat_str[pos++];
				}
				str_read[str_pos] = '\0';
				int64_t temp_int = Util::hexStringToInt(str_read);
				if (temp_int >= 0)
				{
					if (arch == OAT_ARM)
						instrs[instruction_count].address = (uint64_t)temp_int;
					else if (arch == OAT_X86)
						code.decoded[instruction_count].offset = (uint64_t)temp_int;
				}
				else
					printf("Error:Parser::ParseOAT: Wrong hex string . . .");
				if (instruction_count == 0)
				{
					if (arch == OAT_ARM)
						code.offset = instrs[instruction_count].address;
					else if (arch == OAT_X86)
						code.offset = code.decoded[instruction_count].offset;
				}
				pos++;
				// Remove any white spaces
				while (pos < size && (oat_str[pos] == ' ' || oat_str[pos] == '\t'))
					pos++;
				// ---------------------------------------
				// Reading instruction's machine code
				// ---------------------------------------
				str_pos = 0;
				for (int c = 0; c < 32; c++)
				{
					if (pos > size || oat_str[pos] == ' ' || oat_str[pos] == '\t' || oat_str[pos] == '\n' ||  oat_str[pos] == '\r' ||  oat_str[pos] == ';')
						break;
					if (arch == OAT_ARM)
						instrs[instruction_count].bytes[str_pos++] = oat_str[pos++];
					else if (arch == OAT_X86)
						code.decoded[instruction_count].instructionHex.p[str_pos++] = oat_str[pos++];
				}
				if (arch == OAT_ARM)
				{
					instrs[instruction_count].bytes[str_pos] = '\0';
					instrs[instruction_count].size = str_pos / 2;
					size_local += instrs[instruction_count].size;
					size_read += instrs[instruction_count].size;
				}
				else if (arch == OAT_X86)
				{
					code.decoded[instruction_count].instructionHex.p[str_pos] = '\0';
					code.decoded[instruction_count].instructionHex.length = str_pos;
					code.decoded[instruction_count].size = str_pos / 2;
					size_local += code.decoded[instruction_count].size;
					size_read += code.decoded[instruction_count].size;
				}
				pos++;
				// Remove any white spaces
				while (pos < size && (oat_str[pos] == ' ' || oat_str[pos] == '\t'))
					pos++;
				// ---------------------------------------
				// Reading instruction's mnemonic
				// ---------------------------------------
				str_pos = 0;
				for (int c = 0; c < 32; c++)
				{
					if (pos > size || oat_str[pos] == ' ' || oat_str[pos] == '\t' || oat_str[pos] == '\n' ||  oat_str[pos] == '\r' ||  oat_str[pos] == ';')
						break;
					if (arch == OAT_ARM)
						instrs[instruction_count].mnemonic[str_pos++] = oat_str[pos++];
					else if (arch == OAT_X86)
						code.decoded[instruction_count].mnemonic.p[str_pos++] = oat_str[pos++];
				}
				if (arch == OAT_ARM)
					instrs[instruction_count].mnemonic[str_pos] = '\0';
				else if (arch == OAT_X86)
				{
					code.decoded[instruction_count].mnemonic.p[str_pos] = '\0';
					code.decoded[instruction_count].mnemonic.length = str_pos;
				}
				pos++;
				// Remove any white spaces
				while (pos < size && (oat_str[pos] == ' ' || oat_str[pos] == '\t'))
					pos++;
				// ---------------------------------------
				// Reading instruction's operands
				// ---------------------------------------
				str_pos = 0;
				for (int c = 0; c < 160; c++)
				{
					if (pos > size || oat_str[pos] == '\n' ||  oat_str[pos] == '\r' ||  oat_str[pos] == ';')
						break;
				if (arch == OAT_ARM)
					instrs[instruction_count].op_str[str_pos++] = oat_str[pos++];
				else if (arch == OAT_X86)
					code.decoded[instruction_count].operands.p[str_pos++] = oat_str[pos++];
				}
				if (arch == OAT_ARM)
					instrs[instruction_count].op_str[str_pos] = '\0';
				else if (arch == OAT_X86)
				{
					code.decoded[instruction_count].operands.p[str_pos] = '\0';
					code.decoded[instruction_count].operands.length = str_pos;
				}
#ifdef __DEBUG__
				if (arch == OAT_X86)
				{
					printf("%5d %7x ", (int)instruction_count, (int)code.decoded[instruction_count].offset);
					printf(" ");
					printf("%16s", code.decoded[instruction_count].instructionHex.p);
					printf(" ");
					printf(" %10s %36s\n", code.decoded[instruction_count].mnemonic, code.decoded[instruction_count].operands);
				}
				else if (arch == OAT_ARM)
				{
					printf("%5d %7x ", (int)instruction_count, (int)instrs[instruction_count].address);
					printf(" ");
					printf("%16s", instrs[instruction_count].bytes);
					printf(" ");
					printf(" %10s %36s\n", instrs[instruction_count].mnemonic, instrs[instruction_count].op_str);
				}
#endif
				instruction_count++;
			}
			else
			{
				// Find the end of line and move the pos to the start of the next line
				// It assumes that each code line starts with 0x
				// and move the pos to the first character i.e, '0' in the line
				while (pos < size)
				{
					if (oat_str[pos] == '\n' || oat_str[pos] == '\r')
					{
						pos++;
						while (pos < size && (oat_str[pos] == ' ' || oat_str[pos] == '\t'))
							pos++;
						if (pos < (size-1) && oat_str[pos] == '0' && oat_str[pos+1] == 'x')
							break;
					}
					else
						pos++;
				}
			}
		}
	}
	CodePos.erase(CodePos.begin(), CodePos.end());
	oat_str.erase();

	code.instructions = instrs;
//	code.decoded = filled above;
	code.code_size = instruction_count;
	code.buffer = buffer;      // buffer, the dumped file
	code.buffer_size = size;   // Size of the buffer, the dumped file
//	code.addr_align = no need to fill;
//	code.offset = filled above;
	code.name = "oat-dump";
	codes.push_back(code);

#ifdef __DEBUG__
	printf("Total number of instructions: %5d code.offset: %7x\n", (int)instruction_count, (int)code.offset);
	printf("Instructions Start\n");
	printf("Count :   Offset:      Hex Dump    :    Opcode  :              Operands\n");
	for (int i = 0; i < (int)instruction_count; i++)
	{
		printf("%5d : %7x : ", (int)i, (int)code.instructions[i].address);
		printf("%16s : ", code.instructions[i].bytes);
		printf("%10s : %36s\n", code.instructions[i].mnemonic, code.instructions[i].op_str);
	}
	printf("Instructions End\n");
#endif

	return (arch);
}

/*
 *
 */
void Parser::copyInstructions (_DecodedInst *destination, _DecodedInst *source, uint64_t decodedInstructionsCount,
                               uint64_t &totalInstructionsCopied)
{
   for (int i = 0; i < (int)decodedInstructionsCount; i++)
   {
      destination[totalInstructionsCopied].mnemonic.length = source[i].mnemonic.length;
      memcpy(destination[totalInstructionsCopied].mnemonic.p, source[i].mnemonic.p, source[i].mnemonic.length);
      destination[totalInstructionsCopied].instructionHex.length = source[i].instructionHex.length;
      memcpy(destination[totalInstructionsCopied].instructionHex.p, source[i].instructionHex.p, source[i].instructionHex.length);
      destination[totalInstructionsCopied].operands.length = source[i].operands.length;
      memcpy(destination[totalInstructionsCopied].operands.p, source[i].operands.p, source[i].operands.length);
      destination[totalInstructionsCopied].size = source[i].size;
      destination[totalInstructionsCopied].offset = source[i].offset;
      totalInstructionsCopied++;
   }
}
