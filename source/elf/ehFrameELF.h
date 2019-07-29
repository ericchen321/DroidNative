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

#ifndef __EH_FRAME_ELF_H__
#define __EH_FRAME_ELF_H__

#include <iostream>
#include <iomanip>
#include <map>

#include "../include/common.h"
#include "../util/util.h"

#define MAX_AUGMENTATION_STRING_LENGTH      28

/*
 *
 * Exception Header Encoding is used to describe the type
 * of data used in the .eh_frame_hdr section. The upper
 * 4 bits indicate how the value is to be applied. The
 * lower 4 bits indicate the format of the data.
 *
 */
#define DW_EH_PE_omit                       0xff        // No value is present.
#define DW_EH_PE_uleb128                    0x01        // Unsigned value is encoded using the Little Endian Base 128 (LEB128).
#define DW_EH_PE_udata2	                    0x02        // A 2 bytes unsigned value.
#define DW_EH_PE_udata4	                    0x03        // A 4 bytes unsigned value.
#define DW_EH_PE_udata8	                    0x04        // An 8 bytes unsigned value.
#define DW_EH_PE_sleb128                    0x09        // Signed value is encoded using the Little Endian Base 128 (LEB128).
#define DW_EH_PE_sdata2	                    0x0A        // A 2 bytes signed value.
#define DW_EH_PE_sdata4	                    0x0B        // A 4 bytes signed value.
#define DW_EH_PE_sdata8                     0x0C        // An 8 bytes signed value.
#define DW_EH_PE_absptr                     0x00        // Value is used with no modification. In our case that means it needs updating.
#define DW_EH_PE_pcrel                      0x10        // Value is reletive to the current program counter.
//#define DW_EH_PE_textrel                    0x20        // Value is reletive to the beginning of the .text Section.
#define DW_EH_PE_datarel                    0x30        // Value is reletive to the beginning of the .eh_frame_hdr section.
//#define DW_EH_PE_funcrel                    0x40        // Value is reletive to the beginning of the function.


/**
 * <p>
 *
 * This class implements the EhFrame class the .eh_frame section as defined
 * in the following AMD document:
 * System V Application Binary Interface AMD64 (c) 2010
 *
 * From AMD64:
 *
 * The call frame information needed for unwinding the stack is output into one
 * or more ELF sections of type SHT_X86_64_UNWIND. In the simplest case there
 * will be one such section per object file and it will be named .eh_frame. An
 * .eh_frame section consists of one or more subsections. Each subsection
 * contains a CIE (Common Information Entry) followed by varying number of FDEs
 * (Frame Descriptor Entry). A FDE corresponds to an explicit or compiler generated
 * function in a compilation unit, all FDEs can access the CIE that begins their
 * subsection for data. If the code for a function is not one contiguous block,
 * there will be a separate FDE for each contiguous sub-piece.
 *
 * If an object file contains C++ template instantiations there shall be a
 * separate CIE immediately preceding each FDE corresponding to an instantiation.
 *
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since December 21, 2012
 *
 */
class EhFrameELF
{
private:
   bool FRAME_PTR_NEEDS_UPDATING;
   bool TABLE_NEEDS_UPDATING;
   uint64_t SIZE_OF_FRAME_PTR, SIZE_OF_FDE_COUNT, SIZE_OF_FDE_ADDRESS_IN_TABLE, SIZE_OF_PER_ROUTINE_PTR, SIZE_OF_INITIAL_LOCATION_PTR;

   uint64_t offset_hdr, offset_frame, address_hdr, address_frame;

   struct _Eh_Frame_Hdr
   {
      uint8_t version;                      // Version of the .eh_frame_hdr format. This value must be 1.
      uint8_t frame_ptr_enc;                // The encoding format of the eh_frame_ptr field.
      uint8_t fde_count_enc;                // The encoding format of the fde_count field. A value of DW_EH_PE_omit indicates the binary search table is not present.
      uint8_t table_enc;                    // The encoding format of the entries in the binary search table. A value of DW_EH_PE_omit indicates the binary search table is not present.
      uint64_t frame_ptr;                   // The encoded value of the pointer to the start of the .eh_frame section.
      uint64_t fde_count;                   // The encoded value of the count of entries in the binary search table.
      void *table;                          // A binary search table containing fde_count entries.
                                            // Each entry of the table consist of two encoded values,
                                            // the initial location, and the address.
                                            // Initial location is the starting address of the fde function in the code section.
                                            // Address is the location for this function (information) in the FDE.
                                            // The entries are sorted in an increasing order by the initial location value.
   };

	struct _CIE
	{
		uint64_t length;                       // Length of the CIE (not including this 4 - byte field)
                                               // If length = 0xffffffff then read the next 8 bytes for extended length
		uint32_t id;                           // Value 0 for .eh_frame (used to distinguish CIEs and FDEs when scanning the section)
		uint8_t version;                       // Value One (1)
		uint8_t augmentationString[MAX_AUGMENTATION_STRING_LENGTH+1];
                                               // Null-terminated string with legal values being "" or 'z' optionally followed by single
                                               // occurrences of P, L, or R in any order. The presence of character(s) in the
                                               // string dictates the content of field 8, the Augmentation Section. Each character has
                                               // one or two associated operands in the AS (see table I below for which ones).
                                               // Operand order depends on position in the string ('z' must be first).
		uint64_t codeAlignFactor;              // Stored as ULEB128. To be multiplied with the "Advance Location" instructions in the Call Frame Instructions
		int64_t dataAlignFactor;               // Stored as SLEB128. To be multiplied with all offsets in the Call Frame Instructions
		uint64_t returnAddressRegister;        // Stored as ULEB128. A "virtual" register representation of the return address. In Dwarf V2, this is a byte, otherwise it is uleb128. It is a byte in gcc 3.3.x
		uint64_t augmentationLength;           // Length of the augmentation data. Present only if 'z' in the augmentation string.
		uint8_t fde_encoding;                  // Present if Augmentation String's 'z' is present. See table I below for the contents.
		uint8_t lsda_encoding;
		uint8_t per_encoding;
		uint64_t per_routine_ptr;              // Address of a personality routine handler. The personality routine is used to handle
                                               // language and vendor-specific tasks.
		bool PER_ROUTINE_PTR_NEEDS_UPDATING;     // To keep track if the address needs to be updated for this CIE
		uint64_t LOCATION_OF_PER_ROUTINE_PTR;    // TO keep track of the location of this address it it needs to be updated
		//uint8_t *callInstructions;             //
	};

/*
 *
 * ------------------------------------------------------------------------------------------------------------------------------
 *
 *                                                      Table I
 *
 * ------------------------------------------------------------------------------------------------------------------------------
 * Char           Operands          Length (byte)           Description
 * ------------------------------------------------------------------------------------------------------------------------------
 *
 *
 *
 *  z           size                   uleb128              Length of the remainder of the Augmentation Section
 *
 *
 *
 *  P           personality_enc           1                 Encoding specifier - preferred value is a pc-relative, signed 4-byte
 *              personality           (encoded)             Encoded pointer to personality routine
 *              routine                                     (actually to the PLT entry for the personality routine).
 *                                                          It indicates the presence of two arguments in the Augmentation
 *                                                          Data of the CIE. The first argument is 1-byte and represents the
 *                                                          pointer encoding used for the second argument, which is the address
 *                                                          of a personality routine handler. The personality routine is used to
 *                                                          handle language and vendor-specific tasks. The system unwind library
 *                                                          interface accesses the language-specific exception handling semantics
 *                                                          via the pointer to the personality routine. The personality routine
 *                                                          does not have an ABI-specific name. The size of the personality
 *                                                          routine pointer is specified by the pointer encoding used.
 *
 *
 *
 *  R           code_enc                  1                 Non-default encoding for the code-pointers (FDE members
 *                                                          initial_location and address_range and the operand for
 *                                                          DW_CFA_set_loc) - preferred value is pc-relative, signed 4-byte.
 *                                                          If present, The Augmentation Data shall include a 1 byte argument
 *                                                          that represents the pointer encoding for the address pointers used
 *                                                          in the FDE.
 *
 *
 *
 *  L           lsda_enc                  1                 FDE augmentation bodies may contain LSDA pointers. If so they
 *                                                          are encoded as specified here - preferred value is pcrelative,
 *                                                          signed 4-byte possibly indirect thru a GOT entry.
 *                                                          it indicates the presence of one argument in the Augmentation
 *                                                          Data of the CIE, and a corresponding argument in the Augmentation
 *                                                          Data of the FDE. The argument in the Augmentation Data of the CIE
 *                                                          is 1-byte and represents the pointer encoding used for the argument
 *                                                          in the Augmentation Data of the FDE, which is the address of a
 *                                                          language-specific data area (LSDA). The size of the LSDA pointer is
 *                                                          specified by the pointer encoding used.
 *
 */

	struct _FDE
	{
		uint64_t length;                       // Length of the FDE (not including this 4 - byte field)
                                               // If length = 0xffffffff then read the next 8 bytes for extended length
		uint32_t cie_ptr;                      // Distance from this field to the nearest preceding CIE
                                               // (the value is subtracted from the current address).
                                               // This value can never be zero and thus can be used
                                               // to distinguish CIEs and FDEs when scanning the
                                               // .eh_frame section
		int64_t initialLocation;               // Reference to the function code corresponding to this FDE.
                                               // If ’R’ is missing from the CIE Augmentation String, the
                                               // field is an 8-byte absolute pointer. Otherwise, the
                                               // corresponding EH_PE encoding in the CIE Augmentation
                                               // Section is used to interpret the reference
		uint64_t numberOfBytes;                // Size of the function code corresponding to this FDE. If
                                               // R is missing from the CIE Augmentation String, the field
                                               // is an 8-byte unsigned number. Otherwise, the size is
                                               // determined by the corresponding EH_PE encoding in the CIE
                                               // Augmentation Section (the value is always absolute)
		uint64_t augmentationLength;           // Stored as ULEB128. Length of the augmentation data. Present only if 'z' in the
                                               // augmentation string.
		uint64_t lsdaAddress;                  // Present if Augmentation String's 'z' is present. See table I below for the contents.
		//uint8_t *callInstructions;             // Call frame instructions are encoded in one or more bytes. The primary opcode is
                                               // encoded in the high order two bits of the first byte (that is, opcode = byte >> 6).
                                               // An operand or extended opcode may be encoded in the low order 6 bits.
		uint8_t value_DW_CFA_advance_loc;      // The value, opcode (first two bytes = 0x01) + operand (last 6 bits), itself.
		uint64_t LOCATION_OF_DW_CFA_advance_loc;// To store the location of the first DW_CFA_advance_loc instruction to be updated latter.
		bool INITIAL_LOCATION_NEEDS_UPDATING;  // To keep track if the address (initial location) needs to be updated for this FDE
		uint64_t LOCATION_OF_INITIAL_LOCATION; // TO keep track of the location of this address it it needs to be updated
	};

/*
 *
 * ------------------------------------------------------------------------------------------------------------------------------
 *                                                      Table II
 * ------------------------------------------------------------------------------------------------------------------------------
 *
 * Char           Operands          Length (byte)           Description
 *
 *  z           length                 uleb128              Length of the remainder of the Augmentation Section
 *
 *  L           LSDA                     var                LSDA pointer, encoded in the format specified by the corresponding
 *                                                          operand in the CIEs augmentation body. (only present if length > 0).
 *
 */

   struct _cie
   {
		_CIE *cie;
		uint64_t index_of_functions;
   };

	vector<_cie> cie_s;
	vector<_FDE> fde;
	_Eh_Frame_Hdr ElfEhFrameHdr;

   typedef struct
   {
		int64_t initialLocation;
		int64_t address;
   } _FDERecord;

    uint64_t readValue(uint64_t &from, uint8_t encoding, uint8_t *buffer, uint64_t &sizeRead, bool &needsUpdate);
	uint64_t writeValue(uint64_t value, uint64_t &from, uint8_t encoding, uint8_t *buffer);

	void readFramePtr(uint64_t &from, uint8_t encoding, uint8_t *buffer);
	void readFDECount(uint64_t &from, uint8_t encoding, uint8_t *buffer);
	void readTable(uint64_t &from, uint8_t encoding, uint8_t *buffer);
	void readPersonalityRoutinePtr(uint64_t &from, _CIE *cie_p, uint8_t *buffer);
	void readInitialLocationAndSize(_FDE &fde_p, uint64_t &from, uint8_t encoding, uint8_t *buffer);

	void updateFramePtr(uint64_t &from, uint8_t encoding, uint8_t *buffer, uint64_t new_address);
	void updateTableFDERecord(_FDERecord &fdeRecord, uint64_t from, uint64_t offset_to_add,
								uint64_t old_code_offset, uint64_t old_max_offset,
								map<uint64_t, Function> *Functions_Mapped);
	void updateTable(uint64_t &from, uint8_t encoding, uint8_t *buffer, uint64_t offset_to_add,
								uint64_t old_code_offset, uint64_t old_max_offset,
								map<uint64_t, Function> *Functions_Mapped);
	void updatePersonalityRoutinePtr(uint64_t &from, _CIE *cie, uint8_t *buffer, uint64_t new_address);
	void updateInitialLocationAndSize(_FDE &fde_p, uint64_t &from, uint8_t encoding, uint8_t *buffer,
	uint64_t new_address, uint64_t new_size);

	uint64_t decodeULEB128(uint64_t &from, uint8_t *buffer);
	int64_t decodeSLEB128(uint64_t &from, uint8_t *buffer);

public:

	vector<uint64_t> FdeFunctions;
	uint64_t NumberOfFdeFunctions;

	EhFrameELF();
	~EhFrameELF();
	void ReadHdr(uint8_t *buffer, uint64_t len, uint64_t offset_hdr, uint64_t address_hdr);
	void ReadFrame(uint8_t *buffer, uint64_t len, uint64_t offset_frame, uint64_t address_frame);
	void UpdateHdr(uint8_t *buffer, uint64_t len, int64_t offset_to_add, uint64_t old_code_offset, uint64_t old_max_offset,
								map<uint64_t, uint64_t> *updatedOldAddresses, map<uint64_t, Function> *Functions_Mapped);
	void UpdateFrame(uint8_t *buffer, uint64_t len, int64_t offset_to_add, uint64_t old_code_offset, uint64_t old_max_offset,
								map<uint64_t, uint64_t> *updatedOldAddresses, map<uint64_t, Function> *Functions_Mapped);
	void Print();
};

#endif // __EH_FRAME_ELF_H__
