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

public:
   struct _Eh_Frame_Hdr
   {
      uint8_t version;                      // Version of the .eh_frame_hdr format. This value must be 1.
      uint8_t eh_frame_ptr_enc;             // The encoding format of the eh_frame_ptr field.
      uint8_t fde_count_enc;                // The encoding format of the fde_count field. A value of DW_EH_PE_omit indicates the binary search table is not present.
      uint8_t table;                        // The encoding format of the entries in the binary search table. A value of DW_EH_PE_omit indicates the binary search table is not present.
      uint8_t *eh_frame_ptr;                // The encoded value of the pointer to the start of the .eh_frame section.
      uint8_t *fde_count;                   // The encoded value of the count of entries in the binary search table.
   };

	struct _CIE
	{
		uint32_t length;                       // Length of the CIE (not including this 4 - byte field)
		uint32_t id;                           // Value 0 for .eh_frame (used to distinguish CIEs and FDEs when scanning the section)
		uint8_t version;                       // Value One (1)
		char augmentationString;               // Null-terminated string with legal values being "" or ’z’ optionally followed by single
                                             // occurrances of ’P’, ’L’, or ’R’ in any order. The presence of character(s) in the
                                             // string dictates the content of field 8, the Augmentation Section. Each character has
                                             // one or two associated operands in the AS (see table I below for which ones).
                                             // Operand order depends on position in the string (’z’ must be first).
		uint8_t codeAlignFactor[16];           // To be multiplied with the "Advance Location" instructions in the Call Frame Instructions
		uint8_t dataAlignFactor[16];           // To be multiplied with all offsets in the Call Frame Instructions
		uint8_t returnAddressRegister[16];     // A "virtual" register representation of the return address. In Dwarf V2, this is a byte, otherwise it is uleb128. It is a byte in gcc 3.3.x
		uint8_t *augmentationSection;          // Present if Augmentation String in Augmentation Section field 4 is not 0. See table I below for the content.
		uint8_t *callInstructions;             //
	};

/*
 *
 * ------------------------------------------------------------------------------------------------------------------------------
 *                                                      Table I
 * ------------------------------------------------------------------------------------------------------------------------------
 *
 * Char           Operands          Length (byte)           Description
 *  z           size                   uleb128              Length of the remainder of the Augmentation Section
 *  P           personality_enc           1                 Encoding specifier - preferred value is a pc-relative, signed 4-byte
 *              personality           (encoded)             Encoded pointer to personality routine
 *              routine                                     (actually to the PLT entry for the personality routine)
 *  R           code_enc                  1                 Non-default encoding for the code-pointers (FDE members
 *                                                          initial_location and address_range and the operand for
 *                                                          DW_CFA_set_loc) - preferred value is pc-relative, signed 4-byte
 *  L           lsda_enc                  1                 FDE augmentation bodies may contain LSDA pointers. If so they
 *                                                          are encoded as specified here - preferred value is pcrelative,
 *                                                          signed 4-byte possibly indirect thru a GOT entry
 *
 */

	struct _FDE
	{
	   uint32_t length;                       // Length of the FDE (not including this 4 - byte field)
	   uint32_t cie_ptr;                      // Distance from this field to the nearest preceding CIE
                                             // (the value is subtracted from the current address).
                                             // This value can never be zero and thus can be used
                                             // to distinguish CIE’s and FDE’s when scanning the
                                             // .eh_frame section
      uint8_t *initialLocation;              // Reference to the function code corresponding to this FDE.
                                             // If ’R’ is missing from the CIE Augmentation String, the
                                             // field is an 8-byte absolute pointer. Otherwise, the
                                             // corresponding EH_PE encoding in the CIE Augmentation
                                             // Section is used to interpret the reference
      uint8_t *addressRange;                 // Size of the function code corresponding to this FDE. If
                                             // ’R’ is missing from the CIE Augmentation String, the field
                                             // is an 8-byte unsigned number. Otherwise, the size is
                                             // determined by the corresponding EH_PE encoding in the CIE
                                             // Augmentation Section (the value is always absolute)
		uint8_t *augmentationSection;          // Present if Augmentation String (in struct _CIE) is non-empty. See table II below for the content.
		uint8_t *callInstructions;             //
	};

/*
 *
 * ------------------------------------------------------------------------------------------------------------------------------
 *                                                      Table II
 * ------------------------------------------------------------------------------------------------------------------------------
 *
 * Char           Operands          Length (byte)           Description
 *  z           length                 uleb128              Length of the remainder of the Augmentation Section
 *  L           LSDA                     var                LSDA pointer, encoded in the format specified by the corresponding
 *                                                          operand in the CIE’s augmentation body. (only present if length > 0).
 *
 */
};

#endif // __EH_FRAME_ELF_H__
