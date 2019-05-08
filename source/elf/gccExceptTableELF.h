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

#ifndef __GCC_EXCEPT_TABLE__
#define __GCC_EXCEPT_TABLE__

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
#define DW_EH_PE_uleb128                    0x01        // Unsigned value is encoded using the Little Endian Base 128 (ULEB128).
#define DW_EH_PE_udata2	                    0x02        // A 2 bytes unsigned value.
#define DW_EH_PE_udata4	                    0x03        // A 4 bytes unsigned value.
#define DW_EH_PE_udata8	                    0x04        // An 8 bytes unsigned value.
#define DW_EH_PE_sleb128                    0x09        // Signed value is encoded using the Little Endian Base 128 (SLEB128).
#define DW_EH_PE_sdata2	                    0x0A        // A 2 bytes signed value.
#define DW_EH_PE_sdata4	                    0x0B        // A 4 bytes signed value.
#define DW_EH_PE_sdata8                     0x0C        // An 8 bytes signed value.
#define DW_EH_PE_absptr                     0x00        // Value is used with no modification. In our case that means it needs updating.
#define DW_EH_PE_pcrel                      0x10        // Value is reletive to the current program counter.
#define DW_EH_PE_datarel                    0x30        // Value is reletive to the beginning of the .eh_frame_hdr section.

/**
 * <p>
 *
 * This class implements the GccExceptTableELF class the .gcc_except_table
 * Not much is available about this table except the Gcc source code.
 *
 * The Gcc except table is sorted by the start address field. If the
 * personality function finds that there is no entry for the current
 * PC in the call-site table, then there is no exception information.
 * This should not happen in normal operation, and in C++ will lead
 * to a call to std::terminate.
 *
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since December 31, 2012
 *
 */
class GccExceptTableELF
{
private:
   uint64_t offset, address;//, GCC_EXCEPT_TABLE_LOCATION;

   struct _GccExceptTable_Hdr
   {
      uint8_t landing_pad_enc;               // Encoding (format) of the landing pad base.
      uint64_t landing_pad_base;             // Landing pad base. This is the base from which landing pad offsets are
                                             // computed. If this is omitted, the base comes from calling _Unwind_GetRegionStart,
                                             // which returns the beginning of the code described by the current FDE.
      uint8_t types_table_enc;               // Encoding (format) of the types table.
      uint64_t types_table_base;             // Types table  base stored as ULEB128. This is the byte offset from this field
                                             // to the start of the types table used for exception matching.
      uint8_t call_site_entries_enc;         // Encoding (format) of the call site entries in the table.
      uint64_t table_size;                   // Stored as ULEB128. Size (buffer) of the table in bytes.
   };

   struct _GccExceptTable
   {
		uint64_t start_of_region;              // The start of the instructions for the current call site, a byte offset from the
                                             // landing pad base. This is encoded using the encoding from the header.
      uint64_t start_of_region_location;     // Location (where the value is stored) of the start_of_region to update it latter
		uint64_t length_of_region;             // The length of the instructions for the current call site, in bytes. This is
                                             // encoded using the encoding from the header.
		uint64_t start_of_landing_pad;         // A pointer to the landing pad for this sequence of instructions, or 0 if there
                                             // is one. This is a byte offset from the landing pad base. This is encoded
                                             // using the encoding from the header.
      uint64_t start_of_landing_pad_location;// Location (where the value is stored) of the start_of_landing_pad to update it latter
		uint64_t action;                       // The action to take, an unsigned ULEB128. This is 1 plus a byte offset into the
                                             // action table. The value zero means that there is no action.
	};

//   uint64_t *action_records;                 // Action records. These are the records that are stored just after the
                                             // action table. They store the offsets where the address of the exceptions
                                             // are stored in the data section (usually in the .bss section) of the program.
                                             // They need to be updated if the binary of the program is updated.
                                             // action_record[n] = offset
                                             // action_record[n+1] = location
//   uint64_t LEN_ACTION_RECORDS;

   _GccExceptTable_Hdr tableHdr;
   _GccExceptTable table;

   int64_t readValue(uint64_t &from, uint8_t encoding, uint8_t *buffer, uint64_t &sizeRead, bool &needsUpdate);
   uint64_t writeValue(uint64_t value, uint64_t &from, uint8_t encoding, uint8_t *buffer);
   uint64_t readULEB128(uint64_t &from, uint8_t *buffer);
   int64_t readSLEB128(uint64_t &from, uint8_t *buffer);
   void writeULEB128(uint64_t value, uint64_t &from, uint8_t *buffer);

public:

	GccExceptTableELF(uint64_t offset, uint64_t addrress);
	~GccExceptTableELF();
	void Read(uint8_t *buffer, uint64_t len,bool update, int64_t offset_to_add, uint64_t old_code_offset,
	          uint64_t old_max_offset, map<uint64_t, uint64_t> *updatedOldAddresses);
	void Print();
};

#endif // __GCC_EXCEPT_TABLE__
