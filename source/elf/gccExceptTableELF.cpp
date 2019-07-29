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

#include "gccExceptTableELF.h"

GccExceptTableELF::GccExceptTableELF(uint64_t offset, uint64_t address)
{
   this->offset = offset;
   this->address = address;
}

GccExceptTableELF::~GccExceptTableELF()
{
}

void GccExceptTableELF::Read(uint8_t *buffer, uint64_t len,bool update, int64_t offset_to_add, uint64_t old_code_offset,
                             uint64_t old_max_offset, map<uint64_t, uint64_t> *updatedOldAddresses)
{
   uint64_t sizeRead = 0;
   bool needsUpdate = false;

   uint64_t i = 0;
   while (i < len)
   {
      /*
       * The landing_pad_enc is 0xff for now
       * So we don't need to update the respective value
       */
      tableHdr.landing_pad_enc = Util::ReadByte(i, (const char *)buffer);
      i += sizeof(uint8_t);
      tableHdr.landing_pad_base = 0;
      if (tableHdr.landing_pad_enc != DW_EH_PE_omit)
         tableHdr.landing_pad_base = readValue(i, tableHdr.landing_pad_enc, buffer, sizeRead, needsUpdate);
      tableHdr.types_table_enc = Util::ReadByte(i, (const char *)buffer);
      i += sizeof(uint8_t);
      tableHdr.types_table_base = 0;
      if (tableHdr.types_table_enc != DW_EH_PE_omit)
      {
         tableHdr.types_table_base = readULEB128(i, buffer);
         tableHdr.types_table_base += i;
      }

      tableHdr.call_site_entries_enc = Util::ReadByte(i, (const char *)buffer);
      i += sizeof(uint8_t);

      tableHdr.table_size = readULEB128(i, buffer);
#ifdef __DEBUG__
      cout << "--------------------------------------------------------------------------------------------------\n";
      cout << "                                                                                                   \n";
      cout << "                  Printing Gcc Exception Table of size: " << dec << tableHdr.table_size << hex << endl;
      cout << " Landing pad    Landing pad    Types table     Types table     Call site entries    Table size   \n";
      cout << "  encoding          base        encoding           base             encoding                      \n";
      cout << "--------------------------------------------------------------------------------------------------\n";
      cout << setw(8) << (int)tableHdr.landing_pad_enc << setw(15) << (int)tableHdr.landing_pad_base;
      cout << setw(15) << (int)tableHdr.types_table_enc << setw(15) << (int)tableHdr.types_table_base;
      cout << setw(20) << (int)tableHdr.call_site_entries_enc << setw(18) << (int)tableHdr.table_size << endl;
      cout << "--------------------------------------------------------------------------------------------------\n";
#endif
      /*
       *
       * Read the call site (gcc except) table.
       * Note all the call site table entries are absolute (DW_EH_PE_absptr) displacements.
       *
       */
      bool action_records_zero = true;
      if (tableHdr.table_size > 0)
      {
#ifdef __DEBUG__
         cout << " Start of region     Length of region     Start landing pad      Action       Action records . . .\n";
         cout << "--------------------------------------------------------------------------------------------------\n";
#endif
         uint64_t t = i;
         uint64_t action_table_base = tableHdr.table_size + t;
         uint64_t types_table_loc = tableHdr.types_table_base;
         while (i < action_table_base)
         {
            table.start_of_region_location = i;
            table.start_of_region = readValue(i, tableHdr.call_site_entries_enc, buffer, sizeRead, needsUpdate);
            table.length_of_region = readValue(i, tableHdr.call_site_entries_enc, buffer, sizeRead, needsUpdate);

            table.start_of_landing_pad_location = i;
            table.start_of_landing_pad = readValue(i, tableHdr.call_site_entries_enc, buffer, sizeRead, needsUpdate);
            table.action = readULEB128(i, buffer);

            if (update)
            {
               uint64_t old_offset = table.start_of_region;
               uint64_t new_offset = old_offset + 0xc;
               table.start_of_region = new_offset;
               writeValue(table.start_of_region, table.start_of_region_location, tableHdr.call_site_entries_enc, buffer);

               old_offset = table.start_of_landing_pad;
               if (old_offset > 0)
               {
                  new_offset = old_offset + 0xc;
                  table.start_of_landing_pad = new_offset;
                  writeValue(table.start_of_landing_pad, table.start_of_landing_pad_location, tableHdr.call_site_entries_enc, buffer);
               }
//if (i > 2044)
//{
//cerr << setw(12) << table.start_of_region << setw(20) << table.length_of_region;
//cerr << setw(20) << table.start_of_landing_pad << setw(16) << table.action << endl;
//cerr << "-------------------------------------------------------------------------------------------\n";
//}
            }

#ifdef __DEBUG__
            cout << setw(12) << table.start_of_region << setw(20) << table.length_of_region;
            cout << setw(20) << table.start_of_landing_pad << setw(16) << table.action << "   ";
#endif

            /*
             * Read action table
             * Action table contains two values stored as SLEB128 format
             * (1) filter: A type filter.
             *             - If it's positive then it's the negative index into the types table (action_records)
             *               A value of 1 means the entry preceding the types_table_base, a 2 means entry before
             *               that and so on.
             *             - If it's negative then it's the byte offset into the types table (action_records) of
             *               a NULL terminated pointers to type information.
             *             - If it's 0 then it's a cleanup and no type information is required.
             * (2) offset: Byte offset to the next entry in the action table.
             *             A 0 offset value indicates the end of the action table.
             */
            if (table.action != 0)
            {
               uint64_t at = action_table_base + ( sizeof(uint8_t) * (table.action - 1) );
               int64_t filter = readSLEB128(at, buffer);
               if (filter != 0)
               {
                  uint64_t offset = readSLEB128(at, buffer);
               }

               int64_t action_record = 0;
               if (filter > 0)
               {
                  types_table_loc = tableHdr.types_table_base - ( sizeof(uint32_t) * filter );
                  if ( (tableHdr.types_table_enc == DW_EH_PE_udata2) || (tableHdr.types_table_enc == DW_EH_PE_sdata2) )
                     types_table_loc = tableHdr.types_table_base - ( sizeof(uint16_t) * filter );
                  else if ( (tableHdr.types_table_enc == DW_EH_PE_udata8) || (tableHdr.types_table_enc == DW_EH_PE_sdata8) )
                     types_table_loc = tableHdr.types_table_base - ( sizeof(uint64_t) * filter );
                  uint64_t sizeRead = 0; bool needsUpdate = false;
                  uint64_t old_types_table_loc = types_table_loc;
                  action_record = readValue(types_table_loc, tableHdr.types_table_enc, buffer, sizeRead, needsUpdate);

#ifdef __DEBUG__
                  cout << hex << setw(12) << (int)action_record << " ";
#endif

                  if (update && (action_record != 0))
                  {
                     uint64_t old_address = action_record;
                     uint64_t new_address = old_address;
                     map<uint64_t, uint64_t>::iterator it_u = updatedOldAddresses->find(old_address);
                     if (it_u != updatedOldAddresses->end())
                        new_address = it_u->second;
                     else if (old_address >= old_code_offset && old_address < old_max_offset)
                        new_address = old_address + offset_to_add;

                     action_record = new_address;
                     writeValue(action_record, old_types_table_loc, tableHdr.types_table_enc, buffer);
                  }
               }
               else if (filter < 0)
               {
                  types_table_loc = tableHdr.types_table_base + (-filter - 1);
                  while (types_table_loc < len)
                  {
                     uint64_t sizeRead = 0; bool needsUpdate = false;
                     uint64_t old_types_table_loc = types_table_loc;
                     action_record = readValue(types_table_loc, tableHdr.types_table_enc, buffer, sizeRead, needsUpdate);

#ifdef __DEBUG__
                     cout << hex << setw(12) << (int)action_record << " ";
#endif

                     if (action_record == 0)
                        break;
                     else
                     {
                        uint8_t byte = Util::ReadByte(types_table_loc, (const char *)buffer);
                        if (byte == 0xFF)
                           break;
                        else if (update)
                        {
                           uint64_t old_address = action_record;
                           uint64_t new_address = old_address;
                           map<uint64_t, uint64_t>::iterator it_u = updatedOldAddresses->find(old_address);
                           if (it_u != updatedOldAddresses->end())
                              new_address = it_u->second;
                           else if (old_address >= old_code_offset && old_address < old_max_offset)
                              new_address = old_address + offset_to_add;

                           action_record = new_address;
                           writeValue(action_record, old_types_table_loc, tableHdr.types_table_enc, buffer);
                        }
                     }
                  }
               }
            }
            cout << endl;
         }
         if (types_table_loc > i)
            i = types_table_loc;
      }
      /*
       * Skip any zero bytes and read the action records
       */
      uint8_t byte = 0;
      while (i < len)
      {
         byte = Util::ReadByte(i, (const char *)buffer);
         if (byte == 0xFF)
            break;
         else
            i += sizeof(uint8_t);
      }
   }
   cout << "i  ?=  len   <-->   " << hex << i << "  ?=  " << len << endl;
}

/*
 * There are different ways to encode the address of the pointer:
 * (1) Absolute pointer - we need to update
 * (2) Relative to the current program counter - we need to update
 * (3) Relative to the beginning of the .eh_frame_hdr - we need to update
 */
int64_t GccExceptTableELF::readValue(uint64_t &from, uint8_t encoding, uint8_t *buffer, uint64_t &sizeRead, bool &needsUpdate)
{
   int64_t value = 0;
   needsUpdate = false;
   if ((encoding & 0xFF) == 0xFF)
   {
      cerr << "Warning:GccExceptTableELF::readValue: No value present\n";
      return (value);
   }

   uint8_t temp_encoding = encoding & 0x0F;
   switch (temp_encoding)
   {
      case DW_EH_PE_uleb128:
      {
         uint64_t old_from = from;
         value = readULEB128(from, buffer);
         sizeRead = from - old_from;
         break;
      }
      case DW_EH_PE_udata2:
      case DW_EH_PE_sdata2:
         value = Util::ReadShort(from, (const char*)buffer);
         from += sizeof(uint16_t);
         sizeRead = sizeof(uint16_t);
         break;
      case DW_EH_PE_udata4:
      case DW_EH_PE_sdata4:
         value = Util::ReadInt(from, (const char*)buffer);
         from += sizeof(uint32_t);
         sizeRead = sizeof(uint32_t);
         break;
      case DW_EH_PE_udata8:
      case DW_EH_PE_sdata8:
         value = Util::ReadLong(from, (const char*)buffer);
         from += sizeof(uint64_t);
         sizeRead = sizeof(uint64_t);
         break;
      default:
         cerr << "Warning:GccExceptTableELF::readValue: No/Bad encoding\n";
         break;
   }

   encoding = encoding & 0xF0;
   switch(encoding)
   {
      case DW_EH_PE_absptr:
         needsUpdate = true;
         break;
      case DW_EH_PE_pcrel:
         needsUpdate = true;
         break;
      case DW_EH_PE_datarel:
         needsUpdate = true;
         break;
      default:
         cerr << "Warning:GccExceptTableELF::readValue: No/Bad encoding\n";
         break;
   }

   return (value);
}

/*
 * There are different ways to encode the address of the pointer:
 * (1) Absolute pointer - we need to update
 * (2) Relative to the current program counter - we need to update
 * (3) Relative to the beginning of the .eh_frame_hdr - we need to update
 */
uint64_t GccExceptTableELF::writeValue(uint64_t value, uint64_t &from, uint8_t encoding, uint8_t *buffer)
{
   uint64_t sizeWritten = 0;
   if ((encoding & 0xFF) == 0xFF)
   {
      cerr << "Warning:GccExceptTableELF::readValue: No value present\n";
      return (sizeWritten);
   }

   uint8_t temp_encoding = encoding & 0x0F;
   switch (temp_encoding)
   {
      case DW_EH_PE_uleb128:
      {
         uint64_t old_from = from;
         writeULEB128(value, from, buffer);
         sizeWritten = from - old_from;
         break;
      }
      case DW_EH_PE_udata2:
      case DW_EH_PE_sdata2:
         Util::WriteShort(value, from, (char*)buffer);
         from += sizeof(uint16_t);
         sizeWritten = sizeof(uint16_t);
         break;
      case DW_EH_PE_udata4:
      case DW_EH_PE_sdata4:
         Util::WriteInt(value, from, (char*)buffer);
         from += sizeof(uint32_t);
         sizeWritten = sizeof(uint32_t);
         break;
      case DW_EH_PE_udata8:
      case DW_EH_PE_sdata8:
         Util::WriteLong(value, from, (char*)buffer);
         from += sizeof(uint64_t);
         sizeWritten = sizeof(uint64_t);
         break;
      default:
         cerr << "Warning:GccExceptTableELF::writeValue: No/Bad encoding\n";
         break;
   }

   return (sizeWritten);
}

/*
 * Decode ULEB128
 * The algorithm is listed in the DWARF standard:
 * Figure 46 DWARF Debugging Information Format Version 3, 2005
 * http://dwarfstd.org/doc/Dwarf3.pdf
 */
uint64_t GccExceptTableELF::readULEB128(uint64_t &from, uint8_t *buffer)
{
   uint64_t result = 0;
   uint64_t shift = 0;
   uint8_t byte = 0;

   do
   {
      byte = Util::ReadByte(from, (const char*)buffer);
      from += sizeof(uint8_t);
      result |= (uint64_t)( (byte & 0x7f) << shift );
      shift += 7;
   }
   while(byte & 0x80);

   return (result);
}

/*
 * Decode SLEB128
 * The algorithm is listed in the DWARF standard:
 * Figure 47 DWARF Debugging Information Format Version 3, 2005
 * http://dwarfstd.org/doc/Dwarf3.pdf
 */
int64_t GccExceptTableELF::readSLEB128(uint64_t &from, uint8_t *buffer)
{
   int64_t result = 0;
   uint64_t shift = 0;
   uint8_t byte = 0;
   uint64_t size = 0;

   while (1)
   {
      byte = Util::ReadByte(from, (const char*)buffer);
      from += sizeof(uint8_t);
      size += sizeof(uint8_t) * 8;
      result |= (int64_t)( (byte & 0x7f) << shift );
      shift += 7;
      if ( (byte & 0x80) == 0 )
         break;
   }
   if ( (shift < size) && ((byte & 0x40) != 0) )
      result |= -( ((int64_t)1) << shift );

   return (result);
}

/*
 * Encode ULEB128
 * The algorithm is listed in the DWARF standard:
 * Figure 44 DWARF Debugging Information Format Version 3, 2005
 * http://dwarfstd.org/doc/Dwarf3.pdf
 */
void GccExceptTableELF::writeULEB128(uint64_t value, uint64_t &from, uint8_t *buffer)
{
   uint8_t byte = 0;

   do
   {
      byte = value & 0x7F;
      value >>= 7;
      if (value != 0)
         byte |= 0x80;
      Util::WriteByte(byte, from, (char*)buffer);
      from += sizeof(uint8_t);
   }
   while(value != 0);
}
