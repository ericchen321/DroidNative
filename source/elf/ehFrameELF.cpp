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

#include "ehFrameELF.h"

EhFrameELF::EhFrameELF()
{
   FRAME_PTR_NEEDS_UPDATING = false;
   TABLE_NEEDS_UPDATING = false;
   SIZE_OF_FRAME_PTR = SIZE_OF_FDE_COUNT = SIZE_OF_FDE_ADDRESS_IN_TABLE = SIZE_OF_PER_ROUTINE_PTR = SIZE_OF_INITIAL_LOCATION_PTR = 0;
   NumberOfFdeFunctions = 0;

   ElfEhFrameHdr.table = NULL;

   offset_hdr = offset_frame = 0;
   address_hdr = address_frame = 0;
}

EhFrameELF::~EhFrameELF()
{
   if (TABLE_NEEDS_UPDATING)
   {
      if (SIZE_OF_FDE_ADDRESS_IN_TABLE == sizeof(int16_t))
      {
         int16_t *table_i = (int16_t *)ElfEhFrameHdr.table;
         delete (table_i);
      }
      else if (SIZE_OF_FDE_ADDRESS_IN_TABLE == sizeof(int32_t))
      {
         int32_t *table_i = (int32_t *)ElfEhFrameHdr.table;
         delete (table_i);
      }
      else if (SIZE_OF_FDE_ADDRESS_IN_TABLE == sizeof(int64_t))
      {
         int64_t *table_i = (int64_t *)ElfEhFrameHdr.table;
         delete (table_i);
      }
   }

   for (int c = 0; c < (int)cie_s.size(); c++)
      delete (cie_s[c].cie);
   cie_s.erase(cie_s.begin(), cie_s.end());
}

void EhFrameELF::ReadHdr(uint8_t *buffer, uint64_t len, uint64_t offset_hdr, uint64_t address_hdr)
{
   this->offset_hdr = offset_hdr;
   this->address_hdr = address_hdr;

	uint64_t i = 0;
	for ( ; i < len; i++)
	{
      ElfEhFrameHdr.version = Util::ReadByte(i, (const char *)buffer);
      i += sizeof(uint8_t);
      ElfEhFrameHdr.frame_ptr_enc = Util::ReadByte(i, (const char *)buffer);
      i += sizeof(uint8_t);
      ElfEhFrameHdr.fde_count_enc = Util::ReadByte(i, (const char *)buffer);
      i += sizeof(uint8_t);
      ElfEhFrameHdr.table_enc = Util::ReadByte(i, (const char *)buffer);
      i += sizeof(uint8_t);

      readFramePtr(i, ElfEhFrameHdr.frame_ptr_enc, buffer);
      readFDECount(i, ElfEhFrameHdr.fde_count_enc, buffer);
      readTable(i, ElfEhFrameHdr.table_enc, buffer);

      break;
	}
}

void EhFrameELF::ReadFrame(uint8_t *buffer, uint64_t len, uint64_t offset_frame, uint64_t address_frame)
{
   this->offset_frame = offset_frame;
   this->address_frame = address_frame;

   uint64_t f = 0;

	for (uint64_t i = 0; i < len; )
	{
      bool AUGMENTATION_DATA_PRESENT = false;
	   /*
	    * For informatiion on CIE and FDE read the comments in the header file.
	    * First read the length of the first CIE
	    */
      uint64_t length = Util::ReadInt(i, (const char *)buffer);
      i += sizeof(uint32_t);
      /*
       * If length = 0xffffffff then read the next 8 bytes for extended length
       */
      if (length == 0xffffffff)
      {
         length = Util::ReadLong(i, (const char *)buffer);
         i += sizeof(uint64_t);
      }
      uint64_t location_length_field = i;

      _CIE *cie_local;
      if (length > 0)
      {
         cie_local = new _CIE();
         cie_local->length = length;
      }
      else
         break;

      cie_local->id = Util::ReadInt(i, (const char *)buffer);
      i += sizeof(uint32_t);
      cie_local->version = Util::ReadInt(i, (const char *)buffer);
      i += sizeof(uint8_t);
      /*
       * Read the augmentation string - a NULL terminated string
       */
      for (int c = 0; c < MAX_AUGMENTATION_STRING_LENGTH; c++)
      {
         cie_local->augmentationString[c] = (char)Util::ReadByte(i, (const char *)buffer);
         i += sizeof(uint8_t);
         if (cie_local->augmentationString[c] == NULL_CHAR)
            break;
      }

      if (cie_local->augmentationString[0] == 'z')
         AUGMENTATION_DATA_PRESENT = true;
      cie_local->codeAlignFactor = decodeULEB128(i, buffer);
      cie_local->dataAlignFactor = decodeSLEB128(i, buffer);
      cie_local->returnAddressRegister = decodeULEB128(i, buffer);

      if (AUGMENTATION_DATA_PRESENT)
      {
         cie_local->augmentationLength = decodeULEB128(i, buffer);
         /*
          * If 'R' is missing then the fde encoding is 8 bytes absolute pointer
          */
         cie_local->fde_encoding = DW_EH_PE_udata8 | DW_EH_PE_absptr;
         int c = 1;
         while(cie_local->augmentationString[c] != NULL_CHAR)
         {
            switch (cie_local->augmentationString[c])
            {
               case 'R':
                  cie_local->fde_encoding = (char)Util::ReadByte(i, (const char *)buffer);
                  i += sizeof(uint8_t);
                  break;
               case 'L':
                  cie_local->lsda_encoding = (char)Util::ReadByte(i, (const char *)buffer);
                  i += sizeof(uint8_t);
                  break;
               /*
                * There are two arguments in the CIE augmentation data
                * that needs to be read see table I in the header file
                */
               case 'P':
                  cie_local->per_encoding = (char)Util::ReadByte(i, (const char *)buffer);
                  i += sizeof(uint8_t);
                  readPersonalityRoutinePtr(i, cie_local, buffer);
                  break;
            }
            c++;
         }
      }

      /*
       * Skip the rest of the CIE and read all the FDEs after the CIE
       */
      i = cie_local->length + location_length_field;

      for ( ; i < len; f++)
      {
         _FDE fde_p;
         uint64_t can_be_a_cie_location = i;
         fde_p.length = Util::ReadInt(i, (const char *)buffer);
         i += sizeof(uint32_t);

         /*
          * If length = 0 then this is the last CIE
          * OR
          * If length = 0xffffffff then read the next 8 bytes for extended length
          */
         if (fde_p.length == 0)
            break;
         else if (fde_p.length == 0xffffffff)
         {
            fde_p.length = Util::ReadLong(i, (const char *)buffer);
            i += sizeof(uint64_t);
         }
         location_length_field = i;

         fde_p.cie_ptr = Util::ReadInt(i, (const char *)buffer);
         i += sizeof(uint32_t);
         /*
          * If this is a CIE then break and read the CIE
          */
         if (fde_p.cie_ptr == 0)
         {
            i = can_be_a_cie_location;
            break;
         }

         readInitialLocationAndSize(fde_p, i, cie_local->fde_encoding, buffer);

         if ((cie_local->fde_encoding & 0xF0) == DW_EH_PE_absptr)
         {
            FdeFunctions.push_back( (uint64_t)(fde_p.initialLocation) );
            FdeFunctions.push_back( (uint64_t)(fde_p.initialLocation + fde_p.numberOfBytes) );
         }
         else if ((cie_local->fde_encoding & 0xF0) == DW_EH_PE_datarel)
         {
            FdeFunctions.push_back( (uint64_t)(fde_p.initialLocation + address_frame) );
            FdeFunctions.push_back( (uint64_t)(fde_p.initialLocation + address_frame + fde_p.numberOfBytes) );
         }
         else //if ((cie_local->fde_encoding & 0xF0) == DW_EH_PE_pcrel)
         {
            FdeFunctions.push_back( (uint64_t)(fde_p.initialLocation + fde_p.LOCATION_OF_INITIAL_LOCATION + address_frame) );
            FdeFunctions.push_back( (uint64_t)(fde_p.initialLocation + fde_p.LOCATION_OF_INITIAL_LOCATION + address_frame + fde_p.numberOfBytes) );
         }

         /*
          * Read the LSDA address
          */
         if (AUGMENTATION_DATA_PRESENT)
         {
            fde_p.augmentationLength = decodeULEB128(i, buffer);
            if (fde_p.augmentationLength > 0)
            {
               uint64_t sizeRead = 0; bool needsUpdate = false;
               fde_p.lsdaAddress = readValue(i, cie_local->lsda_encoding, buffer, sizeRead, needsUpdate);
            }
         }
         /*
          *
          * Read the specific CFA instruction to be stored latter for updating.
          * Sample CFA instructions:
          *
          * DW_CFA_advance_loc: 1 to 00400a45
          * DW_CFA_def_cfa_offset: 16
          * DW_CFA_advance_loc: 3 to 00400a48
          * DW_CFA_offset: r6 (rbp) at cfa-16
          * DW_CFA_def_cfa_register: r6 (rbp)
          * DW_CFA_advance_loc: 17 to 00400a59
          * DW_CFA_offset: r3 (rbx) at cfa-32
          * DW_CFA_offset: r12 (r12) at cfa-24
          * DW_CFA_nop
          * DW_CFA_nop
          * DW_CFA_nop
          * DW_CFA_nop
          * DW_CFA_nop
          * DW_CFA_nop
          *
          * The original code has been updated from:
          *
          *  0000000000400a44 <main>:
          *    400a44:	55                   	push   %rbp
          *    400a45:	48 89 e5             	mov    %rsp,%rbp
          *    400a48:	41 54                	push   %r12
          *    400a4a:	53                   	push   %rbx
          *    400a4b:	48 83 ec 10          	sub    $0x10,%rsp
          *    400a4f:	48 bf 00 40 94 52 a3 	mov    $0x3a352944000,%rdi
          *    400a56:	03 00 00
          *    400a59:	e8 42 fe ff ff       	callq  4008a0 <_Znam@plt>
          *    400a5e:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
          *    400a62:	eb 55                	jmp    400ab9 <main+0x75>
          *    400a64:	48 83 fa 01          	cmp    $0x1,%rdx
          *
          * to:
          *
          *  0000000000400a44 <main>:
          *    400a44:	ff 05 02 00 00 00    	incl   0x2(%rip)        # 400a4c <main+0x8>
          *    400a4a:	eb 04                	jmp    400a50 <main+0xc>
          *    400a4c:	00 00                	add    %al,(%rax)
          *    400a4e:	00 00                	add    %al,(%rax)
          *    400a50:	55                   	push   %rbp
          *    400a51:	48 89 e5             	mov    %rsp,%rbp
          *    400a54:	41 54                	push   %r12
          *    400a56:	53                   	push   %rbx
          *    400a57:	48 83 ec 10          	sub    $0x10,%rsp
          *    400a5b:	48 bf 00 40 94 52 a3 	mov    $0x3a352944000,%rdi
          *    400a62:	03 00 00
          *    400a65:	e8 36 fe ff ff       	callq  4008a0 <_Znam@plt>
          *    400a6a:	48 89 45 e8          	mov    %rax,-0x18(%rbp)
          *    400a6e:	eb 55                	jmp    400ac5 <main+0x81>
          *    400a70:	48 83 fa 01          	cmp    $0x1,%rdx
          *
          * The first DW_CFA_advance_loc instruction of each FDE needs to be updated.
          * We add the difference and update the FDE as follows latter in another
          * function in function UpdateFrame():
          *
          * DW_CFA_advance_loc: 13 to 00400a51
          * DW_CFA_def_cfa_offset: 16
          * DW_CFA_advance_loc: 3 to 00400a54
          * DW_CFA_offset: r6 (rbp) at cfa-16
          * DW_CFA_def_cfa_register: r6 (rbp)
          * DW_CFA_advance_loc: 17 to 00400a65
          * DW_CFA_offset: r3 (rbx) at cfa-32
          * DW_CFA_offset: r12 (r12) at cfa-24
          * DW_CFA_nop
          * DW_CFA_nop
          * DW_CFA_nop
          * DW_CFA_nop
          * DW_CFA_nop
          * DW_CFA_nop
          *
          * For more information read the DWARF 3.0 debugging information format.
          * Figure 40 lists the call frame instruction encodings used here.
          *
          */
         fde_p.LOCATION_OF_DW_CFA_advance_loc = 0;
         for ( ; i < (location_length_field + fde_p.length); )
         {
            uint8_t instr = Util::ReadByte(i, (const char *)buffer);
            if ( (instr >> 6) == 0x1 )
            {
               fde_p.value_DW_CFA_advance_loc = instr;
               fde_p.LOCATION_OF_DW_CFA_advance_loc = i;
               i += sizeof(uint8_t);
               break;
            }
            i += sizeof(uint8_t);
         }

         fde.push_back(fde_p);
         i = location_length_field + fde_p.length;
      }

      _cie cie_p;
      cie_p.cie = cie_local;
      cie_p.index_of_functions = f - 1;
      cie_s.push_back(cie_p);
	}
	NumberOfFdeFunctions = f;

	if ( (FdeFunctions.size()/2 != f) && (fde.size() == f) )
	{
      cerr << "Error:EhFrameELF::ReadFrame: Reading FDE Records " << FdeFunctions.size()/2 << " != " << endl;
      cerr << "                                              OR " << fde.size() << " != " << f << endl;
	}

#ifdef __DEBUG__
	Print();
#endif
}

void EhFrameELF::UpdateHdr(uint8_t *buffer, uint64_t len, int64_t offset_to_add, uint64_t old_code_offset, uint64_t old_max_offset,
                           map<uint64_t, uint64_t> *updatedOldAddresses, map<uint64_t, Function> *Functions_Mapped)
{
   uint64_t i = 0, current_pc = 0, new_address = 0, old_address = 0;
   map<uint64_t, uint64_t>::iterator it_u;

	for ( ; i < len; i++)
	{
      //ElfEhFrameHdr.version = Util::ReadByte(i, (const char *)buffer);
      i += sizeof(uint8_t);
      //ElfEhFrameHdr.frame_ptr_enc = Util::ReadByte(i, (const char *)buffer);
      i += sizeof(uint8_t);
      //ElfEhFrameHdr.fde_count_enc = Util::ReadByte(i, (const char *)buffer);
      i += sizeof(uint8_t);
      //ElfEhFrameHdr.table_enc = Util::ReadByte(i, (const char *)buffer);
      i += sizeof(uint8_t);

      if (FRAME_PTR_NEEDS_UPDATING)
      {
         if ((ElfEhFrameHdr.frame_ptr_enc & 0xF0) == DW_EH_PE_absptr)
            old_address = new_address = ElfEhFrameHdr.frame_ptr;
         else if ((ElfEhFrameHdr.frame_ptr_enc & 0xF0) == DW_EH_PE_datarel)
         {
            current_pc = address_hdr;
            old_address = new_address = current_pc + ElfEhFrameHdr.frame_ptr;
         }
         else //if ((ElfEhFrameHdr.frame_ptr_enc & 0xF0) == DW_EH_PE_pcrel)
         {
            current_pc = address_hdr + i;
            old_address = new_address = current_pc + ElfEhFrameHdr.frame_ptr;
         }

         it_u = updatedOldAddresses->find(old_address);
         if (it_u != updatedOldAddresses->end())
         {
            new_address = it_u->second;
            new_address = new_address - (current_pc + offset_to_add);
         }
         else if (old_address >= old_code_offset && old_address < old_max_offset)
            new_address = ElfEhFrameHdr.frame_ptr + offset_to_add;
         else
            new_address = new_address - (current_pc + offset_to_add);

         updateFramePtr(i, ElfEhFrameHdr.frame_ptr_enc, buffer, new_address);
      }
      else
         i += SIZE_OF_FRAME_PTR;
      i += SIZE_OF_FDE_COUNT;
      if (TABLE_NEEDS_UPDATING)
         updateTable(i, ElfEhFrameHdr.frame_ptr_enc, buffer, offset_to_add, old_code_offset, old_max_offset, Functions_Mapped);

      break;
	}
}

void EhFrameELF::UpdateFrame(uint8_t *buffer, uint64_t len, int64_t offset_to_add, uint64_t old_code_offset, uint64_t old_max_offset,
                             map<uint64_t, uint64_t> *updatedOldAddresses, map<uint64_t, Function> *Functions_Mapped)
{
   uint64_t f = 0;
   map<uint64_t, uint64_t>::iterator it_u;
   map<uint64_t, Function>::iterator it_u_fm;

   for (int c = 0; c < (int)cie_s.size(); c++)
   {
      uint64_t i = 0, current_pc = 0, new_address = 0, old_address = 0;
      if (cie_s[c].cie->PER_ROUTINE_PTR_NEEDS_UPDATING)
      {
         i = cie_s[c].cie->LOCATION_OF_PER_ROUTINE_PTR;

         if ((cie_s[c].cie->per_encoding & 0xF0) == DW_EH_PE_absptr)
            old_address = new_address = cie_s[c].cie->per_routine_ptr;
         else if ((cie_s[c].cie->per_encoding & 0xF0) == DW_EH_PE_datarel)
         {
            current_pc = address_frame;
            old_address = new_address = current_pc + cie_s[c].cie->per_routine_ptr;
         }
         else //if ((cie_s[c].cie->per_encoding & 0xF0) == DW_EH_PE_pcrel)
         {
            current_pc = address_frame + i;
            old_address = new_address = current_pc + cie_s[c].cie->per_routine_ptr;
         }

         it_u = updatedOldAddresses->find(old_address);
         if (it_u != updatedOldAddresses->end())
         {
            new_address = it_u->second;
            new_address = new_address - current_pc;
         }
         else if (old_address >= old_code_offset && old_address < old_max_offset)
            new_address = old_address + offset_to_add;
         else
            new_address = old_address - current_pc;

         updatePersonalityRoutinePtr(i, cie_s[c].cie, buffer, new_address);
      }

      for ( ; f < NumberOfFdeFunctions; f++)
      {
         if (f > cie_s[c].index_of_functions)
            break;
         else if (fde[f].INITIAL_LOCATION_NEEDS_UPDATING)
         {
            uint64_t new_size = fde[f].numberOfBytes;
            old_address = new_address = 0;
            current_pc = 0;
            i = fde[f].LOCATION_OF_INITIAL_LOCATION;

            if ((cie_s[c].cie->fde_encoding & 0xF0) == DW_EH_PE_absptr)
               old_address = new_address = fde[f].initialLocation;
            else if ((cie_s[c].cie->fde_encoding & 0xF0) == DW_EH_PE_datarel)
            {
               current_pc = address_frame;
               old_address = new_address = current_pc + fde[f].initialLocation;
            }
            else //if ((cie_s[c].cie->fde_encoding & 0xF0) == DW_EH_PE_pcrel)
            {
               current_pc = address_frame + i;
               old_address = new_address = current_pc + fde[f].initialLocation;
            }

            Function fn;
            it_u_fm = Functions_Mapped->find(old_address);
            if (it_u_fm != Functions_Mapped->end())
            {
               fn = it_u_fm->second;
               // --- NOT IMPLEMENTED ---
//               uint64_t new_start_address = fn.start_address;
//               uint64_t new_end_address = fn.end_address;
//               new_size = new_end_address - new_start_address;

//               if ((ElfEhFrameHdr.table_enc & 0xF0) == DW_EH_PE_absptr)
//                  new_address = new_start_address;
//               else if ((ElfEhFrameHdr.table_enc & 0xF0) == DW_EH_PE_datarel)
//                  new_address = new_start_address - (current_pc + offset_to_add);
//               else //if ((ElfEhFrameHdr.table_enc & 0xF0) == DW_EH_PE_pcrel)
//                  new_address = new_start_address - (current_pc + offset_to_add);
            }
            else
               cerr << "Error:EhFrameELF::UpdateFrame: Unable to find the old_address 0x" << hex << old_address << endl;

            updateInitialLocationAndSize(fde[f], i, cie_s[c].cie->fde_encoding, buffer, new_address, new_size);

            /*
             *
             * Update al the DW_CFA_advance_loc's.
             * See the function ReadFrame() for details.
             *
             */
            if (fde[f].LOCATION_OF_DW_CFA_advance_loc > 0)
            {
               uint8_t instr = fde[f].value_DW_CFA_advance_loc;
               // Last 6 bits are the operand
               uint8_t old_operand = instr & 0x3F;
               // We get the old address by adding the operand with the initial location of the FDE
               old_address = old_address + old_operand;
               it_u = updatedOldAddresses->find(old_address);
               if (it_u != updatedOldAddresses->end())
                  new_address = it_u->second;
               else if (old_address >= old_code_offset && old_address < old_max_offset)
                  new_address = old_address + offset_to_add;

               uint64_t old_diff = old_operand;
               uint64_t new_diff = 0;//new_address - fn.start_address;
               uint64_t diff = new_diff - old_diff;
               uint8_t new_operand = old_operand + diff;
               if (new_operand >= 0x7F)
                  cerr << "Error:EhFrameELF::UpdateFrame: The value of new_operand " << hex << (int)new_operand << " exceeds the upper bound (more than 6 bits)" << endl;
               instr |= new_operand;

               uint64_t loc = fde[f].LOCATION_OF_DW_CFA_advance_loc;
               fde[f].value_DW_CFA_advance_loc = instr;
               Util::WriteByte(fde[f].value_DW_CFA_advance_loc, loc, (char *)buffer);
            }

            /*
             * Update the LSDA address
             */
            fde[f].augmentationLength = decodeULEB128(i, buffer);
            if (fde[f].augmentationLength > 0)
            {
               uint8_t encoding = cie_s[c].cie->lsda_encoding;
               current_pc = 0;
               if ((encoding & 0xF0) == DW_EH_PE_absptr)
                  old_address = new_address = fde[f].lsdaAddress;
               else if ((encoding & 0xF0) == DW_EH_PE_datarel)
               {
                  current_pc = address_frame;
                  old_address = new_address = current_pc + fde[f].lsdaAddress;
               }
               else //if ((encoding & 0xF0) == DW_EH_PE_pcrel)
               {
                  current_pc = address_frame + i;
                  old_address = new_address = current_pc + fde[f].lsdaAddress;
               }

               it_u = updatedOldAddresses->find(old_address);
               if (it_u != updatedOldAddresses->end())
               {
                  new_address = it_u->second;
                  new_address = new_address - current_pc;
               }
               else if (old_address >= old_code_offset && old_address < old_max_offset)
                  new_address = old_address + offset_to_add;
               else
                  new_address = old_address - current_pc;

               fde[f].lsdaAddress = new_address;
               writeValue(fde[f].lsdaAddress, i, encoding, buffer);
            }
         }
      }
   }
}

/*
 * There are different ways to encode the address of the pointer:
 * (1) Absolute pointer - we need to update
 * (2) Relative to the current program counter - we need to update
 * (3) Relative to the beginning of the .eh_frame_hdr - we need to update
 */
uint64_t EhFrameELF::readValue(uint64_t &from, uint8_t encoding, uint8_t *buffer, uint64_t &sizeRead, bool &needsUpdate)
{
   uint64_t value = 0;
   needsUpdate = false;
   if ((encoding & 0xFF) == 0xFF)
   {
      cerr << "Warning:EhFrameELF::readValue: No value present\n";
      return (value);
   }

   uint8_t temp_encoding = encoding & 0x0F;
   switch (temp_encoding)
   {
      case DW_EH_PE_uleb128:
      {
         uint64_t old_from = from;
         value = decodeULEB128(from, buffer);
         sizeRead = from - old_from;
         break;
      }
      case DW_EH_PE_sleb128:
      {
         uint64_t old_from = from;
         value = decodeSLEB128(from, buffer);
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
         cerr << "Warning:EhFrameELF::readValue: No/Bad encoding\n";
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
         cerr << "Warning:EhFrameELF::readValue: No/Bad encoding\n";
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
uint64_t EhFrameELF::writeValue(uint64_t value, uint64_t &from, uint8_t encoding, uint8_t *buffer)
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
         // TO DO Still need to encode ULEB128 / SLEB128 numbers
         cerr << "Warning:EhFrameELF::readFramePtr: Pointer size (16 bytes) not yet implemented\n";
         from += sizeof(uint8_t);
         sizeWritten = sizeof(uint8_t);
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
 * There are different ways to encode the address of the
 * pointer:
 * (1) Absolute pointer - we need to update
 * (2) Relative to the current program counter - we need to update
 * (3) Relative to the beginning of the .eh_frame_hdr - we need to update
 */
void EhFrameELF::readFramePtr(uint64_t &from, uint8_t encoding, uint8_t *buffer)
{
   if ((encoding & 0xFF) == 0xFF)
   {
      cerr << "Warning:EhFrameELF::readFramePtr: No value present\n";
      return;
   }

   uint8_t temp_encoding = encoding & 0x0F;
   switch (temp_encoding)
   {
      case DW_EH_PE_sleb128:
      case DW_EH_PE_uleb128:
         // TO DO Still need to encode ULEB128 / SLEB128 numbers
         cerr << "Warning:EhFrameELF::readFramePtr: Pointer size (16 bytes) not yet implemented\n";
         from += sizeof(uint8_t);
         SIZE_OF_FRAME_PTR = sizeof(uint8_t);
         break;
      case DW_EH_PE_udata2:
      case DW_EH_PE_sdata2:
         ElfEhFrameHdr.frame_ptr = Util::ReadShort(from, (const char*)buffer);
         from += sizeof(uint16_t);
         SIZE_OF_FRAME_PTR = sizeof(uint16_t);
         break;
      case DW_EH_PE_udata4:
      case DW_EH_PE_sdata4:
         ElfEhFrameHdr.frame_ptr = Util::ReadInt(from, (const char*)buffer);
         from += sizeof(uint32_t);
         SIZE_OF_FRAME_PTR = sizeof(uint32_t);
         break;
      case DW_EH_PE_udata8:
      case DW_EH_PE_sdata8:
         ElfEhFrameHdr.frame_ptr = Util::ReadLong(from, (const char*)buffer);
         from += sizeof(uint64_t);
         SIZE_OF_FRAME_PTR = sizeof(uint64_t);
         break;
      default:
         cerr << "Warning:EhFrameELF::readFramePtr: No/Bad encoding\n";
         break;
   }

   encoding = encoding & 0xF0;
   switch(encoding)
   {
      case DW_EH_PE_absptr:
         FRAME_PTR_NEEDS_UPDATING = true;
         break;
      case DW_EH_PE_pcrel:
         FRAME_PTR_NEEDS_UPDATING = true;
         break;
      case DW_EH_PE_datarel:
         FRAME_PTR_NEEDS_UPDATING = true;
         break;
      default:
         cerr << "Warning:EhFrameELF::readFramePtr: No/Bad encoding\n";
         break;
   }
}

void EhFrameELF::readFDECount(uint64_t &from, uint8_t encoding, uint8_t *buffer)
{
   if ((encoding & 0xFF) == 0xFF)
   {
      cerr << "Warning:EhFrameELF::readFDECount: No value present\n";
      return;
   }

   encoding = encoding & 0x0F;
   switch (encoding)
   {
      case DW_EH_PE_omit:
         cerr << "Warning:EhFrameELF::readFDECount: No value present\n";
         break;
      case DW_EH_PE_sleb128:
      case DW_EH_PE_uleb128:
         // TO DO Still need to encode ULEB128 / SLEB128 numbers
         cerr << "Warning:EhFrameELF::readFDECount: Pointer size (16 bytes) not yet implemented\n";
         from += sizeof(uint8_t);
         SIZE_OF_FDE_COUNT = sizeof(uint8_t);
         break;
      case DW_EH_PE_udata2:
      case DW_EH_PE_sdata2:
         ElfEhFrameHdr.fde_count = Util::ReadShort(from, (const char*)buffer);
         from += sizeof(uint16_t);
         SIZE_OF_FDE_COUNT = sizeof(uint16_t);
         break;
      case DW_EH_PE_udata4:
      case DW_EH_PE_sdata4:
         ElfEhFrameHdr.fde_count = Util::ReadInt(from, (const char*)buffer);
         from += sizeof(uint32_t);
         SIZE_OF_FDE_COUNT = sizeof(uint32_t);
         break;
      case DW_EH_PE_udata8:
      case DW_EH_PE_sdata8:
         ElfEhFrameHdr.fde_count = Util::ReadLong(from, (const char*)buffer);
         from += sizeof(uint64_t);
         SIZE_OF_FDE_COUNT = sizeof(uint64_t);
         break;
      default:
         cerr << "Warning:EhFrameELF::readFDECount: No/Bad encoding\n";
         break;
   }
}

/*
 * The table contains the FDE information. The initial location and
 * the address.
 * There are different ways to encode the address of these entries:
 * (1) Absolute pointer - we need to update
 * (2) Relative to the current program counter - we need to update
 * (3) Relative to the beginning of the .eh_frame_hdr - we need to update
 */
void EhFrameELF::readTable(uint64_t &from, uint8_t encoding, uint8_t *buffer)
{
   if ((encoding & 0xFF) == 0xFF)
   {
      cerr << "Warning:EhFrameELF::readTable: No value present\n";
      return;
   }

   uint8_t temp_encoding = encoding & 0xF0;
   switch (temp_encoding)
   {
      case DW_EH_PE_absptr:
         TABLE_NEEDS_UPDATING = true;
         break;
      case DW_EH_PE_pcrel:
         TABLE_NEEDS_UPDATING = true;
         break;
      case DW_EH_PE_datarel:
         TABLE_NEEDS_UPDATING = true;
         break;
      default:
         cerr << "Warning:EhFrameELF::readFramePtr: No/Bad encoding\n";
         break;
   }

   encoding = encoding & 0x0F;
   switch(encoding)
   {
      case DW_EH_PE_sleb128:
      case DW_EH_PE_uleb128:
      // TO DO Still need to encode ULEB128 / SLEB128 numbers
         cerr << "Warning:EhFrameELF::readTable: Pointer size (16 bytes) not yet implemented\n";
         from += sizeof(uint8_t);
         SIZE_OF_FDE_ADDRESS_IN_TABLE = sizeof(uint8_t);
         break;
      case DW_EH_PE_udata2:
      case DW_EH_PE_sdata2:
      {
         int16_t *table = new int16_t[ElfEhFrameHdr.fde_count*2];
         for (int i = 0 ; i < (int)ElfEhFrameHdr.fde_count*2; i += 2)
         {
            table[i] = Util::ReadShort(from, (const char*)buffer);
            from += sizeof(int32_t);
            table[i+1] = Util::ReadShort(from, (const char*)buffer);
            from += sizeof(int16_t);
         }
         ElfEhFrameHdr.table = (void *)table;
         SIZE_OF_FDE_ADDRESS_IN_TABLE = sizeof(int16_t);
         break;
      }
      case DW_EH_PE_udata4:
      case DW_EH_PE_sdata4:
      {
         int32_t *table = new int32_t[ElfEhFrameHdr.fde_count*2];
         for (int i = 0 ; i < (int)ElfEhFrameHdr.fde_count*2; i += 2)
         {
            table[i] = Util::ReadInt(from, (const char*)buffer);
            from += sizeof(int32_t);
            table[i+1] = Util::ReadInt(from, (const char*)buffer);
            from += sizeof(int32_t);
         }
         ElfEhFrameHdr.table = (void *)table;
         SIZE_OF_FDE_ADDRESS_IN_TABLE = sizeof(int32_t);
         break;
      }
      case DW_EH_PE_udata8:
      case DW_EH_PE_sdata8:
      {
         int64_t *table = new int64_t[ElfEhFrameHdr.fde_count*2];
         for (int i = 0 ; i < (int)ElfEhFrameHdr.fde_count*2; i += 2)
         {
            table[i] = Util::ReadLong(from, (const char*)buffer);
            from += sizeof(int32_t);
            table[i+1] = Util::ReadLong(from, (const char*)buffer);
            from += sizeof(int64_t);
         }
         ElfEhFrameHdr.table = (void *)table;
         SIZE_OF_FDE_ADDRESS_IN_TABLE = sizeof(int64_t);
         break;
      }
      default:
         cerr << "Warning:EhFrameELF::readTable: No/Bad encoding\n";
         break;
   }
}

void EhFrameELF::readPersonalityRoutinePtr(uint64_t &from, _CIE *cie_p, uint8_t *buffer)
{
   if ((cie_p->per_encoding & 0xFF) == 0xFF)
   {
      cerr << "Warning:EhFrameELF::readPersonalityRoutinePtr: No value present\n";
      return;
   }

   cie_p->LOCATION_OF_PER_ROUTINE_PTR = from;
   uint8_t temp_encoding = cie_p->per_encoding & 0x0F;
   switch (temp_encoding)
   {
      case DW_EH_PE_sleb128:
      case DW_EH_PE_uleb128:
         // TO DO Still need to encode ULEB128 / SLEB128 numbers
         cerr << "Warning:EhFrameELF::readPersonalityRoutinePtr: Pointer size (16 bytes) not yet implemented\n";
         from += sizeof(uint8_t);
         SIZE_OF_PER_ROUTINE_PTR = sizeof(uint8_t);
         break;
      case DW_EH_PE_udata2:
      case DW_EH_PE_sdata2:
         cie_p->per_routine_ptr = Util::ReadShort(from, (const char*)buffer);
         from += sizeof(uint16_t);
         SIZE_OF_PER_ROUTINE_PTR = sizeof(uint16_t);
         break;
      case DW_EH_PE_udata4:
      case DW_EH_PE_sdata4:
         cie_p->per_routine_ptr = Util::ReadInt(from, (const char*)buffer);
         from += sizeof(uint32_t);
         SIZE_OF_PER_ROUTINE_PTR = sizeof(uint32_t);
         break;
      case DW_EH_PE_udata8:
      case DW_EH_PE_sdata8:
         cie_p->per_routine_ptr = Util::ReadLong(from, (const char*)buffer);
         from += sizeof(uint64_t);
         SIZE_OF_PER_ROUTINE_PTR = sizeof(uint64_t);
         break;
      default:
         cerr << "Warning:EhFrameELF::readPersonalityRoutinePtr: No/Bad encoding\n";
         break;
   }

   temp_encoding = cie_p->per_encoding & 0xF0;
   switch(temp_encoding)
   {
      case DW_EH_PE_absptr:
         cie_p->PER_ROUTINE_PTR_NEEDS_UPDATING = true;
         break;
      case DW_EH_PE_pcrel:
         cie_p->PER_ROUTINE_PTR_NEEDS_UPDATING = true;
         break;
      case DW_EH_PE_datarel:
         cie_p->PER_ROUTINE_PTR_NEEDS_UPDATING = false;
         break;
      default:
         cerr << "Warning:EhFrameELF::readPersonalityRoutinePtr: No/Bad encoding\n";
         break;
   }
}

void EhFrameELF::readInitialLocationAndSize(_FDE &fde_p, uint64_t &from, uint8_t encoding, uint8_t *buffer)
{
   if ((encoding & 0xFF) == 0xFF)
   {
      cerr << "Warning:EhFrameELF::readInitialLocationAndSize: No value present\n";
      return;
   }

   fde_p.LOCATION_OF_INITIAL_LOCATION = from;
   uint8_t temp_encoding = encoding & 0x0F;
   switch (temp_encoding)
   {
      case DW_EH_PE_sleb128:
      case DW_EH_PE_uleb128:
         // TO DO Still need to encode ULEB128 / SLEB128 numbers
         cerr << "Warning:EhFrameELF::readInitialLocationAndSize: Pointer size (16 bytes) not yet implemented\n";
         from += sizeof(uint8_t);
         SIZE_OF_INITIAL_LOCATION_PTR = sizeof(uint8_t);
         break;
      case DW_EH_PE_udata2:
      case DW_EH_PE_sdata2:
         fde_p.initialLocation = Util::ReadShort(from, (const char*)buffer);
         from += sizeof(uint16_t);
         fde_p.numberOfBytes = Util::ReadShort(from, (const char*)buffer);
         from += sizeof(uint16_t);
         SIZE_OF_INITIAL_LOCATION_PTR = sizeof(uint16_t);
         break;
      case DW_EH_PE_udata4:
      case DW_EH_PE_sdata4:
         fde_p.initialLocation = Util::ReadInt(from, (const char*)buffer);
         from += sizeof(uint32_t);
         fde_p.numberOfBytes = Util::ReadInt(from, (const char*)buffer);
         from += sizeof(uint32_t);
         SIZE_OF_INITIAL_LOCATION_PTR = sizeof(uint32_t);
         break;
      case DW_EH_PE_udata8:
      case DW_EH_PE_sdata8:
         fde_p.initialLocation = Util::ReadLong(from, (const char*)buffer);
         from += sizeof(uint64_t);
         fde_p.numberOfBytes = Util::ReadLong(from, (const char*)buffer);
         from += sizeof(uint64_t);
         SIZE_OF_INITIAL_LOCATION_PTR = sizeof(uint64_t);
         break;
      default:
         cerr << "Warning:EhFrameELF::readInitialLocationAndSize: No/Bad encoding\n";
         break;
   }

   encoding = encoding & 0xF0;
   switch(encoding)
   {
      case DW_EH_PE_absptr:
         fde_p.INITIAL_LOCATION_NEEDS_UPDATING = true;
         break;
      case DW_EH_PE_pcrel:
         fde_p.INITIAL_LOCATION_NEEDS_UPDATING = true;
         break;
      case DW_EH_PE_datarel:
         fde_p.INITIAL_LOCATION_NEEDS_UPDATING = false;
         break;
      default:
         cerr << "Warning:EhFrameELF::readInitialLocationAndSize: No/Bad encoding\n";
         break;
   }
}

/*
 * The frame_ptr to the start fo the .eh_frame section
 * needs to be updated if the start of .eh_frame section
 * changes.
 */
void EhFrameELF::updateFramePtr(uint64_t &from, uint8_t encoding, uint8_t *buffer, uint64_t new_address)
{
   if ((encoding & 0xFF) == 0xFF)
   {
      cerr << "Warning:EhFrameELF::updateFramePtr: No value present\n";
      return;
   }

   if (FRAME_PTR_NEEDS_UPDATING)
   {
      ElfEhFrameHdr.frame_ptr = new_address;
      encoding = encoding & 0x0F;
      switch (encoding)
      {
         case DW_EH_PE_sleb128:
         case DW_EH_PE_uleb128:
         // TO DO Still need to encode ULEB128 / SLEB128 numbers
            cerr << "Warning:EhFrameELF::updateFramePtr: Pointer size (16 bytes) not yet implemented\n";
            break;
         case DW_EH_PE_udata2:
         case DW_EH_PE_sdata2:
            Util::WriteShort(ElfEhFrameHdr.frame_ptr, from, (char*)buffer);
            from += sizeof(uint16_t);
            break;
         case DW_EH_PE_udata4:
         case DW_EH_PE_sdata4:
            Util::WriteInt(ElfEhFrameHdr.frame_ptr, from, (char*)buffer);
            from += sizeof(uint32_t);
            break;
         case DW_EH_PE_udata8:
         case DW_EH_PE_sdata8:
            Util::WriteLong(ElfEhFrameHdr.frame_ptr, from, (char*)buffer);
            from += sizeof(uint64_t);
            break;
         default:
            cerr << "Warning:EhFrameELF::updateFramePtr: No/Bad encoding\n";
            break;
      }
   }
}

void EhFrameELF::updateTableFDERecord(EhFrameELF::_FDERecord &fdeRecord, uint64_t from, uint64_t offset_to_add,
                                      uint64_t old_code_offset, uint64_t old_max_offset,
                                      map<uint64_t, Function> *Functions_Mapped)
{
   map<uint64_t, Function>::iterator it_u;
   uint64_t current_pc = 0, new_address = 0, old_address = 0;

   if ((ElfEhFrameHdr.table_enc & 0xF0) == DW_EH_PE_absptr)
   {
      old_address = new_address = fdeRecord.initialLocation;
      if (fdeRecord.address >= old_code_offset && fdeRecord.address < (int)old_max_offset)
         fdeRecord.address += offset_to_add;
   }
   else if ((ElfEhFrameHdr.table_enc & 0xF0) == DW_EH_PE_datarel)
   {
      current_pc = address_hdr;
      old_address = new_address = current_pc + fdeRecord.initialLocation;
   }
   else //if ((ElfEhFrameHdr.table_enc & 0xF0) == DW_EH_PE_pcrel)
   {
      current_pc = address_hdr + from;
      old_address = new_address = current_pc + fdeRecord.initialLocation;
   }

   it_u = Functions_Mapped->find(old_address);
   if (it_u != Functions_Mapped->end())
   {
      Function fn = it_u->second;
      // --- NOT IMPLEMENTED ---
//      if ((ElfEhFrameHdr.table_enc & 0xF0) == DW_EH_PE_absptr)
//         new_address = fn.start_address;
//      else if ((ElfEhFrameHdr.table_enc & 0xF0) == DW_EH_PE_datarel)
//         new_address = fn.start_address - (current_pc + offset_to_add);
//      else //if ((ElfEhFrameHdr.table_enc & 0xF0) == DW_EH_PE_pcrel)
//         new_address = fn.start_address - (current_pc + offset_to_add);
   }
   else
      cerr << "Error:EhFrameELF::updateTableFDERecord: Unable to find the old_address " << hex << old_address << endl;

   fdeRecord.initialLocation = new_address;
}

void EhFrameELF::updateTable(uint64_t &from, uint8_t encoding, uint8_t *buffer, uint64_t offset_to_add,
                                      uint64_t old_code_offset, uint64_t old_max_offset,
                                      map<uint64_t, Function> *Functions_Mapped)
{
   if (TABLE_NEEDS_UPDATING)
   {
      _FDERecord fdeRecord;
      if (SIZE_OF_FDE_ADDRESS_IN_TABLE == sizeof(int16_t))
      {
         int16_t *table_i = (int16_t *)ElfEhFrameHdr.table;

         for (int i = 0; i < (int)ElfEhFrameHdr.fde_count*2; i += 2)
         {
            fdeRecord.initialLocation = table_i[i]; fdeRecord.address = table_i[i+1];
            updateTableFDERecord(fdeRecord, from, offset_to_add, old_code_offset, old_max_offset, Functions_Mapped);
            Util::WriteShort(fdeRecord.initialLocation, from, (char*)buffer);
            from += sizeof(uint16_t);
            Util::WriteShort(fdeRecord.address, from, (char*)buffer);
            from += sizeof(uint16_t);
         }
      }
      else if (SIZE_OF_FDE_ADDRESS_IN_TABLE == sizeof(int32_t))
      {
         int32_t *table_i = (int32_t *)ElfEhFrameHdr.table;
         for (int i = 0; i < (int)ElfEhFrameHdr.fde_count*2; i += 2)
         {
            fdeRecord.initialLocation = table_i[i]; fdeRecord.address = table_i[i+1];
            updateTableFDERecord(fdeRecord, from, offset_to_add, old_code_offset, old_max_offset, Functions_Mapped);
            Util::WriteInt(fdeRecord.initialLocation, from, (char*)buffer);
            from += sizeof(uint32_t);
            Util::WriteInt(fdeRecord.address, from, (char*)buffer);
            from += sizeof(uint32_t);
         }
      }
      else if (SIZE_OF_FDE_ADDRESS_IN_TABLE == sizeof(int64_t))
      {
         int64_t *table_i = (int64_t *)ElfEhFrameHdr.table;
         for (int i = 0; i < (int)ElfEhFrameHdr.fde_count*2; i += 2)
         {
            fdeRecord.initialLocation = table_i[i]; fdeRecord.address = table_i[i+1];
            updateTableFDERecord(fdeRecord, from, offset_to_add, old_code_offset, old_max_offset, Functions_Mapped);
            Util::WriteLong(fdeRecord.initialLocation, from, (char*)buffer);
            from += sizeof(uint64_t);
            Util::WriteLong(fdeRecord.address, from, (char*)buffer);
            from += sizeof(uint64_t);
         }
      }
   }
}

void EhFrameELF::updatePersonalityRoutinePtr(uint64_t &from, _CIE *cie_p, uint8_t *buffer, uint64_t new_address)
{
   if ((cie_p->per_encoding & 0xFF) == 0xFF)
   {
      cerr << "Warning:EhFrameELF::updatePersonalityRoutinePtr: No value present\n";
      return;
   }

   if (cie_p->PER_ROUTINE_PTR_NEEDS_UPDATING)
   {
      cie_p->per_routine_ptr = new_address;
      uint8_t encoding = cie_p->per_encoding & 0x0F;
      switch (encoding)
      {
         case DW_EH_PE_sleb128:
         case DW_EH_PE_uleb128:
         // TO DO Still need to encode ULEB128 / SLEB128 numbers
            cerr << "Warning:EhFrameELF::updatePersonalityRoutinePtr: Pointer size (16 bytes) not yet implemented\n";
            break;
         case DW_EH_PE_udata2:
         case DW_EH_PE_sdata2:
            Util::WriteShort(cie_p->per_routine_ptr, from, (char*)buffer);
            from += sizeof(uint16_t);
            break;
         case DW_EH_PE_udata4:
         case DW_EH_PE_sdata4:
            Util::WriteInt(cie_p->per_routine_ptr, from, (char*)buffer);
            from += sizeof(uint32_t);
            break;
         case DW_EH_PE_udata8:
         case DW_EH_PE_sdata8:
            Util::WriteLong(cie_p->per_routine_ptr, from, (char*)buffer);
            from += sizeof(uint64_t);
            break;
         default:
            cerr << "Warning:EhFrameELF::updatePersonalityRoutinePtr: No/Bad encoding\n";
            break;
      }
   }
}

void EhFrameELF::updateInitialLocationAndSize(_FDE &fde_p, uint64_t &from, uint8_t encoding, uint8_t *buffer,
                                                      uint64_t new_address, uint64_t new_size)
{
   if ((encoding & 0xFF) == 0xFF)
   {
      cerr << "Warning:EhFrameELF::updateInitialLocation: No value present\n";
      return;
   }

   if (fde_p.INITIAL_LOCATION_NEEDS_UPDATING)
   {
      fde_p.initialLocation = new_address;
      fde_p.numberOfBytes = new_size;
      encoding = encoding & 0x0F;
      switch (encoding)
      {
         case DW_EH_PE_sleb128:
         case DW_EH_PE_uleb128:
         // TO DO Still need to encode ULEB128 / SLEB128 numbers
            cerr << "Warning:EhFrameELF::updateInitialLocation: Pointer size (16 bytes) not yet implemented\n";
            break;
         case DW_EH_PE_udata2:
         case DW_EH_PE_sdata2:
            Util::WriteShort(fde_p.initialLocation, from, (char*)buffer);
            from += sizeof(uint16_t);
            Util::WriteShort(fde_p.numberOfBytes, from, (char*)buffer);
            from += sizeof(uint16_t);
            break;
         case DW_EH_PE_udata4:
         case DW_EH_PE_sdata4:
            Util::WriteInt(fde_p.initialLocation, from, (char*)buffer);
            from += sizeof(uint32_t);
            Util::WriteInt(fde_p.numberOfBytes, from, (char*)buffer);
            from += sizeof(uint32_t);
            break;
         case DW_EH_PE_udata8:
         case DW_EH_PE_sdata8:
            Util::WriteLong(fde_p.initialLocation, from, (char*)buffer);
            from += sizeof(uint64_t);
            Util::WriteLong(fde_p.numberOfBytes, from, (char*)buffer);
            from += sizeof(uint64_t);
            break;
         default:
            cerr << "Warning:EhFrameELF::updateInitialLocation: No/Bad encoding\n";
            break;
      }
   }
}

/*
 * Decode ULEB128
 * The algorithm is listed in the DWARF standard:
 * Figure 46 DWARF Debugging Information Format Version 3, 2005
 * http://dwarfstd.org/doc/Dwarf3.pdf
 */
uint64_t EhFrameELF::decodeULEB128(uint64_t &from, uint8_t *buffer)
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
int64_t EhFrameELF::decodeSLEB128(uint64_t &from, uint8_t *buffer)
{
   uint64_t result = 0;
   uint64_t shift = 0;
   uint64_t size = 0;
   uint8_t byte = 0;

   do
   {
      byte = Util::ReadByte(from, (const char*)buffer);
      from += sizeof(uint8_t);
      size += 8;
      result |= (uint64_t)( (byte & 0x7f) << shift );
      shift += 7;
   }
   while(byte & 0x80);

   if ( (shift < size) && (byte & 0x40) )
      result |= (uint64_t)( -(1 << shift) );

   return (result);
}

void EhFrameELF::Print()
{
   cout << "|---------------------------------------------------------|\n";
   cout << "|                                                         |\n";
   cout << "|             PRINTING  EH  FRAME  HEADER                 |\n";
   cout << "|                                                         |\n";
   cout << "|---------------------------------------------------------|\n";
   cout << "Version:   " << dec << (int)ElfEhFrameHdr.version << endl;
   cout << "Frame Pointer Encoding:   0x" << hex << (int)ElfEhFrameHdr.frame_ptr_enc << endl;
   cout << "FDE Count Encoding:   0x" << hex << (int)ElfEhFrameHdr.fde_count_enc << endl;
   cout << "Table Encoding:   0x" << hex << (int)ElfEhFrameHdr.table_enc << endl;
   cout << "Address of the Start of the .eh_frame Section:   0x" << hex << (int)ElfEhFrameHdr.frame_ptr << endl;
   cout << "Number of FDE Records:   " << dec << (int)ElfEhFrameHdr.fde_count << endl;

   /*
    * We only read table if it needs updating
    */
   cout << "-----------------------------------\n";
   cout << "       Table of FDE Records        \n";
   cout << "-----------------------------------\n";
   cout << " Count   Initial Location   Address\n";
   cout << "              Start                \n";
   if (TABLE_NEEDS_UPDATING)
   {
      uint64_t to_add = 0;

      if ((ElfEhFrameHdr.table_enc & 0xF0) == DW_EH_PE_absptr)
         to_add = 0;
      else if ((ElfEhFrameHdr.table_enc & 0xF0) == DW_EH_PE_datarel)
         to_add = address_hdr;

      if (SIZE_OF_FDE_ADDRESS_IN_TABLE == sizeof(int16_t))
      {
         int16_t *table_i = (int16_t *)ElfEhFrameHdr.table;

         for (int i = 0; i < (int)ElfEhFrameHdr.fde_count*2; i += 2)
         {
            if ((ElfEhFrameHdr.table_enc & 0xF0) == DW_EH_PE_pcrel)
               to_add = address_hdr + i;
            cout << dec << setw(5) << i/2 << hex << setw(16) << ((int)table_i[i]+to_add) << setw(14) << ((int)table_i[i+1]+to_add) << endl;
         }
      }
      else if (SIZE_OF_FDE_ADDRESS_IN_TABLE == sizeof(int32_t))
      {
         int32_t *table_i = (int32_t *)ElfEhFrameHdr.table;
         for (int i = 0; i < (int)ElfEhFrameHdr.fde_count*2; i += 2)
         {
            if ((ElfEhFrameHdr.table_enc & 0xF0) == DW_EH_PE_pcrel)
               to_add = address_hdr + i;
            cout << dec << setw(5) << i/2 << hex << setw(16) << ((int)table_i[i]+to_add) << setw(14) << ((int)table_i[i+1]+to_add) << endl;
         }
      }
      else if (SIZE_OF_FDE_ADDRESS_IN_TABLE == sizeof(int64_t))
      {
         int64_t *table_i = (int64_t *)ElfEhFrameHdr.table;
         for (int i = 0; i < (int)ElfEhFrameHdr.fde_count*2; i += 2)
         {
            if ((ElfEhFrameHdr.table_enc & 0xF0) == DW_EH_PE_pcrel)
               to_add = address_hdr + i;
            cout << dec << setw(5) << i/2 << hex << setw(16) << ((int)table_i[i]+to_add) << setw(14) << ((int)table_i[i+1]+to_add) << endl;
         }
      }
      else
         cout << "Error:EhFrameELF::Print: Printing the Table. Wrong Encoding or Size not Supported";
      cout << endl;
   }

   cout << "|---------------------------------------------------------|\n";
   cout << "|                                                         |\n";
   cout << "|                   PRINTING  EH  FRAME                   |\n";
   cout << "|                                                         |\n";
   cout << "|---------------------------------------------------------|\n";

   uint64_t f = 0;
   for (int c = 0; c < (int)cie_s.size(); c++)
   {
      cout << "|--------------------------------------------------------------------------------------------------------------------------------|\n";
      cout << "|                                                      PRINTING     CIE                                                          |\n";
      cout << "|--------------------------------------------------------------------------------------------------------------------------------|\n";

      cout << "  ID Version  Length  Augmentation  Code Align  Data Align  Return   Augmentation   FDE       LSDA      PER         PER     PER   \n";
      cout << "              (bytes)    String       Factor      Factor    Register    Length    Encoding  Encoding  Encoding    Pointer  Update \n";
      cout << "----------------------------------------------------------------------------------------------------------------------------------\n\n";
      cout << dec << setw(3) << (int)cie_s[c].cie->id << setw(7) << (int)cie_s[c].cie->version << setw(10) << (int)cie_s[c].cie->length;
      cout << setw(12) << cie_s[c].cie->augmentationString << setw(10) << cie_s[c].cie->codeAlignFactor << setw(12) << cie_s[c].cie->dataAlignFactor;
      cout << setw(10) << "R" << cie_s[c].cie->returnAddressRegister << setw(10) << (int)cie_s[c].cie->augmentationLength;
      cout << hex << setw(12) << (int)cie_s[c].cie->fde_encoding << setw(10) << (int)cie_s[c].cie->lsda_encoding << setw(10) << (int)cie_s[c].cie->per_encoding;
      cout << setw(13) << (int)cie_s[c].cie->per_routine_ptr << setw(7) << cie_s[c].cie->PER_ROUTINE_PTR_NEEDS_UPDATING << endl;
      cout << endl;

      cout << "|----------------------------------------------------------------|\n";
      cout << "|                          PRINTING  FDEs                        |\n";
      cout << "|----------------------------------------------------------------|\n";

      cout << "  Count  Length       CIE    Initial            Address          \n";
      cout << "         (bytes)    Pointer  Location    Start    -->    End     \n";
      cout << "                             Update                              \n";
      cout << "-----------------------------------------------------------------\n\n";
      for ( ; f < NumberOfFdeFunctions; f++)
      {
         if (f > cie_s[c].index_of_functions)
            break;
         cout << dec << setw(6) << f << hex << setw(8) << (int)fde[f].length << hex << setw(10) << (int)fde[f].cie_ptr;
         cout << dec << setw(8) << fde[f].INITIAL_LOCATION_NEEDS_UPDATING;
         if ((cie_s[c].cie->fde_encoding & 0xF0) == DW_EH_PE_absptr)
         {
            cout << hex << setw(15) << (int)( fde[f].initialLocation );
            cout << setw(14) << (int)( fde[f].initialLocation + fde[f].numberOfBytes ) << endl;
         }
         else if ((cie_s[c].cie->fde_encoding & 0xF0) == DW_EH_PE_datarel)
         {
            cout << hex << setw(15) << (int)( fde[f].initialLocation + address_frame);
            cout << setw(14) << (int)( fde[f].initialLocation + address_frame + fde[f].numberOfBytes ) << endl;
         }
         else //if ((cie_s[c].cie->fde_encoding & 0xF0) == DW_EH_PE_pcrel)
         {
            cout << hex << setw(15) << (int)( fde[f].initialLocation + fde[f].LOCATION_OF_INITIAL_LOCATION + address_frame );
            cout << setw(14) << (int)( fde[f].initialLocation + fde[f].LOCATION_OF_INITIAL_LOCATION + address_frame + fde[f].numberOfBytes ) << endl;
         }
      }
   }
}
