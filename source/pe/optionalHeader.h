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

#ifndef __OPTIONAL_HEADER_H__
#define __OPTIONAL_HEADER_H__

#include <iostream>
#include <stdint.h>

using namespace std;

#define PE_64_MAGIC_NUMBER		0x020B
#define PE_32_MAGIC_NUMBER		0x010B

/*
 * Windows Subsystems
 */
#define IMAGE_SUBSYSTEM_UNKNOWN					0	// An unknown subsystem
#define IMAGE_SUBSYSTEM_NATIVE					1	// Device drivers and native Windows processes
#define IMAGE_SUBSYSTEM_WINDOWS_GUI				2	// The Windows graphical user interface (GUI) subsystem
#define IMAGE_SUBSYSTEM_WINDOWS_CUI				3	// The Windows character subsystem
#define IMAGE_SUBSYSTEM_POSIX_CUI				7	// The Posix character subsystem
#define IMAGE_SUBSYSTEM_WINDOWS_CE_GUI			9	// Windows CE
#define IMAGE_SUBSYSTEM_EFI_APPLICATION			10	// An Extensible Firmware Interface (EFI) application
#define IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER	11	// An EFI driver with boot services
#define IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER		12	// An EFI driver with run-time services
#define IMAGE_SUBSYSTEM_EFI_ROM					13	// An EFI ROM image
#define IMAGE_SUBSYSTEM_XBOX					14	// XBOX

/*
 * DLL Characteristics
 */
#define RESERVED_1										0x0001	// Reserved, must be zero.
#define RESERVED_2										0x0002	// Reserved, must be zero.
#define RESERVED_3										0x0004	// Reserved, must be zero.
#define RESERVED_4										0x0008	// Reserved, must be zero.
#define IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE			0x0040	// DLL can be relocated at load time.
#define IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY		0x0080	// Code Integrity checks are enforced.
#define IMAGE_DLL_CHARACTERISTICS_NX_COMPAT				0x0100	// Image is NX compatible.
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION			0x0200	// Isolation aware, but do not isolate the image.
#define IMAGE_DLLCHARACTERISTICS_NO_SEH					0x0400	// Does not use structured exception (SE) handling. No SE handler may
																// be called in this image.
#define IMAGE_DLLCHARACTERISTICS_NO_BIND				0x0800	// Do not bind the image.
#define RESERVED_5										0x1000	// Reserved, must be zero.
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER				0x2000	// A WDM driver.
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE	0x8000	// Terminal Server aware.

/**
 * <p>
 * This class implements the OptionalHeader class.
 * It stores the Optional header as defined in:
 * http://msdn.microsoft.com/en-us/windows/hardware/gg463119.aspx
 * </p>
 *
 * @author Shahid Alam
 * @version 1.0
 * @since March 04, 2013
 *
 */
class OptionalHeader
{
public:
	uint32_t length;
	bool isPE64, isPE32, isROM;
	uint16_t Magic;                    // 2 bytes The unsigned integer that identifies the state of the image file. The most common number is 0x10B, which identifies it as a normal executable file. 0x107 identifies it as a ROM image, and 0x20B identifies it as a PE32+ executable.
	uint8_t  MajorLinkerVersion;       // 1 byte  The linker major version number.
	uint8_t  MinorLinkerVersion;       // 1 byte  The linker minor version number.
	uint32_t SizeOfCode;               // 4 bytes The size of the code (text) section, or the sum of all code sections if there are multiple sections.
	uint32_t SizeOfInitializedData;    // 4 bytes The size of the initialized data section, or the sum of all such sections if there are multiple data sections.
	uint32_t SizeOfUninitializedData;  // 4 bytes The size of the uninitialized data section (BSS), or the sum of all such sections if there are multiple BSS sections.
	uint32_t AddressOfEntryPoint;      // 4 bytes The address of the entry point relative to the image base when the executable file is loaded into memory. For program images, this is the starting address. For device drivers, this is the address of the initialization function. An entry point is optional for DLLs. When no entry point is present, this field must be zero.
	uint32_t BaseOfCode;               // 4 bytes The address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
	uint32_t BaseOfData;               // 4 bytes The address that is relative to the image base of the beginning-of-data section when it is loaded into memory.
	// Windows additional fields
	uint32_t ImageBase;                    // 4/8 bytes The preferred address of the first byte of image when loaded into memory; must be a multiple of 64 K. The default for DLLs is 0x10000000. The default for Windows CE EXEs is 0x00010000. The default for Windows NT, Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
	uint32_t SectionAlignment;             // 4 bytes The alignment (in bytes) of sections when they are loaded into memory. It must be greater than or equal to FileAlignment. The default is the page size for the architecture.
	uint32_t FileAlignment;                // 4 bytes The alignment factor (in bytes) that is used to align the raw data of sections in the image file. The value should be a power of 2 between 512 and 64 K, inclusive. The default is 512. If the SectionAlignment is less than the architecture’s page size, then FileAlignment must match SectionAlignment.
	uint16_t MajorOperatingSystemVersion;  // 2 bytes The major version number of the required operating system.
	uint16_t MinorOperatingSystemVersion;  // 2 bytes The minor version number of the required operating system.
	uint16_t MajorImageVersion;            // 2 bytes The major version number of the image.
	uint16_t MinorImageVersion;            // 2 bytes The minor version number of the image.
	uint16_t MajorSubsystemVersion;        // 2 bytes The major version number of the subsystem.
	uint16_t MinorSubsystemVersion;        // 2 bytes The minor version number of the subsystem.
	uint32_t Win32VersionValue;            // 4 bytes Reserved, must be zero.
	uint32_t SizeOfImage;                  // 4 bytes The size (in bytes) of the image, including all headers, as the image is loaded in memory. It must be a multiple of SectionAlignment.
	uint32_t SizeOfHeaders;                // 4 bytes The combined size of an MS DOS stub, PE header, and section headers rounded up to a multiple of FileAlignment.
	uint32_t CheckSum;                     // 4 bytes The image file checksum. The algorithm for computing the checksum is incorporated into IMAGHELP.DLL. The following are checked for validation at load time: all drivers, any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process.
	uint16_t Subsystem;                    // 2 bytes The subsystem that is required to run this image. For more information, see “Windows Subsystem” later in this specification.
	uint16_t DllCharacteristics;           // 2 bytes For more information, see “DLL Characteristics” later in this specification.
	uint32_t SizeOfStackReserve;           // 4/8 bytes The size of the stack to reserve. Only SizeOfStackCommit is committed; the rest is made available one page at a time until the reserve size is reached.
	uint32_t SizeOfStackCommit;            // 4/8 bytes The size of the stack to commit.
	uint32_t SizeOfHeapReserve;            // 4/8 bytes The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the rest is made available one page at a time until the reserve size is reached.
	uint32_t SizeOfHeapCommit;             // 4/8 bytes The size of the local heap space to commit.
	uint32_t LoaderFlags;                  // 4 bytes Reserved, must be zero.
	uint32_t NumberOfRvaAndSizes;          // 4 bytes The number of data-directory entries in the remainder of the optional header. Each describes a location and size.

	// An 8 byte field. Each data directory gives the address and size of a table or string that Windows uses
	// These data directory entries are all loaded into memory so that the system can use them at run time.
	typedef struct
	{
		uint32_t virtualAddress;
		uint32_t size;
	} _DataDirectory;
	_DataDirectory *DataDirectory;

	void allocateDataDirectory()
	{
		DataDirectory = new _DataDirectory[NumberOfRvaAndSizes];
	}

	void deallocateDataDirectory()
	{
		delete (DataDirectory);
	}

	OptionalHeader()
	{
		length                  = 102;  // 102 bytes
		isPE64                  = false;
		Magic                   = 0;
		MajorLinkerVersion      = 0;
		MinorLinkerVersion      = 0;
		SizeOfCode              = 0;
		SizeOfInitializedData   = 0;
		SizeOfUninitializedData = 0;
		AddressOfEntryPoint     = 0;
		BaseOfCode              = 0;
		BaseOfData              = 0;
	}

	void Print()
	{
		const char *DataDirectoryName[] =
		{
			"Export Table",				// The export table address and size. For more information see section 6.3, “The .edata Section (Image Only).”
			"Import Table",				// The import table address and size. For more information, see section 6.4, “The .idata Section.”
			"Resource Table",			// The resource table address and size. For more information, see section 6.9, “The .rsrc Section.”
			"Exception Table",			// The exception table address and size. For more information, see section 6.5, “The .pdata Section.”
			"Certificate Table",		// The attribute certificate table address and size. For more information, see section 5.7, “The attribute certificate table (Image Only).”
			"Base Relocation Table",	// The base relocation table address and size. For more information, see section 6.6, “The .reloc Section (Image Only).”
			"Debug",					// The debug data starting address and size. For more information, see section 6.1, “The .debug Section.”
			"Architecture",				// Reserved, must be 0 Microsoft Portable Executable and Common Object File Format Specification - 23 160/176 8 Global Ptr The RVA of the value to be stored in the global pointer register. The size member of this structure must be set to zero.
			"TLS Table",				// The thread local storage (TLS) table address and size. For more information, see section 6.7, “The .tls Section.”
			"Load Config Table",		// The load configuration table address and size. For more information, see section 6.8, “The Load Configuration Structure (Image Only).”
			"Bound Import",				// The bound import table address and size.
			"IAT",						// The import address table address and size. For more information, see section 6.4.4, “Import Address Table.”
			"Delay Import Descriptor",	// The delay import descriptor address and size. For more information, see section 5.8, “Delay- Load Import Tables (Image Only).”
			"CLR Runtime Header",		// The CLR runtime header address and size. For more information, see section 6.10, “The .cormeta Section (Object Only).”
			"Reserved",					// must be zero
		};

		printf ("   %s\n", (isPE64 ? "PE64" : "PE32"));
		printf ("   LinkerVersion = 0x%X\n", MajorLinkerVersion);
		printf ("   MinorLinkerVersion = 0x%X\n", MinorLinkerVersion);
		printf ("   SizeOfCode = %d\n", SizeOfCode);
		printf ("   SizeOfInitializedData = %d\n", SizeOfInitializedData);
		printf ("   SizeOfUninitializedData = %d\n", SizeOfUninitializedData);
		printf ("   AddressOfEntryPoint = 0x%X\n", AddressOfEntryPoint);
		printf ("   BaseOfCode = 0x%X\n", BaseOfCode);
		if (isPE32)
			printf ("   BaseOfData = 0x%X\n", BaseOfData);
		printf ("   ImageBase = 0x%X\n", ImageBase);
		printf ("   SectionAlignment = 0x%X\n", SectionAlignment);
		printf ("   FileAlignment = 0x%X\n", FileAlignment);
		printf ("   MajorOperatingSystemVersion = 0x%X\n", MajorOperatingSystemVersion);
		printf ("   MinorOperatingSystemVersion = 0x%X\n", MinorOperatingSystemVersion);
		printf ("   MajorImageVersion = 0x%X\n", MajorImageVersion);
		printf ("   MinorImageVersion = 0x%X\n", MinorImageVersion);
		printf ("   MajorSubsystemVersion = 0x%X\n", MajorSubsystemVersion);
		printf ("   MinorSubsystemVersion = 0x%X\n", MinorSubsystemVersion);
		printf ("   Win32VersionValue = 0x%X\n", Win32VersionValue);
		printf ("   SizeOfImage = 0x%X\n", SizeOfImage);
		printf ("   SizeOfHeaders = 0x%X\n", SizeOfHeaders);
		printf ("   CheckSum = 0x%X\n", CheckSum);
		printf ("   Subsystem = 0x%X\n", Subsystem);
		printf ("   DllCharacteristics = 0x%X\n", DllCharacteristics);
		printf ("   SizeOfStackReserve = 0x%X\n", SizeOfStackReserve);
		printf ("   SizeOfStackCommit = 0x%X\n", SizeOfStackCommit);
		printf ("   SizeOfHeapReserve = 0x%X\n", SizeOfHeapReserve);
		printf ("   SizeOfHeapCommit = 0x%X\n", SizeOfHeapCommit);
		printf ("   LoaderFlags = 0x%X\n\n", LoaderFlags);

		printf ("   Number of data directory entries = %d\n", NumberOfRvaAndSizes);
		for (int i = 0; i < (int)NumberOfRvaAndSizes; i++)
		{
			uint64_t va = 0x0;
			if (DataDirectory[i].virtualAddress > 0)
				va = ImageBase + DataDirectory[i].virtualAddress;
			if (i < 15)
				printf("   %s: virtualAddress = 0x%X size = 0x%X\n", DataDirectoryName[i], (int)va, (int)DataDirectory[i].size);
			else
				printf("   Data Directory # %d: virtualAddress = 0x%X size = 0x%X\n", i, (int)va, (int)DataDirectory[i].size);
		}
	}
};

#endif // __OPTIONAL_HEADER_H__
