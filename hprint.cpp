#include "global.h"
#include "hprint_internal.h"

//Class Function Declarated in "global.h"

int _HEADER_SET::Print_DOS_Header () {
	PIMAGE_DOS_HEADER lv_output = &this->dos_header;
	
	puts("[IMAGE_DOS_HEADER]");
	Print_DOS_Header_Internal(lv_output, e_magic, Print_Magic);
	Print_DOS_Header_Internal(lv_output, e_cblp);
	Print_DOS_Header_Internal(lv_output, e_cp);
	Print_DOS_Header_Internal(lv_output, e_crlc);
	Print_DOS_Header_Internal(lv_output, e_cparhdr);
	Print_DOS_Header_Internal(lv_output, e_minalloc);
	Print_DOS_Header_Internal(lv_output, e_maxalloc);
	Print_DOS_Header_Internal(lv_output, e_ss);
	Print_DOS_Header_Internal(lv_output, e_sp);
	Print_DOS_Header_Internal(lv_output, e_ip);
	Print_DOS_Header_Internal(lv_output, e_cs);
	Print_DOS_Header_Internal(lv_output, e_lfarlc);
	Print_DOS_Header_Internal(lv_output, e_ovno);
	Print_DOS_Header_Internal(lv_output, e_res[0]);
	Print_DOS_Header_Internal(lv_output, e_res[1]);
	Print_DOS_Header_Internal(lv_output, e_res[2]);
	Print_DOS_Header_Internal(lv_output, e_res[3]);
	Print_DOS_Header_Internal(lv_output, e_oemid);
	Print_DOS_Header_Internal(lv_output, e_oeminfo);
	Print_DOS_Header_Internal(lv_output, e_res2[0]);
	Print_DOS_Header_Internal(lv_output, e_res2[1]);
	Print_DOS_Header_Internal(lv_output, e_res2[2]);
	Print_DOS_Header_Internal(lv_output, e_res2[3]);
	Print_DOS_Header_Internal(lv_output, e_res2[4]);
	Print_DOS_Header_Internal(lv_output, e_res2[5]);
	Print_DOS_Header_Internal(lv_output, e_res2[6]);
	Print_DOS_Header_Internal(lv_output, e_res2[7]);
	Print_DOS_Header_Internal(lv_output, e_res2[8]);
	Print_DOS_Header_Internal(lv_output, e_res2[9]);
	Print_DOS_Header_Internal(lv_output, e_lfanew);
	
	puts("\n");
	return 0;
}

int _HEADER_SET::Print_DOS_Stub () {
	PDOS_STUB lv_output = &this->dos_stub;
	char lv_temp[8];
	int lv_count = 0;
	
	printf("[DOS Stub]");
	for (int i = 0; i < (lv_output->Length); i++) {
		lv_temp[lv_count++] = (lv_output->String)[i];
		if (lv_count == 8) {
			Print_DOS_Stub_Internal(lv_temp, lv_count);
			lv_count = 0;
		}
	}
	if (lv_count != 0) {
		Print_DOS_Stub_Internal(lv_temp, lv_count);
	}
	
	puts("\n\n");
	return 0;
}

int _HEADER_SET::Print_NT_Header_Signature () {
	DWORD lv_output = this->nt_header32.Signature;
	
	puts("[IMAGE_NT_HEADERS].Signature");
	printf("0x%08X (", lv_output);
	for (int i = 0; i < sizeof(DWORD); i++) {
		printf("%c", (BYTE)(lv_output >> (i * 8)));
	}
	printf(")");
	
	puts("\n\n");
	return 0;
}

int _HEADER_SET::Print_NT_Header_File () {
	PIMAGE_FILE_HEADER lv_output = &this->nt_header32.FileHeader;
	
	puts("[IMAGE_NT_HEADERS].FileHeader");
	Print_NT_Header_File_Internal(lv_output, Machine, Print_Machine);
	Print_NT_Header_File_Internal(lv_output, NumberOfSections);
	Print_NT_Header_File_Internal(lv_output, TimeDateStamp, Print_DateStamp);
	Print_NT_Header_File_Internal(lv_output, PointerToSymbolTable);
	Print_NT_Header_File_Internal(lv_output, NumberOfSymbols);
	Print_NT_Header_File_Internal(lv_output, SizeOfOptionalHeader);
	Print_NT_Header_File_Internal(lv_output, Characteristics, Print_Characteristics);
	
	puts("\n");
	return 0;
}

int _HEADER_SET::Print_NT_Header_Optional () {
	bool lv_is32 = _32BitCheck(this->nt_header32.FileHeader) ? true : false;
	PIMAGE_OPTIONAL_HEADER64 lv_output = &this->nt_header64.OptionalHeader;
	//32-bit and 64-bit address values are the same
	
	puts("[IMAGE_NT_HEADERS].OptionalHeader");
	Print_NT_Header_Optional_Internal(lv_output, Magic, lv_is32, Print_Magic_Optional);
	Print_NT_Header_Optional_Internal(lv_output, MajorLinkerVersion, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, MinorLinkerVersion, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, SizeOfCode, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, SizeOfInitializedData, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, SizeOfUninitializedData, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, AddressOfEntryPoint, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, BaseOfCode, lv_is32);
	if (lv_is32) { Print_NT_Header_Optional_Internal32(lv_output, BaseOfData); }
	Print_NT_Header_Optional_Internal(lv_output, ImageBase, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, SectionAlignment, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, FileAlignment, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, MajorOperatingSystemVersion, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, MinorOperatingSystemVersion, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, MajorImageVersion, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, MinorImageVersion, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, MajorSubsystemVersion, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, MinorSubsystemVersion, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, Win32VersionValue, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, SizeOfImage, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, SizeOfHeaders, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, CheckSum, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, Subsystem, lv_is32, Print_Subsystem);
	Print_NT_Header_Optional_Internal(lv_output, DllCharacteristics, lv_is32, Print_DllCharacteristics);
	Print_NT_Header_Optional_Internal(lv_output, SizeOfStackReserve, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, SizeOfStackCommit, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, SizeOfHeapReserve, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, SizeOfHeapCommit, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, LoaderFlags, lv_is32);
	Print_NT_Header_Optional_Internal(lv_output, NumberOfRvaAndSizes, lv_is32);
	
	puts("\n");
	return 0;
}

int _HEADER_SET::Print_NT_Header_Optional_DataDirectory () {
	bool lv_is32 = _32BitCheck(this->nt_header32.FileHeader) ? true : false;
	PIMAGE_OPTIONAL_HEADER64 lv_output = &this->nt_header64.OptionalHeader;
	//32-bit and 64-bit address values are the same
	
	puts("[IMAGE_NT_HEADERS].OptionalHeader.DataDirectory");
	Print_NT_Header_Optional_DataDirectory_Internal(lv_output, IMAGE_DIRECTORY_ENTRY_EXPORT, lv_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lv_output, IMAGE_DIRECTORY_ENTRY_IMPORT, lv_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lv_output, IMAGE_DIRECTORY_ENTRY_RESOURCE, lv_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lv_output, IMAGE_DIRECTORY_ENTRY_EXCEPTION, lv_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lv_output, IMAGE_DIRECTORY_ENTRY_SECURITY, lv_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lv_output, IMAGE_DIRECTORY_ENTRY_BASERELOC, lv_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lv_output, IMAGE_DIRECTORY_ENTRY_DEBUG, lv_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lv_output, IMAGE_DIRECTORY_ENTRY_ARCHITECTURE, lv_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lv_output, IMAGE_DIRECTORY_ENTRY_GLOBALPTR, lv_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lv_output, IMAGE_DIRECTORY_ENTRY_TLS, lv_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lv_output, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, lv_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lv_output, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, lv_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lv_output, IMAGE_DIRECTORY_ENTRY_IAT, lv_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lv_output, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, lv_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lv_output, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, lv_is32);
	
	puts("\n");
	return 0;
}

int _HEADER_SET::Print_Section_Header () {
	PIMAGE_SECTION_HEADER lv_output = this->section_header;
	int lv_amount = this->section_amount;
	
	puts("[IMAGE_SECTION_HEADER]");
	for (int i = 0; i < lv_amount; i++) {
		Print_Section_Header_Name(lv_output + i);
		Print_Section_Header_Component(lv_output + i, Misc.VirtualSize);
		Print_Section_Header_Component(lv_output + i, VirtualAddress);
		Print_Section_Header_Component(lv_output + i, SizeOfRawData);
		Print_Section_Header_Component(lv_output + i, PointerToRawData);
		Print_Section_Header_Component(lv_output + i, PointerToRelocations);
		Print_Section_Header_Component(lv_output + i, PointerToLinenumbers);
		Print_Section_Header_Component(lv_output + i, NumberOfRelocations);
		Print_Section_Header_Component(lv_output + i, NumberOfLinenumbers);
		Print_Section_Header_Component(lv_output + i, Characteristics, Print_Characteristics_Section);
		
		puts("");
	}
	
	puts("\n");
	return 0;
}