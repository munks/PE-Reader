#include "global.h"

int Print_DOS_Header (PIMAGE_DOS_HEADER lp_header) {
	puts("[IMAGE_DOS_HEADER]");
	Print_DOS_Header_Internal(lp_header, e_magic, Print_Magic);
	Print_DOS_Header_Internal(lp_header, e_cblp);
	Print_DOS_Header_Internal(lp_header, e_cp);
	Print_DOS_Header_Internal(lp_header, e_crlc);
	Print_DOS_Header_Internal(lp_header, e_cparhdr);
	Print_DOS_Header_Internal(lp_header, e_minalloc);
	Print_DOS_Header_Internal(lp_header, e_maxalloc);
	Print_DOS_Header_Internal(lp_header, e_ss);
	Print_DOS_Header_Internal(lp_header, e_sp);
	Print_DOS_Header_Internal(lp_header, e_ip);
	Print_DOS_Header_Internal(lp_header, e_cs);
	Print_DOS_Header_Internal(lp_header, e_lfarlc);
	Print_DOS_Header_Internal(lp_header, e_ovno);
	Print_DOS_Header_Internal(lp_header, e_res[0]);
	Print_DOS_Header_Internal(lp_header, e_res[1]);
	Print_DOS_Header_Internal(lp_header, e_res[2]);
	Print_DOS_Header_Internal(lp_header, e_res[3]);
	Print_DOS_Header_Internal(lp_header, e_oemid);
	Print_DOS_Header_Internal(lp_header, e_oeminfo);
	Print_DOS_Header_Internal(lp_header, e_res2[0]);
	Print_DOS_Header_Internal(lp_header, e_res2[1]);
	Print_DOS_Header_Internal(lp_header, e_res2[2]);
	Print_DOS_Header_Internal(lp_header, e_res2[3]);
	Print_DOS_Header_Internal(lp_header, e_res2[4]);
	Print_DOS_Header_Internal(lp_header, e_res2[5]);
	Print_DOS_Header_Internal(lp_header, e_res2[6]);
	Print_DOS_Header_Internal(lp_header, e_res2[7]);
	Print_DOS_Header_Internal(lp_header, e_res2[8]);
	Print_DOS_Header_Internal(lp_header, e_res2[9]);
	Print_DOS_Header_Internal(lp_header, e_lfanew);
	
	puts("\n");
	return 0;
}

int Print_DOS_Stub (PDOS_STUB lp_stub) {
	puts("[DOS Stub]");
	for (int i = 0; i < (lp_stub->Length); i++) {
		printf("%c", (lp_stub->String)[i]);
	}
	
	puts("\n\n");
	return 0;
}

int Print_NT_Header_Signature (DWORD lp_signature) {
	puts("[IMAGE_NT_HEADERS].Signature");
	printf("0x%08X (%c%c%c%c)\n", lp_signature, (BYTE)lp_signature, (BYTE)(lp_signature >> 8), (BYTE)(lp_signature >> 16), (BYTE)(lp_signature >> 24));
	
	puts("\n");
	return 0;
}

int Print_NT_Header_File (PIMAGE_FILE_HEADER lp_header) {
	puts("[IMAGE_NT_HEADERS].FileHeader");
	Print_NT_Header_File_Internal(lp_header, Machine, Print_Machine);
	Print_NT_Header_File_Internal(lp_header, NumberOfSections);
	Print_NT_Header_File_Internal(lp_header, TimeDateStamp, Print_DateStamp);
	Print_NT_Header_File_Internal(lp_header, PointerToSymbolTable);
	Print_NT_Header_File_Internal(lp_header, NumberOfSymbols);
	Print_NT_Header_File_Internal(lp_header, SizeOfOptionalHeader);
	Print_NT_Header_File_Internal(lp_header, Characteristics, Print_Characteristics);
	
	puts("\n");
	return 0;
}

int Print_NT_Header_Optional (PIMAGE_OPTIONAL_HEADER64 lp_header, bool lp_is32) {
	puts("[IMAGE_NT_HEADERS].OptionalHeader");
	Print_NT_Header_Optional_Internal(lp_header, Magic, lp_is32, Print_Magic_Optional);
	Print_NT_Header_Optional_Internal(lp_header, MajorLinkerVersion, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, MinorLinkerVersion, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, SizeOfCode, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, SizeOfInitializedData, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, SizeOfUninitializedData, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, AddressOfEntryPoint, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, BaseOfCode, lp_is32);
	if (lp_is32) { Print_NT_Header_Optional_Internal32(lp_header, BaseOfData); }
	Print_NT_Header_Optional_Internal(lp_header, ImageBase, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, SectionAlignment, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, FileAlignment, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, MajorOperatingSystemVersion, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, MinorOperatingSystemVersion, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, MajorImageVersion, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, MinorImageVersion, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, MajorSubsystemVersion, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, MinorSubsystemVersion, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, Win32VersionValue, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, SizeOfImage, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, SizeOfHeaders, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, CheckSum, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, Subsystem, lp_is32, Print_Subsystem);
	Print_NT_Header_Optional_Internal(lp_header, DllCharacteristics, lp_is32, Print_DllCharacteristics);
	Print_NT_Header_Optional_Internal(lp_header, SizeOfStackReserve, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, SizeOfStackCommit, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, SizeOfHeapReserve, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, SizeOfHeapCommit, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, LoaderFlags, lp_is32);
	Print_NT_Header_Optional_Internal(lp_header, NumberOfRvaAndSizes, lp_is32);
	
	puts("\n");
	return 0;
}

int Print_NT_Header_Optional_DataDirectory (PIMAGE_OPTIONAL_HEADER64 lp_header, bool lp_is32) {
	puts("[IMAGE_NT_HEADERS].OptionalHeader.DataDirectory");
	Print_NT_Header_Optional_DataDirectory_Internal(lp_header, IMAGE_DIRECTORY_ENTRY_EXPORT, lp_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lp_header, IMAGE_DIRECTORY_ENTRY_IMPORT, lp_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lp_header, IMAGE_DIRECTORY_ENTRY_RESOURCE, lp_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lp_header, IMAGE_DIRECTORY_ENTRY_EXCEPTION, lp_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lp_header, IMAGE_DIRECTORY_ENTRY_SECURITY, lp_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lp_header, IMAGE_DIRECTORY_ENTRY_BASERELOC, lp_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lp_header, IMAGE_DIRECTORY_ENTRY_DEBUG, lp_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lp_header, IMAGE_DIRECTORY_ENTRY_ARCHITECTURE, lp_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lp_header, IMAGE_DIRECTORY_ENTRY_GLOBALPTR, lp_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lp_header, IMAGE_DIRECTORY_ENTRY_TLS, lp_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lp_header, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, lp_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lp_header, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, lp_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lp_header, IMAGE_DIRECTORY_ENTRY_IAT, lp_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lp_header, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT, lp_is32);
	Print_NT_Header_Optional_DataDirectory_Internal(lp_header, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, lp_is32);
	
	puts("\n");
	return 0;
}