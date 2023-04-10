#ifndef _hprint
	#define _hprint

	int Print_DOS_Header (
		PIMAGE_DOS_HEADER //Pointer of Header (_In)
	);
	int Print_DOS_Stub (
		PDOS_STUB //Stub String (_In)
	);
	int Print_NT_Header_Signature (
		DWORD //Signature (_In)
	);
	int Print_NT_Header_File (
		PIMAGE_FILE_HEADER //Pointer of Header (_In)
	);
	int Print_NT_Header_Optional (
		PIMAGE_OPTIONAL_HEADER64, //Pointer of Header (_In)
		bool //true: 32-bit, false: 64-bit (_In) 
	);
	int Print_NT_Header_Optional_DataDirectory (
		PIMAGE_OPTIONAL_HEADER64, //Pointer of Header (_In)
		bool //true: 32-bit, false: 64-bit (_In) 
	);
	int Print_Section_Header (
		PIMAGE_SECTION_HEADER, //Pointer of Header (_In)
		int //Header Amount (_In)
	);
#endif