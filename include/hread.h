#ifndef _hread
	#define _hread

	int Read_DOS_Header (
		FILE*, //Executable File (_In)
		PIMAGE_DOS_HEADER //Pointer of Header (_Out)
	);
	int Read_DOS_Stub (
		FILE*, //Executable File (_In)
		PIMAGE_DOS_HEADER, //Information for NT Header Offset (_In)
		PDOS_STUB //Pointer of Stub (_Out)
	);
	int Read_NT_Header_Signature (
		FILE*, //Executable File (_In)
		PIMAGE_DOS_HEADER, //Information for NT Header Offset (_In)
		DWORD* //Pointer of Signature (_Out)
	);
	int Read_NT_Header_File (
		FILE*, //Executable File (_In)
		PIMAGE_DOS_HEADER, //Information for NT Header Offset (_In)
		PIMAGE_FILE_HEADER //Pointer of Header (_Out)
	);
	int Read_NT_Header_Optional (
		FILE*, //Executable File (_In)
		PIMAGE_DOS_HEADER, //Information for NT Header Offset (_In)
		PIMAGE_OPTIONAL_HEADER64, //Pointer of Header (_Out)
		bool //true: 32-bit, false: 64-bit (_In) 
	);
#endif