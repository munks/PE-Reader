#ifndef _hprint
	#define _hprint

	int Print_DOS_Header (
		PHEADER_SET //Pointer of Struct
		//IMAGE_DOS_HEADER			(_In)
	);
	int Print_DOS_Stub (
		PHEADER_SET //Pointer of Struct
		//DOS_STUB					(_In)
	);
	int Print_NT_Header_Signature (
		PHEADER_SET //Pointer of Struct
		//DWORD						(_In)
	);
	int Print_NT_Header_File (
		PHEADER_SET //Pointer of Struct
		//IMAGE_FILE_HEADER			(_In)
	);
	int Print_NT_Header_Optional (
		PHEADER_SET //Pointer of Struct
		//bool,						(_In) //_32BitCheck(nt_header32.FileHeader)
		//IMAGE_OPTIONAL_HEADER64,	(_In) //Depending on the result of bool, also used as 32-bit
	);
	int Print_NT_Header_Optional_DataDirectory (
		PHEADER_SET //Pointer of Struct
		//bool,						(_In) //_32BitCheck(nt_header32.FileHeader)
		//IMAGE_OPTIONAL_HEADER64	(_In) //Depending on the result of bool, also used as 32-bit
	);
	int Print_Section_Header (
		PHEADER_SET //Pointer of Struct
		//PIMAGE_SECTION_HEADER		(_In)
		//int						(_In) //section_amount
	);
#endif