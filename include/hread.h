#ifndef _hread
	#define _hread

	int Read_DOS_Header (
		FILE*, //Executable File		(_In)
		PHEADER_SET //Pointer of Struct
		//IMAGE_DOS_HEADER				(_Out)
	);
	int Read_DOS_Stub (
		FILE*, //Executable File		(_In)
		PHEADER_SET //Pointer of Struct
		//IMAGE_DOS_HEADER				(_In)
		//DOS_STUB						(_Out)
	);
	int Read_NT_Header (
		FILE*, //Executable File 		(_In)
		PHEADER_SET //Pointer of Struct
		//IMAGE_DOS_HEADER				(_In)
		//DWORD							(_Out) //nt_header32.Signature
		//IMAGE_FILE_HEADER				(_Out)
		//IMAGE_OPTIONAL_HEADER64		(_Out)
		//int							(_Out) //pe_header_end
	);
	int Read_Section_Header(
		FILE*, //Executable File		(_In)
		PHEADER_SET //Pointer of Struct
		//IMAGE_FILE_HEADER				(_In)
		//PIMAGE_SECTION_HEADER			(_Out)
		//int							(_In) //pe_header_end
		//int							(_Out) //section_amount
	);
#endif