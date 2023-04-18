#ifndef _global
	#define _global
	
	//Standard Include
	#include <stdio.h>
	#include <stdlib.h>
	#include <locale.h>
	#include <windows.h>
	#include <time.h>
	
	//Structure
	typedef struct _DOS_STUB {
		char* String = NULL;
		int Length;
	} DOS_STUB, *PDOS_STUB;

	//class
	typedef class _HEADER_SET {
		private:
			IMAGE_DOS_HEADER dos_header;
			DOS_STUB dos_stub;
			
			union { //The size of the Signature and FileHeader is the same whether 32 bits or 64 bits.
				IMAGE_NT_HEADERS32 nt_header32;
				IMAGE_NT_HEADERS64 nt_header64;
			};
			
			int pe_header_end;
			
			PIMAGE_SECTION_HEADER section_header;
			int section_amount;
		public:
			_HEADER_SET () {
				dos_header = {0, };
				dos_stub = {0, };
				nt_header32 = {0, };
				pe_header_end = 0;
				section_header = NULL;
				section_amount = 0;
			}
			~_HEADER_SET () {
				free(dos_stub.String);
				free(section_header);
			}
			//hread.cpp
			int Read_DOS_Header (FILE*);
			int Read_DOS_Stub (FILE*);
			int Read_NT_Header (FILE*);
			int Read_Section_Header(FILE*);
			//hprint.cpp
			int Print_DOS_Header ();
			int Print_DOS_Stub ();
			int Print_NT_Header_Signature ();
			int Print_NT_Header_File ();
			int Print_NT_Header_Optional ();
			int Print_NT_Header_Optional_DataDirectory ();
			int Print_Section_Header ();
	} HEADER_SET, *PHEADER_SET;
	
	//Custom Include
	#include "main.h"
	
	//Definition
	#define _32BitCheck(h) (h.Machine == IMAGE_FILE_MACHINE_I386)
#endif