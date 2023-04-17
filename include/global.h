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

	typedef struct _HEADER_SET {
		IMAGE_DOS_HEADER dos_header;
		DOS_STUB dos_stub;
		
		union { //The size of the Signature and FileHeader is the same whether 32 bits or 64 bits.
			IMAGE_NT_HEADERS32 nt_header32;
			IMAGE_NT_HEADERS64 nt_header64;
		};
		
		int pe_header_end;
		
		PIMAGE_SECTION_HEADER section_header = NULL;
		int section_amount;
	} HEADER_SET, *PHEADER_SET;
	
	//Custom Include
	#include "main.h"
	#include "hread.h"
	#include "hread_internal.h"
	#include "hprint.h"
	#include "hprint_internal.h"
	
	//Definition
	#define _32BitCheck(h) (h.Machine == IMAGE_FILE_MACHINE_I386)
#endif