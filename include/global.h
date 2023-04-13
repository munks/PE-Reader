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
	
	//Custom Include
	#include "main.h"
	#include "hread.h"
	#include "hread_internal.h"
	#include "hprint.h"
	#include "hprint_internal.h"
	
	//Definition
	#define _32BitCheck(h) (h.Machine == IMAGE_FILE_MACHINE_I386)
#endif