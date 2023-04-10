#include "global.h"

int Read_DOS_Header (FILE* lp_file, PIMAGE_DOS_HEADER lp_output) {
	//Get DOS Header
	fseek(lp_file, 0, SEEK_SET);
	fread(lp_output, sizeof(IMAGE_DOS_HEADER), 1, lp_file);

	return 0;
}

int Read_DOS_Stub (FILE *lp_file, PIMAGE_DOS_HEADER lp_dos_header, PDOS_STUB lp_output) {
	//Calculate DOS Stub Size
	int lv_size = (lp_dos_header->e_lfanew) - sizeof(IMAGE_DOS_HEADER);
	
	lp_output->Length = lv_size;
	
	//Allocate Output Pointer
	lp_output->String = (char*)calloc(1, lv_size);
	
	//Get Dos Stub
	fseek(lp_file, sizeof(IMAGE_DOS_HEADER), SEEK_SET);
	fread(lp_output->String, lv_size, 1, lp_file);
	
	return 0;
}

int Read_NT_Header_Signature (FILE *lp_file, PIMAGE_DOS_HEADER lp_dos_header, DWORD* lp_output) {
	//Get NT Signature
	fseek(lp_file, (lp_dos_header->e_lfanew), SEEK_SET);
	fread(lp_output, sizeof(DWORD), 1, lp_file);
	
	return 0;
}

int Read_NT_Header_File (FILE *lp_file, PIMAGE_DOS_HEADER lp_dos_header, PIMAGE_FILE_HEADER lp_output) {
	//Get NT File Header
	fseek(lp_file, (lp_dos_header->e_lfanew) + sizeof(DWORD), SEEK_SET);
	fread(lp_output, sizeof(IMAGE_FILE_HEADER), 1, lp_file);
	
	return 0;
}

int Read_NT_Header_Optional (FILE *lp_file, PIMAGE_DOS_HEADER lp_dos_header, PIMAGE_OPTIONAL_HEADER64 lp_output, bool lp_is32) {
	//Calculate Optional Header Size
	int lv_size = lp_is32 ? sizeof(IMAGE_OPTIONAL_HEADER32) : sizeof(IMAGE_OPTIONAL_HEADER64);
	
	//Get NT Optional Header
	fseek(lp_file, (lp_dos_header->e_lfanew) + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), SEEK_SET);
	fread(lp_output, lv_size, 1, lp_file);
	
	return 0;
}