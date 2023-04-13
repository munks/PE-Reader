#include "global.h"

int Read_DOS_Header (FILE* lp_file, PIMAGE_DOS_HEADER lp_output) {
	//Get DOS Header
	fseek_i(0, "DOS Header");
	fread_i(lp_output, sizeof(IMAGE_DOS_HEADER), "DOS Header");
	
	PECheck(lp_output->e_magic == IMAGE_DOS_SIGNATURE, "DOS Header", "Signature Mismatch");
	
	return 0;
}

int Read_DOS_Stub (FILE *lp_file, PIMAGE_DOS_HEADER lp_dos_header, PDOS_STUB lp_output) {
	//Calculate DOS Stub Size
	int lv_size = (lp_dos_header->e_lfanew) - sizeof(IMAGE_DOS_HEADER);
	
	PECheck(lv_size != 0, "DOS Stub", "0 Size");
	
	lp_output->Length = lv_size;
	
	//Allocate String
	lp_output->String = (char*)calloc(1, lv_size);
	
	//Get Dos Stub
	fseek_i(sizeof(IMAGE_DOS_HEADER), "DOS Stub");
	fread_i(lp_output->String, lv_size, "DOS Stub");
	
	return 0;
}

int Read_NT_Header_Signature (FILE *lp_file, PIMAGE_DOS_HEADER lp_dos_header, DWORD* lp_output) {
	//Get NT Signature
	fseek_i(lp_dos_header->e_lfanew, "NT Header Signature");
	fread_i(lp_output, sizeof(DWORD), "NT Header Signature");
	
	PECheck(*lp_output == 0x50450000, "NT Header Signature", "Signature Mismatch");
	
	return 0;
}

int Read_NT_Header_File (FILE *lp_file, PIMAGE_DOS_HEADER lp_dos_header, PIMAGE_FILE_HEADER lp_output) {
	//Get NT File Header
	fseek_i(lp_dos_header->e_lfanew + sizeof(DWORD), "COFF File Header");
	fread_i(lp_output, sizeof(IMAGE_FILE_HEADER), "COFF File Header");
	
	return 0;
}

int Read_NT_Header_Optional (FILE *lp_file, PIMAGE_DOS_HEADER lp_dos_header, PIMAGE_OPTIONAL_HEADER64 lp_output, bool lp_is32, int * lp_end) {
	//Calculate Optional Header Size
	int lv_size = lp_is32 ? sizeof(IMAGE_OPTIONAL_HEADER32) : sizeof(IMAGE_OPTIONAL_HEADER64);
	
	//Get NT Optional Header
	fseek_i(lp_dos_header->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), "Optional Header");
	fread_i(lp_output, lv_size, "Optional Header");
	*lp_end = ftell(lp_file);
	
	return 0;
}

int Read_Section_Header(FILE *lp_file, PIMAGE_FILE_HEADER lp_file_header, PIMAGE_SECTION_HEADER *lp_output, int lp_offset, int *lp_amount) {
	//Get Amount From File Header
	int lv_amount = lp_file_header->NumberOfSections;
	
	//Allocate Section Header
	*lp_output = (PIMAGE_SECTION_HEADER)calloc(lv_amount, sizeof(IMAGE_SECTION_HEADER));
	
	//Get Section Header
	fseek_i(lp_offset, "Section Header");
	for (int i = 0; i < lv_amount; i++) {
		fread_i(*lp_output+i, sizeof(IMAGE_SECTION_HEADER), "Section Header");
	}
	*lp_amount = lv_amount;
	
	return 0;
}