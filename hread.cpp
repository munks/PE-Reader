#include "global.h"
#include "hread_internal.h"

//Class Function Declarated in "global.h"

int _HEADER_SET::Read_DOS_Header (FILE* lp_file) {
	//Get DOS Header
	fseek_i(0, "DOS Header");
	fread_i(&this->dos_header, sizeof(IMAGE_DOS_HEADER), "DOS Header");
	
	PECheck(this->dos_header.e_magic == IMAGE_DOS_SIGNATURE, "DOS Header", "Signature Mismatch");
	
	return 0;
}

int _HEADER_SET::Read_DOS_Stub (FILE *lp_file) {
	//Calculate DOS Stub Size
	int lv_size = (this->dos_header.e_lfanew) - sizeof(IMAGE_DOS_HEADER);
	
	PECheck(lv_size != 0, "DOS Stub", "0 Size");
	
	this->dos_stub.Length = lv_size;
	
	//Allocate String
	this->dos_stub.String = (char*)calloc(1, lv_size);
	
	//Get Dos Stub
	fseek_i(sizeof(IMAGE_DOS_HEADER), "DOS Stub");
	fread_i(this->dos_stub.String, lv_size, "DOS Stub");
	
	return 0;
}

int _HEADER_SET::Read_NT_Header (FILE *lp_file) {
	//Get NT Header Offset
	int lv_offset = this->dos_header.e_lfanew;
	
	//Get NT Signature
	fseek_i(lv_offset, "NT Header Signature");
	fread_i(&this->nt_header32.Signature, sizeof(DWORD), "NT Header Signature");
	
	PECheck(this->nt_header32.Signature == 0x50450000, "NT Header Signature", "Signature Mismatch");

	//Get NT File Header
	fseek_i(lv_offset + sizeof(DWORD), "COFF File Header");
	fread_i(&this->nt_header32.FileHeader, sizeof(IMAGE_FILE_HEADER), "COFF File Header");

	//Calculate Optional Header Size
	int lv_size = _32BitCheck(this->nt_header32.FileHeader) ? sizeof(IMAGE_OPTIONAL_HEADER32) : sizeof(IMAGE_OPTIONAL_HEADER64);
	
	//Get NT Optional Header
	fseek_i(lv_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), "Optional Header");
	fread_i(&this->nt_header32.OptionalHeader, lv_size, "Optional Header");
	this->pe_header_end = ftell(lp_file);
	
	return 0;
}

int _HEADER_SET::Read_Section_Header(FILE *lp_file) {
	//Get Amount From File Header
	int lv_amount = this->nt_header32.FileHeader.NumberOfSections;
	
	//Allocate Section Header
	this->section_header = (PIMAGE_SECTION_HEADER)calloc(lv_amount, sizeof(IMAGE_SECTION_HEADER));
	
	//Get Section Header
	fseek_i(this->pe_header_end, "Section Header");
	for (int i = 0; i < lv_amount; i++) {
		fread_i(this->section_header + i, sizeof(IMAGE_SECTION_HEADER), "Section Header");
	}
	this->section_amount = lv_amount;
	
	return 0;
}