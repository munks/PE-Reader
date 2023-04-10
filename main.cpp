#include "global.h"

int FileOpen (wchar_t* lp_fileDir, FILE** lp_output) {
	FILE* lv_file;
	WORD lv_pe;
	
	//Open File
	wprintf(L"Open File: %ls\n", lp_fileDir);
	
	lv_file = _wfopen(lp_fileDir, L"r+b");
	
	if (lv_file == NULL) {
		perror("Could Not Open File. Error Code");
		fclose(lv_file);
		return 1;
	}
	
	//Check Format (File Name)
	if (wcsstr(lp_fileDir, L".exe") == NULL) {
		puts("File is not PE Format.");
		fclose(lv_file);
		return 1;
	}
	
	//Check Format (Header Character)
	fread(&lv_pe, sizeof(WORD), 1, lv_file);
	if (lv_pe != 0x5A4D) {
		puts("File is not PE Format.");
		fclose(lv_file);
		return 1;
	}
	puts("");

	*lp_output = lv_file;
	return 0;
}

int wmain (int argc, wchar_t* argv[]) {
	FILE *lv_file = NULL;
	IMAGE_DOS_HEADER lv_dos_header;
	DOS_STUB lv_dos_stub;
	DWORD lv_nt_signature;
	IMAGE_FILE_HEADER lv_file_header;
	IMAGE_OPTIONAL_HEADER64 lv_optional_header;
	int lv_pe_header_end;
	PIMAGE_SECTION_HEADER lv_section_header;
	int lv_section_amount;
	
	setlocale(LC_ALL, "");

	if (argc == 1) {
		wprintf(L"Usage: %ls [Path]\n", wcsrchr(argv[0], L'\\') + 1);
		goto END;
	}
	
	if (FileOpen(argv[1], &lv_file)) {
		goto END;
	}

	Read_DOS_Header(lv_file, &lv_dos_header);
	Read_DOS_Stub(lv_file, &lv_dos_header, &lv_dos_stub);
	Read_NT_Header_Signature(lv_file, &lv_dos_header, &lv_nt_signature);
	Read_NT_Header_File(lv_file, &lv_dos_header, &lv_file_header);
	Read_NT_Header_Optional(lv_file, &lv_dos_header, &lv_optional_header, _32BitCheck(lv_file_header), &lv_pe_header_end);
	Read_Section_Header(lv_file, &lv_file_header, &lv_section_header, lv_pe_header_end, &lv_section_amount);
	
	Print_DOS_Header(&lv_dos_header);
	Print_DOS_Stub(&lv_dos_stub);
	Print_NT_Header_Signature(lv_nt_signature);
	Print_NT_Header_File(&lv_file_header);
	Print_NT_Header_Optional(&lv_optional_header, _32BitCheck(lv_file_header));
	Print_NT_Header_Optional_DataDirectory(&lv_optional_header, _32BitCheck(lv_file_header));
	Print_Section_Header(lv_section_header, lv_section_amount);
	
	END:
	fclose(lv_file);
	free(lv_dos_stub.String);
	free(lv_section_header);
	system("pause");
	
	return 0;
}