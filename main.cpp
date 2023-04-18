#include "global.h"

int Header_Read (FILE *lp_file, PHEADER_SET lp_set) {
	CheckNE0(lp_set->Read_DOS_Header(lp_file));
	CheckNE0(lp_set->Read_DOS_Stub(lp_file));
	CheckNE0(lp_set->Read_NT_Header(lp_file));
	CheckNE0(lp_set->Read_Section_Header(lp_file));

	return 0;
}

int Header_Print (PHEADER_SET lp_set) {
	CheckNE0(lp_set->Print_DOS_Header());
	CheckNE0(lp_set->Print_DOS_Stub());
	CheckNE0(lp_set->Print_NT_Header_Signature());
	CheckNE0(lp_set->Print_NT_Header_File());
	CheckNE0(lp_set->Print_NT_Header_Optional());
	CheckNE0(lp_set->Print_NT_Header_Optional_DataDirectory());
	CheckNE0(lp_set->Print_Section_Header());

	return 0;
}

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
	if (wcsstr(lp_fileDir, L".dll") == NULL) {
		puts("File is not PE Format.");
		fclose(lv_file);
		return 1;
	}}
	
	//Check Format (Header Character)
	fread(&lv_pe, sizeof(WORD), 1, lv_file);
	if (lv_pe != IMAGE_DOS_SIGNATURE) {
		puts("File is not PE Format.");
		fclose(lv_file);
		return 1;
	}
	puts("");

	*lp_output = lv_file;
	return 0;
}

void CaptionChange (wchar_t* lp_name, wchar_t* lp_path) {
	int lv_length;
	wchar_t* lv_tmpstr;
	
	lv_length = wcslen(lp_name) + wcslen(lp_path);
	lv_tmpstr = (wchar_t*)calloc(1, sizeof(wchar_t) * (lv_length + 20));
	swprintf(lv_tmpstr, L"%s - File: %s", lp_name, lp_path);
	
	SetConsoleTitleW(lv_tmpstr);
	free(lv_tmpstr);
}

int wmain (int argc, wchar_t* argv[]) {
	FILE *lv_file = NULL;
	HEADER_SET lv_header_info;
	
	setlocale(LC_ALL, "");

	if (argc == 1) {
		wprintf(L"Usage: %ls [Path]\n", wcsrchr(argv[0], L'\\') + 1);
		goto END;
	}
	
	if (!FileOpen(argv[1], &lv_file)) {
		CaptionChange(wcsrchr(argv[0], L'\\') + 1, argv[1]);
	} else {
		goto END;
	}
	
	if (!Header_Read(lv_file, &lv_header_info)) {
		Header_Print(&lv_header_info);
	}
	
	END:
	fclose(lv_file);
	system("pause");
	
	return 0;
}