#include "global.h"

void Print_Magic (WORD lp_magic) {
	printf(" (%c%c)", (BYTE)lp_magic, (BYTE)(lp_magic >> 8));
}

void Print_Machine (WORD lp_machine) {
	switch (lp_machine) {
		Print_Machine_Internal(IMAGE_FILE_MACHINE_UNKNOWN);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_TARGET_HOST);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_I386);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_R3000);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_R4000);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_R10000);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_WCEMIPSV2);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_ALPHA);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_SH3);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_SH3DSP);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_SH3E);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_SH4);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_SH5);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_ARM);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_THUMB);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_ARMNT);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_AM33);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_POWERPC);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_POWERPCFP);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_IA64);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_MIPS16);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_ALPHA64 | IMAGE_FILE_MACHINE_AXP64);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_MIPSFPU);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_MIPSFPU16);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_TRICORE);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_CEF);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_EBC);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_AMD64);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_M32R);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_ARM64);
		Print_Machine_Internal(IMAGE_FILE_MACHINE_CEE);
	}
}

void Print_DateStamp (DWORD lp_date) {
	struct tm *lv_time;
	
	lv_time = _localtime32((const __time32_t*)&lp_date);
	printf (" (%04d/%02d/%02d %02d:%02d:%02d)",
		lv_time->tm_year + 1900,
		lv_time->tm_mon + 1,
		lv_time->tm_mday,
		lv_time->tm_hour,
		lv_time->tm_min,
		lv_time->tm_sec
	);
}

void Print_Characteristics (WORD lp_character) {
	int lv_counter = 0;
	
	if (lp_character == 0x00) { return; }
	printf("\n - ");
	Print_Characteristics_Internal(lp_character, IMAGE_FILE_RELOCS_STRIPPED, lv_counter);
	Print_Characteristics_Internal(lp_character, IMAGE_FILE_EXECUTABLE_IMAGE, lv_counter);
	Print_Characteristics_Internal(lp_character, IMAGE_FILE_LINE_NUMS_STRIPPED, lv_counter);
	Print_Characteristics_Internal(lp_character, IMAGE_FILE_LOCAL_SYMS_STRIPPED, lv_counter);
	Print_Characteristics_Internal(lp_character, IMAGE_FILE_AGGRESIVE_WS_TRIM, lv_counter);
	Print_Characteristics_Internal(lp_character, IMAGE_FILE_LARGE_ADDRESS_AWARE, lv_counter);
	Print_Characteristics_Internal(lp_character, IMAGE_FILE_BYTES_REVERSED_LO, lv_counter);
	Print_Characteristics_Internal(lp_character, IMAGE_FILE_32BIT_MACHINE, lv_counter);
	Print_Characteristics_Internal(lp_character, IMAGE_FILE_DEBUG_STRIPPED, lv_counter);
	Print_Characteristics_Internal(lp_character, IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, lv_counter);
	Print_Characteristics_Internal(lp_character, IMAGE_FILE_NET_RUN_FROM_SWAP, lv_counter);
	Print_Characteristics_Internal(lp_character, IMAGE_FILE_SYSTEM, lv_counter);
	Print_Characteristics_Internal(lp_character, IMAGE_FILE_DLL, lv_counter);
	Print_Characteristics_Internal(lp_character, IMAGE_FILE_UP_SYSTEM_ONLY, lv_counter);
	Print_Characteristics_Internal(lp_character, IMAGE_FILE_BYTES_REVERSED_HI, lv_counter);
}

void Print_Magic_Optional (WORD lp_magic) {
	switch (lp_magic) {
		Print_Magic_Optional_Internal(IMAGE_NT_OPTIONAL_HDR32_MAGIC);
		Print_Magic_Optional_Internal(IMAGE_NT_OPTIONAL_HDR64_MAGIC);
		Print_Magic_Optional_Internal(IMAGE_ROM_OPTIONAL_HDR_MAGIC);
	}
}

void Print_Subsystem (WORD lp_subsystem) {
	switch (lp_subsystem) {
		Print_Subsystem_Internal(IMAGE_SUBSYSTEM_UNKNOWN);
		Print_Subsystem_Internal(IMAGE_SUBSYSTEM_NATIVE);
		Print_Subsystem_Internal(IMAGE_SUBSYSTEM_WINDOWS_GUI);
		Print_Subsystem_Internal(IMAGE_SUBSYSTEM_WINDOWS_CUI);
		Print_Subsystem_Internal(IMAGE_SUBSYSTEM_OS2_CUI);
		Print_Subsystem_Internal(IMAGE_SUBSYSTEM_POSIX_CUI);
		Print_Subsystem_Internal(IMAGE_SUBSYSTEM_WINDOWS_CE_GUI);
		Print_Subsystem_Internal(IMAGE_SUBSYSTEM_EFI_APPLICATION);
		Print_Subsystem_Internal(IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER);
		Print_Subsystem_Internal(IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER);
		Print_Subsystem_Internal(IMAGE_SUBSYSTEM_EFI_ROM);
		Print_Subsystem_Internal(IMAGE_SUBSYSTEM_XBOX);
		Print_Subsystem_Internal(IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION);
	}
}

void Print_DllCharacteristics (WORD lp_character) {
	int lv_counter = 0;
	
	if (lp_character == 0x00) { return; }
	printf("\n - ");
	Print_DllCharacteristics_Internal(lp_character, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, lv_counter);
	Print_DllCharacteristics_Internal(lp_character, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, lv_counter);
	Print_DllCharacteristics_Internal(lp_character, IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, lv_counter);
	Print_DllCharacteristics_Internal(lp_character, IMAGE_DLLCHARACTERISTICS_NX_COMPAT, lv_counter);
	Print_DllCharacteristics_Internal(lp_character, IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, lv_counter);
	Print_DllCharacteristics_Internal(lp_character, IMAGE_DLLCHARACTERISTICS_NO_SEH, lv_counter);
	Print_DllCharacteristics_Internal(lp_character, IMAGE_DLLCHARACTERISTICS_NO_BIND, lv_counter);
	Print_DllCharacteristics_Internal(lp_character, IMAGE_DLLCHARACTERISTICS_APPCONTAINER, lv_counter);
	Print_DllCharacteristics_Internal(lp_character, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, lv_counter);
	Print_DllCharacteristics_Internal(lp_character, IMAGE_DLLCHARACTERISTICS_GUARD_CF, lv_counter);
	Print_DllCharacteristics_Internal(lp_character, IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, lv_counter);
}

void Print_Characteristics_Section (DWORD lp_character) {
	int lv_counter = 0;
	
	if (lp_character == 0x0000) { return; }
	printf(":\n  -");
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_TYPE_NO_PAD, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_CNT_CODE, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_CNT_INITIALIZED_DATA, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_CNT_UNINITIALIZED_DATA, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_LNK_OTHER, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_LNK_INFO, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_LNK_REMOVE, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_LNK_COMDAT, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_NO_DEFER_SPEC_EXC, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_GPREL, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_MEM_PURGEABLE, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_MEM_LOCKED, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_MEM_PRELOAD, lv_counter);
	
	Print_Characteristics_Section_Internal_Bit(lp_character, IMAGE_SCN_ALIGN_1BYTES, lv_counter);
	Print_Characteristics_Section_Internal_Bit(lp_character, IMAGE_SCN_ALIGN_2BYTES, lv_counter);
	Print_Characteristics_Section_Internal_Bit(lp_character, IMAGE_SCN_ALIGN_4BYTES, lv_counter);
	Print_Characteristics_Section_Internal_Bit(lp_character, IMAGE_SCN_ALIGN_8BYTES, lv_counter);
	Print_Characteristics_Section_Internal_Bit(lp_character, IMAGE_SCN_ALIGN_16BYTES, lv_counter);
	Print_Characteristics_Section_Internal_Bit(lp_character, IMAGE_SCN_ALIGN_32BYTES, lv_counter);
	Print_Characteristics_Section_Internal_Bit(lp_character, IMAGE_SCN_ALIGN_64BYTES, lv_counter);
	Print_Characteristics_Section_Internal_Bit(lp_character, IMAGE_SCN_ALIGN_128BYTES, lv_counter);
	Print_Characteristics_Section_Internal_Bit(lp_character, IMAGE_SCN_ALIGN_256BYTES, lv_counter);
	Print_Characteristics_Section_Internal_Bit(lp_character, IMAGE_SCN_ALIGN_512BYTES, lv_counter);
	Print_Characteristics_Section_Internal_Bit(lp_character, IMAGE_SCN_ALIGN_1024BYTES, lv_counter);
	Print_Characteristics_Section_Internal_Bit(lp_character, IMAGE_SCN_ALIGN_2048BYTES, lv_counter);
	Print_Characteristics_Section_Internal_Bit(lp_character, IMAGE_SCN_ALIGN_4096BYTES, lv_counter);
	Print_Characteristics_Section_Internal_Bit(lp_character, IMAGE_SCN_ALIGN_8192BYTES, lv_counter);
	
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_LNK_NRELOC_OVFL, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_MEM_DISCARDABLE, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_MEM_NOT_CACHED, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_MEM_NOT_PAGED, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_MEM_SHARED, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_MEM_EXECUTE, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_MEM_READ, lv_counter);
	Print_Characteristics_Section_Internal(lp_character, IMAGE_SCN_MEM_WRITE, lv_counter);
}