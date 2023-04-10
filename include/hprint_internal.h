#ifndef _hprint_internal
	#define _hprint_internal
	
	//Definition
	#define IMAGE_FILE_MACHINE_TARGET_HOST 0x0001
	
	#define Print_DOS_Header_Internal(h, s, ...)	printf("IMAGE_DOS_HEADER.%s: 0x%02X", #s, h->s); __VA_ARGS__(h->s); puts("")
	#define Print_NT_Header_File_Internal(h, s, ...)	printf("IMAGE_FILE_HEADER.%s: 0x%02X", #s, h->s); __VA_ARGS__(h->s); puts("")
	#define Print_NT_Header_Optional_Internal32(h, s, ...)	printf("IMAGE_OPTIONAL_HEADER32.%s: 0x%02X", #s, ((PIMAGE_OPTIONAL_HEADER32)h)->s); \
															__VA_ARGS__(((PIMAGE_OPTIONAL_HEADER32)h)->s); puts("")
	#define Print_NT_Header_Optional_Internal64(h, s, ...)	printf("IMAGE_OPTIONAL_HEADER64.%s: 0x%02X", #s, h->s); \
															__VA_ARGS__(h->s); puts("")
	#define Print_NT_Header_Optional_Internal(h, s, b, ...)	printf("IMAGE_OPTIONAL_HEADER%d.%s: 0x%02X", b ? 32 : 64, #s, b ? ((PIMAGE_OPTIONAL_HEADER32)h)->s : h->s); \
															__VA_ARGS__(b ? ((PIMAGE_OPTIONAL_HEADER32)h)->s : h->s); puts("")
	#define Print_NT_Header_Optional_DataDirectory_Internal(h, s, b)	printf("DataDirectory[%s]:\n -VirtualAddress: 0x%02X\n -Size: 0x%02X\n", \
																			#s, \
																			b ? ((PIMAGE_OPTIONAL_HEADER32)h)->DataDirectory[s].VirtualAddress : h->DataDirectory[s].VirtualAddress, \
																			b ? ((PIMAGE_OPTIONAL_HEADER32)h)->DataDirectory[s].Size : h->DataDirectory[s].Size);
	
	#define Print_Machine_Internal(m) case m: { printf(" (%s)", #m); break; }
	#define Print_Characteristics_Internal(c, v, i)	if (c & v) { \
														if (i == 3) { printf("\n   "); i = 0; } \
														printf("%s%s", i ? " | " : "", #v); i++; \
													}
	#define Print_Magic_Optional_Internal(m) case m: { printf(" (%s)", #m); break; }
	#define Print_Subsystem_Internal(m) case m: { printf(" (%s)", #m); break; }
	#define Print_DllCharacteristics_Internal(c, v, i)	if (c & v) { \
															if (i == 2) { printf("\n   "); i = 0; } \
															printf("%s%s", i ? " | " : "", #v); i++; \
														}
	//Function
	void Print_Magic (WORD);
	void Print_Machine (WORD);
	void Print_DateStamp (DWORD);
	void Print_Characteristics (WORD);
	void Print_Magic_Optional (WORD);
	void Print_Subsystem (WORD);
	void Print_DllCharacteristics (WORD);
#endif