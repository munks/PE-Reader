#ifndef _hread_internal
	#define _hread_internal
	
	#define fseek_i(s, h)	if (fseek(lp_file, s, SEEK_SET)) { \
								perror("fseek Failed While Reading " h); \
								return 1; \
							}
	#define fread_i(o, s, h)	if (!fread(o, s, 1, lp_file)) { \
									printf("fread Failed While Reading " h); \
									if (feof(lp_file)) { \
										puts(": End Of File"); \
									} else { \
										perror(""); \
									} \
									return 1; \
								}
	#define PECheck(b, h, r)	if (!b) { \
									puts("File Check Failed While Reading " h ": " r); \
									return 1; \
								}
	
#endif