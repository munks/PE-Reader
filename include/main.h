#ifndef _main
	#define _main
	
	#define CheckNE0(b) if (b) { return 1; }
	
	int FileOpen (
		wchar_t*, //File Path (_In)
		FILE** //File Pointer (_Out)
	);
	void CaptionChange (
		wchar_t*, //Current .exe File Name (_In)
		wchar_t* //Input File Path (_In)
	);
	int wmain (int argc, wchar_t* argv[]); //Main Entry Point
#endif