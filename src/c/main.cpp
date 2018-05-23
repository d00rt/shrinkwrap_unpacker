#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>
#include "utils.h"


void error(int e, char * message) {
	std::cout << "Error " << e << ": " << message << ".\n";
	getchar();
	exit(e);
}


void info( char * message) {
	std::cout << "Info: " << message << ".\n";
}


int main(int argc, char* argv[])
{

	if (argc > 1){

		/*
		/ Open file and read its bytes.
		*/
		size_t size;
		std::string filename = argv[1];

		char * f_data = read_file(filename, &size);

		if (f_data == 0)
			error(0, "ERROR READING FILE");

		info("Input file was read");
		/*
		/ Using IMAGE_DOS_HEADER and IMAGE_NT_HEADERS for accessing 
		/ to interesting data
		*/
		IMAGE_DOS_HEADER * dosHeader = (IMAGE_DOS_HEADER *)f_data;
		IMAGE_NT_HEADERS * ntHeader = (IMAGE_NT_HEADERS *)((DWORD)dosHeader + (DWORD)dosHeader->e_lfanew);
		
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			error(1, "INVALID IMAGE DOS SIGNATURE");

		if(ntHeader->Signature != IMAGE_NT_SIGNATURE)
			error(1, "INVALID IMAGE NT SIGNATURE");
		
		info("Input file is a valid PE file");
		/*
		/ The packer saves some data 5 bytes after its AddressOfEntryPoint
		/ At this point that data is parsed and saved in the struct
		/ PACKER_ENGINE
		*/
		int ep = rva_to_offset(ntHeader, ntHeader->OptionalHeader.AddressOfEntryPoint);
		char * packer_data = (char *)ep + (DWORD)dosHeader + 5;

		PACKER_ENGINE pke = {};
		get_packer_engine(&pke, packer_data);
		info("Packer engine data obtained");
		/*
		/ The data is encrypted with simple XOR. 
		*/
		try {
			decrypt_block(dosHeader, ntHeader, pke);
			info("Data was decrypted");
		}
		catch (int e) {
			error(e, "ERROR DECRYPTING DATA");
		}
		

		/*
		/ Fix up PE header
		/  - Change entry point to Original Entry Point
		/  - Change import directory to the new import directory
		*/	
		ntHeader->OptionalHeader.AddressOfEntryPoint = pke.original_entry_point - pke.base_address;
		ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pke.import_directory - pke.base_address;
		ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
		info("Import directory and entry point were patched.");

		/*
		/ Save the original file unpacked
		*/
		try {
			write_file(filename, f_data, size);
		}
		catch (int e) {
			error(e, "ERROR WRITTING DATA");
		}

		info("The file was unpacked successfully");
		getchar();
		return 1;

		}
	
	error(-1, "A PACKED FILE MUST BE PROVIDED");
	return 0;
}