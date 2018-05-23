#include <Windows.h>
#include <iostream>
#include <fstream>
#include <string>

struct PACKER_ENGINE {
	int original_entry_point;
	int import_directory;
	int base_address;
	int crypted_block_rva_begin;
	int crypted_block_size;
	int crypted_block_rva_end;
	int bypass_size;
	char xor_key;
};

int neg(int value);

DWORD rva_to_offset(IMAGE_NT_HEADERS32 * pNtHdr, DWORD dwRVA);

char * read_file(std::string filename, size_t * file_size);

void write_file(std::string filename, char * data, size_t size);

void get_packer_engine(PACKER_ENGINE * pke, char * packer_data);

void decrypt_block(IMAGE_DOS_HEADER * dosHeader, IMAGE_NT_HEADERS * ntHeader, PACKER_ENGINE pke);