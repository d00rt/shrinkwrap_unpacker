#include "utils.h"


int neg(int value) {
	__asm {
		lea eax, value
		mov ebx, [eax]
		neg ebx
		mov[eax], ebx
	}
	return value;
}

DWORD rva_to_offset(IMAGE_NT_HEADERS32 * pNtHdr, DWORD dwRVA)
{
	int i;
	WORD wSections;
	PIMAGE_SECTION_HEADER pSectionHdr;

	pSectionHdr = IMAGE_FIRST_SECTION(pNtHdr);
	wSections = pNtHdr->FileHeader.NumberOfSections;

	for (i = 0; i < wSections; i++)
	{
		if (pSectionHdr->VirtualAddress <= dwRVA)
			if ((pSectionHdr->VirtualAddress + pSectionHdr->Misc.VirtualSize) > dwRVA)
			{
				dwRVA -= pSectionHdr->VirtualAddress;
				dwRVA += pSectionHdr->PointerToRawData;

				return (dwRVA);
			}

		pSectionHdr++;
	}

	return 0;
}

char * read_file(std::string filename, size_t * file_size) {
	
	std::ifstream file(filename, std::ios::in | std::ios::binary | std::ios::ate);

	if (file.is_open())
	{
		std::streampos size;
		char * f_data;

		size = file.tellg();
		f_data = new char[size];
		file.seekg(0, std::ios::beg);
		file.read(f_data, size);
		file.close();
		char * file_data = (char *)malloc(size);
		memcpy(file_data, f_data, size);
		*file_size = size;
		return file_data;
	}
	return 0;
}

void write_file(std::string filename, char * data, size_t size) {
	std::string unpacked_filename(filename);
	std::ofstream unpacked_file(filename + "unpacked.exe", std::ios::out | std::ios::binary);
	unpacked_file.write(data, size);
	unpacked_file.close();
}

void get_packer_engine(PACKER_ENGINE * pke, char * packer_data) {
	unsigned int aux;

	memcpy(&aux, packer_data, 4);
	pke->original_entry_point = neg(aux) ^ 0x1111;

	memcpy(&aux, packer_data + 0x04, 4);
	pke->import_directory = neg(aux) ^ 0x1111;

	memcpy(&aux, packer_data + 0x08, 4);
	pke->base_address = aux;

	memcpy(&aux, packer_data + 0x0C, 4);
	pke->crypted_block_rva_begin = neg(aux);

	memcpy(&aux, packer_data + 0x10, 4);
	pke->crypted_block_size = neg(aux);

	memcpy(&aux, packer_data + 0x14, 4);
	pke->crypted_block_rva_end = neg(aux);

	memcpy(&aux, packer_data + 0x18, 4);
	pke->bypass_size = neg(aux);

	memcpy(&aux, packer_data + 0x1C, 1);
	pke->xor_key = neg(aux) & 0xFF;

}

void decrypt_block(IMAGE_DOS_HEADER * dosHeader, IMAGE_NT_HEADERS * ntHeader, PACKER_ENGINE pke) {
	int code_offset = rva_to_offset(ntHeader, pke.crypted_block_rva_begin);
	int code_end_offset = rva_to_offset(ntHeader, pke.crypted_block_rva_end);

	char * crypted_data = (char *)dosHeader + code_offset;

	int i = 0;
	int patched_bytes = 0;
	while (patched_bytes < pke.crypted_block_size) {
		if (code_offset + i == code_end_offset) {
			i = code_end_offset + pke.bypass_size;
			pke.crypted_block_size -= pke.bypass_size;
		}

		if (crypted_data[i] != 0x00 && crypted_data[i] != pke.xor_key)
			crypted_data[i] = crypted_data[i] ^ pke.xor_key;

		i++;
		patched_bytes++;
	}
}