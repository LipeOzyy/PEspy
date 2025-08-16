#include "isPE.h"

bool is_pe_file(PEFILE *pe) {
return pe->hdr_dos->e_magic == 0x5A4D; // 'MZ' magic number
}


bool is_pe_file_init(PEFILE *pe) {
	FILE *fh = fopen(pe->filepath, "rb");
	if (fh == NULL)
		return false;

	pe->hdr_dos = malloc(sizeof(IMAGE_DOS_HEADER));
	if (pe->hdr_dos == NULL) {
		fclose(fh);
		return false;
	}

	size_t read_size = fread(pe->hdr_dos, sizeof(IMAGE_DOS_HEADER), 1, fh);
	fclose(fh);

	if (read_size != 1 || !is_pe_file((unsigned char *)pe->hdr_dos)) {
		free(pe->hdr_dos);
		pe->hdr_dos = NULL;
		return false;
	}

	return true;
}