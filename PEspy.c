#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "lib/isPE.h"

void usage(void){
	fprintf(stderr, "Usage: PEspy <PE_filename>\n");
	exit(1);
}

bool is_pe_file_init(PEFILE *pe){
		FILE *fh = fopen(pe->filepath, "rb");

		if (fh == NULL)
			return false;

		pe->hdr_dos = malloc(sizeof(IMAGE_DOS_HEADER));
		if (pe->hdr_dos == NULL) 
			return false;

		fread(pe->hdr_dos, sizeof(IMAGE_DOS_HEADER), 1, fh);
		fclose(fh);
}  


void fatal_error(char *msg){
	fprintf(stderr, "Fatal error: %s\n", msg);
	exit(1);
}

int main(int argc, char *argv[]){
	
	if (argc != 2)
		usage();

	PEFILE pe;
	pe.filepath = argv[1]; 

	if (is_pe_file_init(&pe))
		printf("The file %s is a valid PE file.\n", pe.filepath);
	else {
		fatal_error("The file is not a valid PE file.");
	}

	printf("===== DOS HEADER =====\n");
	printf("File: %s\n", pe.filepath);

	printf("e_magic   (MZ header):                  0x%04X\n", pe.hdr_dos->e_magic);
	printf("e_cblp    (Bytes on last page):         0x%04X\n", pe.hdr_dos->e_cblp);
	printf("e_cp      (Pages in file):              0x%04X\n", pe.hdr_dos->e_cp);
	printf("e_crlc    (Relocations):                0x%04X\n", pe.hdr_dos->e_crlc);
	printf("e_cparhdr (Size of header paragraphs):  0x%04X\n", pe.hdr_dos->e_cparhdr);
	printf("e_minalloc(Minimum extra paragraphs):   0x%04X\n", pe.hdr_dos->e_minalloc);
	printf("e_maxalloc(Maximum extra paragraphs):   0x%04X\n", pe.hdr_dos->e_maxalloc);
	printf("e_ss      (Initial SS value):           0x%04X\n", pe.hdr_dos->e_ss);
	printf("e_sp      (Initial SP value):           0x%04X\n", pe.hdr_dos->e_sp);
	printf("e_csum    (Checksum):                   0x%04X\n", pe.hdr_dos->e_csum);
	printf("e_ip      (Initial IP value):           0x%04X\n", pe.hdr_dos->e_ip);
	printf("e_cs      (Initial CS value):           0x%04X\n", pe.hdr_dos->e_cs);
	printf("e_lfarlc  (Relocation table offset):    0x%04X\n", pe.hdr_dos->e_lfarlc);
	printf("e_ovno    (Overlay number):             0x%04X\n", pe.hdr_dos->e_ovno);

	printf("e_res     (Reserved):                   ");
	for (int i = 0; i < 4; i++) {
		printf("0x%04X ", pe.hdr_dos->e_res[i]);
	}
	printf("\n");

	printf("e_oemid   (OEM identifier):             0x%04X\n", pe.hdr_dos->e_oemid);
	printf("e_oeminfo (OEM information):            0x%04X\n", pe.hdr_dos->e_oeminfo);

	printf("e_res2    (Reserved):                   ");
	for (int i = 0; i < 10; i++) {
		printf("0x%04X ", pe.hdr_dos->e_res2[i]);
	}
	printf("\n");

	printf("e_lfanew  (Offset to PE header):        0x%08X\n", pe.hdr_dos->e_lfanew);

		return 0;
}
