#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#pragma pack(push, 1)

typedef struct {
    __uint16_t e_magic;
    __uint16_t e_cblp; 
    __uint16_t e_cp;    
    __uint16_t e_crlc; 
    __uint16_t e_cparhdr; 
    __uint16_t e_minalloc; 
    __uint16_t e_maxalloc; 
    __uint16_t e_ss;   
    __uint16_t e_sp;   
    __uint16_t e_csum; 
    __uint16_t e_ip;  
    __uint16_t e_cs;    
    __uint16_t e_lfarlc; 
    __uint16_t e_ovno;  
    __uint16_t e_res[4]; 
    __uint16_t e_oemid; 
    __uint16_t e_oeminfo; 
    __uint16_t e_res2[10];
    __uint32_t e_lfanew; 
} IMAGE_DOS_HEADER;


typedef struct 
{
    char *filepath;
    IMAGE_DOS_HEADER *hdr_dos;
} PEFILE;

bool is_pe_file(PEFILE *pe);
bool is_pe_file_init(PEFILE *pe);