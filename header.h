#pragma once

#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <ctype.h>
#include <Windows.h>

extern int offset;

typedef enum
{
    OPERAND_DWORD,
    OPERAND_ULONGLONG,
    OPERAND_NT32,
    OPERAND_NT64,
    OPERAND_NT32_DATADIRECTORY,
    OPERAND_NT64_DATADIRECTORY,
    OPERAND_IID32,
    OPERAND_IID64
} operand;

// 파일 사이즈를 구한다.
int get_file_size(FILE* fp);
// 파일 사이즈를 구한 후 파일의 내용을 동적 메모리에 저장
void* get_file_content(FILE* fp, int *size);
// 파일 오프셋
int set_file_offset(FILE* fp, int offset);
int get_file_offset(FILE* fp, int offset);

//int rva_to_raw(FILE* fp, u_char** binary_buf, DWORD rva_value);
//DWORD rva_to_raw_dword(FILE* fp, u_char** binary_buf, DWORD rva_value);
//ULONGLONG rva_to_raw_ulonglong(FILE* fp, u_char** binary_buf, ULONGLONG rva_value);
ULONGLONG convert_rva_to_raw(const u_char* binary_buf, void* rva_value, operand operand_type);

void print_dos_header(FILE* fp, IMAGE_DOS_HEADER* idh);
void print_nt_header(FILE* fp, unsigned char* buf, operand operand_type);
void print_inh_ioh_datadirectory(FILE* fp, unsigned char* buf, operand operand_type);
void print_section_header(FILE* fp, IMAGE_SECTION_HEADER* ish, WORD section_num);
//void print_inh32_datadirectory(FILE* fp, IMAGE_NT_HEADERS32* inh32);
//void print_inh64_datadirectory(FILE* fp, IMAGE_NT_HEADERS64* inh64);

//void print_image_import_descriptor(FILE* fp, u_char* buf, IMAGE_IMPORT_DESCRIPTOR* iid, int size);
void print_image_import_descriptor(FILE* fp, u_char* buf, operand operand_type);
int print_image_export_directory(FILE* fp, u_char* buf, IMAGE_EXPORT_DIRECTORY* ied);

