#include "header.h"

void print_section_header(FILE* fp, IMAGE_SECTION_HEADER* ish, WORD section_num)
{
	printf("========== [SECTION HEADERS] ==========\n\n");
	printf("Number of Section : %d\n\n", section_num);
	for (int i = 0; i < section_num; i++, ish++)
	{
		printf("[%08X] - Section Name\t\t: %s\n", offset, ish->Name);
		offset = get_file_offset(fp, sizeof(ish->Name));

		//printf("- PhysicalAddress[%dbyte]\t:%08X\n", sizeof(ish->Misc.PhysicalAddress), ish->Misc.PhysicalAddress);
		printf("[%08X] - VirtualSize[%zdbyte]\t\t: %08X\n", offset, sizeof(ish->Misc.VirtualSize), ish->Misc.VirtualSize);
		offset = get_file_offset(fp, sizeof(ish->Misc.VirtualSize));

		printf("[%08X] - VirtualAddress[%zdbyte]\t: %08X\n", offset, sizeof(ish->VirtualAddress), ish->VirtualAddress);
		offset = get_file_offset(fp, sizeof(ish->VirtualAddress));

		printf("[%08X] - SizeOfRawData[%zdbyte]\t: %08X\n", offset, sizeof(ish->SizeOfRawData), ish->SizeOfRawData);
		offset = get_file_offset(fp, sizeof(ish->SizeOfRawData));

		printf("[%08X] - PointerToRawData[%zdbyte]\t: %08X\n", offset, sizeof(ish->PointerToRawData), ish->PointerToRawData);
		offset = get_file_offset(fp, sizeof(ish->PointerToRawData));

		printf("[%08X] - PointerToRelocations[%zdbyte]: %08X\n", offset, sizeof(ish->PointerToRelocations), ish->PointerToRelocations);
		offset = get_file_offset(fp, sizeof(ish->PointerToRelocations));

		printf("[%08X] - PointerToLinenumbers[%zdbyte]: %08X\n", offset, sizeof(ish->PointerToLinenumbers), ish->PointerToLinenumbers);
		offset = get_file_offset(fp, sizeof(ish->PointerToLinenumbers));

		printf("[%08X] - NumberOfRelocations[%zdbyte]\t: %04X\n", offset, sizeof(ish->NumberOfRelocations), ish->NumberOfRelocations);
		offset = get_file_offset(fp, sizeof(ish->NumberOfRelocations));

		printf("[%08X] - NumberOfLineNumbers[%zdbyte]\t: %04X\n", offset, sizeof(ish->NumberOfLinenumbers), ish->NumberOfLinenumbers);
		offset = get_file_offset(fp, sizeof(ish->NumberOfLinenumbers));

		printf("[%08X] - Characteristics[%zdbyte]\t: %08X\n\n", offset, sizeof(ish->Characteristics), ish->Characteristics);
		offset = get_file_offset(fp, sizeof(ish->Characteristics));

		printf("----------------------------------------\n\n");
	}
	printf("=======================================\n\n");
}