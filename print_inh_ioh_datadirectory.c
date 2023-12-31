#include "header.h"

char* inh32_datadirectory_entries[] = {"EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG\t", "COPYRIGHT", "GLOBALPTR", "TLS\t", "LOAD_CONFIG", "BOUND_IMPORT", "IAT\t", "DELAY_IMPORT", "COM_DESCRIPTOR", "Reserved"};
char* inh64_datadirectory_entries[] = {"EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG\t", "ARCHITECTURE", "GLOBALPTR", "TLS\t", "LOAD_CONFIG", "BOUND_IMPORT", "IAT\t", "DELAY_IMPORT", "COM_DESCRIPTOR", "Reserved" };

void print_inh_ioh_datadirectory(FILE* fp, unsigned char* buf, operand operand_type)
{
	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)buf;

	switch (operand_type)
	{
		case OPERAND_NT32_DATADIRECTORY:
		{
			char* inh32_datadirectory_entries[] = { "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG\t", "COPYRIGHT", "GLOBALPTR", "TLS\t", "LOAD_CONFIG", "BOUND_IMPORT", "IAT\t", "DELAY_IMPORT", "COM_DESCRIPTOR", "Reserved" };

			IMAGE_NT_HEADERS32* inh32 = (IMAGE_NT_HEADERS32*)(buf + idh->e_lfanew);

			for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
			{
				printf("[%08X] - %s Directory RVA[%zdbyte]\t: %08X\n", offset, inh32_datadirectory_entries[i], sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
				offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
				
				printf("[%08X] - %s Directory Size[%zdbyte]\t: %08X\n", offset, inh32_datadirectory_entries[i], sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);
				offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].Size));
			}
			break;
		}
		case OPERAND_NT64_DATADIRECTORY:
		{
			char* inh64_datadirectory_entries[] = { "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC", "DEBUG\t", "ARCHITECTURE", "GLOBALPTR", "TLS\t", "LOAD_CONFIG", "BOUND_IMPORT", "IAT\t", "DELAY_IMPORT", "COM_DESCRIPTOR", "Reserved" };

			IMAGE_NT_HEADERS64* inh64 = (IMAGE_NT_HEADERS64*)(buf + idh->e_lfanew);

			for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
			{
				printf("[%08X] - %s Directory RVA[%zdbyte]\t: %08X\n", offset, inh64_datadirectory_entries[i], sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
				offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
				
				printf("[%08X] - %s Directory Size[%zdbyte]\t: %08X\n", offset, inh64_datadirectory_entries[i], sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
				offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
			}
			break;
		}
	}
}


/*
void print_inh32_datadirectory(FILE* fp, IMAGE_NT_HEADERS32* inh32)
{
	
	int i = 0;
	
	printf("[%08X] : EXPORT Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : EXPORT Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].Size));
	i++;

	printf("[%08X] : IMPORT Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : IMPORT Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);

	i++;

	printf("[%08X] : RESOURCE Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : RESOURCE Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);

	i++;

	printf("[%08X] : EXCEPTION Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : EXCEPTION Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);

	i++;

	printf("[%08X] : SECURITY Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : SECURITY Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);

	i++;

	printf("[%08X] : BASERELOC Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : BASERELOC Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);

	i++;

	printf("[%08X] : DEBUG Directory RVA[%dbyte]\t\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : DEBUG Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);

	i++;

	printf("[%08X] : COPYRIGHT Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : COPYRIGHT Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);

	i++;

	printf("[%08X] : GLOBALPTR Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : GLOBALPTR Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);

	i++;

	printf("[%08X] : TLS Directory RVA[%dbyte]\t\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : TLS Directory Size[%dbyte]\t\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);

	i++;

	printf("[%08X] : LOAD_CONFIG Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : LOAD_CONFIG Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);

	i++;

	printf("[%08X] : BOUND_IMPORT Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : BOUND_IMPORT Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);

	i++;

	printf("[%08X] : IAT Directory RVA[%dbyte]\t\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : IAT Directory Size[%dbyte]\t\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);

	i++;

	printf("[%08X] : DELAY_IMPORT Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : DELAY_IMPORT Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);

	i++;

	printf("[%08X] : COM_DESCRIPTOR Directory RVA[%dbyte]\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : COM_DESCRIPTOR Directory Size[%dbyte]\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);

	i++;

	printf("[%08X] : Reserved Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress), inh32->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh32->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : Reserved Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh32->OptionalHeader.DataDirectory[i].Size), inh32->OptionalHeader.DataDirectory[i].Size);

	i++;
}

void print_inh64_datadirectory(FILE* fp, IMAGE_NT_HEADERS64* inh64)
{
	int i = 0;

	printf("[%08X] : EXPORT Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : EXPORT Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
	i++;

	printf("[%08X] : IMPORT Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : IMPORT Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
	i++;

	printf("[%08X] : RESOURCE Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : RESOURCE Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
	i++;

	printf("[%08X] : EXCEPTION Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : EXCEPTION Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
	i++;

	printf("[%08X] : SECURITY Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : SECURITY Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
	i++;

	printf("[%08X] : BASERELOC Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : BASERELOC Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
	i++;

	printf("[%08X] : DEBUG Directory RVA[%dbyte]\t\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : DEBUG Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
	i++;

	printf("[%08X] : COPYRIGHT Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : COPYRIGHT Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
	i++;

	printf("[%08X] : GLOBALPTR Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : GLOBALPTR Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
	i++;

	printf("[%08X] : TLS Directory RVA[%dbyte]\t\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : TLS Directory Size[%dbyte]\t\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
	i++;

	printf("[%08X] : LOAD_CONFIG Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : LOAD_CONFIG Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
	i++;

	printf("[%08X] : BOUND_IMPORT Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : BOUND_IMPORT Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
	i++;

	printf("[%08X] : IAT Directory RVA[%dbyte]\t\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : IAT Directory Size[%dbyte]\t\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
	i++;

	printf("[%08X] : DELAY_IMPORT Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : DELAY_IMPORT Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
	i++;

	printf("[%08X] : COM_DESCRIPTOR Directory RVA[%dbyte]\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : COM_DESCRIPTOR Directory Size[%dbyte]\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
	i++;

	printf("[%08X] : Reserved Directory RVA[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress), inh64->OptionalHeader.DataDirectory[i].VirtualAddress);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].VirtualAddress));
	printf("[%08X] : Reserved Directory Size[%dbyte]\t\t:%08X\n", offset, sizeof(inh64->OptionalHeader.DataDirectory[i].Size), inh64->OptionalHeader.DataDirectory[i].Size);
	offset = get_file_offset(fp, sizeof(inh64->OptionalHeader.DataDirectory[i].Size));
	i++;
}
*/
