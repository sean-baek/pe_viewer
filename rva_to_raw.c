#include "header.h"

/*operand_type : 넘겨지는 값에 따라 rva 값을 유동적으로 처리하기 위함*/
ULONGLONG convert_rva_to_raw(const u_char* binary_buf, void* rva_value, operand operand_type)
{
	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)binary_buf;

	switch (operand_type)
	{
	case OPERAND_DWORD:
		{
			DWORD raw;
			IMAGE_NT_HEADERS32* rtr_inh32 = (IMAGE_NT_HEADERS32*)(binary_buf + idh->e_lfanew);
			IMAGE_SECTION_HEADER* rtr_ish = (IMAGE_SECTION_HEADER*)(binary_buf + idh->e_lfanew + sizeof(rtr_inh32->Signature) + sizeof(rtr_inh32->FileHeader) + rtr_inh32->FileHeader.SizeOfOptionalHeader);

			for (int i = 0; i < rtr_inh32->FileHeader.NumberOfSections; i++, rtr_ish++)
			{
				// rva 값이 현재 section의 max치 메모리 값 이상이거나 min치 메모리 값보다 작으면 진행하지 않고 for문으로 되돌아간다.
				if (*(DWORD*)rva_value >= rtr_ish->VirtualAddress && *(DWORD*)rva_value < (rtr_ish->VirtualAddress + rtr_ish->Misc.VirtualSize))
				{

					raw = *(DWORD*)rva_value - rtr_ish->VirtualAddress + rtr_ish->PointerToRawData;
					return raw;
				}
			}
			break;
		}
	case OPERAND_ULONGLONG:
		{
			ULONGLONG raw;
			IMAGE_NT_HEADERS64* rtr_inh64 = (IMAGE_NT_HEADERS64*)(binary_buf + idh->e_lfanew);
			IMAGE_SECTION_HEADER* rtr_ish = (IMAGE_SECTION_HEADER*)(binary_buf + idh->e_lfanew + sizeof(rtr_inh64->Signature) + sizeof(rtr_inh64->FileHeader) + rtr_inh64->FileHeader.SizeOfOptionalHeader);

			for (int i = 0; i < rtr_inh64->FileHeader.NumberOfSections; i++, rtr_ish++)
			{
				// rva 값이 현재 section의 max치 메모리 값 이상이거나 min치 메모리 값보다 작으면 진행하지 않고 for문으로 되돌아간다.
				if (*(ULONGLONG*)rva_value >= rtr_ish->VirtualAddress && *(ULONGLONG*)rva_value < (rtr_ish->VirtualAddress + rtr_ish->Misc.VirtualSize))
				{

					raw = *(ULONGLONG*)rva_value - rtr_ish->VirtualAddress + rtr_ish->PointerToRawData;
					return raw;
				}
			}
			break;
		}
	}

	return (ULONGLONG) - 1;
}

// x86을 위한 용도
/*
DWORD rva_to_raw_dword(FILE* fp, u_char** binary_buf, DWORD rva_value)
{
	int raw;
	IMAGE_DOS_HEADER* rtr_idh = (IMAGE_DOS_HEADER*)*binary_buf;
	IMAGE_NT_HEADERS32* rtr_inh32 = (IMAGE_NT_HEADERS32*)(*binary_buf + rtr_idh->e_lfanew);
	IMAGE_SECTION_HEADER* rtr_ish = (IMAGE_SECTION_HEADER*)(*binary_buf + rtr_idh->e_lfanew + sizeof(rtr_inh32->Signature) + sizeof(rtr_inh32->FileHeader) + rtr_inh32->FileHeader.SizeOfOptionalHeader);


	for (int i = 0; i < rtr_inh32->FileHeader.NumberOfSections; i++, rtr_ish++)
	{
		// rva 값이 현재 section의 max치 메모리 값 이상이거나 min치 메모리 값보다 작으면 진행하지 않고 for문으로 되돌아간다.
		if (rva_value >= rtr_ish->VirtualAddress && rva_value < (rtr_ish->VirtualAddress + rtr_ish->Misc.VirtualSize) )
		{

			raw = rva_value - rtr_ish->VirtualAddress + rtr_ish->PointerToRawData;
			return raw;
		}
	}

	return -1;
}
*/

// image_import_descriptor를 출력할 때 사용한다.
/*
ULONGLONG rva_to_raw_ulonglong(FILE* fp, u_char** binary_buf, ULONGLONG rva_value)
{
	ULONGLONG raw;
	IMAGE_DOS_HEADER* rtr_idh = (IMAGE_DOS_HEADER*)*binary_buf;
	IMAGE_NT_HEADERS64* rtr_inh64 = (IMAGE_NT_HEADERS64*)(*binary_buf + rtr_idh->e_lfanew);
	IMAGE_SECTION_HEADER* rtr_ish = (IMAGE_SECTION_HEADER*)(*binary_buf + rtr_idh->e_lfanew + sizeof(rtr_inh64->Signature) + sizeof(rtr_inh64->FileHeader) + rtr_inh64->FileHeader.SizeOfOptionalHeader);


	for (int i = 0; i < rtr_inh64->FileHeader.NumberOfSections; i++, rtr_ish++)
	{
		// rva 값이 현재 section의 max치 메모리 값 이상이거나 min치 메모리 값보다 작으면 진행하지 않고 for문으로 되돌아간다.
		if (rva_value >= rtr_ish->VirtualAddress && rva_value < ((ULONGLONG)rtr_ish->VirtualAddress + (ULONGLONG)rtr_ish->Misc.VirtualSize))
		{

			raw = rva_value - rtr_ish->VirtualAddress + rtr_ish->PointerToRawData;
			return raw;
		}
	}

	return -1;
}
*/