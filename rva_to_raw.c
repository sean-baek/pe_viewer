#include "header.h"

/*size : �Ѱ����� ���� ���� rva ���� ���������� ó���ϱ� ����*/
ULONGLONG convert_rva_to_raw(const u_char* binary_buf, void* rva_value, size_t size)
{
	IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)binary_buf;

	switch (size)
	{
	case 4: 
		{
			DWORD raw;
			IMAGE_NT_HEADERS32* rtr_inh32 = (IMAGE_NT_HEADERS32*)(binary_buf + idh->e_lfanew);
			IMAGE_SECTION_HEADER* rtr_ish = (IMAGE_SECTION_HEADER*)(binary_buf + idh->e_lfanew + sizeof(rtr_inh32->Signature) + sizeof(rtr_inh32->FileHeader) + rtr_inh32->FileHeader.SizeOfOptionalHeader);

			//DWORD* test = (DWORD*)rva_value;
			//printf("rva value : %d\n\n", *test);
			for (int i = 0; i < rtr_inh32->FileHeader.NumberOfSections; i++, rtr_ish++)
			{
				// rva ���� ���� section�� maxġ �޸� �� �̻��̰ų� minġ �޸� ������ ������ �������� �ʰ� for������ �ǵ��ư���.
				if (*(DWORD*)rva_value >= rtr_ish->VirtualAddress && *(unsigned long*)rva_value < (rtr_ish->VirtualAddress + rtr_ish->Misc.VirtualSize))
				{

					raw = *(DWORD*)rva_value - rtr_ish->VirtualAddress + rtr_ish->PointerToRawData;
					return raw;
				}
			}
			break;
		}
	case 8:
		{
			ULONGLONG raw;
			IMAGE_NT_HEADERS64* rtr_inh64 = (IMAGE_NT_HEADERS64*)(binary_buf + idh->e_lfanew);
			IMAGE_SECTION_HEADER* rtr_ish = (IMAGE_SECTION_HEADER*)(binary_buf + idh->e_lfanew + sizeof(rtr_inh64->Signature) + sizeof(rtr_inh64->FileHeader) + rtr_inh64->FileHeader.SizeOfOptionalHeader);

			for (int i = 0; i < rtr_inh64->FileHeader.NumberOfSections; i++, rtr_ish++)
			{
				// rva ���� ���� section�� maxġ �޸� �� �̻��̰ų� minġ �޸� ������ ������ �������� �ʰ� for������ �ǵ��ư���.
				if (*(DWORD*)rva_value >= rtr_ish->VirtualAddress && *(unsigned long*)rva_value < (rtr_ish->VirtualAddress + rtr_ish->Misc.VirtualSize))
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

// x86�� ���� �뵵
int rva_to_raw_dword(FILE* fp, u_char** binary_buf, DWORD rva_value)
{
	int raw;
	IMAGE_DOS_HEADER* rtr_idh = (IMAGE_DOS_HEADER*)*binary_buf;
	IMAGE_NT_HEADERS32* rtr_inh32 = (IMAGE_NT_HEADERS32*)(*binary_buf + rtr_idh->e_lfanew);
	IMAGE_SECTION_HEADER* rtr_ish = (IMAGE_SECTION_HEADER*)(*binary_buf + rtr_idh->e_lfanew + sizeof(rtr_inh32->Signature) + sizeof(rtr_inh32->FileHeader) + rtr_inh32->FileHeader.SizeOfOptionalHeader);


	for (int i = 0; i < rtr_inh32->FileHeader.NumberOfSections; i++, rtr_ish++)
	{
		// rva ���� ���� section�� maxġ �޸� �� �̻��̰ų� minġ �޸� ������ ������ �������� �ʰ� for������ �ǵ��ư���.
		if (rva_value >= rtr_ish->VirtualAddress && rva_value < (rtr_ish->VirtualAddress + rtr_ish->Misc.VirtualSize) )
		{

			raw = rva_value - rtr_ish->VirtualAddress + rtr_ish->PointerToRawData;
			return raw;
		}
	}

	return -1;
}

// image_import_descriptor�� ����� �� ����Ѵ�.
ULONGLONG rva_to_raw_ulonglong(FILE* fp, u_char** binary_buf, ULONGLONG rva_value)
{
	ULONGLONG raw;
	IMAGE_DOS_HEADER* rtr_idh = (IMAGE_DOS_HEADER*)*binary_buf;
	IMAGE_NT_HEADERS64* rtr_inh64 = (IMAGE_NT_HEADERS64*)(*binary_buf + rtr_idh->e_lfanew);
	IMAGE_SECTION_HEADER* rtr_ish = (IMAGE_SECTION_HEADER*)(*binary_buf + rtr_idh->e_lfanew + sizeof(rtr_inh64->Signature) + sizeof(rtr_inh64->FileHeader) + rtr_inh64->FileHeader.SizeOfOptionalHeader);


	for (int i = 0; i < rtr_inh64->FileHeader.NumberOfSections; i++, rtr_ish++)
	{
		// rva ���� ���� section�� maxġ �޸� �� �̻��̰ų� minġ �޸� ������ ������ �������� �ʰ� for������ �ǵ��ư���.
		if (rva_value >= rtr_ish->VirtualAddress && rva_value < ((ULONGLONG)rtr_ish->VirtualAddress + (ULONGLONG)rtr_ish->Misc.VirtualSize))
		{

			raw = rva_value - rtr_ish->VirtualAddress + rtr_ish->PointerToRawData;
			return raw;
		}
	}

	return -1;
}

