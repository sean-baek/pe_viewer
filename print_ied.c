#include "header.h"
#include <conio.h>

int print_image_export_directory(FILE* fp, u_char** buf, IMAGE_EXPORT_DIRECTORY* ied)
{
	int raw = 0, num_of_names = 0, num_of_functions = 0;
	IMAGE_EXPORT_DIRECTORY* pied = (IMAGE_EXPORT_DIRECTORY*)ied;

	// EXPORT dll ���
	printf("[%08X] - Characteristics[%zdbyte]\t\t: %08X\n", offset, sizeof(pied->Characteristics), pied->Characteristics);
	offset = get_file_offset(fp, sizeof(pied->Characteristics));

	printf("[%08X] - TimeDateStamp[%zdbyte]\t\t: %08X\n", offset, sizeof(pied->TimeDateStamp), pied->TimeDateStamp);
	offset = get_file_offset(fp, sizeof(pied->TimeDateStamp));

	printf("[%08X] - MajorVersion[%zdbyte]\t\t: %04X\n", offset, sizeof(pied->MajorVersion), pied->MajorVersion);
	offset = get_file_offset(fp, sizeof(pied->MajorVersion));

	printf("[%08X] - MinorVersion[%zdbyte]\t\t: %04X\n", offset, sizeof(pied->MinorVersion), pied->MinorVersion);
	offset = get_file_offset(fp, sizeof(pied->MinorVersion));

	raw = (int)convert_rva_to_raw(*buf, &(ied->Name), 4);
	printf("[%08X] - Name[%zdbyte]\t\t\t: %08X(RVA), %08X(RAW), %s\n", offset, sizeof(pied->Name), ied->Name, raw, *buf + raw);
	offset = get_file_offset(fp, sizeof(pied->Name));

	printf("[%08X] - Base[%zdbyte]\t\t\t: %08X\n", offset, sizeof(pied->Base), pied->Base);
	offset = get_file_offset(fp, sizeof(pied->Base));

	printf("[%08X] - NumberOfFunctions[%zdbyte]\t\t: %08X\n", offset, sizeof(pied->NumberOfFunctions), pied->NumberOfFunctions);
	offset = get_file_offset(fp, sizeof(pied->NumberOfFunctions));

	printf("[%08X] - NumberOfNames[%zdbyte]\t\t: %08X\n", offset, sizeof(pied->NumberOfNames), pied->NumberOfNames);
	offset = get_file_offset(fp, sizeof(pied->NumberOfNames));

	printf("[%08X] - AddressOfFunctions[%zdbyte]\t\t: %08X(RVA), %08X(RAW)\n", offset, sizeof(pied->AddressOfFunctions), pied->AddressOfFunctions, (int)convert_rva_to_raw(*buf, &(pied->AddressOfFunctions), 4));
	offset = get_file_offset(fp, sizeof(pied->AddressOfFunctions));

	printf("[%08X] - AddressOfNames[%zdbyte]\t\t: %08X(RVA), %08X(RAW)\n", offset, sizeof(pied->AddressOfNames), pied->AddressOfNames, (int)convert_rva_to_raw(*buf, &(pied->AddressOfNames), 4));
	offset = get_file_offset(fp, sizeof(pied->AddressOfNames));

	printf("[%08X] - AddressOfNameOrdinals[%zdbyte]\t: %08X(RVA), %08X(RAW)\n", offset, sizeof(pied->AddressOfNameOrdinals), pied->AddressOfNameOrdinals, (int)convert_rva_to_raw(*buf, &(pied->AddressOfNameOrdinals), 4));
	offset = get_file_offset(fp, sizeof(pied->AddressOfNameOrdinals));

	printf("\n----------------------------------------\n\n");
	printf("-------------------- ( EAT ) --------------------\n\n");

	// �̸� �迭�� ����, �Լ� �迭�� ����
	num_of_names = pied->NumberOfNames;
	num_of_functions = pied->NumberOfFunctions;
	printf("number of names : %d\n", num_of_names);
	printf("number of functions : %d\n\n", num_of_functions);
	printf("-------------------------------------------------\n\n");

	// EXPORT �Լ� �̸��� ���� RAW ��ġ
	raw = (int)convert_rva_to_raw(*buf, &(pied->Name), 4);
	char* offset_export_func_names = (char*)(*buf + raw + (strlen(*buf + raw) + 1));

	// �̸� �迭�� �ּ�(�̸� �迭�� �ִ� �� 4byte RVA ������ ����Ű�� ����)
	raw = (int)convert_rva_to_raw(*buf, &(pied->AddressOfNames), 4);
	DWORD *pnames =(DWORD*)(*buf + raw);

	// ordinals
	raw = (int)convert_rva_to_raw(*buf, &(pied->AddressOfNameOrdinals), 4);
	WORD* pordinals = (WORD*)(*buf + raw);

	// function
	raw = (int)convert_rva_to_raw(*buf, &(pied->AddressOfFunctions), 4);
	DWORD* pfunctions = (DWORD*)(*buf + raw);

	// Export �Լ� �̸� �迭(RAW)�� �ּҸ� ����Ͽ� ���
	char* p_offset_export_func_names = offset_export_func_names;

	for (int i = 0; i < num_of_functions; i++, p_offset_export_func_names += (strlen(p_offset_export_func_names) + 1))
	{
		short ordinal = -1;
		DWORD eat_rva = 0, n_index = -1, f_index = -1;
		DWORD* ppnames = pnames; // addfess of names
		DWORD* ppfunctions = pfunctions; // address of functions
		
		for (int j = 0; j < num_of_names; j++, ppnames++)
		{
			// VirtualOfNames RAW �ּҿ� �ִ� RVA ������ raw�� ��ȯ�Ͽ� �ش� ��ġ�� �ִ� ���ڿ���
			// EXPORT �Լ����� �̸� �迭(RAW)�� �ִ� ���ڿ��� ��ġ���� �˻�
			raw = (int)convert_rva_to_raw(*buf, ppnames, 4);
			if (!strcmp(p_offset_export_func_names, *buf + raw))
			{
				n_index = j;
				break;
			}
		}		
		
		// EXPORT �Լ� �̸��� �ش��ϴ� ordinal
		// n_index = name_index, 
		if (n_index != -1)
		{
			ordinal = *(pordinals + n_index);
		}
		else
		{
			i -= 1;
			continue;
		}

		// EXPORT �Լ� �ּ� �迭���� + ordinal�� ��ġ�� �ش��ϴ� ��
		if (ordinal != -1)
			eat_rva = *(ppfunctions + ordinal);
		

		// function ordinal ���ϱ�
		if (eat_rva != 0)
		{
			for (int k = 0; k < num_of_functions; k++, ppfunctions++)
			{
				if (eat_rva == *ppfunctions)
				{
					f_index = (k + 1);
					break;
				}
			}
		}
		
		if (eat_rva != 0)
		{
			// NO : �Լ��� ������ŭ ��µƴ��� Ȯ���ϱ� ����
			printf("No.%d [%s]\n- %ld(Name Index)\n- %04X(Name Ordinal)\n- %08X(Name RVA), %08X(Name RAW)\n- %08X(Function Ordinal)\n- %08X(Function RVA)\n\n", i+1, p_offset_export_func_names, n_index, ordinal, *ppnames, raw, f_index, eat_rva);
			printf("-------------------------------------------------\n\n");
		}
		
		// ����ڰ� �Է��� ���� q�̸� ���α׷� ����, �װ� �ƴ϶�� ��� �ݺ�
		int ch = _getch();
		if (ch == 'q')
		{
			printf("���α׷� ����\n");
			return 0;
		}
	}

	//�Լ� �̸� ���� Ordinal�θ� Export�� �Լ��� �ּҸ� ã�� ���� �ִ�.
	
	return 0;
}