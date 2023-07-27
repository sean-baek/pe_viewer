#include "header.h"

void print_image_import_descriptor(FILE* fp, u_char* buf, operand operand_type)
{
	IMAGE_DOS_HEADER* piid_idh = (IMAGE_DOS_HEADER*)buf;

	switch (operand_type)
	{
		unsigned int raw = 0;

		case OPERAND_IID32:
		{
			IMAGE_NT_HEADERS32* piid_inh32 = (IMAGE_NT_HEADERS32*)(buf + piid_idh->e_lfanew);

			// IID 구조체 배열의 크기
			int piid_size = piid_inh32->OptionalHeader.DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

			// IMAGE_IMPORT_DESCRIPTOR 구조체 배열의 시작 주소 RVA 값을 RAW로 변환
			raw = (int)convert_rva_to_raw(buf, &(piid_inh32->OptionalHeader.DataDirectory[1].VirtualAddress), OPERAND_DWORD);

			// IMPORT Directory 파일에서의 주소
			printf("IMPORT DESCRIPTOR\t: 0x%X(RVA), 0x%X(RAW)\n\n", piid_inh32->OptionalHeader.DataDirectory[1].VirtualAddress, raw);

			// IID 목록 개수
			printf("IMPORT DESCRIPTOR count\t: 0x%X(%d)\n\n", piid_size, piid_size);

			// IMAGE_IMPORT_DESCRIPTOR 구조체 배열의 실제 주소를 지정
			IMAGE_IMPORT_DESCRIPTOR* iid = (IMAGE_IMPORT_DESCRIPTOR*)(buf + raw);
			// IMPORT DLL 파일들 목록 출력 후 각 IMPORT DLL 파일 속 함수들을 출력하기 위해 다시 초기화해야 하므로 백업
			IMAGE_IMPORT_DESCRIPTOR* piid = iid;

			// IMPORT DLL 파일들 출력
			for (int i = 0; i < piid_size; i++, piid++)
			{
				// IMAGE_IMPORT_DESCRIPTOR 구조체의 마지막 부분은 0으로 되어 있음
				if (piid->Characteristics == 0x00000000 && piid->OriginalFirstThunk == 0x00000000 && piid->TimeDateStamp == 0x00000000 && piid->ForwarderChain == 0x00000000 && piid->Name == 0x00000000 && piid->FirstThunk == 0x00000000)
					break;

				raw = (int)convert_rva_to_raw(buf, &(piid->Name), OPERAND_DWORD);
				printf("Name : [ %s ]\n", buf + raw);

				printf("[%08X] - OriginalFirstThunk[%zdbyte]\t: %08X(RVA), %08X(RAW)\n", offset, sizeof(piid->OriginalFirstThunk), piid->OriginalFirstThunk, (unsigned int)convert_rva_to_raw(buf, &(piid->OriginalFirstThunk), OPERAND_DWORD));
				offset = get_file_offset(fp, sizeof(piid->OriginalFirstThunk));

				printf("[%08X] - TimeDateStamp[%zdbyte]\t: %08X(RVA)\n", offset, sizeof(piid->TimeDateStamp), piid->TimeDateStamp);
				offset = get_file_offset(fp, sizeof(piid->TimeDateStamp));

				printf("[%08X] - ForwarderChain[%zdbyte]\t: %08X(RVA)\n", offset, sizeof(piid->ForwarderChain), piid->ForwarderChain);
				offset = get_file_offset(fp, sizeof(piid->ForwarderChain));

				printf("[%08X] - Name[%zdbyte]\t\t: %08X(RVA), %08X(RAW)\n", offset, sizeof(piid->Name), piid->Name, raw);
				offset = get_file_offset(fp, sizeof(piid->Name));

				printf("[%08X] - FirstThunk[%zdbyte]\t\t: %08X(RVA), %08X(RAW)\n\n", offset, sizeof(piid->FirstThunk), piid->FirstThunk, (unsigned int)convert_rva_to_raw(buf, &(piid->FirstThunk), OPERAND_DWORD));
				offset = get_file_offset(fp, sizeof(piid->FirstThunk));

				printf("-----------------------------------------------\n\n");
			}

			// dll 라이브러리들 이름은 출력했으니 각 라이브러리의 함수들의 hint와 이름 출력
			printf("-------------- (IMAGE NAME TABLE, IMAGE IAT TABLE) --------------\n\n");
			piid = iid;

			// IMAGE_IMPORT_DESCRIPTOR 구조체의 크기만큼 반복한다.
			for (int i = 0; i < piid_size; i++, piid++)
			{
				if (piid->Characteristics == 0x00000000 && piid->OriginalFirstThunk == 0x00000000 && piid->TimeDateStamp == 0x00000000 && piid->ForwarderChain == 0x00000000 && piid->Name == 0x00000000 && piid->FirstThunk == 0x00000000)
					break;

				// IMPORT 함수가 어떤 dll 라이브러리에 속해있는지 확인하기 위해 라이브러리 이름 출력
				raw = (int)convert_rva_to_raw(buf, &(piid->Name), OPERAND_DWORD);
				printf("[%08X] - [***** %s *****]\n\n", raw, buf + raw);

				// IMAGE IMPORT Descriptor 구조체의 OriginalFirstThunk 구조체에 있는 값(RVA)은 IMAGE_THUNK_DATA의 멤버 변수의 값이다.
				raw = (int)convert_rva_to_raw(buf, &(piid->OriginalFirstThunk), OPERAND_DWORD);
				IMAGE_THUNK_DATA32* itd_oft32 = (IMAGE_THUNK_DATA32*)(buf + raw);

				raw = (int)convert_rva_to_raw(buf, &(piid->FirstThunk), OPERAND_DWORD);
				IMAGE_THUNK_DATA32* itd_ft32 = (IMAGE_THUNK_DATA32*)(buf + raw);

				// IMAGE THUNK DATA 구조체의 마지막은 0x00000000 값이다.
				// 해당 값이 아닐 동안 반복하여 dll 라이브러리 속 함수들 출력
				for (; itd_oft32->u1.AddressOfData != 0x00000000; itd_oft32++, itd_ft32++)
				{
					raw = (int)convert_rva_to_raw(buf, &(itd_oft32->u1.AddressOfData), OPERAND_DWORD);
					IMAGE_IMPORT_BY_NAME* iibn32 = (IMAGE_IMPORT_BY_NAME*)(buf + raw);

					// name
					fseek(fp, raw, SEEK_SET);
					offset = get_file_offset(fp, sizeof(iibn32->Hint));
					printf("[%08X] - Name : %s()\n", offset, iibn32->Name);

					// hint value
					offset = get_file_offset(fp, -2);
					printf("[%08X] - Hint : 0x%X\n", ftell(fp), iibn32->Hint);

					// IAT 영역 출력
					fseek(fp, (long)convert_rva_to_raw(buf, &(piid->FirstThunk), OPERAND_DWORD), SEEK_SET);
					offset = ftell(fp);
					printf("[%08X] - IAT : %08X(RVA), %08X(RAW)\n\n", offset, itd_ft32->u1.Function, (unsigned int)convert_rva_to_raw(buf, &(itd_ft32->u1.Function), OPERAND_DWORD));
				}
				printf("----------------------------------------\n\n");
			}
			printf("-----------------------------------------------------------------\n\n");
			
			break;
		}
		case OPERAND_IID64:
		{
			ULONGLONG ull_raw = 0;

			IMAGE_NT_HEADERS64* piid_inh64 = (IMAGE_NT_HEADERS64*)(buf + piid_idh->e_lfanew);

			// IID 구조체 배열의 크기
			int piid_size = piid_inh64->OptionalHeader.DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);

			// IMAGE_IMPORT_DESCRIPTOR 구조체 배열의 시작 주소 RVA 값을 RAW로 변환
			raw = (int)convert_rva_to_raw(buf, &(piid_inh64->OptionalHeader.DataDirectory[1].VirtualAddress), OPERAND_DWORD);

			// IMPORT Directory 파일에서의 주소
			printf("IMPORT DESCRIPTOR\t: 0x%X(RVA), 0x%X(RAW)\n\n", piid_inh64->OptionalHeader.DataDirectory[1].VirtualAddress, raw);

			// IID 목록 개수
			printf("IMPORT DESCRIPTOR count\t: 0x%X(%d)\n\n", piid_size, piid_size);

			// IMAGE_IMPORT_DESCRIPTOR 구조체 배열의 실제 주소를 지정
			IMAGE_IMPORT_DESCRIPTOR* iid = (IMAGE_IMPORT_DESCRIPTOR*)(buf + raw);
			// IMPORT DLL 파일들 목록 출력 후 각 IMPORT DLL 파일 속 함수들을 출력하기 위해 다시 초기화해야 하므로 백업
			IMAGE_IMPORT_DESCRIPTOR* piid = iid;


			// IMPORT DLL 파일들 출력
			for (int i = 0; i < piid_size; i++, piid++)
			{
				// IMAGE_IMPORT_DESCRIPTOR 구조체의 마지막 부분은 0으로 되어 있음
				if (piid->Characteristics == 0x00000000 && piid->OriginalFirstThunk == 0x00000000 && piid->TimeDateStamp == 0x00000000 && piid->ForwarderChain == 0x00000000 && piid->Name == 0x00000000 && piid->FirstThunk == 0x00000000)
					break;

				raw = (int)convert_rva_to_raw(buf, &(piid->Name), OPERAND_DWORD);
				printf("Name : [ %s ]\n", buf + raw);

				printf("[%08X] - OriginalFirstThunk[%zdbyte]\t: %08X(RVA), %08X(RAW)\n", offset, sizeof(piid->OriginalFirstThunk), piid->OriginalFirstThunk, (unsigned int)convert_rva_to_raw(buf, &(piid->OriginalFirstThunk), OPERAND_DWORD));
				offset = get_file_offset(fp, sizeof(piid->OriginalFirstThunk));

				printf("[%08X] - TimeDateStamp[%zdbyte]\t: %08X(RVA)\n", offset, sizeof(piid->TimeDateStamp), piid->TimeDateStamp);
				offset = get_file_offset(fp, sizeof(piid->TimeDateStamp));

				printf("[%08X] - ForwarderChain[%zdbyte]\t: %08X(RVA)\n", offset, sizeof(piid->ForwarderChain), piid->ForwarderChain);
				offset = get_file_offset(fp, sizeof(piid->ForwarderChain));

				printf("[%08X] - Name[%zdbyte]\t\t: %08X(RVA), %08X(RAW)\n", offset, sizeof(piid->Name), piid->Name, raw);
				offset = get_file_offset(fp, sizeof(piid->Name));

				printf("[%08X] - FirstThunk[%zdbyte]\t\t: %08X(RVA), %08X(RAW)\n\n", offset, sizeof(piid->FirstThunk), piid->FirstThunk, (unsigned int)convert_rva_to_raw(buf, &(piid->FirstThunk), OPERAND_DWORD));
				offset = get_file_offset(fp, sizeof(piid->FirstThunk));

				printf("-----------------------------------------------\n\n");
			}

			// dll 라이브러리들 이름은 출력했으니 각 라이브러리의 함수들의 hint와 이름 출력
			printf("-------------- (IMAGE NAME TABLE, IMAGE IAT TABLE) --------------\n\n");
			piid = iid;

			// IMAGE_IMPORT_DESCRIPTOR 구조체의 크기만큼 반복한다.
			for (int i = 0; i < piid_size; i++, piid++)
			{
				if (piid->Characteristics == 0x00000000 && piid->OriginalFirstThunk == 0x00000000 && piid->TimeDateStamp == 0x00000000 && piid->ForwarderChain == 0x00000000 && piid->Name == 0x00000000 && piid->FirstThunk == 0x00000000)
					break;

				// IMPORT 함수가 어떤 dll 라이브러리에 속해있는지 확인하기 위해 라이브러리 이름 출력
				raw = (int)convert_rva_to_raw(buf, &(piid->Name), OPERAND_DWORD);
				printf("[%08X] - [***** %s *****]\n\n", raw, buf + raw);

				// IMAGE IMPORT Descriptor 구조체의 OriginalFirstThunk 구조체에 있는 값(RVA)은 IMAGE_THUNK_DATA의 멤버 변수의 값이다.
				raw = (int)convert_rva_to_raw(buf, &(piid->OriginalFirstThunk), OPERAND_DWORD);
				IMAGE_THUNK_DATA64* itd_oft64 = (IMAGE_THUNK_DATA64*)(buf + raw);

				raw = (int)convert_rva_to_raw(buf, &(piid->FirstThunk), OPERAND_DWORD);
				IMAGE_THUNK_DATA64* itd_ft64 = (IMAGE_THUNK_DATA64*)(buf + raw);

				// IMAGE THUNK DATA 구조체의 마지막은 0x00000000 값이다.
				// 해당 값이 아닐 동안 반복하여 dll 라이브러리 속 함수들 출력
				for (; itd_oft64->u1.AddressOfData != 0x00000000; itd_oft64++, itd_ft64++)
				{
					ull_raw = (ULONGLONG)convert_rva_to_raw(buf, &(itd_oft64->u1.AddressOfData), OPERAND_ULONGLONG);
					IMAGE_IMPORT_BY_NAME* iibn64 = (IMAGE_IMPORT_BY_NAME*)(buf + ull_raw);

					// name
					_fseeki64(fp, ull_raw, SEEK_SET);
					offset = get_file_offset(fp, sizeof(iibn64->Hint));
					printf("[%08X] - Name : %s()\n", offset, iibn64->Name);

					// hint value
					offset = get_file_offset(fp, -2);
					printf("[%08X] - Hint : %X\n", ftell(fp), iibn64->Hint);

					// IAT 영역 출력
					_fseeki64(fp, convert_rva_to_raw(buf, &(piid->FirstThunk), OPERAND_DWORD), SEEK_SET);
					offset = ftell(fp);
					printf("[%08X] - IAT : %llX(RVA), %llX(RAW)\n\n", offset, itd_ft64->u1.Function, convert_rva_to_raw(buf, &(itd_ft64->u1.Function), OPERAND_DWORD));
				}
				printf("----------------------------------------\n\n");
			}
			printf("-----------------------------------------------------------------\n\n");
			break;
		}
	}
}
/*
void print_image_import_descriptor(FILE* fp, u_char* buf, IMAGE_IMPORT_DESCRIPTOR* iid, int size)
{
	IMAGE_DOS_HEADER* piid_idh = (IMAGE_DOS_HEADER*)buf;
	IMAGE_NT_HEADERS* piid_inh = (IMAGE_NT_HEADERS*)(buf + piid_idh->e_lfanew);
	IMAGE_OPTIONAL_HEADER* piid_ioh = (IMAGE_OPTIONAL_HEADER*)(buf + piid_idh->e_lfanew + sizeof(piid_inh->Signature) + sizeof(piid_inh->FileHeader));
	IMAGE_IMPORT_DESCRIPTOR* piid = (IMAGE_IMPORT_DESCRIPTOR*)iid;
	int raw = 0;
	ULONGLONG ull_raw = 0;

	// IMPORT DLL 파일들 출력
	for (int i = 0; i < size; i++, piid++)
	{
		// IMAGE_IMPORT_DESCRIPTOR 구조체의 마지막 부분은 0으로 되어 있음
		if (piid->Characteristics == 0x00000000 && piid->OriginalFirstThunk == 0x00000000 && piid->TimeDateStamp == 0x00000000 && piid->ForwarderChain == 0x00000000 && piid->Name == 0x00000000 && piid->FirstThunk == 0x00000000)
			break;

		raw = (int)convert_rva_to_raw(buf, &(piid->Name), OPERAND_DWORD);
		printf("Name : [ %s ]\n", buf + raw);

		printf("[%08X] - OriginalFirstThunk[%zdbyte]\t: %08X(RVA), %08X(RAW)\n", offset, sizeof(piid->OriginalFirstThunk), piid->OriginalFirstThunk, (unsigned int)convert_rva_to_raw(buf, &(piid->OriginalFirstThunk), OPERAND_DWORD));
		offset = get_file_offset(fp, sizeof(piid->OriginalFirstThunk));

		printf("[%08X] - TimeDateStamp[%zdbyte]\t: %08X(RVA)\n", offset, sizeof(piid->TimeDateStamp), piid->TimeDateStamp);
		offset = get_file_offset(fp, sizeof(piid->TimeDateStamp));

		printf("[%08X] - ForwarderChain[%zdbyte]\t: %08X(RVA)\n", offset, sizeof(piid->ForwarderChain), piid->ForwarderChain);
		offset = get_file_offset(fp, sizeof(piid->ForwarderChain));

		printf("[%08X] - Name[%zdbyte]\t\t: %08X(RVA), %08X(RAW)\n", offset, sizeof(piid->Name), piid->Name, raw);
		offset = get_file_offset(fp, sizeof(piid->Name));

		printf("[%08X] - FirstThunk[%zdbyte]\t\t: %08X(RVA), %08X(RAW)\n\n", offset, sizeof(piid->FirstThunk), piid->FirstThunk, (unsigned int)convert_rva_to_raw(buf, &(piid->FirstThunk), OPERAND_DWORD));
		offset = get_file_offset(fp, sizeof(piid->FirstThunk));

		printf("-----------------------------------------------\n\n");
	}

	// dll 라이브러리들 이름은 출력했으니 각 라이브러리의 함수들의 hint와 이름 출력
	printf("-------------- (IMAGE NAME TABLE, IMAGE IAT TABLE) --------------\n\n");
	piid = (IMAGE_IMPORT_DESCRIPTOR*)iid;
	
	if (piid_ioh->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		// IMAGE_IMPORT_DESCRIPTOR 구조체의 크기만큼 반복한다.
		for (int i = 0; i < size; i++, piid++)
		{
			if (piid->Characteristics == 0x00000000 && piid->OriginalFirstThunk == 0x00000000 && piid->TimeDateStamp == 0x00000000 && piid->ForwarderChain == 0x00000000 && piid->Name == 0x00000000 && piid->FirstThunk == 0x00000000)
				break;

			// IMPORT 함수가 어떤 dll 라이브러리에 속해있는지 확인하기 위해 라이브러리 이름 출력
			raw = (int)convert_rva_to_raw(buf, &(piid->Name), OPERAND_DWORD);
			printf("[%08X] - [***** %s *****]\n\n", raw, buf + raw);

			// IMAGE IMPORT Descriptor 구조체의 OriginalFirstThunk 구조체에 있는 값(RVA)은 IMAGE_THUNK_DATA의 멤버 변수의 값이다.
			raw = (int)convert_rva_to_raw(buf, &(piid->OriginalFirstThunk), OPERAND_DWORD);
			IMAGE_THUNK_DATA32* itd_oft32 = (IMAGE_THUNK_DATA32*)(buf + raw);

			raw = (int)convert_rva_to_raw(buf, &(piid->FirstThunk), OPERAND_DWORD);
			IMAGE_THUNK_DATA32* itd_ft32 = (IMAGE_THUNK_DATA32*)(buf + raw);

			// IMAGE THUNK DATA 구조체의 마지막은 0x00000000 값이다.
			// 해당 값이 아닐 동안 반복하여 dll 라이브러리 속 함수들 출력
			for (; itd_oft32->u1.AddressOfData != 0x00000000; itd_oft32++, itd_ft32++)
			{
				raw = (int)convert_rva_to_raw(buf, &(itd_oft32->u1.AddressOfData), OPERAND_DWORD);
				IMAGE_IMPORT_BY_NAME* iibn32 = (IMAGE_IMPORT_BY_NAME*)(buf + raw);

				// name
				fseek(fp, raw, SEEK_SET);
				offset = get_file_offset(fp, sizeof(iibn32->Hint));
				printf("[%08X] - Name : %s()\n", offset, iibn32->Name);
				
				// hint value
				offset = get_file_offset(fp, -2);
				printf("[%08X] - Hint : 0x%X\n", ftell(fp), iibn32->Hint);

				// IAT 영역 출력
				fseek(fp, (long)convert_rva_to_raw(buf, &(piid->FirstThunk), OPERAND_DWORD), SEEK_SET);
				offset = ftell(fp);
				printf("[%08X] - IAT : %08X(RVA), %08X(RAW)\n\n", offset, itd_ft32->u1.Function, (unsigned int)convert_rva_to_raw(buf, &(itd_ft32->u1.Function), OPERAND_DWORD));
			}
			printf("----------------------------------------\n\n");
		}
		printf("-----------------------------------------------------------------\n\n");
	}
	else if (piid_ioh->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		// IMAGE_IMPORT_DESCRIPTOR 구조체의 크기만큼 반복한다.
		for (int i = 0; i < size; i++, piid++)
		{
			if (piid->Characteristics == 0x00000000 && piid->OriginalFirstThunk == 0x00000000 && piid->TimeDateStamp == 0x00000000 && piid->ForwarderChain == 0x00000000 && piid->Name == 0x00000000 && piid->FirstThunk == 0x00000000)
				break;

			// IMPORT 함수가 어떤 dll 라이브러리에 속해있는지 확인하기 위해 라이브러리 이름 출력
			raw = (int)convert_rva_to_raw(buf, &(piid->Name), OPERAND_DWORD);
			printf("[%08X] - [***** %s *****]\n\n", raw, buf + raw);

			// IMAGE IMPORT Descriptor 구조체의 OriginalFirstThunk 구조체에 있는 값(RVA)은 IMAGE_THUNK_DATA의 멤버 변수의 값이다.
			raw = (int)convert_rva_to_raw(buf, &(piid->OriginalFirstThunk), OPERAND_DWORD);
			IMAGE_THUNK_DATA64* itd_oft64 = (IMAGE_THUNK_DATA64*)(buf + raw);

			raw = (int)convert_rva_to_raw(buf, &(piid->FirstThunk), OPERAND_DWORD);
			IMAGE_THUNK_DATA64* itd_ft64 = (IMAGE_THUNK_DATA64*)(buf + raw);

			// IMAGE THUNK DATA 구조체의 마지막은 0x00000000 값이다.
			// 해당 값이 아닐 동안 반복하여 dll 라이브러리 속 함수들 출력
			for (; itd_oft64->u1.AddressOfData != 0x00000000; itd_oft64++, itd_ft64++)
			{
				ull_raw = (ULONGLONG)convert_rva_to_raw(buf, &(itd_oft64->u1.AddressOfData), OPERAND_ULONGLONG);
				IMAGE_IMPORT_BY_NAME* iibn64 = (IMAGE_IMPORT_BY_NAME*)(buf + ull_raw);

				// name
				_fseeki64(fp, ull_raw, SEEK_SET);
				offset = get_file_offset(fp, sizeof(iibn64->Hint));
				printf("[%08X] - Name : %s()\n", offset, iibn64->Name);

				// hint value
				offset = get_file_offset(fp, -2);
				printf("[%08X] - Hint : %X\n", ftell(fp), iibn64->Hint);

				// IAT 영역 출력
				_fseeki64(fp, convert_rva_to_raw(buf, &(piid->FirstThunk), OPERAND_DWORD), SEEK_SET);
				offset = ftell(fp);
				printf("[%08X] - IAT : %llX(RVA), %llX(RAW)\n\n", offset, itd_ft64->u1.Function, convert_rva_to_raw(buf, &(itd_ft64->u1.Function), OPERAND_DWORD));
			}
			printf("----------------------------------------\n\n");
		}
		printf("-----------------------------------------------------------------\n\n");
	}
}
*/