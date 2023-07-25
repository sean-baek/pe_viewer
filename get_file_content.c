#include "header.h"

// 파일 사이즈를 구한 후 파일의 내용을 동적 메모리에 저장
void* get_file_content(FILE* fp, int *size)
{
	void* buf = NULL;

	// 파일 사이즈 구해오기
	if ((*size = get_file_size(fp)) < 0)
	{
		printf("get_file_size() error\n");
		return NULL;
	}
	
	// 파일 사이즈만큼 메모리 동적 할당
	if ((buf = malloc(*size)) == NULL)
	{
		printf("malloc() error\n");
		return NULL;
	}

	// 동적 할당한 heap 메모리 공간을 0으로 초기화
	if (memset(buf, 0x00, *size) == NULL)
	{
		printf("memset() error\n");
		return NULL;
	}

	// 동적 할당한 메모리에 file 내용 전체 읽기
	if (fread(buf, 1, *size, fp) != *size)
	{
		printf("fread() error\n");
		return NULL;
	}

	// 파일 사이즈를 구해왔고, 내용을 읽었다면 다시 파일 포인터를 처음으로 위치
	rewind(fp);

	return buf;
}