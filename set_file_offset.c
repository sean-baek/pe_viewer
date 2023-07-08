#include "header.h"

// 파일 포인터의 현재 위치를 인자로 넘어온 값으로 맞추고, 현재 파일 포인터의 위치를 반환한다.
int set_file_offset(FILE* fp, int offset)
{
	if (fseek(fp, offset, SEEK_SET) != 0)
	{
		perror("fseek()");
		return -1;
	}
	else
		return ftell(fp);
}