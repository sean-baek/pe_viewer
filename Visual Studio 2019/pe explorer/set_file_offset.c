#include "header.h"

// ���� �������� ���� ��ġ�� ���ڷ� �Ѿ�� ������ ���߰�, ���� ���� �������� ��ġ�� ��ȯ�Ѵ�.
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