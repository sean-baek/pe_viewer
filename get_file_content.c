#include "header.h"

// ���� ����� ���� �� ������ ������ ���� �޸𸮿� ����
void* get_file_content(FILE* fp, int *size)
{
	void* buf = NULL;

	// ���� ������ ���ؿ���
	if ((*size = get_file_size(fp)) < 0)
	{
		printf("get_file_size() error\n");
		return NULL;
	}
	
	// ���� �����ŭ �޸� ���� �Ҵ�
	if ((buf = malloc(*size)) == NULL)
	{
		printf("malloc() error\n");
		return NULL;
	}

	// ���� �Ҵ��� heap �޸� ������ 0���� �ʱ�ȭ
	if (memset(buf, 0x00, *size) == NULL)
	{
		printf("memset() error\n");
		return NULL;
	}

	// ���� �Ҵ��� �޸𸮿� file ���� ��ü �б�
	if (fread(buf, 1, *size, fp) != *size)
	{
		printf("fread() error\n");
		return NULL;
	}

	// ���� ����� ���ؿ԰�, ������ �о��ٸ� �ٽ� ���� �����͸� ó������ ��ġ
	rewind(fp);

	return buf;
}