#pragma
#include <Windows.h>
#include <iostream>
#include <string>
using namespace std;

class RemoteInjector
{
public:
	//Ŀ�����PID
	DWORD targetProcPID = 0;
	string strDllPath;
	//��ȡ���̾��������Ȩ��
	int EnableDebugPriv(const char* name);
	//ִ��Զ��ע��
	int remoteInjection(const DWORD PID);

};