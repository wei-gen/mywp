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
	char cDllPath[250];
	//��ȡ���̾��������Ȩ��
	int enableDebugPriv(const char* name);
	//ִ��Զ��ע��
	int remoteInjection(const DWORD PID);
	void setcDllPath(string path);
	void setTargetProcPID(long pid);

};