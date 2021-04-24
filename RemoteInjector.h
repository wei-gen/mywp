#pragma
#include <Windows.h>
#include <iostream>
#include <string>
using namespace std;

class RemoteInjector
{
public:
	//目标进程PID
	DWORD targetProcPID = 0;
	string strDllPath;
	//获取进程句柄，提升权限
	int EnableDebugPriv(const char* name);
	//执行远程注入
	int remoteInjection(const DWORD PID);

};