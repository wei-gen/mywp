#include "RemoteInjector.h"

int RemoteInjector::EnableDebugPriv(const char* name)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    //打开进程令牌环
    //GetCurrentProcess()获取当前进程句柄
    OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    //获得进程本地唯一ID
    LookupPrivilegeValue(NULL, (LPCWSTR)name, &luid);
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tp.Privileges[0].Luid = luid;
    //调整权限
    int ret = AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    return ret;
}

int RemoteInjector::remoteInjection(const DWORD PID)
{
    HANDLE hRemoteProcess;
    HANDLE hRemoteThread;
    char* pszLibFileRemote;
    // dll路径指针
    const char* cDllPath = strDllPath.data();
    printf("DEFAULT DLL PATH: %s\n", cDllPath);

    if (!EnableDebugPriv((const char*)SE_DEBUG_NAME)) {
        cout << "* FAIL TO: Get SEDEBUG privilege" << endl;
        return 0;
    }
    else {
        cout << "* SUCCESS TO: Get SEDEBUG privilege" << endl;
    }



    hRemoteProcess = OpenProcess(PROCESS_ALL_ACCESS, false, PID);
    if (hRemoteProcess) {
        cout << "* SUCCESS TO: Open process" << endl;
        cout << "Got Handle: " << hRemoteProcess << endl;
    }
    else {
        cout << "* FAIL TO: Open process" << endl;
        return 0;
    }

    pszLibFileRemote = (char*)VirtualAllocEx(hRemoteProcess, NULL, strlen(cDllPath) + 10, MEM_COMMIT, PAGE_READWRITE);
    if (pszLibFileRemote) {
        cout << "* SUCCESS TO: Allocate remote memory space" << endl;
        printf("Remote addr: 0x%p\n", (long long)pszLibFileRemote);
    }
    else {
        cout << "* FAIL TO: Allocate remote memory space" << endl;
        return 0;
    }

    if (WriteProcessMemory(hRemoteProcess, pszLibFileRemote, (void*)cDllPath, strlen(cDllPath) + 10, NULL)) {
        cout << "* SUCCESS TO: Write memory" << endl;
    }
    else {
        cout << "* FAIL TO: Write memory" << endl;
        return 0;
    }
    //PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)LoadLibraryA;
    PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA");
    if (pfnStartAddr == NULL) {
        cout << "* FAIL TO: Get LoadLibraryA() addr" << endl;
        return 0;
    }
    else
    {
        cout << "* SUCCESS TO: Get LoadLibraryA() addr" << endl;
        printf("LoadLibraryA addr: 0x%p\n", (long long)pfnStartAddr);
    }

    hRemoteThread = CreateRemoteThread(hRemoteProcess, NULL, 0, pfnStartAddr, pszLibFileRemote, 0, NULL);
    //在这一步注入了自己创建的DLL
    if (hRemoteThread) {
        cout << "* SUCCESS TO: Create remote thread" << endl;
    }
    else {
        cout << "* FILE TO: Create remote thread" << endl;
        return 0;
    }
    WaitForSingleObject(hRemoteThread, INFINITE);
    CloseHandle(hRemoteProcess);
    CloseHandle(hRemoteThread);
    return 1;
}
