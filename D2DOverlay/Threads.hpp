#pragma once
#include <Windows.h>
#include <cstdint>
#include <thread>
#include <chrono>
#include <mutex>
#include <vector>
#include <string>
#include <iostream>
#include <iostream>
#include <TlHelp32.h>
#include <winternl.h>
#include <strsafe.h>

DWORD OverlayGetModuleSize(DWORD64 base)
{
    IMAGE_DOS_HEADER dos_header = { 0 };
    IMAGE_NT_HEADERS nt_headers = { 0 };
    if (!base)return -1;
    dos_header = *(IMAGE_DOS_HEADER*)base;
    nt_headers = *(IMAGE_NT_HEADERS*)(base + dos_header.e_lfanew);
    return nt_headers.OptionalHeader.SizeOfImage;
}

typedef struct
{
    DWORD64 dwEP;
    void* pParam;
}OVERLAYCALL_MYFUNCTION, * OVERLAYPCALL_MYFUNCTION;
typedef DWORD(*_Function)(VOID* p);


void WINAPI MyOverlayFunctionThread(OVERLAYPCALL_MYFUNCTION pCMF)
{
    if (pCMF != NULL && pCMF->dwEP != NULL)
    {
        _Function Function = (_Function)pCMF->dwEP;
        Function(pCMF->pParam);
    }
}

HANDLE MyOverlayCreateThread(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, LPDWORD lpThreadId)
{
    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (hNtDll != NULL)
    {
        DWORD dwImageSize = OverlayGetModuleSize((DWORD64)hNtDll);
        BYTE* pMemoryData = (BYTE*)hNtDll + dwImageSize - 0x400;

        if (pMemoryData != NULL)
        {
            DWORD dwProtect;
            VirtualProtect(pMemoryData, 0x100, PAGE_EXECUTE_READWRITE, &dwProtect);
            OVERLAYCALL_MYFUNCTION* pCMF = (OVERLAYCALL_MYFUNCTION*)VirtualAlloc(NULL, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            pCMF->dwEP = (DWORD64)(lpStartAddress);
            pCMF->pParam = lpParameter;
            memcpy((LPVOID)pMemoryData, (LPVOID)MyOverlayFunctionThread, 0x200);
            HANDLE hHandle = CreateRemoteThread(GetCurrentProcess(), NULL, 0, (LPTHREAD_START_ROUTINE)pMemoryData, pCMF, NULL, lpThreadId);
            return hHandle;
        }
    }
    return 0;
}