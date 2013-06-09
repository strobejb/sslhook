//
//  sslhook
//
//  www.catch22.net
//
//  Copyright (C) 2013 James Brown
//  Please refer to the file LICENCE.TXT for copying permission
//

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include "detours.h"
#include "Trace.h"

//#define EXPORT comment(linker, "/EXPORT:hook=_hook@4")
#define MakePtr( cast, ptr, addValue ) (cast)( (DWORD_PTR)(ptr) + (DWORD_PTR)(addValue))

PDETOUR_TRAMPOLINE Trampoline;

HMODULE g_hModule;
PVOID hookAddress = 0;

void Hook_OpenSSL(DWORD_PTR write_addr, DWORD_PTR read_addr);
void UnHook_OpenSSL();

BOOL init_dll_notify();
BOOL deinit_dll_notify();

WCHAR szTargetDLL[MAX_PATH];
DWORD_PTR SSL_Read_Target = 0;
DWORD_PTR SSL_Write_Target = 0;

void dump_ptr(char *prefix, PVOID p)
{
	char buf[200];

	__try
	{	
		_snprintf(buf, 100, "%08X: %s: %s", p, prefix, p);
		TraceA(buf);		
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		_snprintf(buf, 100, "%08X: %s", p, prefix);
		TraceA(buf);		
	}
}

void dump_ptrd(char *prefix, PVOID p)
{
	__try
	{	
		DWORD_PTR addr = *(DWORD_PTR *)p;
		dump_ptr(prefix, (PVOID)addr);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		
	}
}

typedef struct _PUSHAD
{
	DWORD EDI;
	DWORD ESI;
	DWORD EBP;
	DWORD ESP;
	DWORD EBX;
	DWORD EDX;
	DWORD ECX;
	DWORD EAX;

} PUSHAD, *PPUSHAD;

void __fastcall dump(PUSHAD *regs)
{
	dump_ptrd("ESP+0 ", (PVOID)(regs->ESP + 0));
	dump_ptrd("ESP+4 ", (PVOID)(regs->ESP + 4));
	dump_ptrd("ESP+8 ", (PVOID)(regs->ESP + 8));
	dump_ptrd("ESP+C ", (PVOID)(regs->ESP + 0xC));
	dump_ptrd("ESP+10", (PVOID)(regs->ESP + 0x10));
	dump_ptrd("ESP+14", (PVOID)(regs->ESP + 0x14));
	dump_ptrd("ESP+18", (PVOID)(regs->ESP + 0x18));
	dump_ptrd("ESP+1C", (PVOID)(regs->ESP + 0x1C));
	dump_ptr("EAX   ", (PVOID)(regs->EAX));
	dump_ptr("ECX   ", (PVOID)(regs->ECX));
	dump_ptr("EDX   ", (PVOID)(regs->EDX));
}

__declspec(naked) void smeg()
{
	__asm pushad
	__asm mov ecx, esp
	__asm call [dump]
	__asm popad
	__asm jmp  [Trampoline]
}

void Hook(DWORD_PTR addr)
{
	hookAddress = (PVOID)addr;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	PVOID DetourPtr;
	PVOID TargetPtr;
	DetourAttachEx((PVOID*)&hookAddress, smeg, &Trampoline, &DetourPtr, &TargetPtr);
	DetourTransactionCommit();

	TraceA("Hooked: %x\n", addr);
}

void Unhook()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach((PVOID *)&hookAddress, smeg);
	DetourTransactionCommit();

	TraceA("Unhooked: %x\n", hookAddress);
	hookAddress = 0;
}

HMODULE WINAPI Detoured()
{
    return g_hModule;
}

DWORD_PTR OriginalImageBase(HMODULE hModule)
{
	TCHAR szPath[MAX_PATH];
	DWORD_PTR base = 0;
	GetModuleFileName(hModule, szPath, MAX_PATH);
	TraceA("FUCK: %ls\n", szPath);
	
	HANDLE hFile = CreateFile(szPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);

	BYTE buf[0x1000];
	DWORD len = 0;
	if(ReadFile(hFile, buf, 0x1000, &len, 0) && len)
	{
		PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)buf;
		PIMAGE_NT_HEADERS ntheaders = MakePtr(PIMAGE_NT_HEADERS, dosheader, dosheader->e_lfanew);
		base = ntheaders->OptionalHeader.ImageBase;
		TraceA("baseB: %x\n", base);
	}

	CloseHandle(hFile);

	return base;
}

BOOL get_param(PVOID param, WCHAR *szPath, int len, DWORD_PTR *p1, DWORD_PTR *p2)
{
	WCHAR *addrStr;

	OutputDebugStringW((WCHAR *)param);

	lstrcpyn(szPath, (WCHAR *)param, len);
	
	if((addrStr = wcschr(szPath, ':')) == 0)
	{
		TraceA("Invalid param: %ls", param);
		return FALSE;
	}

	*addrStr++ = '\0';
	*p1 = wcstol(addrStr, 0, 16);

	if(p2 && (addrStr = wcschr(addrStr, ':')) != 0)
	{
		*addrStr++ = '\0';
		*p2 = wcstol(addrStr, 0, 16);
	}

	return TRUE;
}

DWORD_PTR getModuleAdjustedRVA(WCHAR *szPath, DWORD_PTR addr)
{
	HMODULE hModule = GetModuleHandle(szPath);
	//TraceA("FFF: %x %ls\n", addr, addrStr);

	if(hModule == 0)
	{
		TraceA("Failed GetModuleHandle %ls [%x]", szPath, GetLastError());
		return 0;
	}
	else
	{
		TraceA("Found %ls at %08x\n", szPath, hModule);
	}

	PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS ntheaders = MakePtr(PIMAGE_NT_HEADERS, dosheader, dosheader->e_lfanew);
	
	DWORD_PTR base = OriginalImageBase(hModule);
	DWORD_PTR rva = addr - base;//ntheaders->OptionalHeader.ImageBase;

	TraceA("Magik %x %x\n", ntheaders->Signature, ntheaders->OptionalHeader.Magic);
	TraceA("Base: %x\n", base);//ntheaders->OptionalHeader.ImageBase);
	TraceA("RVA:  %x\n", rva);

	return (DWORD_PTR)hModule + rva;
}

extern "C"
__declspec(dllexport) 
BOOL WINAPI hook(PVOID param)//WCHAR *module, DWORD_PTR addr)
{
	WCHAR szPath[MAX_PATH];
	DWORD_PTR addr;
	DWORD_PTR addr2;

	if(!get_param(param, szPath, MAX_PATH, &addr, 0))
		return FALSE;

	if((addr2 = getModuleAdjustedRVA(szPath, addr)) == 0)
		return FALSE;
	
	__try 
	{
		if(hookAddress)
			Unhook();

		Hook(addr2);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		TraceA("Shit\n");
	}

	return TRUE;
}

extern "C"
__declspec(dllexport) 
BOOL WINAPI hookopenssl(PVOID param)//WCHAR *module, DWORD_PTR addr)
{
	WCHAR szPath[MAX_PATH];
	DWORD_PTR sslWrite;
	DWORD_PTR sslRead;

	if(!get_param(param, szPath, MAX_PATH, &sslRead, &sslWrite))
		return FALSE;

	if((sslRead = getModuleAdjustedRVA(szPath, sslRead)) == 0)
		return FALSE;

	if((sslWrite = getModuleAdjustedRVA(szPath, sslWrite)) == 0)
		return FALSE;

	__try 
	{
		Hook_OpenSSL(sslWrite, sslRead);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		TraceA("Shit\n");
	}

	return TRUE;
}

void GetModuleBaseName(HMODULE hModule, WCHAR *szPath, DWORD nBufLen)
{	
	GetModuleFileName(hModule, szPath, nBufLen);
	WCHAR *ptr = wcsrchr(szPath, '\\'); 
	
	if(ptr) *ptr++ = '\0';
	memmove(szPath, ptr, (lstrlen(ptr) + 1) * sizeof(WCHAR));
}

BOOL check_allow_hooking(HMODULE hSllHook)
{
	BOOL allow = FALSE;

	WCHAR szExeName[MAX_PATH];
	WCHAR szIniPath[MAX_PATH];
	WCHAR *ptr;
	
	// hook parameters that we read from the ini file
	WCHAR raddr[20], waddr[20];

	// get base name of current exe
	GetModuleBaseName(0, szExeName, MAX_PATH);

	TraceA("CurExe: %ls", szExeName);

	// get path of sslhook.dll -> change to sslhook.ini
	GetModuleFileName(hSllHook, szIniPath, MAX_PATH);
	ptr = wcsrchr(szIniPath, '.'); if(ptr) lstrcpyn(ptr, L".ini", MAX_PATH);

	if(0 == GetPrivateProfileString(szExeName, L"targetDll", L"", szTargetDLL, MAX_PATH, szIniPath))
		return FALSE;

	if(0 == GetPrivateProfileString(szExeName, L"SSL_read", L"", raddr, 20, szIniPath))
		return FALSE;

	if(0 == GetPrivateProfileString(szExeName, L"SSL_write", L"", waddr, 20, szIniPath))
		return FALSE;

	SSL_Read_Target  = wcstol(raddr, 0, 16);
	SSL_Write_Target = wcstol(waddr, 0, 16);

	TraceA("targetDLL:     %ls", szTargetDLL);
	TraceA("SSL_Read  RVA: %08x", SSL_Read_Target);
	TraceA("SSL_Write RVA: %08x", SSL_Write_Target);
	return TRUE;
}

void module_loaded(PVOID base, WCHAR *name, WCHAR *path)
{
	TraceW(L"Module loaded: %08x %ls", base, name);

	if(lstrcmpi(name, szTargetDLL) == 0)
	{
		DWORD read_addr  = getModuleAdjustedRVA(path, SSL_Read_Target);
		DWORD write_addr = getModuleAdjustedRVA(path, SSL_Write_Target);

		TraceA("Hooking OpenSSL!");
		TraceA("SSL_Read  = %08x", read_addr);
		TraceA("SSL_Write = %08x", write_addr);

		Hook_OpenSSL(write_addr, read_addr);
	}
}


BOOL CALLBACK DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
	switch(dwReason)
	{
	case DLL_PROCESS_ATTACH:
		g_hModule = hInstance;

		if(check_allow_hooking(hInstance) == FALSE)
		{
			return FALSE;
		}

		//TraceA("Loaded!");
		//Hook();

		// install hook so we are notified when DLLs load
		if(init_dll_notify())
		{
			TraceA("LdrRegisterDllNotification OK");
		}

		break;

	case DLL_PROCESS_DETACH:

		deinit_dll_notify();

		if(hookAddress)
			Unhook();

		UnHook_OpenSSL();
		OutputDebugStringA("Unloaded!");
		break;
	}

	return TRUE;
}
