#include <windows.h>

#define APPINIT_PATH L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
#define APPINIT_NAME L"AppInit_DLLs"
#define LOADINIT_NAME L"LoadAppInit_DLLs"

extern HMODULE g_hModule;

static void remove_string(WCHAR *s1, WCHAR *s2)
{
}
/*

HRESULT WINAPI DllRegisterServer()
{
	HRESULT hr = E_FAIL;

	hr = RegOpenKeyEx(HKEY_LOCAL_MACHINE, APPINIT_PATH, 0, KEY_SET_VALUE, &hKey);
	
	if(S_OK == hr)
	{
		GetModuleFileName(g_hModule, szPath, MAX_PATH);
		

		RegSetValueEx(hKey, APPINIT_NAME, 0, REG_SZ, 0, 0);
		
		DWORD enable = 1;
		RegSetValueEx(hKey, LOADINIT_NAME, 0, REG_DWORD, (BYTE*)&enable, sizeof(DWORD));

		RegCloseKey(hKey);
	}

	return hr;
}

HRESULT WINAPI DllUnregisterServer()
{
}
*/