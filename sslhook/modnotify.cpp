//
//  modnotify.cpp
//
//	DLL load notification
//
//  www.catch22.net
//
//  Copyright (C) 2013 James Brown
//  Please refer to the file LICENCE.TXT for copying permission
//

#include <Windows.h>
#include "modnotify.h"

static PVOID cookie;

static PLDR_REGISTER_DLL_NOTIFICATION    LdrRegisterDllNotification   = 0;
static PLDR_UNREGISTER_DLL_NOTIFICATION  LdrUnRegisterDllNotification = 0;

// we will call this function whenever a DLL is loaded
void module_loaded(PVOID base, WCHAR *name, WCHAR *path);

static VOID CALLBACK LdrDllNotification(
  _In_      ULONG NotificationReason,
  _In_      PCLDR_DLL_NOTIFICATION_DATA NotificationData,
  _In_opt_  PVOID Context
)
{
	if(NotificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED)
	{
		WCHAR szPath[MAX_PATH];		
		lstrcpyn(szPath, NotificationData->Loaded.FullDllName->Buffer, NotificationData->Loaded.FullDllName->Length);

		WCHAR szName[MAX_PATH];
		lstrcpyn(szName, NotificationData->Loaded.BaseDllName->Buffer, NotificationData->Loaded.BaseDllName->Length);

		module_loaded(NotificationData->Loaded.DllBase, szName, szPath);
	}
}

static PVOID GetNativeProc(char *name)
{
	return GetProcAddress(GetModuleHandle(L"ntdll.dll"), name);
}

BOOL init_dll_notify()
{
	NTSTATUS status = 1;

	LdrRegisterDllNotification   = (PLDR_REGISTER_DLL_NOTIFICATION)GetNativeProc("LdrRegisterDllNotification");
	LdrUnRegisterDllNotification = (PLDR_UNREGISTER_DLL_NOTIFICATION)GetNativeProc("LdrUnRegisterDllNotification");

	if(LdrRegisterDllNotification)
	{
		status = LdrRegisterDllNotification( 
									0, // must be zero
									LdrDllNotification,
									0, // context,
									&cookie
									);
	}

	return status == 0;
}

BOOL deinit_dll_notify()
{
	NTSTATUS status = 1;

	if(LdrUnRegisterDllNotification)
	{
		status = LdrUnRegisterDllNotification(cookie);
		cookie = 0;
	}

	return status == 0;
}
