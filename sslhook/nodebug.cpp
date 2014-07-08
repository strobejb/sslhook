#include <Windows.h>
#include "detours.h"

static BOOL (WINAPI * TargetIsDebuggerPresent)() = IsDebuggerPresent;
static BOOL WINAPI DetourIsDebuggerPresent()
{
	return FALSE;
}

// 

void allow_debugging()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach((PVOID*)&TargetIsDebuggerPresent, DetourIsDebuggerPresent);
	DetourTransactionCommit();
}

void restore_debugging()
{
	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach((PVOID*)&TargetIsDebuggerPresent, DetourIsDebuggerPresent);
	DetourTransactionCommit();
}