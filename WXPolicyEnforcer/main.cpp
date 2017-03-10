#include "stdafx.h"
#include "mhook/mhook-lib/mhook.h"

//////////////////////////////////////////////////////////////////////////
// Debug consts

const wchar_t* DEBUG_VIRTUAL_ALLOC_MSG = L"[W^X Policy Enforcer] VirtualAlloc called: pID=%d, address=%p, size=%x, type=%x, protect=%x";
const wchar_t* DEBUG_VIRTUAL_PROTECT_MSG = L"[W^X Policy Enforcer] VirtualProtect called: pID=%d, address=%p, size=%x, protect=%x";
const wchar_t* DEBUG_VIRTUAL_FREE_MSG = L"[W^X Policy Enforcer] VirtualFree called: pID=%d, address=%p, size=%x, type=%x";
const wchar_t* DEBUG_VIRTUAL_ALLOC_RWX_DENY = L"[W^X Policy Enforcer] VirtualAlloc call rejected: pID=%d, address=%p, size=%x, type=%x, protect=%x";
const wchar_t* DEBUG_VIRTUAL_PROTECT_RWX_DENY = L"[W^X Policy Enforcer] VirtualProtect call rejected: pID=%d, address=%p, size=%x, protect=%x, oldProtect=%x";
const wchar_t* DEBUG_TRACKED_PAGE_ADDED = L"[W^X Policy Enforcer] Added tracked page: pID=%d, address=%p, size=%x, tracking=%d";
const wchar_t* DEBUG_TRACKED_PAGE_REMOVED = L"[W^X Policy Enforcer] Removed tracked page: pID=%d, address=%p, size=%x, tracking=%d";
#define DEBUG_BUFFER_SIZE 1024

//////////////////////////////////////////////////////////////////////////
// Defines and typedefs

#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)

typedef LPVOID (WINAPI *PVIRTUAL_ALLOC)(
	  _In_opt_ LPVOID lpAddress,
	  _In_     SIZE_T dwSize,
	  _In_     DWORD  flAllocationType,
	  _In_     DWORD  flProtect
	);

typedef BOOL (WINAPI* PVIRTUAL_PROTECT)(
	  _In_  LPVOID lpAddress,
	  _In_  SIZE_T dwSize,
	  _In_  DWORD  flNewProtect,
	  _Out_ PDWORD lpflOldProtect
	);

typedef BOOL(WINAPI* PVIRTUAL_FREE)(
		_In_ LPVOID lpAddress,
		_In_ SIZE_T dwSize,
		_In_ DWORD  dwFreeType
	);

typedef struct _WRITABLE_PAGE
{
	LPVOID			PageAddress;
	SIZE_T			AllocationSize;
} WRITABLE_PAGE, *PWRITABLE_PAGE;

std::vector<WRITABLE_PAGE> WritablePageAllocations;
std::mutex WritablePageMutex;

//////////////////////////////////////////////////////////////////////////
// Original functions

PVIRTUAL_ALLOC OriginalVirtualAlloc = 
	(PVIRTUAL_ALLOC)::GetProcAddress(::GetModuleHandle(L"kernel32"), "VirtualAlloc");

PVIRTUAL_PROTECT OriginalVirtualProtect = 
	(PVIRTUAL_PROTECT)::GetProcAddress(::GetModuleHandle(L"kernel32"), "VirtualProtect");

PVIRTUAL_FREE OriginalVirtualFree =
	(PVIRTUAL_FREE)::GetProcAddress(::GetModuleHandle(L"kernel32"), "VirtualFree");

	
//////////////////////////////////////////////////////////////////////////
// Hooked function

LPVOID WINAPI HookedVirtualAlloc(
		  _In_opt_ LPVOID lpAddress,
		  _In_     SIZE_T dwSize,
		  _In_     DWORD  flAllocationType,
		  _In_     DWORD  flProtect
	)
{
	wchar_t debugBuffer[DEBUG_BUFFER_SIZE];
#if _DEBUG
	ZeroMemory(debugBuffer, sizeof(wchar_t) * DEBUG_BUFFER_SIZE);
	wsprintf(debugBuffer, DEBUG_VIRTUAL_ALLOC_MSG, GetCurrentProcessId(), lpAddress, dwSize, flAllocationType, flProtect);
	OutputDebugString(debugBuffer);
#endif

	// check if we're trying to set a writable + executable option
	if (((flProtect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) ||
		((flProtect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY))
	{
		// W^X policy violation; reject
		ZeroMemory(debugBuffer, sizeof(wchar_t) * DEBUG_BUFFER_SIZE);
		wsprintf(debugBuffer, DEBUG_VIRTUAL_ALLOC_RWX_DENY, GetCurrentProcessId(), lpAddress, dwSize, flAllocationType, flProtect);
		OutputDebugString(debugBuffer);

		SetLastError(ERROR_ACCESS_DENIED);
		return NULL;
	}

	LPVOID allocPtr = OriginalVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);

	if (allocPtr != NULL && (flProtect == PAGE_READWRITE || flProtect == PAGE_WRITECOPY))
	{
		// add the allocation to the tracked list
		WritablePageMutex.lock();

		WRITABLE_PAGE wp;
		wp.PageAddress = allocPtr;
		wp.AllocationSize = dwSize;
		WritablePageAllocations.push_back(wp);

		ZeroMemory(debugBuffer, sizeof(wchar_t) * DEBUG_BUFFER_SIZE);
		wsprintf(debugBuffer, DEBUG_TRACKED_PAGE_ADDED, GetCurrentProcessId(), allocPtr, dwSize, WritablePageAllocations.size());
		OutputDebugString(debugBuffer);

		WritablePageMutex.unlock();
	}

	return allocPtr;
}



BOOL WINAPI HookedVirtualProtect(
		  _In_  LPVOID lpAddress,
		  _In_  SIZE_T dwSize,
		  _In_  DWORD  flNewProtect,
		  _Out_ PDWORD lpflOldProtect
	)
{
	wchar_t debugBuffer[DEBUG_BUFFER_SIZE];

#if _DEBUG
	// log the VirtualProtect call
	ZeroMemory(debugBuffer, sizeof(wchar_t) * DEBUG_BUFFER_SIZE);
	wsprintf(debugBuffer, DEBUG_VIRTUAL_PROTECT_MSG, GetCurrentProcessId(), lpAddress, dwSize, flNewProtect);
	OutputDebugString(debugBuffer);
#endif

	MEMORY_BASIC_INFORMATION memInfo;

	// reject PAGE_EXECUTE_READWRITE outright
	if ((flNewProtect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE)
	{
		// reject RWX page protection flag
		ZeroMemory(debugBuffer, sizeof(wchar_t) * DEBUG_BUFFER_SIZE);
		wsprintf(debugBuffer, DEBUG_VIRTUAL_PROTECT_RWX_DENY, GetCurrentProcessId(), lpAddress, dwSize, flNewProtect, -1);
		OutputDebugString(debugBuffer);

		SetLastError(ERROR_ACCESS_DENIED);
		return NULL;
	}

	// if they're trying to make the page executable, we need to do some checks
	if (((flNewProtect & PAGE_EXECUTE) == PAGE_EXECUTE) ||
		((flNewProtect & PAGE_EXECUTE_READ) == PAGE_EXECUTE_READ))
	{
		// trying to make this page executable, let's check what its last protection flag was
		VirtualQuery(lpAddress, &memInfo, sizeof(memInfo));

		if (((memInfo.AllocationProtect & PAGE_READWRITE) == PAGE_READWRITE) ||
			((memInfo.AllocationProtect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) ||
			((memInfo.AllocationProtect & PAGE_WRITECOPY) == PAGE_WRITECOPY) ||
			((memInfo.AllocationProtect & PAGE_EXECUTE_WRITECOPY) == PAGE_EXECUTE_WRITECOPY))
		{
			// this was writable, now someone's trying to make it executable. reject.
			ZeroMemory(debugBuffer, sizeof(wchar_t) * DEBUG_BUFFER_SIZE);
			wsprintf(debugBuffer, DEBUG_VIRTUAL_PROTECT_RWX_DENY, GetCurrentProcessId(), lpAddress, dwSize, flNewProtect, memInfo.AllocationProtect);
			OutputDebugString(debugBuffer);

			SetLastError(ERROR_ACCESS_DENIED);
			return NULL;
		}

		// we should also check if the page was writable before then
		ULONG64 requestBegin = (ULONG64)lpAddress;
		ULONG64 requestEnd = requestBegin + (ULONG64)dwSize;

		WritablePageMutex.lock();

		for (std::vector<WRITABLE_PAGE>::iterator page = WritablePageAllocations.begin(); page != WritablePageAllocations.end(); ++page)
		{
			ULONG64 pageBegin = (ULONG64)page->PageAddress;
			ULONG64 pageEnd = pageBegin + (ULONG64)page->AllocationSize;

			if ((requestBegin >= pageBegin && requestBegin <= pageEnd) || /* request begins within the allocation */
				(requestEnd >= pageBegin && requestEnd <= pageEnd) ||     /* request ends within the allocation   */
				(requestBegin <= pageBegin && requestEnd >= pageEnd))     /* request runs over the allocation     */
			{
				// this requested allocation would overwrite a page which, at one stage or another, was writable
				ZeroMemory(debugBuffer, sizeof(wchar_t) * DEBUG_BUFFER_SIZE);
				wsprintf(debugBuffer, DEBUG_VIRTUAL_PROTECT_RWX_DENY, GetCurrentProcessId(), lpAddress, dwSize, flNewProtect, memInfo.AllocationProtect);
				OutputDebugString(debugBuffer);

				SetLastError(ERROR_ACCESS_DENIED);

				WritablePageMutex.unlock();
				return NULL;
			}
		}

		WritablePageMutex.unlock();
	}

	// if we reached here, we passed all policy requirements
	BOOL result = OriginalVirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect);

	if (result == TRUE && (
		((flNewProtect | PAGE_READWRITE) == PAGE_READWRITE) || 
		((flNewProtect | PAGE_WRITECOPY) == PAGE_WRITECOPY)))
	{
		// add the allocation to the tracked list

		WritablePageMutex.lock();

		WRITABLE_PAGE wp;
		wp.PageAddress = lpAddress;
		wp.AllocationSize = dwSize;
		WritablePageAllocations.push_back(wp);

		ZeroMemory(debugBuffer, sizeof(wchar_t) * DEBUG_BUFFER_SIZE);
		wsprintf(debugBuffer, DEBUG_TRACKED_PAGE_ADDED, GetCurrentProcessId(), lpAddress, dwSize, WritablePageAllocations.size());
		OutputDebugString(debugBuffer);

		WritablePageMutex.unlock();
	}

	return result;
}



BOOL WINAPI HookedVirtualFree(
		_In_ LPVOID lpAddress,
		_In_ SIZE_T dwSize,
		_In_ DWORD  dwFreeType
	)
{
	wchar_t debugBuffer[DEBUG_BUFFER_SIZE];

#if _DEBUG
	// log the VirtualFree call
	ZeroMemory(debugBuffer, sizeof(wchar_t) * DEBUG_BUFFER_SIZE);
	wsprintf(debugBuffer, DEBUG_VIRTUAL_FREE_MSG, GetCurrentProcessId(), lpAddress, dwSize, dwFreeType);
	OutputDebugString(debugBuffer);
#endif

	BOOL result = OriginalVirtualFree(lpAddress, dwSize, dwFreeType);
	if (result == TRUE)
	{
		// remove the pages from our allocations list if they were tracked
		WritablePageMutex.lock();

		int pagesRemoved;
		do
		{
			pagesRemoved = 0;
			for (std::vector<WRITABLE_PAGE>::iterator page = WritablePageAllocations.begin(); page != WritablePageAllocations.end(); ++page)
			{
				if (page->PageAddress == lpAddress)
				{
					pagesRemoved++;
					WritablePageAllocations.erase(page);

					ZeroMemory(debugBuffer, sizeof(wchar_t) * DEBUG_BUFFER_SIZE);
					wsprintf(debugBuffer, DEBUG_TRACKED_PAGE_REMOVED, GetCurrentProcessId(), lpAddress, dwSize, WritablePageAllocations.size());
					OutputDebugString(debugBuffer);

					break;
				}
			}
		}
		while (pagesRemoved > 0);

		WritablePageMutex.unlock();
	}

	return result;
}

//////////////////////////////////////////////////////////////////////////
// Entry point

BOOL WINAPI DllMain(
    __in HINSTANCE  hInstance,
    __in DWORD      Reason,
    __in LPVOID     Reserved
    )
{
	wchar_t messageBuffer[DEBUG_BUFFER_SIZE];
	ZeroMemory(messageBuffer, sizeof(wchar_t) * DEBUG_BUFFER_SIZE);

    switch (Reason)
    {
    case DLL_PROCESS_ATTACH:
		wsprintf(messageBuffer, L"[W^X Policy Enforcer] Injected into PID %d", GetCurrentProcessId());
		OutputDebugString(messageBuffer);
		// hook the APIs
		Mhook_SetHook((PVOID*)&OriginalVirtualAlloc, HookedVirtualAlloc);
		Mhook_SetHook((PVOID*)&OriginalVirtualProtect, HookedVirtualProtect);
		Mhook_SetHook((PVOID*)&OriginalVirtualFree, HookedVirtualFree);
        break;

    case DLL_PROCESS_DETACH:
		wsprintf(messageBuffer, L"[W^X Policy Enforcer] Detached from PID %d", GetCurrentProcessId());
		OutputDebugString(messageBuffer);
		// unhook the APIs
        Mhook_Unhook((PVOID*)&OriginalVirtualAlloc);
		Mhook_Unhook((PVOID*)&OriginalVirtualProtect);
		Mhook_Unhook((PVOID*)&OriginalVirtualFree);
        break;
    }

    return TRUE;
}
