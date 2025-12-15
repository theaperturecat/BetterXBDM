/*
 Copyright (c) 2013 Nathan LeRoux
 
 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 */

#include "dmincludes.h"

CRITICAL_SECTION csEch;

DMHRAPI DmStub()
{
	return E_FAIL;
}

PVOID __stdcall DmAllocatePool(ULONG cb)
{
	return ExAllocatePoolWithTag(cb, 'xbdm');
}

PVOID __stdcall DmAllocatePoolWithTag(ULONG cb, ULONG tag)
{
	return ExAllocatePoolWithTag(cb, tag);
}

PVOID DmAllocatePoolTypeWithTag(ULONG cb, ULONG tag, ULONG type)
{
	return ExAllocatePoolTypeWithTag(cb, tag, type);
}

VOID __stdcall DmFreePool(PVOID p)
{
	ExFreePool(p);
}

DMHRAPI DmGetXboxName(LPSTR szName, LPDWORD pcch)
{
	DWORD i;

	if(!szName || !pcch)
		return E_INVALIDARG;

	if(strlen(g_dmGlobals.rgchDbgName) >= *pcch)
		return XBDM_BUFFER_TOO_SMALL;

	for(i = 0;i < *pcch;i++)
	{
		szName[i] = g_dmGlobals.rgchDbgName[i];

		if(g_dmGlobals.rgchDbgName[i] == 0)
			break;
	}

	if(g_dmGlobals.rgchDbgName[i])
		return XBDM_BUFFER_TOO_SMALL;
	else
		return XBDM_NOERR;
}

DMHRAPI DmGetXbeInfo(LPCSTR szName, PDM_XBE pdxbe)
{
	return DmGetXbeInfoEx(szName, pdxbe, 0);
}

DMHRAPI DmGetXbeInfoEx(LPCSTR szName, PDM_XBE pdxbe, DWORD dwFlags)
{
	if(!pdxbe)
		return E_INVALIDARG;

	if(dwFlags & DM_XBEONDISKONLY)
		return XBDM_NOSUCHFILE;

	ZeroMemory(pdxbe, sizeof(DM_XBE));
	
	if(ExLoadedImageName)
		strcpy(pdxbe->LaunchPath, ExLoadedImageName);

	pdxbe->CheckSum = 0;
	pdxbe->StackSize = 0;
	pdxbe->TimeStamp = 0;

	return XBDM_NOERR;
}

DMHRAPI DmGetMemory(LPCVOID lpbAddr, DWORD cb, LPVOID lpbBuf,
    LPDWORD pcbRet)
{
	DWORD page;
	DWORD addr;
	LPCSTR lpBuf = (LPCSTR)lpbBuf;
	LPSTR lpAddr = (LPSTR)lpbAddr;
	BOOL pageValid = TRUE;

	if(!lpbBuf)
		return E_INVALIDARG;

	addr = (DWORD)lpbAddr;
	page = addr + 0x1000;

	while(pageValid && (addr < (DWORD)lpbAddr + cb))
	{
		if((addr ^ page) & 0xFFFFF000)
		{
			page = addr & 0xFFFFF000;
			pageValid = MmIsAddressValid((LPVOID)addr);
		}

		if(pageValid)
			pageValid = FGetMemory(addr, (PBYTE)lpBuf);

		lpBuf++;
		addr++;
	}

	if(!pageValid)
		return XBDM_MEMUNMAPPED;

	return XBDM_NOERR;
}

DMHRAPI DmSetMemory(LPVOID lpbAddr, DWORD cb, LPCVOID lpbBuf,
    LPDWORD pcbRet)
{
	DWORD page;
	DWORD addr;
	LPCSTR lpBuf = (LPCSTR)lpbBuf;
	LPSTR lpAddr = (LPSTR)lpbAddr;
	BOOL pageValid = TRUE;

	if(!lpbBuf)
		return E_INVALIDARG;

	addr = (DWORD)lpbAddr;
	page = addr + 0x1000;

	while(pageValid && (addr < (DWORD)lpbAddr + cb))
	{
		if((addr ^ page) & 0xFFFFF000)
		{
			page = addr & 0xFFFFF000;
			pageValid = MmIsAddressValid((LPVOID)addr);
		}

		if(pageValid)
			pageValid = FSetMemory(addr, *lpBuf);

		lpBuf++;
		addr++;
	}

	if(!pageValid)
		return XBDM_MEMUNMAPPED;

	return XBDM_NOERR;
}

typedef struct _DM_WALK_MODULES
{
	LIST_ENTRY Link;
	DMN_MODLOAD_EX pdml;
} DM_WALK_MODULES;

DWORD g_ = 0;
DMHRAPI DmWalkLoadedModules(PDM_WALK_MODULES *ppdwm, PDMN_MODLOAD pdml)
{
	HRESULT hr;
	DMN_MODLOAD_EX dml;

	dml.SizeOfStruct = sizeof(DMN_MODLOAD_EX);

	hr = DmWalkLoadedModulesEx(ppdwm, &dml);

	if(pdml)
		memcpy(pdml, dml.Name, sizeof(DMN_MODLOAD));

	return hr;
}

DMHRAPI DmWalkLoadedModulesEx(PDM_WALK_MODULES *ppdwm, PDMN_MODLOAD_EX pdml)
{
	BYTE irql;
	PLIST_ENTRY plemod;
	PLIST_ENTRY ple = (PLIST_ENTRY)*ppdwm;
	PLDR_DATA_TABLE_ENTRY pldte;
	PDM_WALK_MODULES pdwm;
	HRESULT hr = XBDM_NOERR;
	PIMAGE_NT_HEADERS pinh;

	if(!ppdwm || !pdml)
		return E_INVALIDARG;

	if(ple == NULL)
	{
		// Initialize the list entry
		ple = (PLIST_ENTRY)DmAllocatePoolWithTag(sizeof(LIST_ENTRY), 'dmwm');

		if(!ple)
			return E_OUTOFMEMORY;

		InitializeListHead(ple);

		*ppdwm = (PDM_WALK_MODULES)ple;

		irql = KfAcquireSpinLock(g_dmDebug.XexLoadedModuleListLock);

		plemod = g_dmDebug.PsLoadedModuleList->Flink;
		while(plemod != g_dmDebug.PsLoadedModuleList)
		{
			pldte = CONTAINING_RECORD(plemod, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			plemod = plemod->Flink;

			pdwm = (PDM_WALK_MODULES)DmAllocatePoolWithTag(sizeof(DM_WALK_MODULES), 'dmwm');

			if(!pdwm)
			{
				hr = E_OUTOFMEMORY;
				break;
			}

			pinh = RtlImageNtHeader(pldte->ImageBase);

			ZeroMemory(pdwm, sizeof(DM_WALK_MODULES));

			InsertTailList(ple, &pdwm->Link);

			pdwm->pdml.SizeOfStruct = sizeof(DMN_MODLOAD_EX);

			// Fetch ALL the info
			pdwm->pdml.BaseAddress = pldte->ImageBase;
			pdwm->pdml.CheckSum = pldte->CheckSum;
			pdwm->pdml.Flags = 0;
			if(!(pinh->FileHeader.Characteristics & 0x20))
				pdwm->pdml.Flags |= DMN_MODFLAG_TLS;

			WideCharToMultiByte(CP_UTF8, 0, pldte->BaseDllName.Buffer, -1, pdwm->pdml.Name, MAX_PATH, NULL, NULL);
			pdwm->pdml.OriginalSize = _byteswap_ulong(pinh->OptionalHeader.SizeOfImage);
			pdwm->pdml.PDataAddress = RtlImageDirectoryEntryToData(pldte->NtHeadersBase, TRUE, 3, &pdwm->pdml.PDataSize);
			pdwm->pdml.Size = pldte->SizeOfNtImage;
			pdwm->pdml.ThreadId = 0;//(DWORD)PsGetCurrentThread()->ThreadId;
			pdwm->pdml.TimeStamp = pldte->TimeDateStamp;
		}

		KfReleaseSpinLock(g_dmDebug.XexLoadedModuleListLock, irql);

		if(FAILED(hr))
		{
			DmCloseLoadedModules(*ppdwm);
			*ppdwm = NULL;
		}
	}

	if(NT_SUCCESS(hr))
	{
		// Take an entry, copy the data, remove from list, free the memory
		ple = ((PLIST_ENTRY)*ppdwm)->Flink;

		if(ple->Flink == ple->Blink)
			hr = XBDM_ENDOFLIST;

		memcpy(pdml, &CONTAINING_RECORD(ple, DM_WALK_MODULES, Link)->pdml, sizeof(DMN_MODLOAD_EX));

		ple->Flink->Blink = ple->Blink;
		ple->Blink->Flink = ple->Flink;

		DmFreePool(CONTAINING_RECORD(ple, DM_WALK_MODULES, Link));
	}

	return hr;
}

DMHRAPI DmCloseLoadedModules(PDM_WALK_MODULES pdwm)
{
	PLIST_ENTRY ple;
	PDM_WALK_MODULES pdwm2;

	if(!pdwm)
		return E_INVALIDARG;

	ple = ((PLIST_ENTRY)pdwm)->Flink;
	while(ple != (PLIST_ENTRY)pdwm)
	{
		pdwm2 = CONTAINING_RECORD(ple, DM_WALK_MODULES, Link);

		ple->Flink->Blink = ple->Blink;
		ple->Blink->Flink = ple->Flink;
		ple = ple->Flink;

		DmFreePool(pdwm2);
	}

	DmFreePool(pdwm);

	return XBDM_NOERR;
}
typedef struct _DM_WALK_MODSECT
{
	LIST_ENTRY Link;
	DMN_SECTIONLOAD pdml;
} DM_WALK_MODSECT;
DMHRAPI DmWalkModuleSections(PDM_WALK_MODSECT *ppWalkModSect, LPCSTR lzModName, PDMN_SECTIONLOAD pSecLoad)
{
	BYTE irql;
	PLIST_ENTRY ple = (PLIST_ENTRY)*ppWalkModSect;
	PLDR_DATA_TABLE_ENTRY pldte;
	HRESULT hr = XBDM_NOERR;
	PIMAGE_SECTION_HEADER pish;
	DWORD dw;
	int i;

	if(!ppWalkModSect || !pSecLoad)
		return E_INVALIDARG;

	if(ple == NULL)
	{
		// Initialize the list entry
		ple = (PLIST_ENTRY)DmAllocatePoolWithTag(sizeof(LIST_ENTRY), 'dmwm');

		if(!ple)
			return E_OUTOFMEMORY;

		InitializeListHead(ple);

		*ppWalkModSect = (PDM_WALK_MODSECT)ple;

		irql = KfAcquireSpinLock(g_dmDebug.XexLoadedModuleListLock);
		
		if(NT_SUCCESS(hr = FGetModuleHandle(lzModName, &pldte, FALSE)))
		{
			pish = (PIMAGE_SECTION_HEADER)(RtlImageNtHeader(pldte->ImageBase) + 1);

			for(i = 0;pish->Name[0];i++)
			{
				PDM_WALK_MODSECT pdmwm = (PDM_WALK_MODSECT)DmAllocatePoolWithTag(sizeof(DM_WALK_MODSECT), 'dmwm');
				if(!pdmwm)
				{
					hr = E_OUTOFMEMORY;
					break;
				}

				ZeroMemory(pdmwm, sizeof(DM_WALK_MODSECT));

				InsertTailList(ple, &pdmwm->Link);

				pdmwm->pdml.Index = i + 1;
				memcpy(pdmwm->pdml.Name, pish->Name, 8);
				pdmwm->pdml.BaseAddress = (PVOID)(_byteswap_ulong(pish->VirtualAddress) + (DWORD)pldte->ImageBase);
				pdmwm->pdml.Size = _byteswap_ulong(pish->Misc.VirtualSize);
				pdmwm->pdml.Flags = 0;
				dw = _byteswap_ulong(pish->Characteristics);
				if(dw & 0x40000000)
					pdmwm->pdml.Flags |= DMN_SECFLAG_READABLE;
				if(dw & 0x80000000)
					pdmwm->pdml.Flags |= DMN_SECFLAG_WRITEABLE;
				if(dw & 0x20000000)
					pdmwm->pdml.Flags |= DMN_SECFLAG_EXECUTABLE;
				if(dw & 0x80)
					pdmwm->pdml.Flags |= DMN_SECFLAG_UNINITIALIZED;

				pish++;
			}
		}
		KfReleaseSpinLock(g_dmDebug.XexLoadedModuleListLock, irql);

		if(FAILED(hr))
		{
			DmCloseModuleSections(*ppWalkModSect);
			*ppWalkModSect = FALSE;
		}
	}

	if(NT_SUCCESS(hr))
	{
		// Take an entry, copy the data, remove from list, free the memory
		ple = ((PLIST_ENTRY)*ppWalkModSect)->Flink;

		if(ple->Flink == ple->Blink)
			hr = XBDM_ENDOFLIST;

		memcpy(pSecLoad, &CONTAINING_RECORD(ple, DM_WALK_MODSECT, Link)->pdml, sizeof(DMN_SECTIONLOAD));

		ple->Flink->Blink = ple->Blink;
		ple->Blink->Flink = ple->Flink;

		DmFreePool(CONTAINING_RECORD(ple, DM_WALK_MODULES, Link));
	}

	return hr;
}

DMHRAPI DmCloseModuleSections(PDM_WALK_MODSECT pWalkMod)
{
	PLIST_ENTRY ple;
	PDM_WALK_MODSECT pdwm2;

	if(!pWalkMod)
		return E_INVALIDARG;

	ple = ((PLIST_ENTRY)pWalkMod)->Flink;
	while(ple != (PLIST_ENTRY)pWalkMod)
	{
		pdwm2 = CONTAINING_RECORD(ple, DM_WALK_MODSECT, Link);

		ple->Flink->Blink = ple->Blink;
		ple->Blink->Flink = ple->Flink;
		ple = ple->Flink;

		DmFreePool(pdwm2);
	}

	DmFreePool(pWalkMod);

	return XBDM_NOERR;
}

DMHRAPI DmReboot(DWORD dwFlags)
{
	return DmRebootEx(dwFlags, NULL, NULL, NULL);
}

ULONG __stdcall DmBootThread(LPVOID param)
{
	XamLoaderLaunchTitleEx(g_dmGlobals.szBootTitle, g_dmGlobals.szBootPath, g_dmGlobals.szBootCmdLine, 0);
	return 0;
}

BOOL FWouldSystemCrash()
{
	BYTE irql;
	PKTHREAD pthr;
	PLIST_ENTRY ple;
	BOOL fRet = FALSE;
	DMTD *pdmtd;
	int i;

	irql = KfAcquireSpinLock(g_dmDebug.KeSystemProcess);

	ple = g_dmDebug.KeSystemProcess->ThreadListHead.Flink;
	
	for(i = 0;i < 2;i++)
	{
		while(ple != &g_dmDebug.KeSystemProcess->ThreadListHead && ple != &g_dmDebug.KeTitleProcess->ThreadListHead)
		{
			pthr = CONTAINING_RECORD(ple, KTHREAD, ThreadListEntry);
			ple = ple->Flink;

			pdmtd = (DMTD*)pthr->DebugMonitorData;

			if(pdmtd &&
				(pdmtd->StopReason == DM_EXCEPTION
				|| pdmtd->StopReason == DM_BREAK
				|| pdmtd->StopReason == DM_SINGLESTEP
				|| pdmtd->StopReason == DM_DATABREAK
				|| pdmtd->StopReason == DM_ASSERT
				|| pdmtd->StopReason == DM_RIP))
			{
				fRet = TRUE;
			}
		}

		ple = g_dmDebug.KeTitleProcess->ThreadListHead.Flink;
	}

	KfReleaseSpinLock(g_dmDebug.KeSystemProcess, irql);

	return fRet;
}

DMHRAPI DmRebootEx(DWORD dwFlags, LPCSTR szImagePath, LPCSTR szMediaPath, LPCSTR szDbgCmdLine)
{
	char sz[MAX_PATH];
	char szM[MAX_PATH];
	int i, j;
#ifdef _DEBUG
	HANDLE h;
#endif

	if((dwFlags & DMBOOT_WAIT) && (dwFlags & DMBOOT_STOP))
		return E_INVALIDARG;

	if(FWouldSystemCrash())	
	{
		DwChangeExecState(DMN_EXEC_REBOOT, FALSE, TRUE, FALSE);
		FStopServ();
		if(KeGetCurrentIrql() >= DISPATCH_LEVEL)
		{
			HalReturnToFirmware(1);
		}
		HalReturnToFirmware(6);
	}

	g_dmGlobals.dwBootFlags = dwFlags;

	if(szImagePath)
		strcpy_s(g_dmGlobals.szBootTitle, sizeof(g_dmGlobals.szBootTitle), szImagePath);
	if(szMediaPath)
		strcpy_s(g_dmGlobals.szBootPath, sizeof(g_dmGlobals.szBootPath), szMediaPath);
	if(szDbgCmdLine)
		strcpy_s(g_dmGlobals.szBootCmdLine, sizeof(g_dmGlobals.szBootCmdLine), szDbgCmdLine);

	if(dwFlags & DMBOOT_COLD)
	{
		DwChangeExecState(DMN_EXEC_REBOOT, FALSE, TRUE, FALSE);
		FStopServ();

		FWriteGlobals();

		if(KeGetCurrentIrql() >= DISPATCH_LEVEL)
			HalReturnToFirmware(1);

		HalReturnToFirmware(6);
	}

	if(dwFlags & DMBOOT_TITLE)
	{
		szImagePath = sz;
		szMediaPath = szM;

		if(ExLoadedImageName)
		{
			strcpy_s(sz, sizeof(sz), ExLoadedImageName);
			strcpy_s(szM, sizeof(szM), sz);

			// Parse out the directory
			for(i = 0, j = 0;szM[i];i++)
				if(szM[i] == '\\' || szM[i] == '//')
					j = i;
			szM[j] = 0;
		}
		else
			return E_FAIL;
	}

	// To make sure we can't get stuck
	DwChangeExecState(DMN_EXEC_START, TRUE, FALSE, FALSE);

	DwChangeExecState(DMN_EXEC_REBOOT_TITLE, FALSE, TRUE, FALSE);

#ifdef _DEBUG
	// DEVKIT
	ExCreateThread(&h, 0, 0, 0, DmBootThread, 0, 0x400);
	SetThreadPriority(h, THREAD_PRIORITY_TIME_CRITICAL);
	CloseHandle(h);

	Sleep(200);
	
#else
	XamLoaderLaunchTitleEx(szImagePath, szMediaPath, szDbgCmdLine, 0);
#endif

	if(KeGetCurrentProcessType() == 1)
		ExTerminateThread(-1); // kill off this thread

	return XBDM_NOERR;
}

LPCSTR ESysSymbolicLinkName =		"\\system??\\E:";
LPCSTR ESymbolicLinkName =			"\\??\\E:";
LPCSTR DEVKITSymbolicLinkName =		"\\??\\DEVKIT:";
LPCSTR DEVKITSysSymbolicLinkName =	"\\system??\\DEVKIT:";
LPCSTR DevkitDeviceName =			"\\Device\\Harddisk0\\Partition1\\DEVKIT";

DMHRAPI DmMapDevkitDrive()
{
	ANSI_STRING symName, devName;
	NTSTATUS st;

	DWORD b = KeGetCurrentProcessType();

	if(b == 2)
		RtlInitAnsiString(&symName, ESysSymbolicLinkName);
	else
		RtlInitAnsiString(&symName, ESymbolicLinkName);

	RtlInitAnsiString(&devName, DevkitDeviceName);

	st = ObCreateSymbolicLink(&symName, &devName);

	if(st < STATUS_OBJECT_NAME_COLLISION && st < 0)
		return (RtlNtStatusToDosError(st) & 0xFFFF) | 0x80070000;

	if(b == 2)
		RtlInitAnsiString(&symName, DEVKITSysSymbolicLinkName);
	else
		RtlInitAnsiString(&symName, DEVKITSymbolicLinkName);

	st = ObCreateSymbolicLink(&symName, &devName);

	if(st < STATUS_OBJECT_NAME_COLLISION && st < 0)
		return (RtlNtStatusToDosError(st) & 0xFFFF) | 0x80070000;

	return S_OK;
}

DMHRAPI DmSetDumpMode(DWORD dwDumpMode)
{
	if(dwDumpMode > DM_DUMPMODE_DISABLED)
		return E_INVALIDARG;

	g_dmGlobals.dwDumpMode = dwDumpMode;
	g_dmGlobals.bDirty = TRUE;
	
	return XBDM_NOERR;
}

DMHRAPI DmGetDumpMode(DWORD * pdwDumpMode)
{
	if(!pdwDumpMode)
		return E_INVALIDARG;

	*pdwDumpMode = g_dmGlobals.dwDumpMode;

	return XBDM_NOERR;
}

HRESULT FGetModuleHandle(LPCSTR ModuleName, PLDR_DATA_TABLE_ENTRY *ppdte, BOOL bSpinLock)
{
	BYTE irql;
	PLDR_DATA_TABLE_ENTRY pdte;
	PLIST_ENTRY ple;
	HRESULT hr = XBDM_NOSUCHFILE;
	char sz[MAX_PATH];
	int i;

	if(!ppdte || !ModuleName)
		return E_INVALIDARG;

	*ppdte = NULL;

	if(bSpinLock)
		irql = KfAcquireSpinLock(g_dmDebug.XexLoadedModuleListLock);

	ple = g_dmDebug.PsLoadedModuleList->Flink;
	while(ple != g_dmDebug.PsLoadedModuleList)
	{
		pdte = CONTAINING_RECORD(ple, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		ple = ple->Flink;

		sz[0] = 0;
		wcstombs_s(&i, sz, sizeof(sz), pdte->BaseDllName.Buffer, pdte->BaseDllName.Length);

		if(!strnicmp(sz, ModuleName, sizeof(sz)))
		{
			*ppdte = pdte;
			hr = XBDM_NOERR;
			break;
		}
	}

	if(bSpinLock)
		KfReleaseSpinLock(g_dmDebug.XexLoadedModuleListLock, irql);

	return hr;
}

DMHRAPI DmGetThreadContext(DWORD dwThreadId, PXCONTEXT pdmcr)
{
	PKTHREAD pthr;
	BYTE irql;
	DMTD *pdmtd;
	HRESULT hr;
	char *stack;
	DWORD flags;

	if(!pdmcr)
		return E_INVALIDARG;

	if(FAILED(ObLookupAnyThreadByThreadId(dwThreadId, &pthr)))
		return XBDM_NOTHREAD;

	irql = KfAcquireSpinLock(&pthr->Process->ThreadListLock);

	flags = pdmcr->ContextFlags;
	ZeroMemory(pdmcr, sizeof(XCONTEXT));

	pdmtd = (DMTD*)pthr->DebugMonitorData;

	if(pdmtd && !(pdmtd->DebugFlags & DMFLAG_DEBUGTHREAD))
	{
		stack = (char*)pthr->KernelStack;

		if(pdmtd->Context)
		{
			if(flags & CONTEXT_INTEGER)
			{
				pdmcr->ContextFlags |= CONTEXT_INTEGER;

				memcpy(&pdmcr->Gpr0, &pdmtd->Context->Gpr0, ((char*)&pdmcr->Xer - (char*)&pdmcr->Gpr0));
			}
			if(flags & CONTEXT_CONTROL)
			{
				pdmcr->ContextFlags |= CONTEXT_CONTROL;
				
				memcpy(&pdmcr->Msr, &pdmtd->Context->Msr, ((char*)&pdmcr->Ctr - (char*)&pdmcr->Msr));
			}
			if(flags & CONTEXT_FLOATING_POINT)
			{
				pdmcr->ContextFlags |= CONTEXT_FLOATING_POINT;
				
				memcpy(&pdmcr->Fpscr, &pdmtd->Context->Fpscr, ((char*)&pdmcr->Fill - (char*)&pdmcr->Fpscr));
			}
			if(flags & CONTEXT_VECTOR)
			{
				pdmcr->ContextFlags |= CONTEXT_VECTOR;
				
				memcpy(&pdmcr->Vscr[0], &pdmtd->Context->Vscr[0], ((char*)&pdmcr->Vr127[3] - (char*)&pdmcr->Vscr[0]));
			}
		}
		else
		{
			if(flags & CONTEXT_INTEGER)
			{
				pdmcr->ContextFlags |= CONTEXT_INTEGER;

				memset(&pdmcr->Gpr0, 0xFF, 0x70);
				memcpy(&pdmcr->Gpr14, stack + 0x50, 0x90);
				pdmcr->Xer = -1;
				pdmcr->Cr = ((LPDWORD)stack)[0x38];
				pdmcr->Gpr1 = (DWORD)stack;
			}
			if(flags & CONTEXT_CONTROL)
			{
				pdmcr->ContextFlags |= CONTEXT_CONTROL;

				pdmcr->Msr = -1;
				pdmcr->Iar = ((LPDWORD)stack)[0x39];
				pdmcr->Ctr = -1;
				pdmcr->Lr = ((LPDWORD)stack)[0x3A];
			}
		}

		hr = XBDM_NOERR;
	}
	else
		hr = XBDM_NOTHREAD;

	KfReleaseSpinLock(&pthr->Process->ThreadListLock, irql);

	ObDereferenceObject(pthr);

	return hr;
}

DMHRAPI DmSetThreadContext(DWORD dwThreadId, PXCONTEXT pdmcr)
{
	BYTE irql;
	PKTHREAD pthr;
	DMTD *pdmtd;
	HRESULT hr = XBDM_NOERR;

	if(!pdmcr)
		return E_FAIL;

	if(FAILED(ObLookupAnyThreadByThreadId(dwThreadId, &pthr)))
		return XBDM_NOTHREAD;

	irql = KfAcquireSpinLock(&pthr->Process->ThreadListLock);

	pdmtd = (DMTD*)pthr->DebugMonitorData;

	if(pdmtd && !(pdmtd->DebugFlags & DMFLAG_DEBUGTHREAD))
	{
		if(pdmtd->Context)
		{
			if(pdmcr->ContextFlags & CONTEXT_INTEGER)
				memcpy(&pdmtd->Context->Gpr0, &pdmcr->Gpr0, ((char*)&pdmcr->Xer - (char*)&pdmcr->Gpr0));
			if(pdmcr->ContextFlags & CONTEXT_CONTROL)
			{
				if(pdmcr->Msr & 0x400) // Just a quick fix
					pdmtd->DebugFlags |= DMFLAG_SINGLESTEP;

				memcpy(&pdmtd->Context->Msr, &pdmcr->Msr, ((char*)&pdmcr->Ctr - (char*)&pdmcr->Msr));
			}
			if(pdmcr->ContextFlags & CONTEXT_FLOATING_POINT)
				memcpy(&pdmtd->Context->Fpscr, &pdmcr->Fpscr, ((char*)&pdmcr->Fill - (char*)&pdmcr->Fpscr));
			if(pdmcr->ContextFlags & CONTEXT_VECTOR)
				memcpy(&pdmtd->Context->Vscr[0], &pdmcr->Vscr[0], ((char*)&pdmcr->Vr127[3] - (char*)&pdmcr->Vscr[0]));
		}
		else
			hr = XBDM_NOTSTOPPED;
	}

	KfReleaseSpinLock(&pthr->Process->ThreadListLock, irql);
	ObDereferenceObject(pthr);

	return hr;
}

DMHRAPI DmGetThreadList(LPDWORD rgdwThreads, LPDWORD pcThreads)
{
	BYTE irql;
	PLIST_ENTRY ple;
	PKTHREAD pthr;
	HRESULT hr = XBDM_NOERR;
	DWORD cchThreads = 0;
	DMTD *pdmtd;
	int i;

	if(!rgdwThreads || !pcThreads)
		return E_FAIL;

	if(*pcThreads == 0)
		return XBDM_BUFFER_TOO_SMALL;

	irql = KfAcquireSpinLock(&g_dmDebug.KeSystemProcess->ThreadListLock);
	KeAcquireSpinLockAtRaisedIrql(&g_dmDebug.KeTitleProcess->ThreadListLock);

	ple = g_dmDebug.KeSystemProcess->ThreadListHead.Flink;
	for(i = 0;i < 2;i++)
	{
		while(ple != &g_dmDebug.KeSystemProcess->ThreadListHead && ple != &g_dmDebug.KeTitleProcess->ThreadListHead)
		{
			pthr = CONTAINING_RECORD(ple, KTHREAD, ThreadListEntry);
			ple = ple->Flink;

			if(!pthr->DebugMonitorData)
				FInitThreadDebugData(pthr);

			pdmtd = (DMTD*)pthr->DebugMonitorData;

			if(pdmtd && !(pdmtd->DebugFlags & DMFLAG_DEBUGTHREAD))
			{
				if(cchThreads++ < *pcThreads)
					rgdwThreads[cchThreads - 1] = (DWORD)pthr->ThreadId;
				else
					hr = XBDM_BUFFER_TOO_SMALL;
			}
		}

		ple = g_dmDebug.KeTitleProcess->ThreadListHead.Flink;
	}

	*pcThreads = cchThreads;

	KeReleaseSpinLockFromRaisedIrql(&g_dmDebug.KeTitleProcess->ThreadListLock);
	KfReleaseSpinLock(&g_dmDebug.KeSystemProcess->ThreadListLock, irql);

	return hr;
}

DMHRAPI DmContinueThread(DWORD dwThreadId, BOOL fException)
{
	PKTHREAD pthr;
	BYTE irql;
	HRESULT hr = XBDM_NOERR;
	DMTD *pdmtd;

	if(dwExecState > 3)
		return XBDM_NOTHREAD;

	if(FAILED(ObLookupAnyThreadByThreadId(dwThreadId, &pthr)))
		return XBDM_NOTHREAD;

	irql = KfAcquireSpinLock(&pthr->Process->ThreadListLock);
	
	pdmtd = (DMTD*)pthr->DebugMonitorData;
	
	if(pdmtd && (pdmtd->DebugFlags & DMFLAG_CONTINUEABLE))
	{
		if(fException)
			pdmtd->DebugFlags |= DMFLAG_EXCEPTION;

		if(dwExecState != DMN_EXEC_START)
		{
			if(!(pdmtd->DebugFlags & DMFLAG_STOPPED))
			{
				pdmtd->DebugFlags |= DMFLAG_STOPPED;
				KeSuspendThread(pthr);
			}
		}

		pdmtd->DebugFlags &= ~DMFLAG_CONTINUEABLE;

		KeSetEvent(pdmtd->DebugEvent, TRUE, FALSE);
	}
	else
		hr = XBDM_NOTSTOPPED;

	KfReleaseSpinLock(&pthr->Process->ThreadListLock, irql);

	ObDereferenceObject(pthr);

	return hr;
}

DMHRAPI DmStopOn(DWORD dwStopFlags, BOOL fStop)
{
	// We should probably be synchronizing this for when titles feel like being dicks and not synchronizing
	// Oh well :/

	if(fStop)
		g_dmGlobals.dwStopFlags |= dwStopFlags;
	else
		g_dmGlobals.dwStopFlags &= ~dwStopFlags;

	return XBDM_NOERR;
}

DMHRAPI DmIsThreadStopped(DWORD dwThreadId, PDM_THREADSTOP pdmts)
{
	PKTHREAD pthr;
	DMTD *pdmtd;
	BYTE irql;
	HRESULT hr = XBDM_NOERR;

	pdmts->NotifiedReason = DM_NONE;

	if(FAILED(ObLookupAnyThreadByThreadId(dwThreadId, &pthr)))
		return XBDM_NOTHREAD;

	irql = KfAcquireSpinLock(&pthr->Process->ThreadListLock);

	pdmtd = (DMTD*)pthr->DebugMonitorData;

	if(pdmtd && !(pdmtd->DebugFlags & DMFLAG_DEBUGTHREAD))
	{
		if(pdmtd->Exception && (pdmtd->DebugFlags & DMFLAG_CONTINUEABLE))
		{
			// Time to play some FIGUREOUTWTFISWRONGWITHTHISTHREAD!
			pdmts->NotifiedReason = pdmtd->StopReason;
			switch(pdmtd->StopReason)
			{
			case DM_DEBUGSTR:
			case DM_ASSERT:
				pdmts->u.DebugStr.ThreadId = dwThreadId;
				pdmts->u.DebugStr.String = (LPCSTR)pdmtd->Context->Gpr3;
				pdmts->u.DebugStr.Length = (DWORD)pdmtd->Context->Gpr4;
				break;
			case DM_SINGLESTEP:
			case DM_BREAK:
				pdmts->u.Break.ThreadId = dwThreadId;
				pdmts->u.Break.Address = (PVOID)pdmtd->Context->Iar;
				break;
			case DM_DATABREAK:
				pdmts->u.DataBreak.ThreadId = dwThreadId;
				pdmts->u.DataBreak.Address = (PVOID)pdmtd->Context->Iar;
				pdmts->u.DataBreak.DataAddress = (PVOID)pdmtd->Exception->ExceptionInformation[1];
				// if FMatchDataBreak
				break;
			case DM_EXCEPTION:
				pdmts->u.Exception.ThreadId = dwThreadId;
				pdmts->u.Exception.Address = (PVOID)pdmtd->Context->Iar;
				if(pdmtd->DebugFlags & DMFLAG_FIRSTCHANCE)
					pdmts->u.Exception.Flags = DM_EXCEPT_FIRSTCHANCE;
				else
					pdmts->u.Exception.Flags = 0;
				
				pdmts->u.Exception.Information[0] = pdmtd->Exception->ExceptionInformation[0];
				pdmts->u.Exception.Information[1] = pdmtd->Exception->ExceptionInformation[1];
				break;
			}
		}
		else
			hr = XBDM_NOTSTOPPED;
	}
	else
		hr = XBDM_NOTHREAD;

	KfReleaseSpinLock(&pthr->Process->ThreadListLock, irql);
	ObDereferenceObject(pthr);

	return hr;
}

DMHRAPI DmSuspendThread(DWORD dwThreadId)
{
	PKTHREAD pthr;

	if(FAILED(ObLookupAnyThreadByThreadId(dwThreadId, &pthr)))
		return XBDM_NOTHREAD;

	KeSuspendThread(pthr);
	ObDereferenceObject(pthr);

	return XBDM_NOERR;
}

DMHRAPI DmResumeThread(DWORD dwThreadId)
{
	PKTHREAD pthr;

	if(FAILED(ObLookupAnyThreadByThreadId(dwThreadId, &pthr)))
		return XBDM_NOTHREAD;

	KeResumeThread(pthr);
	ObDereferenceObject(pthr);

	return XBDM_NOERR;
}

DMHRAPI DmGetSystemInfo(PDM_SYSTEM_INFO pdmGetSystemInfo)
{
	if(!pdmGetSystemInfo)
		return E_INVALIDARG;

	if(pdmGetSystemInfo->SizeOfStruct != sizeof(DM_SYSTEM_INFO))
		return E_INVALIDARG;

	memcpy(&pdmGetSystemInfo->BaseKernelVersion, &XboxKrnlBaseVersion, sizeof(DM_SYSTEM_INFO));
	memcpy(&pdmGetSystemInfo->KernelVersion, &XboxKrnlVersion, sizeof(DM_SYSTEM_INFO));
	
	pdmGetSystemInfo->XDKVersion.Major = 2;
	pdmGetSystemInfo->XDKVersion.Minor = 0;
	pdmGetSystemInfo->XDKVersion.Build = 20353;
	pdmGetSystemInfo->XDKVersion.Qfe = 0;

	pdmGetSystemInfo->dmSystemInfoFlags = (XboxHardwareInfo->Flags & 0x20) ? DM_XBOX_HW_FLAG_HDD : 0;

	return XBDM_NOERR;
}

/*typedef struct HHHH
{
	char szProcessor[64];
	int pfn;
	int Flags;
} _HHHH;

int DAT_ffffffff9809ff98;*/
//TODO: Fix critical section stuff
//TODO: If a program exits, where does microsofts xbdm clear its command processor entries? Does it?
DMHRAPI DmRegisterCommandProcessorEx(LPCSTR szProcessor, PDM_CMDPROC pfn, BOOL fThread)
{
	if (cchcmdmax > cchcmdlen)
	{
		rgbcmd[cchcmdlen].szName = szProcessor;
		rgbcmd[cchcmdlen].pdmcp = pfn;
		rgbcmd[cchcmdlen].dwPriv = 0;
		cchcmdlen++;
		return XBDM_NOERR;
	}
	else
	{
		return E_OUTOFMEMORY;
	}

	/*char cVar1;
	char* pcVar2;
	int uVar3;
	long lVar4;
	_HHHH * pvVar5;
	int iVar6;
	char* pcVar7;
	ulong uVar8;
	uint uVar9;
	uint* puVar10;
	int* piVar11;
	unsigned int uVar12;

	pcVar2 = (char*)__savegprlr_25();
	if (pcVar2 == 0) 
	{
		uVar3 = 0x80070057;
	}
	else {
		KeEnterCriticalRegion();
		RtlEnterCriticalSection(csEch);
		uVar12 = 0;
		if (pfn == 0) 
		{
			cVar1 = *pcVar2;
			while (cVar1 != '\0') {
				uVar12 = uVar12 + 1;
				cVar1 = pcVar2[uVar12];
			}
			puVar10 = &DAT_ffffffff9809ff98;
			do {
				pcVar7 = (char*)(ulong)*puVar10;
				if (pcVar7 != (char*)0x0) {
					lVar4 = SgnCompareRgch(pcVar7, pcVar2, (int)uVar12);
					if ((int)lVar4 == 0) {
						XlnsMemFreeDefault(pcVar7);
						*puVar10 = 0;
					}
				}
				puVar10 = puVar10 + 1;
			} while ((int)puVar10 < -0x67f60028);
			uVar3 = 0x2da0000;
		}
		else 
		{
			//Find null entry
			piVar11 = &DAT_ffffffff9809ff98;
			do {
				if (*piVar11 == 0) break;
				piVar11 = piVar11 + 1;
				uVar12 = uVar12 + 1;
			} while ((int)piVar11 < -0x67f60028);

			if (uVar12 < 16) 
			{//Must be less than 16
				pvVar5 = (_HHHH*)DmAllocatePoolWithTag(0x48, 0x68636d64);
			}
			else 
			{
				pvVar5 = NULL;
			}

			if (pvVar5 == NULL) 
			{
				uVar3 = 0x8007000e;
			}
			else 
			{
				//Copy and get length of string (max 63)
				uVar8 = 0;
				if (*pcVar2 != '\0') 
				{
					while (pcVar2[uVar8] != '\0')
					{
						if (62 < uVar8) break;
						uVar8 = uVar8 + 1;
						pvVar5->szProcessor[uVar8] = pcVar2[uVar8];
					}
				}

				if (pcVar2[uVar8] == '\0') 
				{
					pvVar5->szProcessor[uVar8] = '\0';
					pvVar5->pfn = pfn;
					iVar6 = KeGetCurrentProcessType();
					uVar9 = (uint)LZCOUNT(iVar6 + -1) >> 5;
					pvVar5->Flags = uVar9;
					if (fThread) 
					{
						pvVar5->Flags |= 2;
					}

					uVar3 = 0x2da0000;
					DAT_ffffffff9809ff98[uVar12] = (int)pvVar5;
				}
				else {
					XlnsMemFreeDefault(pvVar5);
					uVar3 = 0x80070057;
				}
			}
		}
		RtlLeaveCriticalSection();
		KeLeaveCriticalRegion();
	}
	return uVar3;*/
}


DMHRAPI DmRegisterCommandProcessor(LPCSTR szProcessor, PDM_CMDPROC pfn)
{
	DmRegisterCommandProcessorEx(szProcessor,pfn,0);
	return XBDM_NOERR;
}

XBDMAPI BOOL DmIsDebuggerPresent(void)
{
	return g_dmGlobals.bDebugging;
}

DMHRAPI DmGetProcAddress(HMODULE moduleHandle, DWORD ord, PVOID of)
{
	NTSTATUS status;
	if (ord == 0 || of == NULL)
	{
		return 0x80070057;
	}

	status = XexGetProcedureAddress(moduleHandle, ord, of);

	if (status < 0)
		return XBDM_NOSUCHFILE;

	return XBDM_NOERR;
}

//From this point on the code is pretty much stubs

DMHRAPI DmCrashDump(BOOL fReturn)
{
	return XBDM_NOERR;
}

DMHRAPI DmSendNotificationString(LPCSTR sz)
{
	DbgPrint(sz);
	return XBDM_NOERR;
}

DMHRAPI DmGetModuleLongName(LPCSTR sz)
{
	return 0x80004001;
}





DMHRAPI DmGetDumpSettings(PDM_DUMP_SETTINGS pSettings)
{
	//Nothing for now
	return XBDM_NOERR;
}

DMHRAPI DmAbortProfiling(VOID)
{
	//Nothing for now
	return XBDM_NOERR;
}

DMHRAPI DmAddUser(LPCSTR szUserName, DWORD dwAccess)
{
	//Nothing for now
	return XBDM_NOERR;
}

DMHRAPI DmAutomationBindController(IN DWORD dwUserIndex, IN DWORD dwQueueLength)
{
	//Nothing for now
	return XBDM_NOERR;
}

DMHRAPI DmAutomationClearGamepadQueue(VOID)
{
	//Nothing for now
	return XBDM_NOERR;
}

DMHRAPI DmAutomationConnectController(VOID)
{
	//Nothing for now
	return XBDM_NOERR;
}

DMHRAPI DmAutomationDisconnectController(VOID)
{
	//Nothing for now
	return XBDM_NOERR;
}

DMHRAPI DmAutomationGetInputProcess(IN DWORD dwUserIndex, OUT BOOL* pfSystemProcess)
{
	pfSystemProcess = NULL;
	//Nothing for now
	//return XBDM_NOERR;
	return XBDM_INVALIDCMD;
}

DMHRAPI DmAutomationGetUserDefaultProfile(OUT PDM_XUID pXuid)
{
	return XBDM_INVALIDCMD;
}

DMHRAPI DmAutomationQueryGamepadQueue(IN  DWORD   dwUserIndex,
	OUT PDWORD  pdwQueueLength OPTIONAL,
	OUT PDWORD  pdwItemsInQueue OPTIONAL,
	OUT PDWORD  pdwTimedDurationRemaining OPTIONAL,
	OUT PDWORD  pdwCountDurationRemaining OPTIONAL)
{
	return XBDM_INVALIDCMD;
}

DMHRAPI DmAutomationQueueGamepadState(
	IN  DWORD  dwUserIndex,
	IN  PDM_XINPUT_GAMEPAD pGamepadArray,
	IN  PDWORD pdwTimedDurationArray OPTIONAL,
	IN  PDWORD pdwCountDurationArray OPTIONAL,
	IN  DWORD  dwItemCount,
	OUT PDWORD pdwItemsAddedToQueue
)
{
	return XBDM_INVALIDCMD;
}

DMHRAPI DmAutomationSetGamepadState(
	IN DWORD dwUserIndex,
	IN PDM_XINPUT_GAMEPAD pXGamepad)
{
	return XBDM_NOERR;
}

DMHRAPI DmAutomationSetUserDefaultProfile(DM_XUID xuid)
{
	return XBDM_NOERR;
}

DMHRAPI DmAutomationUnbindController(VOID)
{
	return XBDM_NOERR;
}

void __CAP_Enter_Function(VOID)
{

}

void __CAP_End_Profiling(VOID)
{

}

void __CAP_Exit_Function(VOID)
{

}

void __CAP_Start_Profiling(VOID)
{

}

DMHRAPI DmCapFreeFileHeader(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmCapGetFileHeader(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmCaptureStackBackTrace(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmCloseCommittedMemory(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmCloseUserList(VOID)
{
	return XBDM_NOERR;
}


DMHRAPI DmCloseCounters(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmClosePerformanceCounter(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmCreateSystemThread(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmEnableGPUCounter(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmEnableSecurity(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmEnableStackTrace(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmFindPdbSignature(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmGetAdditionalTitleMemorySetting(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmGetConsoleDebugMemoryStatus(OUT PDWORD pdwConsoleMemConfig)
{
	*pdwConsoleMemConfig = 0;
	return XBDM_NOERR;
}

DMHRAPI DmGetConsoleFeatures(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmGetConsoleType(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmGetDebugMemorySize(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmGetEventDeferFlags(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmGetFileAccessCount(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmGetHttpRegistration(VOID)
{
	return XBDM_NOERR;
}

XBDMAPI DWORD DmGetMouseChanges(OUT PUCHAR Buttons,OUT PSHORT X, OUT PSHORT Y,OUT PSHORT Wheel)
{
	return ERROR_DEVICE_NOT_CONNECTED;//XBDM_NOERR;
}

DMHRAPI DmGetProfilingStatus(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmGetSamplingProfilerInfo(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmGetUserAccess(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmGetUtilityDriveInfo(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmGetXexHeaderField(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmGo(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmHaltThread(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmInsertAllocationEntry(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmIsFastCAPEnabled(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmIsSecurityEnabled(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmLoadDebuggerExtension(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmMarkFileEventWorkerThreadBegin(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmMarkFileEventWorkerThreadEnd(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmMarkPseudoCreateBegin(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmMarkPseudoCreateEnd(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmMarkPseudoEventBegin(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmMarkPseudoEventEnd(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmMountFdfxVolume(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmNetCaptureStart(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmNetCaptureStop(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmNetSimGetNumIpv4Redirects(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmNetSimGetNumQueues(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmNetSimGetQueueSettings(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmNetSimGetQueueStats(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmNetSimInsertIpv4Redirect(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmNetSimInsertQueue(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmNetSimModifyQueueSettings(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmNetSimRemoveAllQueues(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmNetSimRemoveIpv4Redirect(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmNetSimRemoveQueue(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmNetSimSetLinkStatusHidden(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmOpenPerformanceCounter(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmOpticalDiscLogStart(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmOpticalDiscLogStop(VOID)
{
	return XBDM_NOERR;
}

__int64 DmPMCComputeFrequency(VOID)
{
	return 0;
}

VOID DmPMCDumpCounters(PPMCState pmcstate)
{
}

VOID DmPMCDumpCountersVerbose(PPMCState pmcstate, ULONG verbosity)
{
}

DMHRAPI DmPMCGetCounter(VOID)
{
	return XBDM_NOERR;
}

int DmPMCGetCounterCostEstimate(int h)
{
	return 0;
}

const char* DmPMCGetCounterName(int counterNumber)
{
	return "Hi";//XBDM_NOERR;
}

DMHRAPI DmPMCGetCounterSource(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmPMCGetCounters(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmPMCInstallAndStart(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmPMCInstallSetup(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmPMCResetCounters(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmPMCSetTriggerProcessor(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmPMCStart(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmPMCStop(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmPMCStopAndReport(VOID)
{
	return XBDM_NOERR;
}

VOID DmPMCUnInstallSetup(VOID)
{
}

DMHRAPI DmPgoSaveSnapshot(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmPgoStartDataCollection(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmPgoStopDataCollection(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmQueryAllocationTypeName(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmQueryMemoryStatistics(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmQueryPerformanceCounterHandle(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmQuerySystemSettings(VOID)
{
	return XBDM_NOERR;
}

//DMHRAPI DmQueryTitleMemoryStatistics()
//{
//	return XBDM_NOERR;
//}

// DmQueryTitleMemoryStatistics
byte bSystemMemoryInfo[] = { 0x00, 0x00, 0x00, 0x20, 0x00, 0x02, 0x00, 0x00,
0x07, 0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x44, 0x97, 0x00, 0x00, 0x00,
0x02, 0x00, 0x00, 0x53, 0x08, 0x00, 0x00, 0x40, 0x00, 0x00, 0x23, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
DMHRAPI DmQueryTitleMemoryStatistics(PDM_MEMORY_STATISTICS MemStat)
{

	if (!MemStat)
		return 0x82DA0017;

	memcpy(MemStat, bSystemMemoryInfo, 0x30);

	return 0x02DA0000;
}

DMHRAPI DmRegisterAllocationType(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmRegisterNotificationProcessor(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmRegisterPerformanceCounter(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmRemoveAllocationEntry(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmRemoveUser(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmSaveSystemSettings(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmSetDumpSettings(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmSetEventDeferFlags(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmSetFileEventMarker(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmSetProfilingOptions(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmSetTitle(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmSetTitleEx(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmSetUserAccess(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmSetXboxName(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmStartFileEventCapture(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmStartProfiling(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmStartSamplingProfiler(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmStop(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmStopFileEventCapture(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmStopProfiling(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmStopSamplingProfiler(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmThreadUserData(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmTraceIsRecording(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmTraceSaveBuffer(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmTraceSetBufferSize(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmTraceSetIOThread(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmTraceStartRecording(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmTraceStartRecordingFunction(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmTraceStopRecording(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmUnloadDebuggerExtension(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmWalkCommittedMemory(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmWalkPerformanceCounters(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmWalkUserList(VOID)
{
	return XBDM_NOERR;
}

DMHRAPI DmpGetPgoModuleHandleForBaseAddress(VOID){return XBDM_NOERR;}
DMHRAPI DmpOnPgoModuleLoad(VOID){return XBDM_NOERR;}
DMHRAPI DmpPgoCounterOverflow(VOID){return XBDM_NOERR;}
DMHRAPI IrtAutoSweepA(VOID){return XBDM_NOERR;}
DMHRAPI IrtAutoSweepW(VOID){return XBDM_NOERR;}
DMHRAPI IrtClientAbort(VOID){return XBDM_NOERR;}
DMHRAPI IrtPogoInit(VOID){return XBDM_NOERR;}
DMHRAPI IrtSetStaticInfo(VOID){return XBDM_NOERR;}
DMHRAPI Ordinal_181(VOID){return XBDM_NOERR;}
DMHRAPI Ordinal_182(VOID){return XBDM_NOERR;}
DMHRAPI Ordinal_183(VOID){return XBDM_NOERR;}
DMHRAPI Ordinal_184(VOID){return XBDM_NOERR;}
DMHRAPI Ordinal_185(VOID){return XBDM_NOERR;}
DMHRAPI Ordinal_186(VOID){return XBDM_NOERR;}
DMHRAPI Ordinal_187(VOID){return XBDM_NOERR;}
DMHRAPI Ordinal_188(VOID){return XBDM_NOERR;}
DMHRAPI Ordinal_189(VOID){return XBDM_NOERR;}
DMHRAPI Ordinal_190(VOID){return XBDM_NOERR;}
DMHRAPI Ordinal_191(VOID){return XBDM_NOERR;}
DMHRAPI Ordinal_193(VOID){return XBDM_NOERR;}

int Ordinal_227() { DbgPrint("[xbdm] Called 227\n"); return 0; }
int Ordinal_228() { DbgPrint("[xbdm] Called 228\n"); return 0; }
int Ordinal_229() { DbgPrint("[xbdm] Called 229\n"); return 0; }
int Ordinal_230() { DbgPrint("[xbdm] Called 230\n"); return 0; }
int Ordinal_231() { DbgPrint("[xbdm] Called 231\n"); return 0; }
int Ordinal_232() { DbgPrint("[xbdm] Called 232\n"); return 0; }
int Ordinal_233() { DbgPrint("[xbdm] Called 233\n"); return 0; }
int Ordinal_234() { DbgPrint("[xbdm] Called 234\n"); return 0; }
int Ordinal_235() { DbgPrint("[xbdm] Called 235\n"); return 0; }
int Ordinal_236() { DbgPrint("[xbdm] Called 236\n"); return 0; }
int Ordinal_237() { DbgPrint("[xbdm] Called 237\n"); return 0; }
int Ordinal_238() { DbgPrint("[xbdm] Called 238\n"); return 0; }
int Ordinal_239() { DbgPrint("[xbdm] Called 239\n"); return 0; }
int Ordinal_240() { DbgPrint("[xbdm] Called 240\n"); return 0; }
int Ordinal_241() { DbgPrint("[xbdm] Called 241\n"); return 0; }
int Ordinal_242() { DbgPrint("[xbdm] Called 242\n"); return 0; }
int Ordinal_243() { DbgPrint("[xbdm] Called 243\n"); return 0; }
int Ordinal_244() { DbgPrint("[xbdm] Called 244\n"); return 0; }
int Ordinal_245() { DbgPrint("[xbdm] Called 245\n"); return 0; }
int Ordinal_246() { DbgPrint("[xbdm] Called 246\n"); return 0; }
int Ordinal_247() { DbgPrint("[xbdm] Called 247\n"); return 0; }
int Ordinal_248() { DbgPrint("[xbdm] Called 248\n"); return 0; }
int Ordinal_249() { DbgPrint("[xbdm] Called 249\n"); return 0; }
int Ordinal_250() { DbgPrint("[xbdm] Called 250\n"); return 0; }
int Ordinal_251() { DbgPrint("[xbdm] Called 251\n"); return 0; }
int Ordinal_252() { DbgPrint("[xbdm] Called 252\n"); return 0; }
int Ordinal_253() { DbgPrint("[xbdm] Called 253\n"); return 0; }
int Ordinal_254() { DbgPrint("[xbdm] Called 254\n"); return 0; }
int Ordinal_255() { DbgPrint("[xbdm] Called 255\n"); return 0; }
int Ordinal_256() { DbgPrint("[xbdm] Called 256\n"); return 0; }
int Ordinal_257() { DbgPrint("[xbdm] Called 257\n"); return 0; }
int Ordinal_258() { DbgPrint("[xbdm] Called 258\n"); return 0; }
int Ordinal_259() { DbgPrint("[xbdm] Called 259\n"); return 0; }
int Ordinal_260() { DbgPrint("[xbdm] Called 260\n"); return 0; }
int Ordinal_261() { DbgPrint("[xbdm] Called 261\n"); return 0; }
int Ordinal_262() { DbgPrint("[xbdm] Called 262\n"); return 0; }
int Ordinal_263() { DbgPrint("[xbdm] Called 263\n"); return 0; }
int Ordinal_264() { DbgPrint("[xbdm] Called 264\n"); return 0; }
int Ordinal_265() { DbgPrint("[xbdm] Called 265\n"); return 0; }
int Ordinal_266() { DbgPrint("[xbdm] Called 266\n"); return 0; }
int Ordinal_267() { DbgPrint("[xbdm] Called 267\n"); return 0; }
int Ordinal_268() { DbgPrint("[xbdm] Called 268\n"); return 0; }
int Ordinal_269() { DbgPrint("[xbdm] Called 269\n"); return 0; }
int Ordinal_270() { DbgPrint("[xbdm] Called 270\n"); return 0; }
int Ordinal_271() { DbgPrint("[xbdm] Called 271\n"); return 0; }
int Ordinal_272() { DbgPrint("[xbdm] Called 272\n"); return 0; }
int Ordinal_273() { DbgPrint("[xbdm] Called 273\n"); return 0; }
int Ordinal_274() { DbgPrint("[xbdm] Called 274\n"); return 0; }
int Ordinal_275() { DbgPrint("[xbdm] Called 275\n"); return 0; }
int Ordinal_276() { DbgPrint("[xbdm] Called 276\n"); return 0; }
int Ordinal_277() { DbgPrint("[xbdm] Called 277\n"); return 0; }
int Ordinal_278() { DbgPrint("[xbdm] Called 278\n"); return 0; }
int Ordinal_279() { DbgPrint("[xbdm] Called 279\n"); return 0; }
int Ordinal_280() { DbgPrint("[xbdm] Called 280\n"); return 0; }
int Ordinal_281() { DbgPrint("[xbdm] Called 281\n"); return 0; }
int Ordinal_282() { DbgPrint("[xbdm] Called 282\n"); return 0; }
int Ordinal_283() { DbgPrint("[xbdm] Called 283\n"); return 0; }
int Ordinal_284() { DbgPrint("[xbdm] Called 284\n"); return 0; }
int Ordinal_285() { DbgPrint("[xbdm] Called 285\n"); return 0; }
int Ordinal_286() { DbgPrint("[xbdm] Called 286\n"); return 0; }
int Ordinal_287() { DbgPrint("[xbdm] Called 287\n"); return 0; }
int Ordinal_288() { DbgPrint("[xbdm] Called 288\n"); return 0; }
int Ordinal_289() { DbgPrint("[xbdm] Called 289\n"); return 0; }
int Ordinal_290() { DbgPrint("[xbdm] Called 290\n"); return 0; }
int Ordinal_291() { DbgPrint("[xbdm] Called 291\n"); return 0; }
int Ordinal_292() { DbgPrint("[xbdm] Called 292\n"); return 0; }
int Ordinal_293() { DbgPrint("[xbdm] Called 293\n"); return 0; }
int Ordinal_294() { DbgPrint("[xbdm] Called 294\n"); return 0; }
int Ordinal_295() { DbgPrint("[xbdm] Called 295\n"); return 0; }
int Ordinal_296() { DbgPrint("[xbdm] Called 296\n"); return 0; }
int Ordinal_297() { DbgPrint("[xbdm] Called 297\n"); return 0; }
int Ordinal_298() { DbgPrint("[xbdm] Called 298\n"); return 0; }
int Ordinal_299() { DbgPrint("[xbdm] Called 299\n"); return 0; }
int Ordinal_300() { DbgPrint("[xbdm] Called 300\n"); return 0; }
int Ordinal_301() { DbgPrint("[xbdm] Called 301\n"); return 0; }
int Ordinal_302() { DbgPrint("[xbdm] Called 302\n"); return 0; }
int Ordinal_303() { DbgPrint("[xbdm] Called 303\n"); return 0; }
int Ordinal_304() { DbgPrint("[xbdm] Called 304\n"); return 0; }
int Ordinal_305() { DbgPrint("[xbdm] Called 305\n"); return 0; }
int Ordinal_306() { DbgPrint("[xbdm] Called 306\n"); return 0; }
int Ordinal_307() { DbgPrint("[xbdm] Called 307\n"); return 0; }
int Ordinal_308() { DbgPrint("[xbdm] Called 308\n"); return 0; }
int Ordinal_309() { DbgPrint("[xbdm] Called 309\n"); return 0; }
int Ordinal_310() { DbgPrint("[xbdm] Called 310\n"); return 0; }
int Ordinal_311() { DbgPrint("[xbdm] Called 311\n"); return 0; }
int Ordinal_312() { DbgPrint("[xbdm] Called 312\n"); return 0; }
int Ordinal_313() { DbgPrint("[xbdm] Called 313\n"); return 0; }
int Ordinal_314() { DbgPrint("[xbdm] Called 314\n"); return 0; }
int Ordinal_315() { DbgPrint("[xbdm] Called 315\n"); return 0; }
int Ordinal_316() { DbgPrint("[xbdm] Called 316\n"); return 0; }
int Ordinal_317() { DbgPrint("[xbdm] Called 317\n"); return 0; }
int Ordinal_318() { DbgPrint("[xbdm] Called 318\n"); return 0; }
int Ordinal_319() { DbgPrint("[xbdm] Called 319\n"); return 0; }
int Ordinal_320() { DbgPrint("[xbdm] Called 320\n"); return 0; }
int Ordinal_321() { DbgPrint("[xbdm] Called 321\n"); return 0; }
int Ordinal_322() { DbgPrint("[xbdm] Called 322\n"); return 0; }
int Ordinal_323() { DbgPrint("[xbdm] Called 323\n"); return 0; }
int Ordinal_324() { DbgPrint("[xbdm] Called 324\n"); return 0; }
int Ordinal_325() { DbgPrint("[xbdm] Called 325\n"); return 0; }
int Ordinal_326() { DbgPrint("[xbdm] Called 326\n"); return 0; }
int Ordinal_327() { DbgPrint("[xbdm] Called 327\n"); return 0; }
int Ordinal_328() { DbgPrint("[xbdm] Called 328\n"); return 0; }
int Ordinal_329() { DbgPrint("[xbdm] Called 329\n"); return 0; }
int Ordinal_330() { DbgPrint("[xbdm] Called 330\n"); return 0; }
int Ordinal_331() { DbgPrint("[xbdm] Called 331\n"); return 0; }
int Ordinal_332() { DbgPrint("[xbdm] Called 332\n"); return 0; }
int Ordinal_333() { DbgPrint("[xbdm] Called 333\n"); return 0; }
int Ordinal_334() { DbgPrint("[xbdm] Called 334\n"); return 0; }
int Ordinal_335() { DbgPrint("[xbdm] Called 335\n"); return 0; }
int Ordinal_336() { DbgPrint("[xbdm] Called 336\n"); return 0; }
int Ordinal_337() { DbgPrint("[xbdm] Called 337\n"); return 0; }
int Ordinal_338() { DbgPrint("[xbdm] Called 338\n"); return 0; }
int Ordinal_339() { DbgPrint("[xbdm] Called 339\n"); return 0; }
int Ordinal_340() { DbgPrint("[xbdm] Called 340\n"); return 0; }
int Ordinal_341() { DbgPrint("[xbdm] Called 341\n"); return 0; }
int Ordinal_342() { DbgPrint("[xbdm] Called 342\n"); return 0; }
int Ordinal_343() { DbgPrint("[xbdm] Called 343\n"); return 0; }
int Ordinal_344() { DbgPrint("[xbdm] Called 344\n"); return 0; }
int Ordinal_345() { DbgPrint("[xbdm] Called 345\n"); return 0; }
int Ordinal_346() { DbgPrint("[xbdm] Called 346\n"); return 0; }
int Ordinal_347() { DbgPrint("[xbdm] Called 347\n"); return 0; }
int Ordinal_348() { DbgPrint("[xbdm] Called 348\n"); return 0; }
int Ordinal_349() { DbgPrint("[xbdm] Called 349\n"); return 0; }
int Ordinal_350() { DbgPrint("[xbdm] Called 350\n"); return 0; }
int Ordinal_351() { DbgPrint("[xbdm] Called 351\n"); return 0; }
int Ordinal_352() { DbgPrint("[xbdm] Called 352\n"); return 0; }
int Ordinal_353() { DbgPrint("[xbdm] Called 353\n"); return 0; }
int Ordinal_354() { DbgPrint("[xbdm] Called 354\n"); return 0; }
int Ordinal_355() { DbgPrint("[xbdm] Called 355\n"); return 0; }
int Ordinal_356() { DbgPrint("[xbdm] Called 356\n"); return 0; }
int Ordinal_357() { DbgPrint("[xbdm] Called 357\n"); return 0; }
int Ordinal_358() { DbgPrint("[xbdm] Called 358\n"); return 0; }
int Ordinal_359() { DbgPrint("[xbdm] Called 359\n"); return 0; }
int Ordinal_360() { DbgPrint("[xbdm] Called 360\n"); return 0; }
int Ordinal_361() { DbgPrint("[xbdm] Called 361\n"); return 0; }
int Ordinal_362() { DbgPrint("[xbdm] Called 362\n"); return 0; }
int Ordinal_363() { DbgPrint("[xbdm] Called 363\n"); return 0; }
int Ordinal_364() { DbgPrint("[xbdm] Called 364\n"); return 0; }
int Ordinal_365() { DbgPrint("[xbdm] Called 365\n"); return 0; }
int Ordinal_366() { DbgPrint("[xbdm] Called 366\n"); return 0; }
int Ordinal_367() { DbgPrint("[xbdm] Called 367\n"); return 0; }
int Ordinal_368() { DbgPrint("[xbdm] Called 368\n"); return 0; }
int Ordinal_369() { DbgPrint("[xbdm] Called 369\n"); return 0; }
int Ordinal_370() { DbgPrint("[xbdm] Called 370\n"); return 0; }
int Ordinal_371() { DbgPrint("[xbdm] Called 371\n"); return 0; }
int Ordinal_372() { DbgPrint("[xbdm] Called 372\n"); return 0; }
int Ordinal_373() { DbgPrint("[xbdm] Called 373\n"); return 0; }
int Ordinal_374() { DbgPrint("[xbdm] Called 374\n"); return 0; }
int Ordinal_375() { DbgPrint("[xbdm] Called 375\n"); return 0; }
int Ordinal_376() { DbgPrint("[xbdm] Called 376\n"); return 0; }
int Ordinal_377() { DbgPrint("[xbdm] Called 377\n"); return 0; }
int Ordinal_378() { DbgPrint("[xbdm] Called 378\n"); return 0; }
int Ordinal_379() { DbgPrint("[xbdm] Called 379\n"); return 0; }
int Ordinal_380() { DbgPrint("[xbdm] Called 380\n"); return 0; }
int Ordinal_381() { DbgPrint("[xbdm] Called 381\n"); return 0; }
int Ordinal_382() { DbgPrint("[xbdm] Called 382\n"); return 0; }
int Ordinal_383() { DbgPrint("[xbdm] Called 383\n"); return 0; }
int Ordinal_384() { DbgPrint("[xbdm] Called 384\n"); return 0; }
int Ordinal_385() { DbgPrint("[xbdm] Called 385\n"); return 0; }
int Ordinal_386() { DbgPrint("[xbdm] Called 386\n"); return 0; }
int Ordinal_387() { DbgPrint("[xbdm] Called 387\n"); return 0; }
int Ordinal_388() { DbgPrint("[xbdm] Called 388\n"); return 0; }
int Ordinal_389() { DbgPrint("[xbdm] Called 389\n"); return 0; }
int Ordinal_390() { DbgPrint("[xbdm] Called 390\n"); return 0; }
int Ordinal_391() { DbgPrint("[xbdm] Called 391\n"); return 0; }
int Ordinal_392() { DbgPrint("[xbdm] Called 392\n"); return 0; }
int Ordinal_393() { DbgPrint("[xbdm] Called 393\n"); return 0; }
int Ordinal_394() { DbgPrint("[xbdm] Called 394\n"); return 0; }
int Ordinal_395() { DbgPrint("[xbdm] Called 395\n"); return 0; }
int Ordinal_396() { DbgPrint("[xbdm] Called 396\n"); return 0; }
int Ordinal_397() { DbgPrint("[xbdm] Called 397\n"); return 0; }
int Ordinal_398() { DbgPrint("[xbdm] Called 398\n"); return 0; }
int Ordinal_399() { DbgPrint("[xbdm] Called 399\n"); return 0; }
int Ordinal_400() { DbgPrint("[xbdm] Called 400\n"); return 0; }
int Ordinal_401() { DbgPrint("[xbdm] Called 401\n"); return 0; }
int Ordinal_402() { DbgPrint("[xbdm] Called 402\n"); return 0; }
int Ordinal_403() { DbgPrint("[xbdm] Called 403\n"); return 0; }
int Ordinal_404() { DbgPrint("[xbdm] Called 404\n"); return 0; }
int Ordinal_405() { DbgPrint("[xbdm] Called 405\n"); return 0; }
int Ordinal_406() { DbgPrint("[xbdm] Called 406\n"); return 0; }
int Ordinal_407() { DbgPrint("[xbdm] Called 407\n"); return 0; }
int Ordinal_408() { DbgPrint("[xbdm] Called 408\n"); return 0; }
int Ordinal_409() { DbgPrint("[xbdm] Called 409\n"); return 0; }
int Ordinal_410() { DbgPrint("[xbdm] Called 410\n"); return 0; }
int Ordinal_411() { DbgPrint("[xbdm] Called 411\n"); return 0; }
int Ordinal_412() { DbgPrint("[xbdm] Called 412\n"); return 0; }
int Ordinal_413() { DbgPrint("[xbdm] Called 413\n"); return 0; }
int Ordinal_414() { DbgPrint("[xbdm] Called 414\n"); return 0; }
int Ordinal_415() { DbgPrint("[xbdm] Called 415\n"); return 0; }
int Ordinal_416() { DbgPrint("[xbdm] Called 416\n"); return 0; }
int Ordinal_417() { DbgPrint("[xbdm] Called 417\n"); return 0; }
int Ordinal_418() { DbgPrint("[xbdm] Called 418\n"); return 0; }
int Ordinal_419() { DbgPrint("[xbdm] Called 419\n"); return 0; }
int Ordinal_420() { DbgPrint("[xbdm] Called 420\n"); return 0; }
int Ordinal_421() { DbgPrint("[xbdm] Called 421\n"); return 0; }
int Ordinal_422() { DbgPrint("[xbdm] Called 422\n"); return 0; }
int Ordinal_423() { DbgPrint("[xbdm] Called 423\n"); return 0; }
int Ordinal_424() { DbgPrint("[xbdm] Called 424\n"); return 0; }
int Ordinal_425() { DbgPrint("[xbdm] Called 425\n"); return 0; }
int Ordinal_426() { DbgPrint("[xbdm] Called 426\n"); return 0; }
int Ordinal_427() { DbgPrint("[xbdm] Called 427\n"); return 0; }
int Ordinal_428() { DbgPrint("[xbdm] Called 428\n"); return 0; }
int Ordinal_429() { DbgPrint("[xbdm] Called 429\n"); return 0; }
int Ordinal_430() { DbgPrint("[xbdm] Called 430\n"); return 0; }
int Ordinal_431() { DbgPrint("[xbdm] Called 431\n"); return 0; }
int Ordinal_432() { DbgPrint("[xbdm] Called 432\n"); return 0; }
int Ordinal_433() { DbgPrint("[xbdm] Called 433\n"); return 0; }
int Ordinal_434() { DbgPrint("[xbdm] Called 434\n"); return 0; }
int Ordinal_435() { DbgPrint("[xbdm] Called 435\n"); return 0; }
int Ordinal_436() { DbgPrint("[xbdm] Called 436\n"); return 0; }
int Ordinal_437() { DbgPrint("[xbdm] Called 437\n"); return 0; }
int Ordinal_438() { DbgPrint("[xbdm] Called 438\n"); return 0; }
int Ordinal_439() { DbgPrint("[xbdm] Called 439\n"); return 0; }
int Ordinal_440() { DbgPrint("[xbdm] Called 440\n"); return 0; }
int Ordinal_441() { DbgPrint("[xbdm] Called 441\n"); return 0; }
int Ordinal_442() { DbgPrint("[xbdm] Called 442\n"); return 0; }
int Ordinal_443() { DbgPrint("[xbdm] Called 443\n"); return 0; }
int Ordinal_444() { DbgPrint("[xbdm] Called 444\n"); return 0; }
int Ordinal_445() { DbgPrint("[xbdm] Called 445\n"); return 0; }
int Ordinal_446() { DbgPrint("[xbdm] Called 446\n"); return 0; }
int Ordinal_447() { DbgPrint("[xbdm] Called 447\n"); return 0; }
int Ordinal_448() { DbgPrint("[xbdm] Called 448\n"); return 0; }
int Ordinal_449() { DbgPrint("[xbdm] Called 449\n"); return 0; }
int Ordinal_450() { DbgPrint("[xbdm] Called 450\n"); return 0; }
int Ordinal_451() { DbgPrint("[xbdm] Called 451\n"); return 0; }
int Ordinal_452() { DbgPrint("[xbdm] Called 452\n"); return 0; }
int Ordinal_453() { DbgPrint("[xbdm] Called 453\n"); return 0; }
int Ordinal_454() { DbgPrint("[xbdm] Called 454\n"); return 0; }
int Ordinal_455() { DbgPrint("[xbdm] Called 455\n"); return 0; }
int Ordinal_456() { DbgPrint("[xbdm] Called 456\n"); return 0; }
int Ordinal_457() { DbgPrint("[xbdm] Called 457\n"); return 0; }
int Ordinal_458() { DbgPrint("[xbdm] Called 458\n"); return 0; }
int Ordinal_459() { DbgPrint("[xbdm] Called 459\n"); return 0; }
int Ordinal_460() { DbgPrint("[xbdm] Called 460\n"); return 0; }
int Ordinal_461() { DbgPrint("[xbdm] Called 461\n"); return 0; }
int Ordinal_462() { DbgPrint("[xbdm] Called 462\n"); return 0; }
int Ordinal_463() { DbgPrint("[xbdm] Called 463\n"); return 0; }
int Ordinal_464() { DbgPrint("[xbdm] Called 464\n"); return 0; }
int Ordinal_465() { DbgPrint("[xbdm] Called 465\n"); return 0; }
int Ordinal_466() { DbgPrint("[xbdm] Called 466\n"); return 0; }
int Ordinal_467() { DbgPrint("[xbdm] Called 467\n"); return 0; }
int Ordinal_468() { DbgPrint("[xbdm] Called 468\n"); return 0; }
int Ordinal_469() { DbgPrint("[xbdm] Called 469\n"); return 0; }
int Ordinal_470() { DbgPrint("[xbdm] Called 470\n"); return 0; }
int Ordinal_471() { DbgPrint("[xbdm] Called 471\n"); return 0; }
int Ordinal_472() { DbgPrint("[xbdm] Called 472\n"); return 0; }
int Ordinal_473() { DbgPrint("[xbdm] Called 473\n"); return 0; }
int Ordinal_474() { DbgPrint("[xbdm] Called 474\n"); return 0; }
int Ordinal_475() { DbgPrint("[xbdm] Called 475\n"); return 0; }
int Ordinal_476() { DbgPrint("[xbdm] Called 476\n"); return 0; }
int Ordinal_477() { DbgPrint("[xbdm] Called 477\n"); return 0; }
int Ordinal_478() { DbgPrint("[xbdm] Called 478\n"); return 0; }
int Ordinal_479() { DbgPrint("[xbdm] Called 479\n"); return 0; }
int Ordinal_480() { DbgPrint("[xbdm] Called 480\n"); return 0; }
int Ordinal_481() { DbgPrint("[xbdm] Called 481\n"); return 0; }
int Ordinal_482() { DbgPrint("[xbdm] Called 482\n"); return 0; }
int Ordinal_483() { DbgPrint("[xbdm] Called 483\n"); return 0; }
int Ordinal_484() { DbgPrint("[xbdm] Called 484\n"); return 0; }
int Ordinal_485() { DbgPrint("[xbdm] Called 485\n"); return 0; }
int Ordinal_486() { DbgPrint("[xbdm] Called 486\n"); return 0; }
int Ordinal_487() { DbgPrint("[xbdm] Called 487\n"); return 0; }
int Ordinal_488() { DbgPrint("[xbdm] Called 488\n"); return 0; }
int Ordinal_489() { DbgPrint("[xbdm] Called 489\n"); return 0; }
int Ordinal_490() { DbgPrint("[xbdm] Called 490\n"); return 0; }
int Ordinal_491() { DbgPrint("[xbdm] Called 491\n"); return 0; }
int Ordinal_492() { DbgPrint("[xbdm] Called 492\n"); return 0; }
int Ordinal_493() { DbgPrint("[xbdm] Called 493\n"); return 0; }
int Ordinal_494() { DbgPrint("[xbdm] Called 494\n"); return 0; }
int Ordinal_495() { DbgPrint("[xbdm] Called 495\n"); return 0; }
int Ordinal_496() { DbgPrint("[xbdm] Called 496\n"); return 0; }
int Ordinal_497() { DbgPrint("[xbdm] Called 497\n"); return 0; }
int Ordinal_498() { DbgPrint("[xbdm] Called 498\n"); return 0; }
int Ordinal_499() { DbgPrint("[xbdm] Called 499\n"); return 0; }
int Ordinal_500() { DbgPrint("[xbdm] Called 500\n"); return 0; }
int Ordinal_501() { DbgPrint("[xbdm] Called 501\n"); return 0; }
int Ordinal_502() { DbgPrint("[xbdm] Called 502\n"); return 0; }
int Ordinal_503() { DbgPrint("[xbdm] Called 503\n"); return 0; }
int Ordinal_504() { DbgPrint("[xbdm] Called 504\n"); return 0; }
int Ordinal_505() { DbgPrint("[xbdm] Called 505\n"); return 0; }
int Ordinal_506() { DbgPrint("[xbdm] Called 506\n"); return 0; }
int Ordinal_507() { DbgPrint("[xbdm] Called 507\n"); return 0; }
int Ordinal_508() { DbgPrint("[xbdm] Called 508\n"); return 0; }
int Ordinal_509() { DbgPrint("[xbdm] Called 509\n"); return 0; }
int Ordinal_510() { DbgPrint("[xbdm] Called 510\n"); return 0; }
int Ordinal_511() { DbgPrint("[xbdm] Called 511\n"); return 0; }
int Ordinal_512() { DbgPrint("[xbdm] Called 512\n"); return 0; }


int Ordinal_14() { DbgPrint("[xbdm] Called 14\n"); return 0; }
int Ordinal_18() { DbgPrint("[xbdm] Called 18\n"); return 0; }
int Ordinal_44() { DbgPrint("[xbdm] Called 44\n"); return 0; }
int Ordinal_86() { DbgPrint("[xbdm] Called 86\n"); return 0; }
int Ordinal_87() { DbgPrint("[xbdm] Called 87\n"); return 0; }

int Ordinal_100() { DbgPrint("[xbdm] Called 100\n"); return 0;}
int Ordinal_101() { DbgPrint("[xbdm] Called 101\n"); return 0;}
int Ordinal_102() { DbgPrint("[xbdm] Called 102\n"); return 0;}
int Ordinal_103() { DbgPrint("[xbdm] Called 103\n"); return 0;}
int Ordinal_104() { DbgPrint("[xbdm] Called 104\n"); return 0;}
int Ordinal_105() { DbgPrint("[xbdm] Called 105\n"); return 0;}
int Ordinal_116() { DbgPrint("[xbdm] Called 106\n"); return 0;}
int Ordinal_126() { DbgPrint("[xbdm] Called 126\n"); return 0;}
int Ordinal_127() { DbgPrint("[xbdm] Called 127\n"); return 0;}
int Ordinal_128() { DbgPrint("[xbdm] Called 128\n"); return 0;}
int Ordinal_129() { DbgPrint("[xbdm] Called 129\n"); return 0;}
int Ordinal_138() { DbgPrint("[xbdm] Called 138\n"); return 0;}
int Ordinal_139() { DbgPrint("[xbdm] Called 139\n"); return 0;}
int Ordinal_23() { DbgPrint("[xbdm] Called 23\n"); return 0;}
int Ordinal_29() { DbgPrint("[xbdm] Called 29\n"); return 0;}
int Ordinal_31() { DbgPrint("[xbdm] Called 31\n"); return 0;}
int Ordinal_47() { DbgPrint("[xbdm] Called 47\n"); return 0;}
int Ordinal_50() { DbgPrint("[xbdm] Called 50\n"); return 0;}
int Ordinal_54() { DbgPrint("[xbdm] Called 54\n"); return 0;}
int Ordinal_67() { DbgPrint("[xbdm] Called 67\n"); return 0;}
int Ordinal_68() { DbgPrint("[xbdm] Called 68\n"); return 0;}
int Ordinal_69() { DbgPrint("[xbdm] Called 69\n"); return 0;}
int Ordinal_93() { DbgPrint("[xbdm] Called 93\n"); return 0;}
int Ordinal_94() { DbgPrint("[xbdm] Called 94\n"); return 0;}
int Ordinal_95() { DbgPrint("[xbdm] Called 95\n"); return 0;}
int Ordinal_96() { DbgPrint("[xbdm] Called 96\n"); return 0;}
int Ordinal_97() { DbgPrint("[xbdm] Called 97\n"); return 0;}
int Ordinal_98() { DbgPrint("[xbdm] Called 98\n"); return 0;}
int Ordinal_99() { DbgPrint("[xbdm] Called 99\n"); return 0;}