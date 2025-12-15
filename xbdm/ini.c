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

//extern DMCMD rgbcmd[];
//extern int cchcmd;

void FLoadGlobals()
{
	HANDLE hFile;
	NTSTATUS st;
	char szBuf[0x200];
	char sz[0x200];
	int cch, i;

	st = FCreateFile(&hFile, GENERIC_READ | SYNCHRONIZE, "Hdd:\\xbdm.ini", NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT);
	if(FAILED(st))
		st = FCreateFile(&hFile, GENERIC_READ | SYNCHRONIZE, "IntUsb:\\xbdm.ini", NULL, 0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT);

	if(NT_SUCCESS(st))
	{
		ZeroMemory(szBuf, sizeof(szBuf));
		ZeroMemory(sz, sizeof(sz));

		cch = 0;
		while(NT_SUCCESS(st))
		{
			st = FReadFile(hFile, szBuf + cch, 1);
			
			if(FAILED(st) || szBuf[cch] == '\n') // FAILED(st) == END_OF_FILE
			{
				szBuf[cch] = 0;
				cch = 0;

				for(i = 0;szBuf[i];i++)
				{
					if(szBuf[i] == ' ')
						break;
				}

				if(szBuf[i] == ' ')
					for(cch = 0;cch < cchcmdlen;cch++)
						if(!strnicmp(rgbcmd[cch].szName, szBuf, i))
							rgbcmd[cch].pdmcp(szBuf, sz, sizeof(sz), NULL); // The ini settings is basically just a list of commands to execute

				cch = 0;
			}
			else if(szBuf[cch] != '\r') // dont include \r
				cch++;

			if(cch == 0)
			{
				ZeroMemory(szBuf, sizeof(szBuf));
				ZeroMemory(sz, sizeof(sz));
			}

			if(cch == sizeof(szBuf))
			{
				DbgPrint("[xbdm] Line too long!\n");
				st = E_INVALIDARG;
			}
		}

		NtClose(hFile);
	}
	else
	{
		DbgPrint("[xbdm] unable to open settings file for reading, result 0x%08x\n", st);

		if(st != STATUS_OBJECT_NAME_NOT_FOUND)
			DebugBreak();
	}
}

void FWriteGlobals()
{
	HANDLE hFile;
	NTSTATUS st;
	INF inf;

	inf.cbBuf = 0x1000;
	inf.cbUsed = 0;
	inf.pbBuf = ExAllocatePoolWithTag(0x1000, 'Xbdm');

	if(!inf.pbBuf)
	{
		DbgPrint("[xbdm] unable to allocate memory for settings write\n");
		return;
	}

	st = FCreateFile(&hFile, GENERIC_WRITE | SYNCHRONIZE, "Hdd:\\xbdm.ini", NULL, 0, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT);
	if(FAILED(st))
		st = FCreateFile(&hFile, GENERIC_WRITE | SYNCHRONIZE, "IntUsb:\\xbdm.ini", NULL, 0, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT);

	if(NT_SUCCESS(st))
	{
		// Debug name
		FWriteText(hFile, &inf, "dbgname name=\"%s\"\r\n", g_dmGlobals.rgchDbgName);

		// FLASH:\\ in Neighborhood
		if(g_dmGlobals.bDriveMap)
			FWriteText(hFile, &inf, "drivemap internal\r\n");

		// Console image in Neighborhood
		FWriteText(hFile, &inf, "setcolor name=\"");

		switch(g_dmGlobals.dwConsoleColor)
		{
		case CONSOLE_COLOR_FLAG_BLACK:
			FWriteText(hFile, &inf, "black"); // Black
			break;
		case CONSOLE_COLOR_FLAG_BLUE:
			FWriteText(hFile, &inf, "grayblue"); // Gray Blue
			break;
		case (CONSOLE_COLOR_FLAG_BLACK | CONSOLE_COLOR_FLAG_BLUE):
			FWriteText(hFile, &inf, "blue"); // Blue
			break;
		case CONSOLE_COLOR_FLAG_WHITE:
			FWriteText(hFile, &inf, "white"); // White
			break;
		default:
			FWriteText(hFile, &inf, "nosidecar");
			break;
		}

		FWriteText(hFile, &inf, "\"\r\n");

		// The debug dump mode
		FWriteText(hFile, &inf, "dumpmode %s\r\n", rgszDumpMode[g_dmGlobals.dwDumpMode]);

		// Close and flush to disk
		FCloseFile(hFile, &inf);
	}
	else
	{
		DbgPrint("[xbdm] unable to open settings file for writing, result 0x%08x\n", st);
		DebugBreak();
	}

	ExFreePool(inf.pbBuf);
}