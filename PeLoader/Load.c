// ReSharper disable CppClangTidyClangDiagnosticBadFunctionCast
#include <stdio.h>
#include <Windows.h>

#include "PEB.h"

static BOOL
// ReSharper disable once CppParameterMayBeConst
PeLdrProcessIat(DWORD dwMapBase)
{
	BOOL						ret = FALSE;
	PIMAGE_DOS_HEADER			pDosHeader;
	PIMAGE_NT_HEADERS			pNtHeaders;
	PIMAGE_IMPORT_DESCRIPTOR	pImportDesc;
	PIMAGE_THUNK_DATA			pThunkData;
	PIMAGE_THUNK_DATA			pThunkDataOrig;
	PIMAGE_IMPORT_BY_NAME		pImportByName;
	PIMAGE_EXPORT_DIRECTORY		pExportDir;
	DWORD						flError = 0;
	DWORD						dwTmp;
	BYTE* pLibName;
	HMODULE						hMod;

	printf("Processing IAT (Image Base: 0x%08lx)\n", dwMapBase);

	pDosHeader = (PIMAGE_DOS_HEADER)dwMapBase;
	pNtHeaders = (PIMAGE_NT_HEADERS)(dwMapBase + pDosHeader->e_lfanew);

	do {
		pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(dwMapBase +
			pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		if (!pImportDesc) {
			printf("IAT not found\n");
			break;
		}

		while ((pImportDesc->Name != 0) && (!flError)) {
			pLibName = (BYTE*)(dwMapBase + pImportDesc->Name);
			printf("Loading Library and processing Imports: %s\n", (CHAR*)pLibName);

			if (pImportDesc->ForwarderChain != -1) {  // NOLINT(clang-diagnostic-sign-compare)
				printf("FIXME: Cannot handle Import Forwarding\n");
				//flError = 1;
				//break;
			}

			hMod = LoadLibraryA((CHAR*)pLibName);
			if (!hMod) {
				printf("Failed to load library: %s\n", (const CHAR*)pLibName);
				flError = 1;
				break;
			}

			pThunkData = (PIMAGE_THUNK_DATA)(dwMapBase + pImportDesc->FirstThunk);
			if (pImportDesc->Characteristics == 0)
				/* Borland compilers doesn't produce Hint Table */
				pThunkDataOrig = pThunkData;
			else
				/* Hint Table */
				pThunkDataOrig = (PIMAGE_THUNK_DATA)(dwMapBase + pImportDesc->Characteristics);

			while (pThunkDataOrig->u1.AddressOfData != 0) {
				if (pThunkDataOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
					/* Import via. Export Ordinal */
					PIMAGE_DOS_HEADER		dos;
					PIMAGE_NT_HEADERS		nt;

					dos = (PIMAGE_DOS_HEADER)hMod;
					nt = (PIMAGE_NT_HEADERS)(((DWORD)hMod) + dos->e_lfanew);

					pExportDir = (PIMAGE_EXPORT_DIRECTORY)
						(((DWORD)hMod) + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
					dwTmp = (((DWORD)hMod) + pExportDir->AddressOfFunctions) + (((IMAGE_ORDINAL(pThunkDataOrig->u1.Ordinal) - pExportDir->Base)) * sizeof(DWORD));
					dwTmp = ((DWORD)hMod) + *((DWORD*)dwTmp);

					pThunkData->u1.Function = dwTmp;
				}
				else {
					pImportByName = (PIMAGE_IMPORT_BY_NAME)
						(dwMapBase + pThunkDataOrig->u1.AddressOfData);
					pThunkData->u1.Function = (DWORD)GetProcAddress(hMod, (LPCSTR)pImportByName->Name);

					if (!pThunkData->u1.Function) {
						printf("Failed to resolve API: %s!%s\n",
							(CHAR*)pLibName, (CHAR*)pImportByName->Name);
						flError = 1;
						break;
					}
				}

				pThunkDataOrig++;
				pThunkData++;
			}

			pImportDesc++;
		}

		if (!flError)
			ret = TRUE;

	} while (0);
	return ret;
}

#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)

int main(int argc, char* argv[])
{
	char fileName[MAX_PATH] = { 0 };
	memcpy_s(&fileName, MAX_PATH, argv[1], MAX_PATH);
	//char fileName[] = "C:\\Windows\\System32\\notepad.exe";
	//char fileName[] = "C:\\Users\\Philip\\source\\repos\\PE2ShellCode\\Release\\TestExe.exe";

	HANDLE	hFile = NULL;
	DWORD	dwFileSize = 0;
	DWORD	dwBytesRead = 0;
	DWORD	ret = 0;
	DWORD	dwLoaderBase;
	DWORD	i;
	DWORD	dwMapBase = 0;
	DWORD	dwOld;
	DWORD	dwEp;
	LPVOID	lpFileData = NULL;

	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeaders;

	_PPEB	peb;

	MEMORY_BASIC_INFORMATION	mi;
	PIMAGE_SECTION_HEADER		pSectionHeader;

	NTSTATUS(NTAPI * NtUnmapViewOfSection)
		(HANDLE, LPVOID) = NULL;

	// open file
	hFile = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Could not read file\n");
		ret = -1;
		goto Cleanup;
	}

	// allocate heap
	dwFileSize = GetFileSize(hFile, NULL);
	lpFileData = HeapAlloc(GetProcessHeap(), 0, dwFileSize);

	// read file bytes to memory
	if (!ReadFile(hFile, lpFileData, dwFileSize, &dwBytesRead, NULL))
	{
		printf("Unable to read file into memory\n");
		ret = -1;
		goto Cleanup;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)lpFileData;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("DOS Signature invalid\n");
		ret = -1;
		goto Cleanup;
	}

	pNtHeaders = (PIMAGE_NT_HEADERS)(((DWORD_PTR)lpFileData) + pDosHeader->e_lfanew);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("NT Signature mismatch\n");
		ret = -1;
		goto Cleanup;
	}

	peb = (_PPEB)__readfsdword(0x30);
	dwLoaderBase = (DWORD)peb->lpImageBaseAddress;

	printf("Mapping Target PE File\n");

	NtUnmapViewOfSection = (NTSTATUS(NTAPI*)(HANDLE, LPVOID))
		GetProcAddress(GetModuleHandle(TEXT("ntdll.dll")), "ZwUnmapViewOfSection");
	if (!NtUnmapViewOfSection)
	{
		printf("Failed to resolve address of NtUnmapViewOfSection\n");
		ret = -1;
		goto Cleanup;
	}

	do {
		printf("Target PE Load Base: 0x%08lx Image Size: 0x%08lx\n",
			pNtHeaders->OptionalHeader.ImageBase,
			pNtHeaders->OptionalHeader.SizeOfImage);

		// Find the size of our mapping
		i = dwLoaderBase;
		while (VirtualQuery((LPVOID)i, &mi, sizeof(mi))) {
			if (mi.State == MEM_FREE)
				break;

			i += mi.RegionSize;
		}

		if ((pNtHeaders->OptionalHeader.ImageBase >= dwLoaderBase) &&
			(pNtHeaders->OptionalHeader.ImageBase < i)) {
			if (NtUnmapViewOfSection) {
				printf("Unmapping original loader mapping\n");
				if (NtUnmapViewOfSection(GetCurrentProcess(), (VOID*)dwLoaderBase) == STATUS_SUCCESS) {
					dwMapBase = (DWORD)VirtualAlloc((LPVOID)pNtHeaders->OptionalHeader.ImageBase,
						pNtHeaders->OptionalHeader.SizeOfImage + 1,
						MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
				}
				else {
					printf("Failed to unmap original loader mapping\n");
				}
			}
		}

		dwMapBase = (DWORD)VirtualAlloc((LPVOID)pNtHeaders->OptionalHeader.ImageBase,
			pNtHeaders->OptionalHeader.SizeOfImage + 1,
			MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		if (!dwMapBase)
			printf("Failed to allocate PE ImageBase: 0x%08lx\n",
				pNtHeaders->OptionalHeader.ImageBase);

		if (!dwMapBase) {
			printf("Attempting to allocate new memory\n");

			if (!pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
				printf("Failed to map required memory address, need relocation to continue\n");
				printf("[WARNING] Forcing re-use of mapped memory\n");

				dwMapBase = (DWORD)pNtHeaders->OptionalHeader.ImageBase;
			}
			else {
				dwMapBase = (DWORD)VirtualAlloc(NULL, pNtHeaders->OptionalHeader.SizeOfImage + 1,
					MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			}
		}

		if (!dwMapBase) {
			printf("Failed to map memory for Target PE\n");
			break;
		}

		printf("Allocated memory for Target PE: 0x%08lx\n", dwMapBase);

		printf("Copying Headers\n");
		CopyMemory((LPVOID)dwMapBase, lpFileData,
			pNtHeaders->OptionalHeader.SizeOfHeaders);

		printf("Copying Sections\n");
		pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
		for (i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
			printf("Copying Section: %s\n", (CHAR*)pSectionHeader[i].Name);
			printf("Characteristics: 0x%lX\n", pSectionHeader[i].Characteristics);

			CopyMemory(
				(LPVOID)(dwMapBase + pSectionHeader[i].VirtualAddress),
				(LPVOID)((DWORD)lpFileData + pSectionHeader[i].PointerToRawData),
				pSectionHeader[i].SizeOfRawData
			);
		}

	} while (0);

	if (!PeLdrProcessIat(dwMapBase))
	{
		printf("Iat processing failed\n");
		ret = -1;
		goto Cleanup;
	}

	// TODO: Fix permission as per section flags
	if (!VirtualProtect((LPVOID)dwMapBase, pNtHeaders->OptionalHeader.SizeOfImage,
		PAGE_EXECUTE_READWRITE, &dwOld))
	{
		printf("Failed to change mapping protection\n");
		ret = -1;
		goto Cleanup;
	}

	printf("Fixing Image Base address in PEB\n");
	peb->lpImageBaseAddress = (LPVOID)dwMapBase;

	dwEp = dwMapBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint;
	printf("Executing Entry Point: 0x%08lx\n", dwEp);

	__asm {
		mov eax, dwEp
		call eax
		int 3
	}

Cleanup:
	if (lpFileData)
		HeapFree(GetProcessHeap(), 0, lpFileData);

	if (dwMapBase)
		VirtualFree((LPVOID)dwMapBase, 0, MEM_RELEASE);

	return ret;
}
